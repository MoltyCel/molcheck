"""Read-only client for the Coinbase Advanced Trade REST API.

Two locks keep this adapter read-only:

1. The client sends GET only, to an allowlist of read endpoints. There is no code path that
   builds a POST, PUT or DELETE.
2. Before any other request the client calls `GET /key_permissions` and refuses to continue
   unless the key can view and can neither trade nor transfer. A key with more rights is
   rejected, not downgraded, because the adapter cannot drop rights from a key.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Iterator, List, Optional

from .cdp_auth import API_HOST, CdpKey, build_jwt

BASE_PATH = "/api/v3/brokerage"

# Read endpoints this adapter may call. Anything else raises before a request is built.
_ALLOWED = (
    re.compile(r"^/key_permissions$"),
    re.compile(r"^/orders/historical/fills$"),
    re.compile(r"^/orders/historical/batch$"),
    re.compile(r"^/portfolios/[0-9A-Za-z-]{1,64}$"),
    re.compile(r"^/products/[0-9A-Z]{1,20}-[0-9A-Z]{1,20}/candles$"),
)

# transport(method, path, query) -> parsed JSON. Swapped for recorded fixtures in tests.
Transport = Callable[[str, str, Dict[str, Any]], Any]


class KeyTooPowerful(Exception):
    """The key has trade or transfer rights, or its rights cannot be established."""


class ApiError(Exception):
    pass


def http_transport(key: CdpKey, timeout: float = 20.0) -> Transport:
    def send(method: str, path: str, query: Dict[str, Any]) -> Any:
        full_path = BASE_PATH + path
        url = f"https://{API_HOST}{full_path}"
        if query:
            url += "?" + urllib.parse.urlencode(query, doseq=True)
        request = urllib.request.Request(url, method=method, headers={
            "Authorization": "Bearer " + build_jwt(key, method, full_path),
            "Accept": "application/json",
            "User-Agent": "molcheck-coinbase/0.1",
        })
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Body may echo request details; report status and path only.
            raise ApiError(f"HTTP {exc.code} on GET {path}") from None
    return send


def check_permissions(perms: Any) -> Dict[str, Any]:
    """Fail closed: every flag must be present and boolean, view on, trade and transfer off."""
    if not isinstance(perms, dict):
        raise KeyTooPowerful("key_permissions response is not an object")
    flags = {}
    for name in ("can_view", "can_trade", "can_transfer"):
        value = perms.get(name)
        if not isinstance(value, bool):
            raise KeyTooPowerful(f"key_permissions.{name} missing or not boolean")
        flags[name] = value
    if not flags["can_view"]:
        raise KeyTooPowerful("key cannot view; the adapter needs the View permission")
    granted = [n for n in ("can_trade", "can_transfer") if flags[n]]
    if granted:
        raise KeyTooPowerful("key has " + " and ".join(granted) + "; create a key with View "
                             "only. The adapter does not run with trade or transfer rights.")
    portfolio = perms.get("portfolio_uuid")
    if not isinstance(portfolio, str) or not portfolio:
        raise KeyTooPowerful("key is not bound to a portfolio")
    return {**flags, "portfolio_uuid": portfolio,
            "portfolio_type": perms.get("portfolio_type")}


class ReadOnlyClient:
    def __init__(self, transport: Transport):
        self._send = transport
        self.permissions: Optional[Dict[str, Any]] = None

    def _get(self, path: str, query: Optional[Dict[str, Any]] = None) -> Any:
        if not any(p.match(path) for p in _ALLOWED):
            raise ApiError(f"path not on the read allowlist: {path}")
        if self.permissions is None and path != "/key_permissions":
            raise KeyTooPowerful("permissions not checked yet")
        return self._send("GET", path, dict(query or {}))

    def verify_read_only(self) -> Dict[str, Any]:
        self.permissions = None
        self.permissions = check_permissions(self._get("/key_permissions"))
        return self.permissions

    @property
    def portfolio_uuid(self) -> str:
        assert self.permissions is not None
        return self.permissions["portfolio_uuid"]

    def fills(self, start: str, end: str) -> List[dict]:
        out: List[dict] = []
        cursor = ""
        for _ in range(1000):
            query = {"start_sequence_timestamp": start, "end_sequence_timestamp": end,
                     "limit": 250, "sort_by": "TRADE_TIME"}
            if cursor:
                query["cursor"] = cursor
            page = self._get("/orders/historical/fills", query)
            out.extend(page.get("fills") or [])
            cursor = page.get("cursor") or ""
            if not cursor or not page.get("fills"):
                return out
        raise ApiError("fills pagination did not terminate")

    def open_orders(self) -> List[dict]:
        out: List[dict] = []
        cursor = ""
        for _ in range(1000):
            query: Dict[str, Any] = {"order_status": "OPEN", "limit": 250}
            if cursor:
                query["cursor"] = cursor
            page = self._get("/orders/historical/batch", query)
            out.extend(page.get("orders") or [])
            cursor = page.get("cursor") or ""
            if not page.get("has_next") or not cursor:
                return out
        raise ApiError("orders pagination did not terminate")

    def portfolio_breakdown(self) -> dict:
        return self._get(f"/portfolios/{self.portfolio_uuid}").get("breakdown") or {}

    def minute_open(self, product_id: str, minute_epoch: int) -> Optional[str]:
        """Open price of the ONE_MINUTE candle that starts at `minute_epoch`."""
        page = self._get(f"/products/{product_id}/candles", {
            "start": str(minute_epoch), "end": str(minute_epoch + 60),
            "granularity": "ONE_MINUTE"})
        for candle in page.get("candles") or []:
            if str(candle.get("start")) == str(minute_epoch):
                return candle.get("open")
        return None
