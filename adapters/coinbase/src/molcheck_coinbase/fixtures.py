"""Record live responses (with account identifiers replaced) and replay them offline."""
from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.parse
from typing import Any, Dict

from .client import Transport

# Values under these keys identify the account, an order or a trade and are replaced before
# anything is written. The same value always gets the same placeholder, so fills of one order
# still group together on replay.
REDACT_KEYS = {"portfolio_uuid", "retail_portfolio_id", "user_id", "account_uuid", "uuid",
               "account_id", "client_order_id", "name", "order_id", "trade_id", "entry_id",
               "asset_uuid"}

# Any other UUID-shaped value, wherever it appears, is replaced as well.
_UUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def request_key(method: str, path: str, query: Dict[str, Any]) -> str:
    q = urllib.parse.urlencode(sorted((k, str(v)) for k, v in query.items()))
    return hashlib.sha256(f"{method} {path}?{q}".encode()).hexdigest()[:20]


def _placeholder(value: str) -> str:
    return "redacted-" + hashlib.sha256(value.encode()).hexdigest()[:12]


def _redact(obj: Any, seen: Dict[str, str]) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in REDACT_KEYS and isinstance(v, str) and v:
                seen.setdefault(v, _placeholder(v))
                out[k] = seen[v]
            else:
                out[k] = _redact(v, seen)
        return out
    if isinstance(obj, list):
        return [_redact(v, seen) for v in obj]
    if isinstance(obj, str) and _UUID.search(obj):
        def sub(match: "re.Match[str]") -> str:
            return seen.setdefault(match.group(0), _placeholder(match.group(0)))
        return _UUID.sub(sub, obj)
    return obj


def recording(inner: Transport, directory: str) -> Transport:
    os.makedirs(directory, exist_ok=True)
    seen: Dict[str, str] = {}

    def send(method: str, path: str, query: Dict[str, Any]) -> Any:
        response = inner(method, path, query)
        clean = _redact(response, seen)
        stored_path = path
        for original, placeholder in seen.items():
            stored_path = stored_path.replace(original, placeholder)
        with open(os.path.join(directory, request_key(method, stored_path, query) + ".json"),
                  "w", encoding="utf-8") as handle:
            json.dump({"method": method, "path": stored_path, "query": query,
                       "response": clean}, handle, indent=2, sort_keys=True)
        return response
    return send


def replay(directory: str) -> Transport:
    def send(method: str, path: str, query: Dict[str, Any]) -> Any:
        name = os.path.join(directory, request_key(method, path, query) + ".json")
        if not os.path.exists(name):
            raise FileNotFoundError(f"no recorded response for {method} {path} {sorted(query)}")
        with open(name, "r", encoding="utf-8") as handle:
            return json.load(handle)["response"]
    return send
