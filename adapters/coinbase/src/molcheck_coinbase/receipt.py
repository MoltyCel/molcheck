"""Turn Coinbase fills into AER receipts: one decision per fill, checked against the mandate.

Each receipt is a JSON object that `moltrust-verify --input <receipt> --trust-list <trust>`
reads directly: `record`, `bundle`, `mandate`, `transaction`. The extra key
`molcheck_receipt` carries the human-readable account of the numbers: window definition,
loss basis, valuation time, prices, and the portfolio status at the time of the run. The
verifier ignores it.

How the mandate maps onto the AER kernel
----------------------------------------
One grant for the action {verb: trade, venue: coinbase-advanced, market: spot} with four
constraints:

- `exact` quote_currency: the fill trades against the mandate's quote currency.
- `evidence_range` on `coinbase.order_notional`: single-order cap.
- `evidence_range` on `coinbase.volume_24h`: rolling 24-hour volume cap.
- `evidence_range` on `coinbase.loss_mtm`: loss threshold.

The three numbers are evidence items signed by the adapter's Ed25519 key. Each item's
window is the decision second (valid_from = valid_until = T) and its nonce names the
Coinbase fill (`coinbase-entry:<entry_id>`), so a signed number cannot be moved to another
fill without breaking the signature. Coinbase does not sign fills; the trust list therefore
names the adapter key, and anyone holding the same fills can recompute the numbers from the
definitions in `molcheck_receipt`.
"""
from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import ROUND_HALF_EVEN, Decimal, getcontext
from typing import Any, Callable, Dict, List, Optional, Tuple

from moltrust_enforce import (
    PAYLOAD_TYPE, action_digest, build_bundle, evidence_payload_bytes, f_ext,
    make_envelope, make_statement, pae,
)
from moltrust_enforce.evidence import query_key

getcontext().prec = 50

RECEIPT_FORMAT = "molcheck-coinbase-receipt/1"
ACTION = {"verb": "trade", "venue": "coinbase-advanced", "market": "spot"}
ROUNDING = ("exact decimal arithmetic on the strings Coinbase returns; each reported number "
            "is rounded once to quote minor units, half-even")
WINDOW_SECONDS = 24 * 3600

# (asset, minute_epoch) -> price of one unit of `asset` in the quote currency, as a string.
PriceFn = Callable[[str, int], Optional[str]]
SignFn = Callable[[bytes], bytes]


class ReceiptError(Exception):
    pass


# ------------------------------------------------------------------ parsing helpers

def parse_time(value: str) -> datetime:
    """RFC 3339 from Coinbase, any fractional precision, to an aware UTC datetime."""
    text = value.strip().replace("Z", "+00:00")
    if "." in text:
        head, rest = text.split(".", 1)
        n = 0
        while n < len(rest) and rest[n].isdigit():
            n += 1
        digits, tz = rest[:n], rest[n:]
        text = f"{head}.{(digits + '000000')[:6]}{tz}"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        raise ReceiptError(f"timestamp without zone: {value}")
    return parsed.astimezone(timezone.utc)


def iso_second(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def iso_micro(moment: datetime) -> str:
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def minute_floor(moment: datetime) -> datetime:
    return moment.replace(second=0, microsecond=0)


def portfolio_ref(portfolio_uuid: str) -> str:
    """Receipts name the portfolio by a hash, never by its Coinbase UUID."""
    return "pf:" + hashlib.sha256(("coinbase-portfolio:" + portfolio_uuid).encode()).hexdigest()[:16]


# ------------------------------------------------------------------ mandate

@dataclass(frozen=True)
class PilotMandate:
    mandate_id: str
    agent: str
    quote_currency: str
    quote_decimals: int
    max_order_notional: Decimal
    max_volume_24h: Decimal
    max_loss: Decimal
    baseline_as_of: datetime
    baseline_holdings: Dict[str, Decimal]

    @staticmethod
    def from_json(blob: Dict[str, Any]) -> "PilotMandate":
        try:
            baseline = blob["baseline"]
            mandate = PilotMandate(
                mandate_id=str(blob["mandate_id"]),
                agent=str(blob["agent"]),
                quote_currency=str(blob["quote_currency"]).upper(),
                quote_decimals=int(blob.get("quote_decimals", 2)),
                max_order_notional=Decimal(str(blob["max_order_notional"])),
                max_volume_24h=Decimal(str(blob["max_volume_24h"])),
                max_loss=Decimal(str(blob["max_loss"])),
                baseline_as_of=parse_time(str(baseline["as_of"])),
                baseline_holdings={str(k).upper(): Decimal(str(v))
                                   for k, v in dict(baseline["holdings"]).items()},
            )
        except (KeyError, TypeError, ValueError, ArithmeticError) as exc:
            raise ReceiptError(f"mandate file incomplete or malformed: {exc}") from None
        for name in ("max_order_notional", "max_volume_24h", "max_loss"):
            if getattr(mandate, name) < 0:
                raise ReceiptError(f"mandate {name} is negative")
        if not 0 <= mandate.quote_decimals <= 8:
            raise ReceiptError("mandate quote_decimals outside 0..8")
        return mandate

    def minor(self, amount: Decimal) -> int:
        return int((amount * (Decimal(10) ** self.quote_decimals)).quantize(
            Decimal(1), rounding=ROUND_HALF_EVEN))

    def to_aae(self, pf_ref: str) -> Dict[str, Any]:
        q = self.quote_currency
        return {"mandate_version": "1.0", "grants": [{
            "action_binding": action_digest(ACTION),
            "type_fields": ["verb", "venue", "market"],
            "disposition": "allow",
            "constraints": [
                {"type": "exact", "field": "quote_currency", "value": q},
                {"type": "evidence_range", "query": query("coinbase.order_notional", pf_ref, q),
                 "lo": 0, "hi": self.minor(self.max_order_notional)},
                {"type": "evidence_range", "query": query("coinbase.volume_24h", pf_ref, q),
                 "lo": 0, "hi": self.minor(self.max_volume_24h)},
                {"type": "evidence_range", "query": query("coinbase.loss_mtm", pf_ref, q),
                 "lo": 0, "hi": self.minor(self.max_loss)},
            ]}]}


def query(kind: str, pf_ref: str, quote: str) -> Dict[str, Any]:
    return {"kind": kind, "portfolio": pf_ref, "quote": quote}


# ------------------------------------------------------------------ fills

@dataclass(frozen=True)
class Fill:
    raw: Dict[str, Any]
    entry_id: str
    order_id: str
    trade_id: str
    trade_type: str
    product_id: str
    base: str
    quote: str
    side: str
    price: Decimal
    size: Decimal
    size_in_quote: bool
    commission: Decimal
    time: datetime
    sort_key: Tuple

    @property
    def notional(self) -> Decimal:
        return self.size if self.size_in_quote else self.price * self.size

    @property
    def base_quantity(self) -> Decimal:
        return self.size / self.price if self.size_in_quote else self.size


def parse_fill(raw: Dict[str, Any]) -> Fill:
    try:
        product = str(raw["product_id"]).upper()
        parts = product.split("-")
        if len(parts) != 2 or not all(parts):
            raise ReceiptError(f"product {product} is not a spot pair; this adapter covers "
                               "spot fills only")
        base, quote = parts
        moment = parse_time(str(raw["trade_time"]))
        entry_id = str(raw.get("entry_id") or raw["trade_id"])
        fill = Fill(
            raw=raw, entry_id=entry_id, order_id=str(raw["order_id"]),
            trade_id=str(raw.get("trade_id", "")), trade_type=str(raw.get("trade_type", "FILL")),
            product_id=product, base=base, quote=quote, side=str(raw["side"]).upper(),
            price=Decimal(str(raw["price"])), size=Decimal(str(raw["size"])),
            size_in_quote=bool(raw.get("size_in_quote", False)),
            commission=Decimal(str(raw.get("commission") or "0")), time=moment,
            sort_key=(moment, str(raw.get("sequence_timestamp") or ""), entry_id))
    except (KeyError, ValueError, ArithmeticError) as exc:
        raise ReceiptError(f"fill not parseable: {type(exc).__name__}: {exc}") from None
    if fill.side not in ("BUY", "SELL") or fill.price <= 0 or fill.size < 0:
        raise ReceiptError(f"fill {entry_id} has an invalid side, price or size")
    return fill


# ------------------------------------------------------------------ status

def portfolio_status(observed_at: datetime, open_orders: List[dict], breakdown: Dict[str, Any],
                     fills: List[Fill], declared_stop_at: Optional[datetime]) -> Dict[str, Any]:
    """Agent stopped, open orders and open positions, each reported on its own."""
    positions = []
    for pos in breakdown.get("spot_positions") or []:
        if pos.get("is_cash"):
            continue
        qty = Decimal(str(pos.get("total_balance_crypto") or "0"))
        if qty != 0:
            positions.append({"market": "spot", "asset": str(pos.get("asset")),
                              "quantity": str(qty)})
    for kind in ("futures_positions", "perp_positions"):
        for pos in breakdown.get(kind) or []:
            positions.append({"market": kind.split("_")[0],
                              "asset": str(pos.get("product_id") or pos.get("symbol")),
                              "quantity": str(pos.get("number_of_contracts")
                                              or pos.get("net_size") or "")})

    orders = [{"product_id": o.get("product_id"), "side": o.get("side"),
               "status": o.get("status"), "created_time": o.get("created_time")}
              for o in open_orders]

    stopped: Dict[str, Any] = {
        "value": None,
        "declared_stop_at": iso_second(declared_stop_at) if declared_stop_at else None,
        "activity_after_stop": None,
        "basis": ("Coinbase has no API for an agent's run state. The agent counts as stopped "
                  "when its operator has revoked the agent's access (OAuth connection or "
                  "trading key) and declared that time with --agent-stopped-at, and no fill "
                  "and no open order was created after it. Without a declaration the value "
                  "is null."),
    }
    if declared_stop_at is not None:
        after = sum(1 for f in fills if f.time > declared_stop_at)
        after += sum(1 for o in open_orders if o.get("created_time")
                     and parse_time(str(o["created_time"])) > declared_stop_at)
        stopped["activity_after_stop"] = after
        stopped["value"] = after == 0

    return {"observed_at": iso_second(observed_at),
            "agent_stopped": stopped,
            "open_orders": {"count": len(orders), "orders": orders},
            "open_positions": {"count": len(positions), "positions": positions,
                               "basis": "portfolio breakdown at observed_at; cash balances "
                                        "excluded"}}


# ------------------------------------------------------------------ receipts

class _Book:
    """Holdings replayed from the baseline through every FILL in order."""

    def __init__(self, holdings: Dict[str, Decimal]):
        self.h: Dict[str, Decimal] = dict(holdings)

    def apply(self, f: Fill) -> None:
        sign = Decimal(1) if f.side == "BUY" else Decimal(-1)
        self.h[f.base] = self.h.get(f.base, Decimal(0)) + sign * f.base_quantity
        self.h[f.quote] = (self.h.get(f.quote, Decimal(0)) - sign * f.notional - f.commission)


def _value(holdings: Dict[str, Decimal], quote: str, minute: datetime,
           price_fn: PriceFn) -> Tuple[Decimal, Dict[str, str]]:
    total = Decimal(0)
    prices: Dict[str, str] = {}
    epoch = int(minute.timestamp())
    for asset in sorted(holdings):
        qty = holdings[asset]
        if asset == quote:
            total += qty
            continue
        if qty == 0:
            continue
        price = price_fn(asset, epoch)
        if price is None:
            raise ReceiptError(f"no {asset}-{quote} price for {iso_second(minute)}")
        prices[asset] = str(price)
        total += qty * Decimal(str(price))
    return total, prices


def build_receipts(mandate: PilotMandate, raw_fills: List[dict], portfolio_uuid: str,
                   price_fn: PriceFn, sign: SignFn, source_id: str, keyid: str,
                   status: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    pf_ref = portfolio_ref(portfolio_uuid)
    q = mandate.quote_currency
    aae = mandate.to_aae(pf_ref)

    parsed = sorted((parse_fill(r) for r in raw_fills), key=lambda f: f.sort_key)
    seen = set()
    fills: List[Fill] = []
    for f in parsed:
        if f.entry_id in seen:
            continue
        seen.add(f.entry_id)
        fills.append(f)
    in_force = [f for f in fills if f.time >= mandate.baseline_as_of]
    counted = [f for f in in_force if f.trade_type == "FILL"]
    adjustments = len(in_force) - len(counted)

    base_minute = minute_floor(mandate.baseline_as_of)
    baseline_value, baseline_prices = _value(mandate.baseline_holdings, q, base_minute, price_fn)

    book = _Book(mandate.baseline_holdings)
    receipts: List[Dict[str, Any]] = []
    for idx, f in enumerate(counted):
        book.apply(f)
        upto = counted[: idx + 1]
        same_quote = [g for g in upto if g.quote == q]
        window_start = max(f.time - timedelta(seconds=WINDOW_SECONDS), mandate.baseline_as_of)
        in_window = [g for g in same_quote if window_start <= g.time <= f.time]
        volume = sum((g.notional for g in in_window), Decimal(0))
        order_notional = sum((g.notional for g in upto if g.order_id == f.order_id), Decimal(0))

        minute = minute_floor(f.time)
        value_now, prices = _value(book.h, q, minute, price_fn)
        loss = max(Decimal(0), baseline_value - value_now)

        decision_ts = iso_second(f.time)
        nonce = "coinbase-entry:" + f.entry_id

        def item(kind: str, value: int) -> Dict[str, Any]:
            statement = make_statement(source_id, query(kind, pf_ref, q), value,
                                       decision_ts, decision_ts, nonce)
            payload = evidence_payload_bytes(statement)
            sig = sign(pae(PAYLOAD_TYPE, payload))
            return make_envelope(statement, [{"keyid": keyid,
                                              "sig": base64.b64encode(sig).decode("ascii")}])

        items = [item("coinbase.volume_24h", mandate.minor(volume)),
                 item("coinbase.loss_mtm", mandate.minor(loss))]
        if f.quote == q:
            # A fill in another quote currency has no order notional in the mandate's
            # currency; the item is left out and the constraint fails closed.
            items.append(item("coinbase.order_notional", mandate.minor(order_notional)))

        transaction = {
            "action": dict(ACTION),
            "quote_currency": f.quote,
            "base_currency": f.base,
            "product_id": f.product_id,
            "side": f.side,
            "price": str(f.price),
            "size": str(f.size),
            "size_in_quote": f.size_in_quote,
            "commission": str(f.commission),
            "trade_time": iso_micro(f.time),
            "entry_id": f.entry_id,
            "trade_id": f.trade_id,
            "order_id": f.order_id,
        }
        bundle = build_bundle(items, aae, transaction, decision_ts)
        record = f_ext(aae, transaction, bundle)

        meta = {
            "format": RECEIPT_FORMAT,
            "mandate_id": mandate.mandate_id,
            "agent": mandate.agent,
            "portfolio_ref": pf_ref,
            "fill": {"entry_id": f.entry_id, "order_id": f.order_id,
                     "trade_time": iso_micro(f.time), "decision_timestamp": decision_ts},
            "verdict": record.get("verdict"),
            "reason": record.get("reason"),
            "rounding": ROUNDING,
            # The kernel trace names evidence by query digest; this maps digest to name.
            "evidence_fields": {"evidence:" + query_key(query(k, pf_ref, q)): k for k in
                                ("coinbase.order_notional", "coinbase.volume_24h",
                                 "coinbase.loss_mtm")},
            "checks": {
                "order_cap": {
                    "value_minor": mandate.minor(order_notional) if f.quote == q else None,
                    "limit_minor": mandate.minor(mandate.max_order_notional),
                    "definition": ("sum of notional of every FILL entry of this order_id up to "
                                   "and including this fill; notional = price x size, or size "
                                   "when size_in_quote is true; commission excluded")},
                "volume_24h": {
                    "value_minor": mandate.minor(volume),
                    "limit_minor": mandate.minor(mandate.max_volume_24h),
                    "window": {
                        "start": iso_micro(window_start),
                        "end": iso_micro(f.time),
                        "definition": ("closed interval [trade_time - 24h, trade_time] at "
                                       "microsecond precision, start clipped at the mandate "
                                       "baseline; FILL entries in the mandate quote currency, "
                                       "buys and sells, ordered at or before this fill by "
                                       "(trade_time, sequence_timestamp, entry_id); notional "
                                       "as in order_cap; commission excluded"),
                        "fills_counted": len(in_window)}},
                "loss": {
                    "value_minor": mandate.minor(loss),
                    "limit_minor": mandate.minor(mandate.max_loss),
                    "basis": {
                        "definition": ("mark-to-market drawdown: baseline value minus the value "
                                       "of the holdings right after this fill, floored at 0; "
                                       "holdings = baseline holdings plus the effect of every "
                                       "FILL since the baseline, commission deducted in the "
                                       "quote currency; realized and unrealized together"),
                        "baseline_as_of": iso_micro(mandate.baseline_as_of),
                        "baseline_value_minor": mandate.minor(baseline_value),
                        "baseline_prices": baseline_prices,
                        "not_seen": ("deposits, withdrawals and transfers after the baseline; "
                                     "they shift the result and are outside a View-only key")},
                    "valuation": {
                        "time": iso_second(minute),
                        "price_source": ("open of the ONE_MINUTE candle that starts at the "
                                         "valuation time, GET /api/v3/brokerage/products/"
                                         "{ASSET}-{QUOTE}/candles"),
                        "portfolio_value_minor": mandate.minor(value_now),
                        "prices": prices}},
            },
            "status": status,
            "trust": ("the three numbers are evidence items signed by " + source_id + "; "
                      "Coinbase does not sign fills. Recompute them from the fills with the "
                      "definitions above; check the verdict with moltrust-verify."),
        }
        receipts.append({"record": record, "bundle": bundle, "mandate": aae,
                         "transaction": transaction, "molcheck_receipt": meta})

    summary = {"fills_seen": len(fills), "fills_before_baseline": len(fills) - len(in_force),
               "adjustment_entries_ignored": adjustments, "receipts": len(receipts),
               "verdicts": _count(r["record"].get("verdict") for r in receipts)}
    return receipts, summary


def _count(values) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for v in values:
        out[str(v)] = out.get(str(v), 0) + 1
    return out
