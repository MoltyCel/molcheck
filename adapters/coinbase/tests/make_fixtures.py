"""Writes tests/fixtures/pilot/: responses in the shape the Advanced Trade API documents.

These are constructed fixtures, built from the documented response schemas (List Fills,
List Orders, Get Portfolio Breakdown, Get Product Candles, Get API Key Permissions). A live
run with `--record DIR` stores real responses in the same format, account ids replaced.

Run: python3 tests/make_fixtures.py
"""
import json
import pathlib
import sys
from datetime import datetime, timezone

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "src"))

from molcheck_coinbase.fixtures import request_key  # noqa: E402

OUT = HERE / "fixtures" / "pilot"
PORTFOLIO = "redacted-0a1b2c3d4e5f"
NOW = "2026-11-12T00:00:00.000000Z"
BASELINE = "2026-11-10T00:00:00.000000Z"


def epoch(text):
    return int(datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp())


def fill(entry, order, product, side, price, size, t, commission, size_in_quote=False,
         trade_type="FILL"):
    return {"entry_id": entry, "trade_id": "t-" + entry, "order_id": order,
            "trade_time": t, "trade_type": trade_type, "price": price, "size": size,
            "commission": commission, "product_id": product, "sequence_timestamp": t,
            "liquidity_indicator": "TAKER", "size_in_quote": size_in_quote,
            "user_id": "redacted-5e6f7a8b9c0d", "side": side,
            "retail_portfolio_id": PORTFOLIO}


FILLS = [
    # before the baseline: ignored
    fill("e0", "o0", "BTC-USD", "BUY", "85000.00", "0.001", "2026-11-09T23:00:00.000Z", "0.51"),
    # 1: 90.00 USD, all limits held
    fill("e1", "o1", "BTC-USD", "BUY", "90000.00", "0.001", "2026-11-10T09:15:20.123Z", "0.54"),
    # 2: 60.00 USD placed in quote currency
    fill("e2", "o2", "ETH-USD", "BUY", "3000.00", "60.00", "2026-11-10T12:00:05.500Z", "0.36",
         size_in_quote=True),
    # 3: second fill of o2, order total 120.00 > 100.00 cap
    fill("e3", "o2", "ETH-USD", "BUY", "3000.00", "0.02", "2026-11-10T12:00:06.000Z", "0.36"),
    # adjustment entry: listed, not counted
    fill("e3r", "o2", "ETH-USD", "BUY", "3000.00", "0.02", "2026-11-10T12:30:00.000Z", "0",
         trade_type="CORRECTION"),
    # 4: ETH has dropped, loss 31.74 > 15.00
    fill("e4", "o3", "BTC-USD", "SELL", "80000.00", "0.001", "2026-11-11T10:00:00.000Z", "0.48"),
]

CANDLES = {  # (product, minute) -> open
    ("BTC-USD", "2026-11-10T09:15:00Z"): "90010.00",
    ("BTC-USD", "2026-11-10T12:00:00Z"): "89900.00",
    ("ETH-USD", "2026-11-10T12:00:00Z"): "3001.00",
    ("ETH-USD", "2026-11-11T10:00:00Z"): "2500.00",
}


def write(path, query, response):
    OUT.mkdir(parents=True, exist_ok=True)
    name = request_key("GET", path, query) + ".json"
    (OUT / name).write_text(json.dumps({"method": "GET", "path": path, "query": query,
                                        "response": response}, indent=2, sort_keys=True) + "\n")


def main():
    for old in OUT.glob("*.json"):
        old.unlink()
    write("/key_permissions", {}, {"can_view": True, "can_trade": False, "can_transfer": False,
                                   "portfolio_uuid": PORTFOLIO, "portfolio_type": "CONSUMER"})
    write("/orders/historical/fills",
          {"start_sequence_timestamp": BASELINE, "end_sequence_timestamp": NOW, "limit": 250,
           "sort_by": "TRADE_TIME"},
          {"fills": FILLS, "cursor": "", "proof_token_required": False})
    write("/orders/historical/batch", {"order_status": "OPEN", "limit": 250},
          {"orders": [{"order_id": "o9", "product_id": "ETH-USD", "side": "SELL",
                       "status": "OPEN", "created_time": "2026-11-11T11:00:00Z",
                       "filled_size": "0", "retail_portfolio_id": PORTFOLIO}],
           "has_next": False, "cursor": ""})
    write(f"/portfolios/{PORTFOLIO}", {}, {"breakdown": {
        "portfolio": {"name": "redacted-1111", "uuid": PORTFOLIO, "type": "CONSUMER"},
        "spot_positions": [
            {"asset": "USD", "total_balance_crypto": "368.26", "is_cash": True},
            {"asset": "ETH", "total_balance_crypto": "0.04", "is_cash": False},
            {"asset": "BTC", "total_balance_crypto": "0", "is_cash": False}],
        "futures_positions": [], "perp_positions": []}})
    for (product, minute), open_ in CANDLES.items():
        start = epoch(minute)
        write(f"/products/{product}/candles",
              {"start": str(start), "end": str(start + 60), "granularity": "ONE_MINUTE"},
              {"candles": [{"start": str(start), "low": open_, "high": open_, "open": open_,
                            "close": open_, "volume": "1"}]})
    print(f"wrote {len(list(OUT.glob('*.json')))} fixtures to {OUT}")


if __name__ == "__main__":
    main()
