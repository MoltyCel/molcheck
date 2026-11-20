"""molcheck-coinbase: keygen, trust-list, run, summary."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import fixtures, signing
from .cdp_auth import KeyLoadError, load_key
from .client import ApiError, KeyTooPowerful, ReadOnlyClient, http_transport
from .receipt import (
    PilotMandate, ReceiptError, build_receipts, iso_micro, parse_fill, parse_time,
    portfolio_status,
)


def _write_json(path: str, payload: Any) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def cmd_keygen(args: argparse.Namespace) -> int:
    signing.generate(args.out)
    key = signing.load(args.out)
    print(f"signing key written to {args.out} (mode 0600)")
    print(f"keyid {signing.keyid(key)}")
    return 0


def cmd_trust_list(args: argparse.Namespace) -> int:
    key = signing.load(args.signing_key)
    source_id = args.source_id or signing.default_source_id(key)
    print(json.dumps(signing.trust_list(key, source_id), indent=2, sort_keys=True))
    return 0


def run(client: ReadOnlyClient, mandate: PilotMandate, signing_key, source_id: str,
        now: datetime, stop_at: Optional[datetime]) -> tuple:
    perms = client.verify_read_only()
    raw_fills = client.fills(iso_micro(mandate.baseline_as_of), iso_micro(now))
    open_orders = client.open_orders()
    breakdown = client.portfolio_breakdown()

    cache: Dict[tuple, Optional[str]] = {}

    def price(asset: str, minute_epoch: int) -> Optional[str]:
        k = (asset, minute_epoch)
        if k not in cache:
            cache[k] = client.minute_open(f"{asset}-{mandate.quote_currency}", minute_epoch)
        return cache[k]

    parsed = [parse_fill(r) for r in raw_fills]
    status = portfolio_status(now, open_orders, breakdown, parsed, stop_at)
    sign, keyid = signing.signer(signing_key)
    receipts, summary = build_receipts(mandate, raw_fills, perms["portfolio_uuid"], price,
                                       sign, source_id, keyid, status)
    return receipts, summary, status


def cmd_run(args: argparse.Namespace) -> int:
    with open(args.mandate, "r", encoding="utf-8") as handle:
        mandate = PilotMandate.from_json(json.load(handle))
    signing_key = signing.load(args.signing_key)
    source_id = args.source_id or signing.default_source_id(signing_key)

    if args.fixtures:
        transport = fixtures.replay(args.fixtures)
    else:
        transport = http_transport(load_key(args.cdp_key))
        if args.record:
            transport = fixtures.recording(transport, args.record)
    now = parse_time(args.now) if args.now else datetime.now(timezone.utc).replace(microsecond=0)
    stop_at = parse_time(args.agent_stopped_at) if args.agent_stopped_at else None

    receipts, summary, status = run(ReadOnlyClient(transport), mandate, signing_key,
                                    source_id, now, stop_at)
    os.makedirs(args.out, exist_ok=True)
    for r in receipts:
        meta = r["molcheck_receipt"]
        name = f"{meta['fill']['decision_timestamp'].replace(':', '')}-{meta['fill']['entry_id']}"
        _write_json(os.path.join(args.out, f"receipt-{name}.json"), r)
    _write_json(os.path.join(args.out, "trust.json"), signing.trust_list(signing_key, source_id))
    _write_json(os.path.join(args.out, "run.json"), {
        "observed_at": status["observed_at"], "summary": summary, "status": status})
    print(json.dumps(redacted_summary(receipts, summary, status), indent=2, sort_keys=True))
    return 0


def redacted_summary(receipts: List[dict], summary: Dict[str, Any],
                     status: Dict[str, Any]) -> Dict[str, Any]:
    """What can be posted publicly: verdicts and checks against limits, no identifiers,
    no prices, sizes or balances."""
    rows = []
    for i, r in enumerate(receipts, 1):
        m = r["molcheck_receipt"]
        c = m["checks"]
        rows.append({
            "n": i,
            "decision_timestamp": m["fill"]["decision_timestamp"],
            "verdict": m["verdict"],
            "reason": m["reason"],
            "order_cap": _within(c["order_cap"]),
            "volume_24h": _within(c["volume_24h"]),
            "loss": _within(c["loss"]),
            "core_digest": r["record"].get("core_digest"),
        })
    return {
        "summary": summary,
        "status": {"observed_at": status["observed_at"],
                   "agent_stopped": status["agent_stopped"]["value"],
                   "open_orders": status["open_orders"]["count"],
                   "open_positions": status["open_positions"]["count"]},
        "receipts": rows,
    }


def _within(check: Dict[str, Any]) -> str:
    v, lim = check.get("value_minor"), check.get("limit_minor")
    if v is None:
        return "no value"
    return "within" if v <= lim else "exceeded"


def cmd_summary(args: argparse.Namespace) -> int:
    receipts = []
    for name in sorted(os.listdir(args.dir)):
        if name.startswith("receipt-") and name.endswith(".json"):
            with open(os.path.join(args.dir, name), "r", encoding="utf-8") as handle:
                receipts.append(json.load(handle))
    with open(os.path.join(args.dir, "run.json"), "r", encoding="utf-8") as handle:
        run_blob = json.load(handle)
    print(json.dumps(redacted_summary(receipts, run_blob["summary"], run_blob["status"]),
                     indent=2, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="molcheck-coinbase", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    k = sub.add_parser("keygen", help="create the adapter's Ed25519 signing key")
    k.add_argument("--out", required=True)
    k.set_defaults(fn=cmd_keygen)

    t = sub.add_parser("trust-list", help="print the trust list for moltrust-verify")
    t.add_argument("--signing-key", required=True)
    t.add_argument("--source-id")
    t.set_defaults(fn=cmd_trust_list)

    r = sub.add_parser("run", help="read fills and write one receipt per fill")
    r.add_argument("--mandate", required=True)
    r.add_argument("--signing-key", required=True)
    r.add_argument("--source-id")
    r.add_argument("--out", required=True)
    src = r.add_mutually_exclusive_group(required=True)
    src.add_argument("--cdp-key", nargs="?", const="", metavar="FILE",
                     help="CDP key JSON file; without FILE the key comes from "
                          "CDP_API_KEY_NAME and CDP_API_KEY_PRIVATE_KEY")
    src.add_argument("--fixtures", metavar="DIR", help="replay recorded responses")
    r.add_argument("--record", metavar="DIR", help="also store responses, account ids replaced")
    r.add_argument("--now", help="end of the read window (RFC 3339); default: now")
    r.add_argument("--agent-stopped-at", help="time the operator revoked the agent's access")
    r.set_defaults(fn=cmd_run)

    s = sub.add_parser("summary", help="print the redacted summary of a run directory")
    s.add_argument("dir")
    s.set_defaults(fn=cmd_summary)
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.fn(args)
    except KeyTooPowerful as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return 3
    except (KeyLoadError, ApiError, ReceiptError, FileExistsError, FileNotFoundError,
            ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
