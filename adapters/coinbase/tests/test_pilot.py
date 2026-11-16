import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from moltrust_enforce.verify import verify_record as verify_aer

from molcheck_coinbase import fixtures, signing
from molcheck_coinbase.cli import main, redacted_summary, run
from molcheck_coinbase.client import ApiError, KeyTooPowerful, ReadOnlyClient, check_permissions
from molcheck_coinbase.receipt import PilotMandate, parse_time

HERE = pathlib.Path(__file__).resolve().parent
FIX = HERE / "fixtures" / "pilot"
NOW = parse_time("2026-11-12T00:00:00Z")


@pytest.fixture(scope="module")
def key():
    return Ed25519PrivateKey.from_private_bytes(bytes(range(32)))


@pytest.fixture(scope="module")
def mandate():
    return PilotMandate.from_json(json.loads((HERE / "fixtures" / "pilot-mandate.json").read_text()))


@pytest.fixture(scope="module")
def result(key, mandate):
    client = ReadOnlyClient(fixtures.replay(str(FIX)))
    return run(client, mandate, key, signing.default_source_id(key), NOW, None)


def by_entry(receipts):
    return {r["molcheck_receipt"]["fill"]["entry_id"]: r for r in receipts}


# ---------------------------------------------------------------- criterion 2: read-only key

@pytest.mark.parametrize("perms", [
    {"can_view": True, "can_trade": True, "can_transfer": False, "portfolio_uuid": "p"},
    {"can_view": True, "can_trade": False, "can_transfer": True, "portfolio_uuid": "p"},
    {"can_view": True, "can_trade": True, "can_transfer": True, "portfolio_uuid": "p"},
    {"can_view": False, "can_trade": False, "can_transfer": False, "portfolio_uuid": "p"},
    {"can_view": True, "can_transfer": False, "portfolio_uuid": "p"},
    {"can_view": True, "can_trade": "false", "can_transfer": False, "portfolio_uuid": "p"},
    {"can_view": True, "can_trade": False, "can_transfer": False},
    [],
])
def test_key_with_more_or_unclear_rights_is_refused(perms):
    with pytest.raises(KeyTooPowerful):
        check_permissions(perms)


def test_view_only_key_passes():
    out = check_permissions({"can_view": True, "can_trade": False, "can_transfer": False,
                             "portfolio_uuid": "p", "portfolio_type": "CONSUMER"})
    assert out["portfolio_uuid"] == "p"


def test_refused_key_stops_before_any_data_request(key, mandate):
    calls = []

    def transport(method, path, query):
        calls.append((method, path))
        return {"can_view": True, "can_trade": True, "can_transfer": False,
                "portfolio_uuid": "p"}

    with pytest.raises(KeyTooPowerful):
        run(ReadOnlyClient(transport), mandate, key, "s", NOW, None)
    assert calls == [("GET", "/key_permissions")]


def test_client_sends_get_only_and_only_allowlisted_paths():
    sent = []
    client = ReadOnlyClient(lambda m, p, q: sent.append((m, p)) or {
        "can_view": True, "can_trade": False, "can_transfer": False, "portfolio_uuid": "p"})
    client.verify_read_only()
    with pytest.raises(ApiError):
        client._get("/orders")  # the create-order path
    with pytest.raises(ApiError):
        client._get("/orders/batch_cancel")
    assert all(m == "GET" for m, _ in sent)


def test_no_data_request_before_permission_check():
    client = ReadOnlyClient(lambda m, p, q: {})
    with pytest.raises(KeyTooPowerful):
        client.fills("a", "b")


def test_cli_exit_code_3_on_powerful_key(tmp_path, key, monkeypatch):
    fx = tmp_path / "fx"
    fx.mkdir()
    for f in FIX.glob("*.json"):
        blob = json.loads(f.read_text())
        if blob["path"] == "/key_permissions":
            blob["response"]["can_trade"] = True
        (fx / f.name).write_text(json.dumps(blob))
    kpath = tmp_path / "k.pem"
    signing.generate(str(kpath))
    code = main(["run", "--mandate", str(HERE / "fixtures" / "pilot-mandate.json"),
                 "--signing-key", str(kpath), "--out", str(tmp_path / "out"),
                 "--fixtures", str(fx), "--now", "2026-11-12T00:00:00Z"])
    assert code == 3
    assert not (tmp_path / "out").exists()


# ---------------------------------------------------------------- criterion 3: mandate checks

def test_verdicts_per_fill(result):
    receipts, summary, _ = result
    r = by_entry(receipts)
    assert set(r) == {"e1", "e2", "e3", "e4"}
    assert summary["fills_before_baseline"] == 1
    assert summary["adjustment_entries_ignored"] == 1
    assert r["e1"]["record"]["verdict"] == "PERMIT"
    assert r["e2"]["record"]["verdict"] == "PERMIT"
    assert r["e3"]["record"]["verdict"] == "DENY"
    assert r["e4"]["record"]["verdict"] == "DENY"


def test_order_cap_sums_fills_of_one_order(result):
    c = by_entry(result[0])["e3"]["molcheck_receipt"]["checks"]
    assert c["order_cap"]["value_minor"] == 12000
    assert c["order_cap"]["limit_minor"] == 10000


def test_volume_window_is_stated_and_rolls(result):
    r = by_entry(result[0])
    w1 = r["e3"]["molcheck_receipt"]["checks"]["volume_24h"]
    assert w1["value_minor"] == 21000
    assert w1["window"]["start"] == "2026-11-10T00:00:00.000000Z"  # clipped at baseline
    w4 = r["e4"]["molcheck_receipt"]["checks"]["volume_24h"]
    assert w4["window"]["start"] == "2026-11-10T10:00:00.000000Z"
    assert w4["window"]["end"] == "2026-11-11T10:00:00.000000Z"
    assert w4["window"]["fills_counted"] == 3  # e1 fell out of the window
    assert w4["value_minor"] == 20000
    assert "24h" in w4["window"]["definition"]


def test_loss_basis_and_valuation_time_are_stated(result):
    loss = by_entry(result[0])["e4"]["molcheck_receipt"]["checks"]["loss"]
    assert loss["basis"]["baseline_value_minor"] == 50000
    assert loss["basis"]["baseline_as_of"] == "2026-11-10T00:00:00.000000Z"
    assert loss["valuation"]["time"] == "2026-11-11T10:00:00Z"
    assert loss["valuation"]["prices"] == {"ETH": "2500.00"}
    assert loss["valuation"]["portfolio_value_minor"] == 46826
    assert loss["value_minor"] == 3174
    assert loss["limit_minor"] == 1500


def test_deny_reason_names_the_failed_limit(result):
    r = by_entry(result[0])

    def failed(entry):
        meta = r[entry]["molcheck_receipt"]
        return {meta["evidence_fields"].get(p["field"], p["field"])
                for p in r[entry]["record"]["trace"] if p["result"] == "FAIL"}

    assert failed("e3") == {"coinbase.order_notional"}
    assert failed("e4") == {"coinbase.loss_mtm"}
    assert failed("e1") == set()


# ---------------------------------------------------------------- criterion 4: status apart

def test_status_reports_three_things_separately(result):
    status = result[2]
    assert set(status) >= {"agent_stopped", "open_orders", "open_positions"}
    assert status["agent_stopped"]["value"] is None
    assert status["open_orders"]["count"] == 1
    assert status["open_positions"]["count"] == 1
    assert status["open_positions"]["positions"][0]["asset"] == "ETH"
    for r in result[0]:
        assert r["molcheck_receipt"]["status"] == status


def test_agent_stopped_with_declaration(key, mandate):
    client = ReadOnlyClient(fixtures.replay(str(FIX)))
    _, _, late = run(client, mandate, key, "s", NOW, parse_time("2026-11-11T12:00:00Z"))
    assert late["agent_stopped"]["value"] is True
    client = ReadOnlyClient(fixtures.replay(str(FIX)))
    _, _, early = run(client, mandate, key, "s", NOW, parse_time("2026-11-11T09:00:00Z"))
    assert early["agent_stopped"]["value"] is False
    assert early["agent_stopped"]["activity_after_stop"] == 2  # fill e4 + open order o9


# ---------------------------------------------------------------- criterion 5: AER verifier

def test_every_receipt_recomputes_offline(result, key):
    trust = signing.trust_list(key, signing.default_source_id(key))
    for r in result[0]:
        out = verify_aer(r["record"], r["bundle"], r["mandate"], r["transaction"], trust)
        assert out.ok, out


def test_tampered_receipt_fails(result, key):
    trust = signing.trust_list(key, signing.default_source_id(key))
    r = json.loads(json.dumps(by_entry(result[0])["e4"]))
    r["record"]["verdict"] = "PERMIT"
    assert not verify_aer(r["record"], r["bundle"], r["mandate"], r["transaction"], trust).ok


def test_foreign_key_fails(result, key):
    other = Ed25519PrivateKey.from_private_bytes(bytes(32))
    trust = signing.trust_list(other, signing.default_source_id(key))
    r = result[0][0]
    assert not verify_aer(r["record"], r["bundle"], r["mandate"], r["transaction"], trust).ok


# ---------------------------------------------------------------- output hygiene

def test_redacted_summary_has_no_account_data(result):
    text = json.dumps(redacted_summary(*result))
    for needle in ("redacted-0a1b2c3d4e5f", "redacted-5e6f7a8b9c0d", '"o1"', '"e1"', "90000",
                   "368.26", "0.04", "user_id", "portfolio_ref", "pf:", "ETH"):
        assert needle not in text, needle


def test_receipts_name_portfolio_by_hash_only(result):
    blob = json.dumps(result[0])
    assert "redacted-0a1b2c3d4e5f" not in blob
    assert "redacted-5e6f7a8b9c0d" not in blob


def test_recording_replaces_account_ids(tmp_path):
    def live(method, path, query):
        return {"can_view": True, "can_trade": False, "can_transfer": False,
                "portfolio_uuid": "11111111-2222-3333-4444-555555555555"}
    rec = fixtures.recording(live, str(tmp_path))
    rec("GET", "/key_permissions", {})
    written = "".join(p.read_text() for p in tmp_path.glob("*.json"))
    assert "11111111-2222" not in written


def test_cli_run_end_to_end(tmp_path):
    kpath = tmp_path / "k.pem"
    assert main(["keygen", "--out", str(kpath)]) == 0
    assert (kpath.stat().st_mode & 0o777) == 0o600
    out = tmp_path / "out"
    assert main(["run", "--mandate", str(HERE / "fixtures" / "pilot-mandate.json"),
                 "--signing-key", str(kpath), "--out", str(out), "--fixtures", str(FIX),
                 "--now", "2026-11-12T00:00:00Z"]) == 0
    assert len(list(out.glob("receipt-*.json"))) == 4
    assert (out / "trust.json").exists()
    assert main(["summary", str(out)]) == 0


# ---------------------------------------------------------------- edge cases

def _fill(entry, product, side, price, size, t):
    return {"entry_id": entry, "trade_id": "t" + entry, "order_id": "o" + entry,
            "trade_time": t, "trade_type": "FILL", "price": price, "size": size,
            "commission": "0", "product_id": product, "side": side}


def test_foreign_quote_fill_is_denied(key, mandate):
    from molcheck_coinbase.receipt import build_receipts
    prices = {"BTC": "90000", "EUR": "1.10"}
    receipts, _ = build_receipts(
        mandate, [_fill("x1", "BTC-EUR", "BUY", "80000", "0.0001", "2026-11-10T10:00:00Z")],
        "p", lambda a, m: prices.get(a), key.sign, "s", "k", {})
    assert receipts[0]["record"]["verdict"] == "DENY"
    assert receipts[0]["molcheck_receipt"]["checks"]["order_cap"]["value_minor"] is None


def test_non_spot_product_stops_the_run(key, mandate):
    from molcheck_coinbase.receipt import ReceiptError, build_receipts
    with pytest.raises(ReceiptError):
        build_receipts(mandate, [_fill("x2", "BIT-28NOV26-CDE", "BUY", "1", "1",
                                       "2026-11-10T10:00:00Z")],
                       "p", lambda a, m: "1", key.sign, "s", "k", {})


def test_missing_price_fails_closed(key, mandate):
    from molcheck_coinbase.receipt import ReceiptError, build_receipts
    with pytest.raises(ReceiptError):
        build_receipts(mandate, [_fill("x3", "BTC-USD", "BUY", "90000", "0.001",
                                       "2026-11-10T10:00:00Z")],
                       "p", lambda a, m: None, key.sign, "s", "k", {})


# ---------------------------------------------------------------- live run 2026-11-16
# Responses recorded from the pilot portfolio with `--record` (account, order, trade and entry
# ids replaced). Three market buys placed by hand: 1.50 BTC, 1.50 ETH (filled in two parts),
# 3.00 BTC, all in USDC. Mandate: 10.00 USDC baseline, 2.00 per order, 5.00 per 24 h,
# 0.50 loss. Access revoked at 16:50:00Z.

LIVE = HERE / "fixtures" / "live-2026-11-16"
LIVE_NOW = parse_time("2026-11-16T21:00:00Z")
LIVE_STOP = parse_time("2026-11-16T16:50:00Z")


@pytest.fixture(scope="module")
def live(key):
    m = PilotMandate.from_json(json.loads(
        (HERE / "fixtures" / "live-mandate-2026-11-16.json").read_text()))
    client = ReadOnlyClient(fixtures.replay(str(LIVE)))
    return run(client, m, key, signing.default_source_id(key), LIVE_NOW, LIVE_STOP)


def test_live_verdicts(live):
    receipts, summary, _ = live
    assert summary["fills_seen"] == 4
    assert [r["molcheck_receipt"]["verdict"] for r in receipts] == \
        ["PERMIT", "PERMIT", "PERMIT", "DENY"]


def test_live_third_order_breaks_order_cap_and_volume(live):
    receipts = live[0]
    checks = [r["molcheck_receipt"]["checks"] for r in receipts]
    assert [c["order_cap"]["value_minor"] for c in checks] == [149, 70, 149, 299]
    assert all(c["order_cap"]["limit_minor"] == 200 for c in checks)
    assert [c["volume_24h"]["value_minor"] for c in checks] == [149, 219, 298, 597]
    assert checks[3]["volume_24h"]["limit_minor"] == 500
    assert checks[3]["volume_24h"]["window"]["fills_counted"] == 4
    assert checks[3]["volume_24h"]["window"]["start"] == "2026-11-16T14:00:00.000000Z"
    assert all(c["loss"]["value_minor"] <= c["loss"]["limit_minor"] for c in checks)


def test_live_two_fills_of_one_order_share_the_cap(live):
    fills = [r["molcheck_receipt"]["fill"] for r in live[0]]
    assert fills[1]["order_id"] == fills[2]["order_id"]
    assert len({f["order_id"] for f in fills}) == 3


def test_live_status_after_revocation(live):
    status = live[2]
    assert status["agent_stopped"]["value"] is True
    assert status["agent_stopped"]["activity_after_stop"] == 0
    assert status["open_orders"]["count"] == 0
    assert sorted(p["asset"] for p in status["open_positions"]["positions"]) == ["BTC", "ETH"]


def test_live_receipts_recompute_offline(live, key):
    trust = signing.trust_list(key, signing.default_source_id(key))
    for r in live[0]:
        out = verify_aer(r["record"], r["bundle"], r["mandate"], r["transaction"], trust)
        assert out.ok, out


def test_live_fixtures_carry_no_uuid():
    import re
    uuid = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                      r"[0-9a-fA-F]{12}")
    for path in LIVE.glob("*.json"):
        assert not uuid.search(path.read_text()), path.name


def test_recording_replaces_order_trade_entry_ids_and_embedded_uuids(tmp_path):
    def live_api(method, path, query):
        return {"fills": [{"order_id": "o-123", "trade_id": "t-456", "entry_id": "abc",
                           "note": "ref 11111111-2222-3333-4444-555555555555"}]}
    rec = fixtures.recording(live_api, str(tmp_path))
    rec("GET", "/orders/historical/fills", {})
    written = "".join(p.read_text() for p in tmp_path.glob("*.json"))
    for needle in ('"o-123"', '"t-456"', '"abc"', "11111111-2222"):
        assert needle not in written, needle
