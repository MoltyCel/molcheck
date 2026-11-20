# MolCheck adapter for Coinbase for Agents

This adapter reads the executed trades (fills) of one Coinbase Advanced Trade portfolio
that an agent trades in. It checks each fill against a mandate with three limits and writes
one receipt per fill. Anyone holding a receipt can recompute its verdict offline with
`moltrust-verify`, without access to Coinbase, MolTrust or the person who ran the adapter.

The adapter only reads. It refuses a CDP API key that is allowed to trade or transfer, and
it has no code that places, changes or cancels an order.

The adapter runs on your machine. Your CDP key goes from your disk to `api.coinbase.com`
and nowhere else; the hosted MolCheck verifier never receives it.

## What you need

- A Coinbase account with Advanced Trade, and the agent trading in a portfolio of its own.
  Coinbase recommends this setup for agents: in Coinbase Advanced (web only), go to
  Portfolio > Spot > All portfolios > New portfolio, and fund it with what the agent may
  risk.
- Python 3.10 or later.

## 1. Create a View-only CDP API key

1. Open https://portal.cdp.coinbase.com/api-keys/secret and choose **Create API Key**.
2. Under **Advanced Settings**, pick **Coinbase App & Advanced Trade**.
3. Under **Accounts**, select the agent's portfolio.
4. Leave **View** on. Leave **Trade** and **Transfer** off.
5. Select **ECDSA** as signature algorithm. Ed25519 keys do not work with this API.
6. Leave the IP allowlist empty, or add the address the adapter runs from.
7. Download the key file and keep it outside any repository, readable only by you:
   `chmod 600 cdp_api_key.json`. Use the file exactly as downloaded. Its `name` field holds
   the key name `organizations/<org-id>/apiKeys/<key-id>`, which signs every request; the
   nickname you typed in the portal does not work there.

The first request of every run is `GET /api/v3/brokerage/key_permissions`. If the key
reports `can_trade` or `can_transfer` as true, cannot view, or the answer is incomplete, the
adapter stops with exit code 3 before it reads any trade data.

If this first request ends with `error: HTTP 401 on GET /key_permissions`, Coinbase did not
accept the key. Check, in this order: the `name` field is the full key name from the
download, not the nickname; the private key and the name come from the same download; the
key is not restricted to other IP addresses; the clock of the machine is correct.

## 2. Install

```bash
git clone https://github.com/MoltyCel/molcheck.git
cd molcheck/adapters/coinbase
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

This also installs `moltrust-enforce`, which provides `moltrust-verify`.

## 3. Create the adapter's signing key

```bash
molcheck-coinbase keygen --out ~/.molcheck/coinbase-signing.pem
```

This Ed25519 key signs the numbers in each receipt. It is your key, separate from the CDP
key. The file is written with mode 0600; the command prints only its key id.

## 4. Write the mandate

`mandate.json`, amounts in the quote currency as decimal strings:

```json
{
  "mandate_id": "my-agent-pilot-1",
  "agent": "did:moltrust:your-agent",
  "quote_currency": "USD",
  "quote_decimals": 2,
  "max_order_notional": "100.00",
  "max_volume_24h": "250.00",
  "max_loss": "15.00",
  "baseline": {
    "as_of": "2026-11-10T00:00:00Z",
    "holdings": {"USD": "500.00"}
  }
}
```

| Field | Meaning |
|---|---|
| `quote_currency` | Currency all limits are expressed in. Fills against another quote currency are denied. USD and USDC count as different currencies: a portfolio funded with USDC that trades `BTC-USDC` needs `USDC` here. |
| `max_order_notional` | Largest value of a single order, summed over all its fills. |
| `max_volume_24h` | Largest traded value, buys and sells together, within any rolling 24 hours. |
| `max_loss` | Largest drop of the portfolio value below the baseline value. |
| `baseline.as_of` | Start of the mandate. Fills before this time are ignored. Pick a time after the last deposit into the portfolio. |
| `baseline.holdings` | What the portfolio held at `as_of`. Assets other than the quote currency are valued with the price at `as_of`. |

## 5. Run

```bash
molcheck-coinbase run \
  --cdp-key cdp_api_key.json \
  --mandate mandate.json \
  --signing-key ~/.molcheck/coinbase-signing.pem \
  --out receipts/
```

Instead of `--cdp-key FILE` you can set `CDP_API_KEY_NAME` and `CDP_API_KEY_PRIVATE_KEY`
and pass `--cdp-key` without a file name.

`receipts/` then holds:

- `receipt-<time>-<entry_id>.json`, one per fill
- `trust.json`, the trust list naming your signing key
- `run.json`, the counts and the portfolio status of this run

The command prints a summary with verdicts and limit checks. The summary contains no
identifiers, prices, sizes or balances, so you can share it.

If you have stopped the agent, add `--agent-stopped-at 2026-11-12T08:00:00Z` with the time
you revoked its access (see Status below).

## 6. Verify a receipt

```bash
moltrust-verify --input receipts/receipt-2026-11-10T091520Z-e1.json \
  --trust-list receipts/trust.json
```

```
V1 PASS bundle commit and input binding hold
V2 PASS every item carries a signature from a trusted source
V3 PASS every item window covers the decision timestamp
V4 PASS recomputed PERMIT from the same inputs

PASS — recomputed verdict PERMIT
```

Exit code 0 means all four checks hold. Any change to the receipt makes at least one of them
fail. A verifier should take `trust.json` from you through a separate channel, not from the
same folder as the receipt.

## What a receipt contains

A receipt holds `record`, `bundle`, `mandate` and `transaction`, the four inputs
`moltrust-verify` reads. A fifth block, `molcheck_receipt`, explains every number:

- **Single-order cap** (`checks.order_cap`): sum of the notional of all fills of this order
  up to and including this fill. Notional is price times size, or size when Coinbase marks
  the fill as placed in the quote currency. Commission is not included.
- **24-hour volume** (`checks.volume_24h`): the window is the closed interval from 24 hours
  before the fill's trade time to the trade time, at microsecond precision, starting no
  earlier than the baseline. The receipt states the window's start and end and the number of
  fills counted. Buys and sells both count; commission does not.
- **Loss** (`checks.loss`): baseline value minus the portfolio value right after this fill,
  never below zero. The portfolio after the fill is the baseline holdings plus every fill
  since the baseline, with commission deducted. Each asset is valued at the opening price of
  the one-minute Coinbase candle that contains the trade time. The receipt states the
  baseline value, the valuation time and every price used.
- **Rounding**: all arithmetic is exact on the decimal strings Coinbase returns; each number
  is rounded once to minor units of the quote currency (half-even).

The mandate is translated into one AAE grant. The three numbers enter the receipt as
evidence items signed by your adapter key, each valid only at the decision second and tied
to its fill by a nonce (`coinbase-entry:<entry_id>`). The kernel trace names the items by a
digest; `molcheck_receipt.evidence_fields` maps each digest to its name.

## Status

Every receipt of a run also carries the portfolio status at the time of the run, in three
separate fields:

- `agent_stopped`: Coinbase has no API that reports whether an agent is running. The value
  is `true` when you declared a stop time with `--agent-stopped-at` and no fill and no open
  order was created after it, `false` when there was activity after that time, and `null`
  when you declared nothing. You stop an agent by revoking its OAuth connection at
  accounts.coinbase.com/security/connections or by deleting its trading key in the CDP
  portal.
- `open_orders`: number and list of open orders (product, side, status, creation time).
- `open_positions`: non-cash spot positions with a non-zero balance, plus any futures or
  perpetual positions the portfolio reports.

The status is not part of the recomputed verdict; it records what the adapter saw at
`observed_at`.

## Sharing receipts

The redacted summary printed by `run` and `summary` contains no identifiers and can be
posted publicly. A receipt is meant for the people who check the agent. It names the
portfolio only by a hash, but it carries the Coinbase order id and trade id of its fill, so
that anyone with access to the account can match it to the trade. Share receipts like
account statements.

## Limits

- Coinbase does not sign fills. The receipt shows that your adapter key attested these
  numbers and that the verdict follows from them. Someone with access to the same fills can
  recompute the numbers from the definitions above; someone without that access is relying
  on your key.
- Deposits, withdrawals and transfers after the baseline are not visible to a View-only key
  and are not accounted for. They shift the loss figure. Keep the pilot portfolio free of
  transfers during the mandate, or set a new baseline after one.
- Spot fills only. A fill on a futures or other non-spot product stops the run with an
  error. Fills against a quote currency other than the mandate's are denied.
- Correction, reversal and synthetic entries are listed in the run counts but not included
  in any sum.
- Valuation uses the one-minute candle that contains the trade time. Prices within that
  minute can differ from the candle's opening price.

## Recorded responses

`--record DIR` stores every API response next to the run. Identifiers (portfolio, user,
account, asset, order, client order, trade and entry ids, portfolio names, and any other
UUID in a response) are replaced with stable placeholders before writing; the same id always
gets the same placeholder, so fills of one order still belong together. Balances, prices and
sizes stay as they are. Pass the same `--now` to the replay that the recording run used. `--fixtures DIR` replays such a folder without network access:

```bash
molcheck-coinbase run --fixtures tests/fixtures/pilot --now 2026-11-12T00:00:00Z \
  --mandate tests/fixtures/pilot-mandate.json \
  --signing-key ~/.molcheck/coinbase-signing.pem --out /tmp/replay
```

## Tests

```bash
pip install '.[test]'
pytest
```

`tests/fixtures/pilot/` is built by `tests/make_fixtures.py` from the response schemas
Coinbase documents. `tests/fixtures/live-2026-11-16/` is the recording of the pilot run
below.

## Pilot run, 16 November 2026

A View-only key on a separate portfolio funded with 10 USDC. The mandate set 2.00 USDC per
order, 5.00 USDC per 24 hours and 0.50 USDC loss, with the baseline at 14:00Z. Three market
buys were placed by hand between 16:46Z and 16:48Z: 1.50 USDC of BTC, 1.50 USDC of ETH
(filled in two parts) and 3.00 USDC of BTC, the last one above the per-order limit on
purpose. Access was revoked at 16:50Z and passed as `--agent-stopped-at`.

| Fill | Order | Single order | 24-hour volume | Loss | Verdict |
|---|---|---|---|---|---|
| 1 | BTC 1.50 | 1.49 of 2.00 | 1.49 of 5.00 | 0.00 of 0.50 | PERMIT |
| 2 | ETH 1.50, part 1 | 0.70 of 2.00 | 2.19 of 5.00 | 0.01 of 0.50 | PERMIT |
| 3 | ETH 1.50, part 2 | 1.49 of 2.00 | 2.98 of 5.00 | 0.01 of 0.50 | PERMIT |
| 4 | BTC 3.00 | 2.99 of 2.00 | 5.97 of 5.00 | 0.02 of 0.50 | DENY |

Notional excludes commission, so each order counts slightly below the amount spent. The
status block showed the agent stopped with no activity after 16:50Z, no open orders and two
open spot positions (BTC, ETH). `moltrust-verify` recomputed all four verdicts offline with
exit code 0.

## Secrets

Never commit the CDP key file or the signing key. Neither the adapter nor its error messages
print key material; API errors report the HTTP status and path only.
