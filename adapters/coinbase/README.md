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
6. Download the key file and keep it outside any repository, readable only by you:
   `chmod 600 cdp_api_key.json`.

The first request of every run is `GET /api/v3/brokerage/key_permissions`. If the key
reports `can_trade` or `can_transfer` as true, cannot view, or the answer is incomplete, the
adapter stops with exit code 3 before it reads any trade data.

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
| `quote_currency` | Currency all limits are expressed in. Fills against another quote currency are denied. USD and USDC count as different currencies. |
| `max_order_notional` | Largest value of a single order, summed over all its fills. |
| `max_volume_24h` | Largest traded value, buys and sells together, within any rolling 24 hours. |
| `max_loss` | Largest drop of the portfolio value below the baseline value. |
| `baseline.as_of` | Start of the mandate. Fills before this time are ignored. |
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

`--record DIR` stores every API response next to the run. Account identifiers (portfolio,
user, account and order client ids, portfolio names) are replaced with stable placeholders
before writing. `--fixtures DIR` replays such a folder without network access:

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
Coinbase documents.

## Secrets

Never commit the CDP key file or the signing key. Neither the adapter nor its error messages
print key material; API errors report the HTTP status and path only.
