# New Token Volume Scanner — ⚠️ HIGH RISK ⚠️

Two discovery feeds + automated safety checking:

- **Feed A — GeckoTerminal new pools** (free): catches tokens after a
  liquidity pool exists, across Ethereum, Base, Solana, BSC, Arbitrum
- **Feed B — pump.fun via PumpPortal** (free WebSocket): catches Solana
  tokens at the moment of creation, before a DEX pool even exists —
  earlier than Feed A for Solana specifically, and the rawest, most
  unfiltered layer of the entire memecoin pipeline

Plus:

- **Contract safety check (GoPlus Security, free)** — for EVM chains
  (eth/base/bsc/arbitrum), every alerted token is checked for honeypot
  status, sell tax, mint function, hidden owner, and creator holding %
  before you see it. Confirmed honeypots are blocked from alerting as
  an "opportunity" and get a warning instead. Solana isn't automated
  yet (GoPlus's Solana support is still Beta) — those alerts tell you
  to check RugCheck.xyz manually.

## Why this is a separate deployment

This is by far the highest-risk tool in the signal stack. The large
majority of brand-new tokens — especially pump.fun launches — are rug
pulls, honeypots, or abandoned within hours. Safety checks catch SOME
scams, not all. This is deployed with its own bot and chat on purpose,
so it can be muted or ignored independently of your other, lower-risk
signal feeds.

## Setup

1. Create a NEW Telegram bot via @BotFather (don't reuse your other one)
2. Create a NEW Telegram group/chat for this feed specifically
3. Add the bot to that group, get the chat ID (same process as your other bots)
4. Deploy to Railway: scanner.js, package.json, railway.toml
5. Set variables — see .env.example for the full list

## Testing

Temporarily set the start command to `node scanner.js --test` to run one
GeckoTerminal scan pass immediately (this does not test the pump.fun feed,
which connects automatically on normal startup — check the logs for
"pump.fun feed connected" to confirm that side is working). Revert to
`node scanner.js` afterward.

## What the filters do (and don't do)

- **MIN_LIQUIDITY_USD / MAX_AGE_HOURS / MIN_VOL_LIQ_RATIO** — reduce noise
  on Feed A, not risk
- **PUMPFUN_MIN_INITIAL_BUY_SOL** — filters out zero-conviction launches
  on Feed B, not risk
- **GoPlus safety check** — catches real, verifiable contract-level scams
  (honeypots, extreme taxes, hidden owner) for EVM chains — this is a
  genuine risk reduction, not just noise filtering, but it is not
  foolproof and contracts can be upgraded/changed after the check runs

**Treat every alert from this bot as a lottery ticket, not a trade —
even the ones that pass every filter.**
