#!/usr/bin/env bash
# One live x402 payment on Base Sepolia (G2-8, [decision] 11.10): μ Gate pays the
# issuer's 402 answer with the payer's own key, the issuer's till accepts the
# header, the facilitator settles it on chain. Test USDC only.
#
#   MU_DIR=/path/to/agents-blockchain/mu \
#   MU_PAYER_KEY_FILE=~/.secrets/keysingate/base-sepolia/payer.hex \
#   KSG_ISSUER=0x<issuer address> \
#   scripts/e2e_ksg_x402_live.sh [--dry]
#
# --dry stops after the facilitator's /verify: nothing moves.
# Addresses and the transaction hash are printed here only: they go to the
# owner's local registry, never to GitHub or the PR bus.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MU_DIR="${MU_DIR:?set MU_DIR to agents-blockchain/mu (branch keysingate)}"
: "${MU_PAYER_KEY_FILE:?set MU_PAYER_KEY_FILE to the payer key file (64 hex, mode 600)}"
ISSUER="${KSG_ISSUER:?set KSG_ISSUER to the issuer receiving address}"
AMOUNT="${KSG_AMOUNT:-100000}"   # 0.10 USDC (6 decimals)
RES=https://issuer.example/bare/issue
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

(cd "$ROOT" && cargo build -q -p ksg-pay-v2 --example till)
(cd "$MU_DIR" && cargo build -q -p ksg-smoke)
TILL="$ROOT/target/debug/examples/till"
SMOKE="$MU_DIR/target/debug/ksg-smoke"

"$TILL" required "$ISSUER" "$AMOUNT" "$RES" > "$tmp/402.json"
MU_PAYER_KEY_FILE="$MU_PAYER_KEY_FILE" "$SMOKE" < "$tmp/402.json" > "$tmp/header"
"$TILL" accept "$ISSUER" "$AMOUNT" "$RES" < "$tmp/header"
python3 "$ROOT/scripts/x402_settle.py" "$tmp/402.json" "$tmp/header" "$@"
