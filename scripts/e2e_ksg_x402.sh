#!/usr/bin/env bash
# Cross-repository E2E: keysingate issuer (ksg-pay-v2) <-> μ Gate KSG (ksg-smoke).
#   402 answer from the issuer's till -> μ Gate pipeline pays it -> the till accepts the header.
# Stand only: Base Sepolia, μ Gate test wallet 0x11..11, nothing goes to a chain.
#   MU_DIR=/path/to/agents-blockchain/mu scripts/e2e_ksg_x402.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MU_DIR="${MU_DIR:?set MU_DIR to agents-blockchain/mu (branch keysingate)}"
ISSUER=0x209693Bc6afc0C5328bA36FaF03C514EF312287C
RES=https://issuer.example/bare/issue
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

(cd "$ROOT" && cargo build -q -p ksg-pay-v2 --example till)
(cd "$MU_DIR" && cargo build -q -p ksg-smoke)
TILL="$ROOT/target/debug/examples/till"
SMOKE="$MU_DIR/target/debug/ksg-smoke"

fail() { echo "E2E FAIL: $*"; exit 1; }

"$TILL" required "$ISSUER" 100000 "$RES" > "$tmp/402.json"
"$SMOKE" < "$tmp/402.json" > "$tmp/header" 2>"$tmp/smoke.err" || fail "μ Gate did not pay: $(cat "$tmp/smoke.err")"
out=$("$TILL" accept "$ISSUER" 100000 "$RES" < "$tmp/header") || fail "till refused: $out"
echo "1/3 paid and accepted: $out"

# A higher price than the payer authorized is refused by the till.
if "$TILL" accept "$ISSUER" 100001 "$RES" < "$tmp/header" >/dev/null; then fail "underpayment accepted"; fi
echo "2/3 underpayment refused"

# A 402 answer above the μ Gate policy's \$1 cap is not paid at all.
"$TILL" required "$ISSUER" 2000000 "$RES" > "$tmp/402big.json"
if "$SMOKE" < "$tmp/402big.json" > /dev/null 2>&1; then fail "μ Gate paid over its cap"; fi
echo "3/3 over-cap 402 not paid"
echo "E2E OK"
