#!/usr/bin/env bash
# Network tests on our own Solana node (owner's decision 13.10: "network tests with
# the node - into the run"). Brings up `solana-test-validator` on 127.0.0.1, funds a
# throw-away payer from the node's faucet, and runs against it:
#
#   1. demo/localnet_suite.sh - S1..S6, every anchoring path, with the gas;
#   2. the localnet tests of crates/ksg-cli-v2/tests/devnet.rs (`#[ignore]` in the
#      ordinary gate: they need the node) - a heavy life anchored, an older copy;
#   3. with NET_DEVNET=1 also the two devnet tests (`live_devnet_read`,
#      `live_devnet_parses_our_transaction`): reads and a simulation only, no
#      transaction is sent and nothing is spent.
#
# Test SOL only, from the node's own faucet; the node and the payer are thrown away
# at the end. Exit 2 when this machine has no Solana CLI (the cloud has none): the
# gate says "localnet NOT checked" then. Run on the owner's machine.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"
for t in solana-test-validator solana solana-keygen; do
  command -v "$t" >/dev/null || { echo "no $t on this machine: localnet NOT checked"; exit 2; }
done
RPC=http://127.0.0.1:8899
LEDGER=$(mktemp -d); KEYS=$(mktemp -d)
cleanup() { [ -n "${VALIDATOR:-}" ] && kill "$VALIDATOR" 2>/dev/null; rm -rf "$LEDGER" "$KEYS"; }
trap cleanup EXIT
solana-test-validator --ledger "$LEDGER" --reset --quiet --bind-address 127.0.0.1 \
  --limit-ledger-size 500000 --gossip-port 8001 --rpc-port 8899 >/dev/null 2>&1 &
VALIDATOR=$!
for _ in $(seq 120); do solana cluster-version --url "$RPC" >/dev/null 2>&1 && break; sleep 1; done
solana cluster-version --url "$RPC" >/dev/null 2>&1 || { echo "the node did not come up"; exit 1; }
echo "node: $(solana-test-validator --version)"
PAYER=$KEYS/payer.json
solana-keygen new --no-bip39-passphrase --silent --outfile "$PAYER" >/dev/null
solana airdrop 50 "$(solana-keygen pubkey "$PAYER")" --url "$RPC" >/dev/null || { echo "airdrop failed"; exit 1; }

failed=0
echo "== 1. localnet_suite.sh"
PAYER="$PAYER" RPC="$RPC" "$ROOT/demo/localnet_suite.sh" || failed=1

echo "== 2. localnet tests of devnet.rs"
(cd "$ROOT" && KSG_LOCALNET_RPC="$RPC" KSG_LOCALNET_PAYER="$PAYER" \
  cargo test -q -p ksg-cli-v2 --test devnet -- --ignored localnet) || failed=1

if [ "${NET_DEVNET:-0}" = 1 ]; then
  echo "== 3. devnet: reads and a simulation, nothing sent"
  (cd "$ROOT" && cargo test -q -p ksg-verify-v2 --test solana -- --ignored live_devnet_read &&
    cargo test -q -p ksg-cli-v2 --test devnet -- --ignored live_devnet_parses_our_transaction) || failed=1
else
  echo "== 3. devnet: skipped (NET_DEVNET=1 to run)"
fi
[ "$failed" -eq 0 ] && echo "LOCALNET: ALL PASS" || echo "LOCALNET: SOME FAILED"
exit "$failed"
