#!/usr/bin/env bash
# Hackathon demo, K5 Pro through the capsule on our own Solana node (owner's
# decision 17.10: test SOL comes from our own node, not from devnet). Brings
# up solana-test-validator on 127.0.0.1, funds a throw-away payer from the
# node's faucet, builds the capsule module (wasm), then drives the reader's
# binary `ksg-capsule` (not the test): print (heavy, anchored) -> initiation
# (the seals are anchored on the node) -> work pages (KSG_DEMO_PAGES, 1 by default) -> export of those pages
# 1..PAGES. Node, payer and capsule are thrown away.
#
# `ksg-capsule` has no `scan-key` command (it cannot hand out the holder's
# scan key in the hex form `ksg-verify-v2 --scan-key` takes), and no code is
# added for the demo: the verify half (ACCEPTED x3 against the node, one
# flipped seal byte REJECTED) runs as the network test below, the fallback
# path (`crates/ksg-capsule-reader/tests/k5_offline.rs`, `k5_network_*`).
#
#   scripts/demo_pro_capsule_localnet.sh   (heavy, own node)
#
# KSG_DEMO_VERIFY_NET=1 (default) runs the verify half above after the demo
# part (10 more anchors); 0 skips it, so the video can film the two parts
# separately (and the mainnet probe pays for the demo part only).
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$PATH"
for t in solana-test-validator solana solana-keygen; do
  command -v "$t" >/dev/null || { echo "no $t on this machine: Pro capsule demo NOT checked"; exit 2; }
done
RPC=http://127.0.0.1:8899
LEDGER=$(mktemp -d); W=$(mktemp -d)
cleanup() { [ -n "${VALIDATOR:-}" ] && kill "$VALIDATOR" 2>/dev/null; rm -rf "$LEDGER" "$W"; }
trap cleanup EXIT
solana-test-validator --ledger "$LEDGER" --reset --quiet --bind-address 127.0.0.1 \
  --limit-ledger-size 500000 --gossip-port 8001 --rpc-port 8899 >/dev/null 2>&1 &
VALIDATOR=$!
for _ in $(seq 120); do solana cluster-version --url "$RPC" >/dev/null 2>&1 && break; sleep 1; done
solana cluster-version --url "$RPC" >/dev/null 2>&1 || { echo "the node did not come up"; exit 1; }
PAYER=$W/payer.json
solana-keygen new --no-bip39-passphrase --silent --outfile "$PAYER" >/dev/null
solana airdrop 50 "$(solana-keygen pubkey "$PAYER")" --url "$RPC" >/dev/null || { echo "airdrop failed"; exit 1; }
# The anchorer waits 120 s by default; the demo names its own 20 s.
export KSG_ANCHOR_WAIT_S=20

(cd "$ROOT" && cargo build -q --release -p ksg-capsule-reader -p ksg-verify-v2) || exit 1
(cd "$ROOT" && cargo build -q --release -p ksg-capsule-module --target wasm32-unknown-unknown) || exit 1
# The verify half's test binary is built here, before any timer starts, so
# "time verify half" is the anchoring, not the compiler.
if [ "${KSG_DEMO_VERIFY_NET:-1}" = 1 ]; then
  (cd "$ROOT" && cargo test -q -p ksg-capsule-reader --no-run) || exit 1
fi
C=$ROOT/target/release/ksg-capsule
MOD=$ROOT/target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm
H=$W/h
T_DEMO=$(date +%s)
step() { "$@" >"$W/out" 2>&1 || { echo "FAIL: ${*:2}"; tail -5 "$W/out"; exit 1; }; }
size() { stat -c%s "$H/capsule.bin"; }

step "$C" --home "$H" init --class heavy --anchor solana:localnet --payer "$PAYER" --rpc "$RPC" --wasm "$MOD"
[ "$(size)" = 6291456 ] || { echo "FAIL: the capsule is $(size) bytes after init"; exit 1; }
step "$C" --home "$H" initiate
[ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after the initiation"; exit 1; }
# Every Pro page costs two anchors (its seal and the status record pressed
# with it), each waited to `finalized` (~14 s on an idle node); the initiation
# with the journal opening costs four. KSG_DEMO_PAGES=1 (default) keeps the
# anchored part of the demo at 6 anchors (~1.5 min); 3 shows all three pages
# (10 anchors, ~2.5 min).
PAGES=${KSG_DEMO_PAGES:-1}
if [ "$PAGES" -ge 3 ]; then
  TEXTS=("input: claim 4417, water damage, policy P-88 (synthetic)"
         "tool call: policy_lookup(P-88) -> exclusion 7.2 gradual leak"
         "result: claim rejected, exclusion 7.2")
else
  TEXTS=("result: claim 4417 rejected, exclusion 7.2 gradual leak (policy P-88, synthetic)")
  PAGES=1
fi
for t in "${TEXTS[@]}"; do
  step "$C" --home "$H" work "$t"
  [ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after a work page"; exit 1; }
done
"$C" --home "$H" status
for n in $(seq 1 "$PAGES"); do
  step "$C" --home "$H" export-page "$n" --out "$W/p$n.json"
  [ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after export-page $n"; exit 1; }
done
step "$C" --home "$H" keys --out "$W/k.json"

echo "time demo part: $(( $(date +%s) - T_DEMO )) s"
T_VERIFY=$(date +%s)

# Fallback path (no `scan-key` in `ksg-capsule`, no code added for the demo):
# the network test prints its own heavy capsule on this node, works three
# pages, checks each against the node (`ACCEPTED`), and flips one byte of a
# seal signature (`REJECTED`). It reads the node, the payer and the module
# from the environment this script prepared.
if [ "${KSG_DEMO_VERIFY_NET:-1}" = 1 ]; then
  (cd "$ROOT" && KSG_PAYER=$PAYER KSG_RPC="$RPC" KSG_CAPSULE_WASM=$MOD \
    cargo test -p ksg-capsule-reader -- --ignored k5_network --nocapture) || exit 1
else
  echo "verify half skipped (KSG_DEMO_VERIFY_NET=${KSG_DEMO_VERIFY_NET})"
fi

echo "time verify half: $(( $(date +%s) - T_VERIFY )) s"
# The payer's transactions on this node, read before the node goes away
# (roadmap 2.3: anchors = 6 for the demo part + 10 for the verify half);
# one of them is the airdrop.
SIGS=$(curl -s "$RPC" -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"getSignaturesForAddress\",\"params\":[\"$(solana-keygen pubkey "$PAYER")\",{\"limit\":1000}]}" \
  | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["result"]))' 2>/dev/null || echo "?")
echo "payer transactions: $SIGS (one is the airdrop; the rest are anchor memos)"
echo "DEMO PRO CAPSULE LOCALNET OK"
