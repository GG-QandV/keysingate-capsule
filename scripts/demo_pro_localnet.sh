#!/usr/bin/env bash
# Hackathon demo, Pro with anchors on our own Solana node (owner's decision 17.10:
# test SOL comes from our own node, not from devnet). Brings up solana-test-validator
# on 127.0.0.1, funds a throw-away payer from the node's faucet, and runs the demo
# chain: print (heavy, anchored) -> packet -> buyer key -> initiation -> three work
# pages -> export of pages 1..3 -> offline check of each page against the node ->
# one tampered page, which must be rejected. Node and payer are thrown away.
#
#   scripts/demo_pro_localnet.sh        (owner's machine; exit 2 without Solana CLI)
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$HOME/.local/share/solana/install/active_release/bin:$HOME/.cargo/bin:$PATH"
for t in solana-test-validator solana solana-keygen; do
  command -v "$t" >/dev/null || { echo "no $t on this machine: Pro demo NOT checked"; exit 2; }
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
solana airdrop 10 "$(solana-keygen pubkey "$PAYER")" --url "$RPC" >/dev/null || { echo "airdrop failed"; exit 1; }

(cd "$ROOT" && cargo build -q --release -p ksg-cli-v2 -p ksg-verify-v2) || exit 1
P=$ROOT/target/release/ksg-remote-panel
V=$ROOT/target/release/ksg-verify-v2
H=$W/h; M=$W/m.json
step() { "$@" >"$W/out" 2>&1 || { echo "FAIL: ${*:3}"; tail -5 "$W/out"; exit 1; }; }

step "$P" --home "$H" init --class heavy --anchor solana:localnet --payer "$PAYER" --rpc "$RPC"
step "$P" --home "$H" packet
step "$P" --home "$H" buyer-key
step "$P" --home "$H" --mobile "$M" initiate
step "$P" --home "$H" --mobile "$M" open-journal
for t in "input: claim 4417, water damage, policy P-88 (synthetic)" \
         "tool call: policy_lookup(P-88) -> exclusion 7.2 gradual leak" \
         "result: claim rejected, exclusion 7.2"; do
  step "$P" --home "$H" --mobile "$M" work --did "$t"
done
"$P" --home "$H" status | grep -E '^(class|status|pages|form|owed)'
"$P" --home "$H" status | grep -qE '^owed +0$' || { echo "FAIL: anchors owed to the network"; exit 1; }
step "$P" --home "$H" --mobile "$M" export-page --number 1,2,3 --by owner --out "$W/e.json"
step "$P" --home "$H" keys --out "$W/k.json"
# Pro seals are anchored blind: the expert reads them with the scan key the holder gives.
step "$P" --home "$H" scan-key --out "$W/scan.key"
ID=$(python3 -I -c "import json,sys;print(json.load(open(sys.argv[1]))['id'])" "$H/container.json")
python3 -I - "$W" <<'PY'
import base64, json, sys
w = sys.argv[1]
pages = json.load(open(f"{w}/e.json"))
for i, p in enumerate(pages, 1):
    json.dump(p, open(f"{w}/p{i}.json", "w"))
bad = pages[1]
bad["page"]["body"]["content"]["content"]["inline"] = base64.urlsafe_b64encode(
    b"tool call: policy_lookup(P-88) -> exclusion 7.3").decode().rstrip("=")
json.dump(bad, open(f"{w}/bad.json", "w"))
PY
failed=0
for f in p1 p2 p3 bad; do
  r=$("$V" --export "$W/$f.json" --container "$ID" --class heavy --keys "$W/k.json" \
        --scan-key "$W/scan.key" --rpc "$RPC" --cluster localnet 2>&1 | head -1)
  echo "$f: $r"
  case "$f:$r" in bad:REJECTED*|p?:ACCEPTED*) ;; *) failed=1 ;; esac
done
[ $failed = 0 ] && echo "DEMO PRO LOCALNET OK" || { echo "DEMO PRO LOCALNET FAIL"; exit 1; }
