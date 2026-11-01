#!/usr/bin/env bash
# Hackathon demo, K5, on the capsule: print -> initiation (the owner's file
# signs the bytes the module asks for) -> three work pages -> export of pages
# 1..3 -> offline check of each page by ksg-verify-v2 -> one tampered page,
# which must be rejected. Every command is one session: open, one call, close,
# the capsule written atomically; the capsule is 6 MiB after every step.
#
# The network half of the original demo (`demo_pro_localnet.sh`) is NOT here:
# the reader's anchoring is not wired into `ksg-capsule` yet (see the report
# and `crates/ksg-capsule-reader/tests/k5_offline.rs`, `k5_network_*`). This
# script is the offline part: a `light` container, whose pages carry no anchor,
# so no node is needed and nothing has to be run in the cloud.
#
#   scripts/demo_pro_capsule.sh   (light, no node, no network)
#
# A `heavy` (Pro) capsule is printed with `--anchor` only, and its pages carry
# anchors a verifier must read from a node — the network half of the reader,
# which is not wired into `ksg-capsule` yet.
set -uo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
export PATH="$HOME/.cargo/bin:$PATH"
CLASS=light
if [ "${KSG_CLASS:-light}" != light ]; then
  echo "only the light capsule is checked offline: the Pro half runs in scripts/demo_pro_capsule_localnet.sh"
  exit 2
fi
W=$(mktemp -d)
cleanup() { rm -rf "$W"; }
trap cleanup EXIT

(cd "$ROOT" && cargo build -q --release -p ksg-capsule-reader -p ksg-verify-v2) || exit 1
(cd "$ROOT" && cargo build -q --release -p ksg-capsule-module --target wasm32-unknown-unknown) || exit 1
C=$ROOT/target/release/ksg-capsule
V=$ROOT/target/release/ksg-verify-v2
MOD=$ROOT/target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm
H=$W/h
step() { "$@" >"$W/out" 2>&1 || { echo "FAIL: ${*:2}"; tail -5 "$W/out"; exit 1; }; }
size() { stat -c%s "$H/capsule.bin"; }

step "$C" --home "$H" init --class "$CLASS" --wasm "$MOD"
[ "$(size)" = 6291456 ] || { echo "FAIL: the capsule is $(size) bytes after init"; exit 1; }
step "$C" --home "$H" initiate
[ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after the initiation"; exit 1; }
for t in "input: claim 4417, water damage, policy P-88 (synthetic)" \
         "tool call: policy_lookup(P-88) -> exclusion 7.2 gradual leak" \
         "result: claim rejected, exclusion 7.2"; do
  step "$C" --home "$H" work "$t"
  [ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after a work page"; exit 1; }
done
"$C" --home "$H" status
for n in 1 2 3; do
  step "$C" --home "$H" export-page "$n" --out "$W/p$n.json"
  [ "$(size)" = 6291456 ] || { echo "FAIL: the capsule after export-page $n"; exit 1; }
done
step "$C" --home "$H" keys --out "$W/k.json"
ID=$("$C" --home "$H" status | python3 -I -c "import json,sys;print(json.load(sys.stdin)['id'])")

python3 -I - "$W" <<'PY'
import base64, json, sys
w = sys.argv[1]
pages = json.load(open(f"{w}/p2.json"))
inline = pages["page"]["body"]["content"]["content"]["inline"]
raw = base64.urlsafe_b64decode(inline + "=" * (-len(inline) % 4))
bad = bytes([raw[0] ^ 0x01]) + raw[1:]
pages["page"]["body"]["content"]["content"]["inline"] = (
    base64.urlsafe_b64encode(bad).decode().rstrip("="))
json.dump(pages, open(f"{w}/bad.json", "w"))
PY

failed=0
for f in p1 p2 p3 bad; do
  r=$("$V" --export "$W/$f.json" --container "$ID" --class "$CLASS" --keys "$W/k.json" 2>&1 | head -1)
  echo "$f: $r"
  case "$f:$r" in bad:REJECTED*|p?:ACCEPTED*) ;; *) failed=1 ;; esac
done
[ $failed = 0 ] && echo "DEMO PRO CAPSULE (offline) OK" || { echo "DEMO PRO CAPSULE (offline) FAIL"; exit 1; }
