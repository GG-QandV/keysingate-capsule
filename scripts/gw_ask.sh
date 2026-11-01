#!/usr/bin/env bash
# Give a task to a local agent through the ACP-A2A gateway and print its answer.
#
#   scripts/gw_ask.sh <agent_id> <task-file|-> [max_seconds]
#
# agent_id: opencode-cloud | hermes-cloud (agents in the owner's gateway config).
# The task goes as a non-blocking message/send (configuration.blocking: false):
# the gateway answers at once with a task id, the script polls tasks/get every
# 5 s until the state is not "working". No connection stays open while the
# agent works, so the cloud egress proxy cannot cut it (~30 s of silence).
# From the cloud the bearer token is added by the egress proxy. On the owner's
# machine the gateway is reached directly, so the token comes from the
# environment (GW_TOKEN or GW_TOKEN_CLOUD): a file-sourced variable, never an
# argument — the value is not printed and not part of any command line.
set -euo pipefail

AGENT=${1:?agent_id}
SRC=${2:?task file or -}
MAX=${3:-1800}
BASE=${GW_BASE:-https://gw.keysingate.com}
URL="$BASE/agents/$AGENT/rpc"
TOKEN=${GW_TOKEN:-${GW_TOKEN_CLOUD:-}}
AUTH=()
[ -n "$TOKEN" ] && AUTH=(-H "Authorization: Bearer $TOKEN")

if [ "$SRC" = "-" ]; then TEXT=$(cat); else TEXT=$(cat "$SRC"); fi

# GW_CONTEXT_ID: continue the agent's session from an earlier task (A2A contextId);
# GW_CONTEXT_OUT: file to write the task's contextId to (for the next call).
# "stream capacity exhausted" (the agent's single slot is still held by the
# previous task) is not a failure: wait and resend, up to GW_BUSY_WAIT seconds.
BUSY_UNTIL=$(( $(date +%s) + ${GW_BUSY_WAIT:-120} ))
while :; do
  START=$(python3 -I -c '
import json, os, sys
msg = {"role": "user", "parts": [{"kind": "text", "text": sys.argv[1]}]}
ctx = os.environ.get("GW_CONTEXT_ID", "")
if ctx: msg["contextId"] = ctx
print(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "message/send",
  "params": {"message": msg, "configuration": {"blocking": False}}}, ensure_ascii=False))' "$TEXT" \
    | curl -sS --max-time 60 "${AUTH[@]}" -X POST "$URL" -H 'Content-Type: application/json' --data-binary @-)
  if printf '%s' "$START" | grep -q 'capacity exhausted' && [ "$(date +%s)" -lt "$BUSY_UNTIL" ]; then
    echo "agent busy (previous task still holds the slot): waiting 10 s" >&2
    sleep 10
    continue
  fi
  break
done

TASK=$(printf '%s' "$START" | python3 -I -c '
import json, os, sys
d = json.load(sys.stdin)
if "error" in d: sys.exit("gateway error: " + json.dumps(d["error"], ensure_ascii=False))
out = os.environ.get("GW_CONTEXT_OUT", "")
ctx = d["result"].get("contextId") or d["result"].get("context_id") or ""
if out and ctx:
    open(out, "w").write(ctx)
print(d["result"]["id"])')
echo "task $TASK started" >&2

DEADLINE=$(( $(date +%s) + MAX ))
while :; do
  GOT=$(curl -sS --max-time 30 "${AUTH[@]}" -X POST "$URL" -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tasks/get\",\"params\":{\"id\":\"$TASK\"}}")
  STATE=$(printf '%s' "$GOT" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
print(d.get("result", {}).get("status", {}).get("state", "error"))')
  if [ "$STATE" != "working" ]; then break; fi
  if [ "$(date +%s)" -ge "$DEADLINE" ]; then
    # Cancel the task so the agent's slot is free for a retry (no double work).
    curl -sS --max-time 15 "${AUTH[@]}" -X POST "$URL" -H 'Content-Type: application/json' \
      -d "{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tasks/cancel\",\"params\":{\"id\":\"$TASK\"}}" >/dev/null 2>&1 || true
    echo "timeout: task $TASK still working: cancelled" >&2; exit 2
  fi
  sleep 5
done

printf '%s' "$GOT" | python3 -I -c '
import json, sys
d = json.load(sys.stdin)
if "error" in d: sys.exit("gateway error: " + json.dumps(d["error"], ensure_ascii=False))
st = d["result"]["status"]
for p in (st.get("message") or {}).get("parts", []):
    if p.get("kind") == "text": print(p["text"])
print("[state: " + st["state"] + "]")
# A task that did not complete is not an answer: the caller (demo_orchestrator.sh)
# must see the failure and stop instead of explaining half-written pages.
sys.exit(0 if st["state"] == "completed" else 3)'
