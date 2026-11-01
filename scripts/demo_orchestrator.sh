#!/usr/bin/env bash
# Hackathon demo, steps 1 and 9: the orchestrator hands the claim to the agent
# through the ACP-A2A gateway; the agent records every step through the ksg MCP
# tools (scripts/ksg_mcp.py) — including every Muse Spark call and the SAM mask —
# exports the pages the expert will get, and writes the explanation for the
# judge. The program checks what that explanation points at.
#
#   scripts/demo_orchestrator.sh [agent_id] [case_file]
#
# agent_id defaults to hermes-cloud (Muse Spark through Meta Model API, owner 26.10);
# the agent must have the `ksg` MCP server (scripts/ksg_mcp.py) with MODEL_API_KEY,
# KSG_PANEL, KSG_VERIFY, KSG_WORK set, and the Meta Model API provider (Muse Spark).
#
# Owner's decision 27.10: the explanation for the judge is written by the agent
# itself (Hermes, Muse Spark) — it ends its answer with an `EXPLANATION:` block and
# this script checks that block's [p:N] links. So the orchestrator needs no Meta
# key of its own: the key load below only serves the old mode (judge_explain.py
# without --text, where the program asks the model itself).
#
# Environment of this script: MODEL_API_KEY (optional, old mode only; when it is
# empty the key is read from the file named by KSG_META_KEY_FILE — but only when
# that variable is set: there is no default key path, and the value is never
# printed), KSG_WORK (default: ./ksg-work), KSG_PANEL, KSG_VERIFY, KSG_CLASS.
#
# KSG_WORK must be the same directory the agent's `ksg` MCP server writes to
# (its own `env:` block in the gateway's Hermes config): the orchestrator reads
# the pages the agent exported from there in step 9.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT=${1:-hermes-cloud}
CASE=${2:-$ROOT/demo/case_4417.md}
WORK=${KSG_WORK:-$ROOT/ksg-work}
export KSG_WORK="$WORK"
export KSG_CLASS=${KSG_CLASS:-light}
export KSG_PANEL=${KSG_PANEL:-$ROOT/target/release/ksg-remote-panel}
export KSG_VERIFY=${KSG_VERIFY:-$ROOT/target/release/ksg-verify-v2}
[ -x "$KSG_PANEL" ] || KSG_PANEL=$ROOT/target/debug/ksg-remote-panel
[ -x "$KSG_VERIFY" ] || KSG_VERIFY=$ROOT/target/debug/ksg-verify-v2
export KSG_PANEL KSG_VERIFY

# The Meta Model API key is not needed for step 9: the agent writes the explanation
# and this script only checks its [p:N] links. A key is loaded best-effort for the
# old mode only (judge_explain.py without --text): the environment first, then the
# file named by KSG_META_KEY_FILE — and that file only when the variable is set.
# There is no default key path here; the value never reaches stdout, stderr or the
# trace of this script.
if [ -z "${MODEL_API_KEY:-}" ] && [ -n "${KSG_META_KEY_FILE:-}" ]; then
  KEY_FILE=$KSG_META_KEY_FILE
  if [ -r "$KEY_FILE" ]; then
    MODEL_API_KEY=$(head -n 1 "$KEY_FILE" | tr -d '[:space:]')
    if [ -n "$MODEL_API_KEY" ]; then
      export MODEL_API_KEY
    else
      unset MODEL_API_KEY
    fi
  else
    echo "note: KSG_META_KEY_FILE ($KEY_FILE) is not readable; only the old model-written mode needs a key" >&2
  fi
fi
if [ -z "${MODEL_API_KEY:-}" ]; then
  echo "note: no Meta key (MODEL_API_KEY unset, no readable KSG_META_KEY_FILE): the old mode" >&2
  echo "(judge_explain.py without --text, the program asks the model) is unavailable here;" >&2
  echo "the agent-written mode below (judge_explain.py --text) needs no key" >&2
fi

# Steps of the demo (ops/supervisor/spec_demo_checklist.md item 1): each step is
# a SEPARATE gateway task with a short timeout (<=300 s) and one retry on a
# cut or empty answer. The agent's reply to a step is exactly one line
# `STEP <n> OK page=<p>` (or `STEP <n> FAIL <reason>`); the page itself is
# written through the `ksg` MCP tools. The last step appends the EXPLANATION
# block after its STEP line. Step→page recording ($KSG_WORK/steps.json) is the
# next stage (N7); step 9 below re-discovers the pages the agent exported.
STEP_TIMEOUT=300
# Steps that call Muse Spark / SAM 3.1 or export+verify every page take longer.
step_timeout() {
  case "$1" in
    3|4|6|7) echo 600 ;;
    *) echo "$STEP_TIMEOUT" ;;
  esac
}
LAST_STEP=7

# step_prompt <n>: print the prompt for step <n> on stdout. Every step is
# self-contained (the gateway may start a fresh task): it re-opens the
# container with ksg_get_container and does exactly one tool step.
step_prompt() {
  case "$1" in
    1) cat <<'STEP'
Call the tool ksg_get_container now. Then call the tool ksg_write_page with
that `name` and the text "input: " followed by the insurance claim below as
you read it (one short paragraph). Then reply with the exact JSON that
ksg_write_page returned, nothing else.
The claim (synthetic data):
STEP
      ;;
    2) cat <<'STEP'
Call the tool ksg_get_container now. Then call the tool ksg_write_page with
that `name` and the text "tool call: policy_lookup(P-88) -> " followed by the
policy clauses you rely on for this claim (water damage, apartment 4417,
policy P-88). Then reply with the exact JSON that ksg_write_page returned,
nothing else.
STEP
      ;;
    3) cat <<'STEP'
Call the tool ksg_get_container now. Then call the tool ksg_model_call with
that `name`, a prompt asking Muse Spark to read the evidence (claim: water
damage, apartment 4417, policy P-88) and name the clause that applies, and
tool_args {"claim": "4417", "policy": "P-88"}. Then call the tool
ksg_write_page with that `name` and the text "model answer: " followed by a
quote of the model's answer. Then reply with the exact JSON that
ksg_write_page returned, nothing else.
STEP
      ;;
    4) cat <<'STEP'
Call the tool ksg_get_container now. Then call the tool ksg_mask_damage with
that `name`, image_path "demo/damage_4417.png" and box [600, 380, 1120, 1080].
Then reply with the exact JSON that ksg_mask_damage returned, nothing else.
STEP
      ;;
    5) cat <<'STEP'
Call the tool ksg_get_container now. Then call the tool ksg_write_page with
that `name` and the text "result: " followed by the decision on the claim,
the reason and the clause (claim: water damage, apartment 4417, policy P-88).
Then reply with the exact JSON that ksg_write_page returned, nothing else.
STEP
      ;;
    6) cat <<'STEP'
Call the tool ksg_get_container now. Then, for every page number listed
below, call the tool ksg_export_page with that `name` and the number, and
then the tool ksg_verify with that `name` and the returned file. Then reply
with the exact JSON that the last ksg_verify returned, nothing else.
STEP
      ;;
    7) cat <<'STEP'
New task. You are an insurance claims agent. Last step, and part of your reply:
1. Call ksg_get_container once (returns the existing container).
2. Finish the answer with a block that starts with the line `EXPLANATION:` —
   the decision explained to the hackathon judge in plain language, no jargon,
   at most 120 words. Every statement in it must carry a citation `[p:N]` to
   its own page, N being a page you wrote above. The program checks those
   links; a citation of a page that does not exist is a failed demo.
First line of your reply: `STEP 7 OK`. Then the `EXPLANATION:` block. Also
report: the container name and identifier, the decision, and for each exported
page its number, its file and whether it was ACCEPTED.
STEP
      ;;
  esac
}

# 1.6a: the agent's `STEP n OK page=p` is a claim; the journal is the fact.
# journal_pages: how many pages the run's container holds now (0: no container
# yet). Read with the panel itself, not through the agent.
journal_pages() {
  local name out
  [ -s "$WORK/.current" ] || { echo 0; return; }
  name=$(cat "$WORK/.current")
  [ -f "$WORK/$name/h/container.json" ] || { echo 0; return; }
  out=$("$KSG_PANEL" --home "$WORK/$name/h" status 2>&1) || {
    echo "journal_pages: $KSG_PANEL status failed: $(echo "$out" | tail -1)" >&2; echo 0; return; }
  echo "$out" | awk '$1 == "pages" && NF == 2 { print $2; found = 1 } END { if (!found) print 0 }'
}
# journal_where: why the journal reads as it does — for the stop message, so a
# failed check names the cause (no .current in this KSG_WORK, no container, a
# panel that does not run) instead of blaming the agent.
journal_where() {
  if [ ! -s "$WORK/.current" ]; then
    echo "no $WORK/.current (the agent's ksg MCP writes to another KSG_WORK?)"
  elif [ ! -f "$WORK/$(cat "$WORK/.current")/h/container.json" ]; then
    echo "$WORK/.current names $(cat "$WORK/.current"), no container there"
  elif [ ! -x "$KSG_PANEL" ]; then
    echo "panel $KSG_PANEL is not executable"
  else
    echo "container $WORK/$(cat "$WORK/.current")"
  fi
}
# step_written <step> <page> <pages before the step>: the page steps (1-5) must
# have added a page to the journal during this step, and the claimed page must
# be one of them; step 6 must have left an export file for every recorded page.
# Prints the reason and fails when the claim does not hold.
step_written() {
  local step=$1 page=$2 before=$3 after
  case "$step" in
    1|2|3|4|5)
      after=$(journal_pages)
      if [ -z "$page" ]; then
        echo "no page=<n> in the STEP line"; return 1
      fi
      if [ "$after" -le "$before" ]; then
        echo "the journal did not grow (pages $before -> $after; $(journal_where)): no tool call wrote a page there"; return 1
      fi
      if [ "$page" -lt "$before" ] || [ "$page" -ge "$after" ]; then
        echo "page=$page is not one written in this step (new pages $before..$((after - 1)))"; return 1
      fi
      ;;
    6)
      local name missing=""
      name=$(cat "$WORK/.current" 2>/dev/null || true)
      for p in $(python3 -c 'import json,sys; print(" ".join(str(v) for v in sorted(set(json.load(open(sys.argv[1])).values()))))' "$STEPS_JSON"); do
        [ -s "$WORK/$name/page-$p.json" ] || missing="$missing $p"
      done
      if [ -n "$missing" ]; then
        echo "no export file for page(s):$missing"; return 1
      fi
      ;;
  esac
  return 0
}

# Step 10b-pre (J13): capsule noise before the agent works, for judge_page (2).
# The claim scenario has no capsule step of its own, so the pair is assembled
# by a print step exactly like scripts/demo_pro_capsule.sh (offline, no
# network): `ksg-capsule init` + `initiate` in a scratch home under $WORK.
# Best-effort under `set -e`: anything missing or failing leaves no snapshot
# and the judge page renders the honest placeholder instead.
CAPSULE_BEFORE=""
CAPSULE_AFTER=""
CAPSULE_SNAP_HOME="$WORK/capsule-snap"
CAPSULE_BIN="$ROOT/target/release/ksg-capsule"
[ -x "$CAPSULE_BIN" ] || CAPSULE_BIN="$ROOT/target/debug/ksg-capsule"
CAPSULE_MOD="$ROOT/target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm"
if [ "${KSG_CLASS:-light}" = light ] && [ -x "$CAPSULE_BIN" ] && [ -f "$CAPSULE_MOD" ]; then
  rm -rf "$CAPSULE_SNAP_HOME"
  mkdir -p "$CAPSULE_SNAP_HOME"
  if "$CAPSULE_BIN" --home "$CAPSULE_SNAP_HOME" init --class light --wasm "$CAPSULE_MOD" >/dev/null 2>&1 \
    && "$CAPSULE_BIN" --home "$CAPSULE_SNAP_HOME" initiate >/dev/null 2>&1 \
    && [ -f "$CAPSULE_SNAP_HOME/capsule.bin" ]; then
    cp "$CAPSULE_SNAP_HOME/capsule.bin" "$WORK/capsule.before.bin" 2>/dev/null || true
    [ -f "$WORK/capsule.before.bin" ] && CAPSULE_BEFORE="$WORK/capsule.before.bin" || true
  else
    echo "note: capsule print step failed before the agent run: section (2) will say so" >&2
  fi
else
  echo "note: capsule step not in this run (needs light class + ksg-capsule binary/module): section (2) renders the placeholder" >&2
fi

ANSWERS_DIR="$WORK/answers"
mkdir -p "$ANSWERS_DIR"
# spec_demo_checklist item 3 (N7): the orchestrator records step→page here;
# judge_page.py --steps reads it in N8. Written fresh on every run.
STEPS_JSON="$WORK/steps.json"
echo '{}' >"$STEPS_JSON"
# The run's container: ksg_get_container makes it once and returns it to every
# later step (KSG_WORK/.current). A fresh run starts without one.
rm -f "$WORK/.current"
# One agent session for the whole checklist: step 1 opens it, every later step
# continues it (A2A contextId), so the agent keeps the claim in its context.
CTX_FILE="$WORK/context_id"
rm -f "$CTX_FILE"
# Seconds per step (for the judge page and the anchoring-time budget).
TIMES_JSON="$WORK/step_times.json"
echo '{}' >"$TIMES_JSON"
STEP=1
STEP7_ANSWER=""
while [ "$STEP" -le "$LAST_STEP" ]; do
  PROMPT_FILE=$(mktemp /tmp/ksg-step.XXXXXX.txt)
  if [ "$STEP" -eq 1 ]; then
    { step_prompt 1; cat "$CASE"; } >"$PROMPT_FILE"
  else
    step_prompt "$STEP" >"$PROMPT_FILE"
  fi
  if [ "$STEP" -eq 6 ]; then
    # The export range comes from the orchestrator, not from the agent's memory.
    LAST_PAGE=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(max(d.values()) if d else 0)' "$STEPS_JSON")
    # Every page from the first recorded to the last — a step may write more
    # than the one it reports (step 3: the Muse Spark call's own page, then
    # the quote), and the judge must see the model call too.
    PAGE_LIST=$(python3 -c 'import json,sys; v=json.load(open(sys.argv[1])).values(); print(", ".join(str(p) for p in range(min(v), max(v)+1)) if v else "")' "$STEPS_JSON")
    echo "Pages: $PAGE_LIST." >>"$PROMPT_FILE"
  fi
  # Every page step must show in the journal (1.6a): said so to the agent too.
  if [ "$STEP" -lt "$LAST_STEP" ]; then
    cat >>"$PROMPT_FILE" <<'NOTE'
This is done only by calling the tools: a reply without the tool calls does
nothing. The orchestrator reads the container's journal after your reply.
NOTE
  fi
  BEFORE_PAGES=$(journal_pages)
  ATTEMPT=0
  while :; do
    ATTEMPT=$((ATTEMPT + 1))
    STEP_ANSWER="$ANSWERS_DIR/step-$STEP.attempt-$ATTEMPT.txt"
    if [ "$ATTEMPT" -ge 2 ]; then
      # N10: idempotent retry — the first attempt may have written the page
      # but its answer got cut. Tell the agent not to redo the step.
      {
        echo
        echo "Retry note: if step $STEP is already done and its page is written, do NOT do it again — just reply STEP $STEP OK page=<the number of the page you already wrote>."
      } >>"$PROMPT_FILE"
    fi
    T0=$(date +%s)
    set +e
    if [ -s "$CTX_FILE" ]; then
      GW_CONTEXT_ID=$(cat "$CTX_FILE") "$ROOT/scripts/gw_ask.sh" "$AGENT" "$PROMPT_FILE" "$(step_timeout "$STEP")" >"$STEP_ANSWER" 2>"$STEP_ANSWER.err"
    else
      GW_CONTEXT_OUT="$CTX_FILE" "$ROOT/scripts/gw_ask.sh" "$AGENT" "$PROMPT_FILE" "$(step_timeout "$STEP")" >"$STEP_ANSWER" 2>"$STEP_ANSWER.err"
    fi
    GW_RC=$?
    set -e
    python3 - "$TIMES_JSON" "$STEP" "$ATTEMPT" "$(( $(date +%s) - T0 ))" "$GW_RC" <<'PY'
import json, sys
path, step, attempt, secs, rc = sys.argv[1:]
try:
    data = json.load(open(path))
except Exception:
    data = {}
data.setdefault(step, []).append({"attempt": int(attempt), "seconds": int(secs), "gw_rc": int(rc)})
json.dump(data, open(path, "w"), indent=1, sort_keys=True)
PY
    echo "step $STEP attempt $ATTEMPT: $(( $(date +%s) - T0 )) s (gw rc=$GW_RC)" >&2
    # N10: the STEP line may sit anywhere in the answer (no newline before
    # it), so it is searched anywhere — no ^ anchor — and the OK/FAIL verdict
    # plus page=<n> are read from that line, not from the whole answer.
    STEP_LINE=$(grep -oE "STEP $STEP (OK|FAIL)[^[:cntrl:]]*" "$STEP_ANSWER" | tail -1 || true)
    # 1.6c (diag16c, 30.10): steps 1-6 ask for the tool's own JSON, not a
    # STEP line (a STEP-line template got answered without the tool call).
    # The page is the one the tool returned; the journal check below decides.
    if [ -z "$STEP_LINE" ] && [ "$GW_RC" -eq 0 ] && [ "$STEP" -lt "$LAST_STEP" ]; then
      JPAGE=$(grep -oE '"page"[[:space:]]*:[[:space:]]*[0-9]+' "$STEP_ANSWER" | tail -1 | grep -oE '[0-9]+$' || true)
      STEP_LINE="STEP $STEP OK${JPAGE:+ page=$JPAGE}"
    fi
    WHY=""
    if [ "$GW_RC" -eq 0 ] && [ -n "$STEP_LINE" ] && echo "$STEP_LINE" | grep -qE "STEP $STEP OK"; then
      PAGE=$(echo "$STEP_LINE" | grep -oE "page=[0-9]+" | head -1 | cut -d= -f2 || true)
      WHY=$(step_written "$STEP" "${PAGE:-}" "$BEFORE_PAGES") || {
        echo "step $STEP attempt $ATTEMPT: the agent said OK but $WHY" >&2
        if [ "$ATTEMPT" -ge 2 ]; then
          echo "step $STEP: claimed twice without the journal behind it: stop" >&2
          echo "the agent's answer: $STEP_ANSWER" >&2
          rm -f "$PROMPT_FILE"
          exit 1
        fi
        {
          echo
          echo "Your previous reply did not do the step: $WHY. Call the tools now, exactly as listed above, and reply with the JSON the last tool returned."
        } >>"$PROMPT_FILE"
        continue
      }
      echo "step $STEP OK (attempt $ATTEMPT): $STEP_LINE"
      # N7: record step→page (step 7 has no page — its line is bare `STEP 7 OK`).
      python3 - "$STEPS_JSON" "$STEP" "${PAGE:-}" <<'PY'
import json, sys
path, step, page = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    with open(path) as f:
        data = json.load(f)
except Exception:
    data = {}
if page:
    data[str(step)] = int(page)
with open(path, "w") as f:
    json.dump(data, f, indent=1, sort_keys=True)
PY
      break
    fi
    if [ "$GW_RC" -eq 0 ] && [ -n "$STEP_LINE" ] && echo "$STEP_LINE" | grep -qE "STEP $STEP FAIL"; then
      echo "step $STEP refused by the agent: $STEP_LINE" >&2
      echo "the agent's answer: $STEP_ANSWER" >&2
      rm -f "$PROMPT_FILE"
      exit 1
    fi
    # A cut task (timeout, an agent crash) or an empty answer: retry once.
    if [ "$ATTEMPT" -ge 2 ]; then
      echo "step $STEP gave no usable answer twice (gw rc=$GW_RC): not retrying" >&2
      echo "the agent's partial answer: $STEP_ANSWER" >&2
      rm -f "$PROMPT_FILE"
      exit 1
    fi
    echo "step $STEP attempt $ATTEMPT cut or empty (gw rc=$GW_RC): retrying once" >&2
  done
  rm -f "$PROMPT_FILE"
  if [ "$STEP" -eq 1 ] && [ ! -s "$WORK/.current" ]; then
    # The agent's ksg MCP keeps the run's container in KSG_WORK/.current. No file
    # here means the agent writes somewhere else (another KSG_WORK) or runs an
    # old ksg_mcp.py — every later step would land in another container.
    echo "step 1: no $WORK/.current — the agent's ksg MCP does not write to this KSG_WORK (or is an old ksg_mcp.py): stop" >&2
    exit 1
  fi
  if [ "$STEP" -eq "$LAST_STEP" ]; then STEP7_ANSWER="$STEP_ANSWER"; fi
  STEP=$((STEP + 1))
done

# Step 9 reads the explanation from the last step's answer.
ANSWER="$STEP7_ANSWER"

# Step 9: the explanation for the judge, written by the agent itself (Muse Spark).
# This script only cuts the `EXPLANATION:` block out of the agent's answer and lets
# judge_explain.py check that every [p:N] points at a page that exists and was
# ACCEPTED offline — no model is called here.
if [ -s "$WORK/.current" ]; then
  BOX="$WORK/$(cat "$WORK/.current")"
else
  BOX=$(ls -dt "$WORK"/c-* 2>/dev/null | head -1 || true)
fi
if [ -z "${BOX:-}" ]; then
  echo "no container under $WORK: the agent wrote no pages" >&2
  exit 1
fi
NAME=$(basename "$BOX")
PAGES=()
for file in "$BOX"/page-*.json; do
  [ -e "$file" ] || continue
  number=$(basename "$file" .json); number=${number#page-}
  PAGES+=(--page "$number=$file")
done
if [ ${#PAGES[@]} -eq 0 ]; then
  echo "no exported pages under $BOX: nothing to explain" >&2
  exit 1
fi

# The block starts at the line `EXPLANATION:` and runs to the end of the answer; text
# on that same line counts too (the agent may write `EXPLANATION: the claim ...`).
EXPLANATION=$(mktemp /tmp/ksg-explanation.XXXXXX.txt)
awk 'found { print; next }
     /^[[:space:]]*EXPLANATION:/ { found = 1
       sub(/^[[:space:]]*EXPLANATION:[[:space:]]*/, "")
       if (length($0)) print }' "$ANSWER" > "$EXPLANATION"
if [ ! -s "$EXPLANATION" ]; then
  echo "the agent's answer has no EXPLANATION: block: nothing to check for the judge" >&2
  echo "the agent's answer: $ANSWER" >&2
  echo "the agent's explanation: $EXPLANATION (empty)" >&2
  exit 1
fi

python3 "$ROOT/scripts/judge_explain.py" --name "$NAME" --work "$WORK" "${PAGES[@]}" --text "$EXPLANATION"
echo
echo "explanation of the agent: $EXPLANATION"
echo "answer of the agent: $ANSWER"


# Step 10a (J12): the expert re-asks SAM 3.1 for the mask page's box and
# compares the mask byte for byte; the verdict JSON feeds judge_page --mask-json.
# Best-effort under `set -e`: a MISMATCH (exit 1) or a missing mask page must not
# abort the run — judge_page renders the recheck state either way.
MASK_JSON="$WORK/mask_recheck.json"
MASK_PAGE=$(ROOT="$ROOT" python3 - "$BOX" <<'PY'
import os
import sys
sys.path.insert(0, os.path.join(os.environ["ROOT"], "scripts"))
from judge_page import page_kind, read_pages
box = sys.argv[1]
hit = ""
try:
    import glob as _g
    found = read_pages(box)
    for number in sorted(found):
        if page_kind(found[number].get("text", "")) == "SAM mask":
            cands = sorted(_g.glob(os.path.join(box, "page-%d.json" % number)))
            if cands:
                hit = cands[0]
                break
except Exception:
    pass
sys.stdout.write(hit)
PY
)
if [ -n "${MASK_PAGE:-}" ]; then
  python3 "$ROOT/scripts/expert_recheck_mask.py" --page "$MASK_PAGE" \
    --image "$ROOT/demo/damage_4417.png" --json "$MASK_JSON" || true
else
  echo "note: no SAM mask page under $BOX: mask recheck skipped" >&2
fi

# Step 10b-post (J13): capsule noise after the export — one offline print step
# (`work`, like scripts/demo_pro_capsule.sh, no network) so before/after differ.
# Best-effort under `set -e`: a failed print still snapshots the capsule as-is.
if [ -n "${CAPSULE_BEFORE:-}" ] && [ -d "$CAPSULE_SNAP_HOME" ]; then
  "$CAPSULE_BIN" --home "$CAPSULE_SNAP_HOME" work "print: claim evidence snapshot for the judge (synthetic)" >/dev/null 2>&1 || true
  cp "$CAPSULE_SNAP_HOME/capsule.bin" "$WORK/capsule.after.bin" 2>/dev/null || true
  [ -f "$WORK/capsule.after.bin" ] && CAPSULE_AFTER="$WORK/capsule.after.bin" || true
fi

# Step 10d (J14): tamper check — a copy of the export with one byte flipped in
# one page must be REJECTED by ksg-verify-v2; the verdict JSON feeds
# judge_page --tamper-json ("tampered copy: REJECTED, reason ...").
# Best-effort under `set -e`: anything missing never aborts the run —
# judge_page renders the placeholder/unavailable state instead.
TAMPER_JSON="$WORK/tamper_recheck.json"
FIRST_PAGE=$(ls "$BOX"/page-*.json 2>/dev/null | sort | head -1 || true)
if [ -n "${FIRST_PAGE:-}" ]; then
  TAMPER_COPY="$WORK/tampered-$(basename "$FIRST_PAGE")"
  cp "$FIRST_PAGE" "$TAMPER_COPY" 2>/dev/null || true
  KSG_VERIFY_BIN="${KSG_VERIFY:-$ROOT/target/release/ksg-verify-v2}"
  [ -x "$KSG_VERIFY_BIN" ] || KSG_VERIFY_BIN="$ROOT/target/debug/ksg-verify-v2"
  TAMPER_PAGE_NUM=$(basename "$FIRST_PAGE" .json); TAMPER_PAGE_NUM=${TAMPER_PAGE_NUM#page-}
  BOX_ID=""; [ -f "$BOX/h/container.json" ] && BOX_ID=$(python3 -c "import json;print(json.load(open('$BOX/h/container.json')).get('id',''))" 2>/dev/null || true)
  python3 - "$TAMPER_COPY" "$TAMPER_PAGE_NUM" "$TAMPER_JSON" "$KSG_VERIFY_BIN" "$BOX" "$BOX_ID" "${KSG_CLASS:-light}" "$TAMPER_COPY" <<'PY' || true
import json
import subprocess
import sys
copy_path, page_num, out_json, verify_bin, box, box_id, klass, src = sys.argv[1:8]
verdict = {"exists": True, "tampered_page": page_num, "source": src,
           "accepted": None, "verdict": "not checked", "reason": ""}
try:
    raw = open(copy_path, "rb").read()
    if raw:
        pos = len(raw) // 2
        raw = raw[:pos] + bytes([(raw[pos] + 1) % 256]) + raw[pos + 1:]
        open(copy_path, "wb").write(raw)
    else:
        verdict["reason"] = "empty page file, nothing to flip"
        raise RuntimeError("empty")
except RuntimeError:
    pass
except Exception as exc:
    verdict["reason"] = "tamper flip failed: %s" % exc
else:
    import os
    keys = os.path.join(box, "keys.json")
    if os.path.exists(verify_bin) and os.access(verify_bin, os.X_OK) and box_id and os.path.exists(keys):
        try:
            proc = subprocess.run([verify_bin, "--export", copy_path,
                                   "--container", box_id, "--keys", keys,
                                   "--class", klass],
                                  capture_output=True, text=True, timeout=120)
            report = (proc.stdout + proc.stderr).strip()
            first = report.splitlines()[0] if report else "empty verify output"
            verdict["accepted"] = report.startswith("ACCEPTED")
            verdict["verdict"] = "ACCEPTED" if verdict["accepted"] else "REJECTED"
            verdict["reason"] = first[:300]
        except Exception as exc:
            verdict["reason"] = "verify error: %s" % exc
    else:
        verdict["reason"] = "not checked (no binary/keys/container id)"
try:
    open(out_json, "w").write(json.dumps(verdict))
except Exception:
    pass
PY
else
  echo "note: no exported pages under $BOX: tamper check skipped" >&2
fi

# Step 10 (J8): static judge page for the hackathon — no server, EN, opens from
# file. Reads the exported pages, the explanation text and ksg-verify-v2
# verdicts; section (2) shows the capsule before/after pair, or — when this run
# has no capsule step — the honest placeholder (capsule step not in this run).
if [ -n "${CAPSULE_BEFORE:-}" ] && [ -n "${CAPSULE_AFTER:-}" ]; then
  python3 "$ROOT/scripts/judge_page.py" --work "$WORK" --box "$BOX" \
    --text "$EXPLANATION" --class "${KSG_CLASS:-light}" \
    --mask-json "$MASK_JSON" \
    --tamper-json "$TAMPER_JSON" \
    --steps "$STEPS_JSON" \
    --capsule-before "$CAPSULE_BEFORE" --capsule-after "$CAPSULE_AFTER" \
    --out "$ROOT/demo/out/judge.html"
else
  echo "note: capsule step not in this run: judge page section (2) renders the placeholder" >&2
  python3 "$ROOT/scripts/judge_page.py" --work "$WORK" --box "$BOX" \
    --text "$EXPLANATION" --class "${KSG_CLASS:-light}" \
    --mask-json "$MASK_JSON" \
    --tamper-json "$TAMPER_JSON" \
    --steps "$STEPS_JSON" \
    --out "$ROOT/demo/out/judge.html"
fi
echo
echo "judge page: $ROOT/demo/out/judge.html"
