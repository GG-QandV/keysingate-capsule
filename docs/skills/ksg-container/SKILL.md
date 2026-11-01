---
name: ksg-container
description: Work with a bare KeysInGate container through the ksg MCP tools — one page per step, export and verify.
---

# ksg-container (bare) — draft

Work with a `bare` container only through the `ksg` MCP tools
(`core-v2/scripts/ksg_mcp.py`).

## Rules (always)

1. Never print keys, tokens, or secrets (no `MODEL_API_KEY`, no key files,
   no halves of the client key) — to stdout, logs, reports, or chat.
2. Touch only your own container (the `name` your `ksg_get_container` returned).
   Other containers — never.
3. Never edit container files by hand (`ksg-work/c-*/**`, `*.json`,
   `page-*.json`, `keys.json`). Only the `ksg_*` tools change them.
4. A tool failure is a stop signal: stop, keep what is written, and report
   the tool name plus its error text (without secrets).
5. `prompt` arguments are synthetic demo data only: never repository code,
   private documents, or keys (API Terms § 6.2).

## Start

1. Call `ksg_get_container` exactly once per task and keep its `name`.
   Containers are cheap and copyable: a copy keeps the same identifier,
   so take a fresh one instead of reusing someone else's.
2. Initiation is done together with the owner. `Initiate` gives birth to
   the client's Ed25519 key in two halves: one half stays inside,
   the second half is on the owner's phone. The agent never sees or
   reconstructs the full key.
3. What the agent does: `ksg_get_container`, `ksg_write_page`,
   `ksg_model_call`, `ksg_mask_damage`, `ksg_export_page`, `ksg_verify`.
4. What only the owner does: keeps the phone half of the key, confirms
   `TransferOwnership` / `attach-to` / `detach`, and may delete the whole
   container (`delete --template ID`). The agent never presses these.

## Work

1. One page = one step of work, written at the moment of the step
   (see `core-v2/scripts/demo_orchestrator.sh`, steps 1–8):
   `input` → `policy_lookup` → model answer → mask → `result`.
2. Record with `ksg_write_page(name, text)`: first line is the kind
   (`input: ...`, `tool call: policy_lookup(P-88) -> ...`, `result: ...`).
   It returns the page number — remember it.
3. Every model call goes only through `ksg_model_call`. The tool journals
   the call itself (model, sha256 of request, sha256 of answer, tool args,
   time) and returns the answer plus its page number. Quote the answer
   in the next page; never call the model outside this tool.
4. One damage picture goes through `ksg_mask_damage`
   (e.g. `image_path="demo/damage_4417.png"`, `box=[600, 380, 1120, 1080]`).
   It journals model, sha256 of the picture, box, and sha256 of the mask.
5. `bare` proves *who* wrote a page and that it was untouched — never
   *when* (no anchors; see `core-v2/docs/bare.md`). Keep pages small;
   journal holds 1000 pages; idle term 730 days empty, 365 days with work.
6. One step = one tool call = one page = one reply line: after each tool
   call reply exactly `STEP <n> OK page=<p>` (or `STEP <n> FAIL <reason>`);
   never do two steps in one answer.

## Export & verify

1. Export every page you wrote with `ksg_export_page(name, number)`
   (pointwise export, 1–24 pages at once; the container lives on).
2. Check each file with `ksg_verify(name, file)` — offline, no network.
   Only `ACCEPTED` pages count. `REJECTED` = stop and report.
3. A whole-file check answers `NOT VERIFIABLE` (exit 3) for `bare` —
   that is the class, not a failure. Check page exports instead:
   `ksg-verify-v2 --export page.json --container MULTIHASH --class bare
   --keys keys.json`.
4. Finish with an `EXPLANATION:` block (plain language, ≤ 120 words).
   Every statement carries a citation `[p:N]` to its own ACCEPTED page.
   A link to a missing or non-ACCEPTED page fails the demo.

## If something goes wrong

- Tool error (`ksg_*` raises): stop, do not retry blindly, report tool +
   error tail. A half-written run gets no explanation built on it.
- Empty model answer: raise `max_tokens` (thinking counts too), retry once.
- `no container <name>`: you used a wrong `name` or another workdir —
   re-check the `ksg_get_container` reply and `KSG_WORK`.
- No `EXPLANATION:` / no exports: report "nothing to check", keep the
   partial answer path for the owner.

## light / Pro — later

Anchored classes (`light`, Pro/heavy: ML-DSA-65, X25519 + ML-KEM-768
seals, disputes, succession, promotion) are out of scope here — later.
This skill covers `bare` only: `bare` never becomes `light` or Pro.
