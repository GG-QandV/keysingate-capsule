# Keys in Gate — the capsule

**Meta Global AI Developer Hackathon 2026 · Indie Developer track · solo: Yevhenii Nam ([@GG-QandV](https://github.com/GG-QandV))**

> **Built during the hackathon** (after the kickoff ended on 26 Oct 2026, 12:24 PM ET): the **capsule** — a sealed
> container for an AI agent's work record with no doors. It is one fixed-size 6 MiB file that looks like noise; nothing
> inside can be pulled out, and it answers only through its own buttons: a signed export and a status. An agent built on
> **Muse Spark** writes every step of its work into the capsule as a signed page; every model call and every **SAM 3.1**
> image mask becomes a page too; anyone can check the exported pages offline.
>
> **Pre-existing:** the Keys in Gate core existed before the hackathon and is used here as a library
> ([`keysingate/keysingate-core`](https://github.com/keysingate/keysingate-core)) — see [below](#pre-existing-work-a-library).

Each claim of the demo, and where to see it: [`demo/CLAIMS.md`](demo/CLAIMS.md). What the demo does not cover yet, and
the known limits: [`docs/after-the-demo.md`](docs/after-the-demo.md).
The capsule file was also checked as a whole for noise-likeness and for code or format patterns (entropy, chi-square, runs, compression, signature and repeat search against an `os.urandom` control; no structure found, limits stated): [`docs/noise-check.md`](docs/noise-check.md).

## Built during the hackathon

| | What | Where |
|---|---|---|
| 🧊 | **The capsule**: one 6 MiB file indistinguishable from noise; each party holds one secret file; the parts are sealed to the parties' maps (X25519 + ML-KEM-768) | [`crates/ksg-capsule-module`](crates/ksg-capsule-module), [`crates/ksg-capsule-reader`](crates/ksg-capsule-reader) |
| ⚙️ | The container's code runs **inside** the capsule: a WebAssembly module in wasmtime behind two host imports; a session open → call ×N → close; the `ksg-capsule` command line | [`crates/ksg-capsule-reader`](crates/ksg-capsule-reader) |
| ⛓️ | Through the capsule: print → initiation → three pages → export → each page ACCEPTED offline; a tampered page REJECTED. With anchors on a local Solana node: initiation, journal opening with the owner's co-seal, three anchored pages | [`scripts/demo_pro_capsule.sh`](scripts/demo_pro_capsule.sh), `crates/ksg-capsule-reader/tests/k5_offline.rs` |
| 🤖 | Agent tools over MCP; every Muse Spark call recorded as a page; the SAM 3.1 damage mask as a page, byte-identical when the expert re-asks with the same box | [`scripts/ksg_mcp.py`](scripts/ksg_mcp.py), [`scripts/ksg_model_api.py`](scripts/ksg_model_api.py), [`scripts/expert_recheck_mask.py`](scripts/expert_recheck_mask.py) |
| ⚖️ | The judge explanation: every sentence cites a page `[p:N]`; a program — not a model — refuses a citation to a missing or unverified page; the judge page | [`scripts/judge_explain.py`](scripts/judge_explain.py), [`scripts/judge_page.py`](scripts/judge_page.py), sample: [`demo/sample/judge_sample.html`](demo/sample/judge_sample.html) |
| 🗝️ | **The capsule's operations** through the session: two maps (the owner never sees the client's half of the key), sale, transfer, attachments, expert, loss and freeze, backup and restore, succession, unload by a voluntary opening; commands from parties without a map arrive as blind memos in the chain and are applied before the holder's action; `light` anchors on Base Sepolia; the Pro demo part anchored on Solana mainnet-beta — claims 20–31 | [`demo/CLAIMS.md`](demo/CLAIMS.md) §«The capsule's operations», tests in [`crates/ksg-capsule-module/tests`](crates/ksg-capsule-module/tests), [`crates/ksg-capsule-reader/tests`](crates/ksg-capsule-reader/tests) |
| ▶️ | The whole insurance scene ([`demo/case_4417.md`](demo/case_4417.md)) with one command, the agent reached through an ACP-A2A gateway | [`scripts/demo_orchestrator.sh`](scripts/demo_orchestrator.sh) |

## Open a capsule yourself

[`demo/capsule/`](demo/capsule) holds one real capsule and both parties' side files (a throw-away demo; the keys are public on purpose). Its [README](demo/capsule/README.md) walks you through it: build, look at the 6 MiB of noise, write a page as the client agent, export it, check it offline — ACCEPTED — and change one bit — REJECTED.

## Build and test

```bash
cargo build --workspace --all-targets
cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release   # the module the reader runs
cargo test --workspace -- --include-ignored --skip k5_network                 # 115 tests
python3 -m unittest discover -s scripts/tests                                  # 69 tests
```

The toolchain is pinned in `rust-toolchain.toml` (Rust 1.94.1). `k5_network_pro_through_the_capsule` needs its own
Solana node (`solana-test-validator`) and is skipped above. The demo scripts expect the full core next to them: run them
from a `keysingate-core` checkout, where the same files live (`scripts/`, `demo/`).

## Pre-existing work (a library)

The core — signed journal, FROST client key, post-quantum signatures, anchors on Solana and Base, the offline checker —
the ACP-A2A gateway and μ Gate existed before 26 October 2026. Two IETF Internet-Drafts describe the container and export
formats: `draft-nam-ksg-core-00`, `draft-nam-ksg-journal-export-01`. This repository does not copy the core: the capsule
crates depend on [`keysingate/keysingate-core`](https://github.com/keysingate/keysingate-core) at commit
[`d2ce37f`](https://github.com/keysingate/keysingate-core/commit/d2ce37f), the tree checked in full before submission.

## Bugs found and fixed in the pre-existing code during the event

Building the capsule and its demo exposed defects in the earlier core. They were fixed in the core itself, in public:

| Commit in `keysingate-core` | What was wrong | Fix |
|---|---|---|
| [`d4741d4`](https://github.com/keysingate/keysingate-core/commit/d4741d4) | the bare-issuance and orchestrator request ledgers grew without bound on open endpoints | at most 10 000 pending entries per ledger and 3 per contact; 429 past the cap |
| [`e85a282`](https://github.com/keysingate/keysingate-core/commit/e85a282) | slow or silent clients held request threads; one request with a huge `Content-Length` aborted the process; an accept error stopped the server for good | 5 s socket timeouts, 10 s body deadline (408), bounded body drain, accept errors retried (patched `tiny_http`); outgoing calls take at most half the threads (503 past that) |
| [`6c56897`](https://github.com/keysingate/keysingate-core/commit/6c56897) | the `did:web` proof fetch took its host from the request (SSRF) | public DNS names only, public addresses checked at connect time, no redirects, HTTPS only, 64 KiB cap |
| [`409b91e`](https://github.com/keysingate/keysingate-core/commit/409b91e) | a Base anchor whose confirmation did not come could still land, and the file was then taken for a copy | the anchor is noted as pending before it is sent and recognised at the next opening or before the next anchor |
| [`806a15c`](https://github.com/keysingate/keysingate-core/commit/806a15c) | readers fetched every note of a kind from the open `KsgAnchors` contract, so a stranger's flood grew every read | notes are asked by the expected senders only |
| [`0e46bc9`](https://github.com/keysingate/keysingate-core/commit/0e46bc9) | a poisoned lock let half-applied state be saved; Base answers missing fields became silent empty values | the service stops and restarts from the last whole write; missing fields are errors, one failed question is "unknown" |
| [`1c0a3a8`](https://github.com/keysingate/keysingate-core/commit/1c0a3a8) | a service test waited for an anchor by a count of tries, not by time | a 60 s deadline |
| [`d2ce37f`](https://github.com/keysingate/keysingate-core/commit/d2ce37f) | `rustls` and its root certificates had published advisories | updated; `cargo audit` 30 → 23 — the rest (wasmtime 47, which needs Rust 1.95 for the fix; `crypto-bigint` via `k256`; `rsa` via `mail-auth`, verify-only) is scheduled after the hackathon |

Other event work inside the pre-existing crates, kept in the core: the client agent named by the `did:key` of its group
key; the issuer's seal and the post-quantum key laid at initiation, not at print; the bare-issuance service; the phone
and browser halves of the client key (birth key, encrypted backup of the holder half); the README of the core; English
comments and messages.

## Licence

The capsule crates are licensed like the container crates of the core: [`LICENSE-PROPRIETARY`](LICENSE-PROPRIETARY)
(their `Cargo.toml` names it). Everything else here is Apache-2.0 ([`LICENSE`](LICENSE)).
