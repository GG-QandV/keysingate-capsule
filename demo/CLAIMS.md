# What the demo claims — and where you can see it

Every claim below names the place where a judge can check it. **Stand** — shown in the hackathon
demo as it runs today (a test stand: one machine, test keys next to the container). **Product** —
true of the code and covered by its tests, but not shown on the judge page. What the demo does not
cover is listed at the end and in [`docs/after-the-demo.md`](../docs/after-the-demo.md).

## The insurance scene (`scripts/demo_orchestrator.sh`)

| # | Claim | Where you see it | Scope |
|---|---|---|---|
| 1 | An agent built on Muse Spark triages a synthetic insurance claim ([`case_4417.md`](case_4417.md)) and rejects it | the judge page: the decision page, REJECTED under clause 7.2 | stand |
| 2 | Every step lands as a signed page: the reading of the claim, the policy lookup, each model call, the damage mask | the judge page: pages in order, each with its tool call and hashes | stand |
| 3 | Every Muse Spark call becomes a page: model, request hash, answer hash (`ksg_model_call`) | the judge page: the model-call page | stand |
| 4 | The SAM 3.1 damage mask becomes a page: picture hash, box, mask hash (`ksg_mask_damage`) | the judge page: the mask page | stand |
| 5 | The expert re-asks SAM 3.1 with the same box; the mask hash matches byte for byte | the judge page, expert section ✓; [`scripts/expert_recheck_mask.py`](../scripts/expert_recheck_mask.py) | stand |
| 6 | The agent explains its decision for the judge; every sentence cites a page `[p:N]`, and a program — not a model — checks that each cited page exists and verifies offline | the judge page: "citations checked by program", clickable `[p:N]` | stand |
| 7 | An explanation that cites a missing or unverified page is refused | [`scripts/judge_explain.py`](../scripts/judge_explain.py) — such a citation lands in its refusals; on the judge page every citation is valid, so no refusal is shown | product |
| 8 | Each page verifies offline with the open-source checker, without our servers or the agent's platform | the judge page: the checker's verdict per page, `ACCEPTED (BoundPoint)` | stand |
| 9 | One changed word makes a page REJECTED | the judge page: "tampered copy: REJECTED" with the checker's reason | stand |
| 10 | The capsule is one 6 MiB file (6 291 456 bytes) and stays that size after writing | the judge page: capsule size before and after | stand |
| 11 | Only the named pages are disclosed; the rest stays sealed | the judge page renders the exported pages one by one | stand |
| 12 | The whole scene runs with one command | [`scripts/demo_orchestrator.sh`](../scripts/demo_orchestrator.sh); without a live run — the labelled sample [`demo/sample/judge_sample.html`](sample/judge_sample.html) | stand |
| 13 | The agent works through MCP tools (`ksg_get_container`, `ksg_write_page`, `ksg_model_call`, `ksg_mask_damage`, `ksg_export_page`, `ksg_verify`) and receives the claim through an ACP-A2A gateway | the tool calls recorded on the pages; [`scripts/ksg_mcp.py`](../scripts/ksg_mcp.py) | stand |

## The capsule and the anchored run

| # | Claim | Where you see it | Scope |
|---|---|---|---|
| 14 | The capsule file is indistinguishable from noise; each party holds one secret file; the parts are sealed to the parties' maps with X25519 + ML-KEM-768 | `crates/ksg-capsule-module`, `crates/ksg-container-v2` (capsule tests). On the stand both party files live on the same machine | product |
| 15 | The container's code runs inside the capsule: a WASM module in wasmtime behind two imports, a session open → call ×N → close | `crates/ksg-capsule-reader`, the `ksg-capsule` command line | product |
| 16 | Through the capsule, offline: print → initiation → three pages → export → each page ACCEPTED; a tampered page REJECTED; the capsule is 6 MiB after every step | [`scripts/demo_pro_capsule.sh`](../scripts/demo_pro_capsule.sh) — a separate run, not the judge page | stand |
| 17 | Pro with anchors on a local Solana node: through the capsule — initiation, journal opening with the owner's co-seal, three anchored pages exported and ACCEPTED, tampered pages REJECTED | one run: [`scripts/demo_pro_capsule_localnet.sh`](../scripts/demo_pro_capsule_localnet.sh) — brings up the node, prints the capsule with anchors, initiates and exports a page, then its verify half runs the test `k5_network_pro_through_the_capsule` (`crates/ksg-capsule-reader/tests/k5_offline.rs`): three pages ACCEPTED against the node, a flipped seal byte REJECTED; without the capsule — [`scripts/demo_pro_localnet.sh`](../scripts/demo_pro_localnet.sh) | stand (local node) |
| 18 | The container number is paid with x402 through μ Gate; the agent never holds a wallet key | [`scripts/e2e_ksg_x402.sh`](../scripts/e2e_ksg_x402.sh) — on the stand μ Gate pays from its test wallet and nothing is sent to a chain | stand (test wallet) |
| 19 | The client agent is named by the `did:key` of its own group key; two receivers never share an identifier | `crates/ksg-capsule-module` (session tests) | product |

## The capsule's operations (phase 4b)

Each claim is a test in this repository (`cargo test` from the root; the reader's tests need the module built for wasm32 first), except where noted.

| # | Claim | Where you see it | Scope |
|---|---|---|---|
| 20 | After the initiation the client and the owner each hold a map of their own; the owner's map opens the container's state, and that state carries **no** half of the client's key — the half lives only in the client's part | [`two_maps.rs`](../crates/ksg-capsule-reader/tests/two_maps.rs) `after_the_initiation_each_party_has_its_own_map` | product |
| 21 | A transfer of ownership through the capsule: the new owner's map opens the capsule, the former owner's map opens nothing, the client works on | [`transfer.rs`](../crates/ksg-capsule-reader/tests/transfer.rs) `after_the_transfer_the_former_owners_map_opens_nothing` | product |
| 22 | The sale through the capsule: the packet seats its distributor, the buyer's key is laid with the owner's consent, the issuer's layer work is handed in, and the initiation goes through | [`sale.rs`](../crates/ksg-capsule-module/tests/sale.rs), [`buyer_key.rs`](../crates/ksg-capsule-reader/tests/buyer_key.rs) `after_the_buyers_key_through_the_session_the_initiation_goes_through` | product |
| 23 | The holder's operations: change of form (Pro needs the issuer), full export, the client's key declared lost (by the owner, or by the distributor with the client), freeze, lost shares; a dead container refuses all further work | [`holder_ops.rs`](../crates/ksg-capsule-module/tests/holder_ops.rs), [`key_lost.rs`](../crates/ksg-capsule-module/tests/key_lost.rs) | product |
| 24 | Attachments: an artefact, the rule of two seals, an ownership claim; in Pro the page waits for the owner's seal | [`attach.rs`](../crates/ksg-capsule-module/tests/attach.rs) | product |
| 25 | A court-appointed expert: appointed by the client or the owner; disclosure takes both and hands out only the pages asked for | [`expert.rs`](../crates/ksg-capsule-module/tests/expert.rs) | product |
| 26 | A command from a party that holds no map (tested: the issuer's finalization and declaration of lost shares) arrives as a blind memo in the public chain; the reader finds it and applies it **before** the holder's own action; a replay is refused; without the network at most ten records, then the next waits | [`command.rs`](../crates/ksg-capsule-module/tests/command.rs), [`command_net.rs`](../crates/ksg-capsule-reader/tests/command_net.rs), [`command_auto.rs`](../crates/ksg-capsule-reader/tests/command_auto.rs); on a local Solana node: an issuer's finalization published, applied, work refused after it | product |
| 27 | A `light` capsule anchors on Base Sepolia on the stand's schedule; a copy learns it is one from the contract and does only the full export | [`base_light.rs`](../crates/ksg-capsule-reader/tests/base_light.rs) (a local EVM in the test) | product |
| 28 | A lost side file comes back from its sealed backup; a wrong password, another party's copy or a stale copy is refused | [`backup.rs`](../crates/ksg-capsule-reader/tests/backup.rs) `backup_restores_a_lost_client_file_and_refuses_the_rest` | product |
| 29 | Succession with the heir named on a coupling page; an unload by a voluntary opening (client, owner, two arbiters) | [`succession.rs`](../crates/ksg-capsule-module/tests/succession.rs), [`voluntary.rs`](../crates/ksg-capsule-module/tests/voluntary.rs) | product |
| 30 | 100 capsules pass NIST SP 800-22 (monobit, block frequency, runs, longest run, cumulative sums) | `keysingate-core`: `crates/ksg-container-v2/tests/capsule.rs` `k1_hundred_capsules_pass_nist_sp800_22` (`--release -- --ignored`) | product |
| 31 | The Pro demo part through the capsule anchored on **Solana mainnet-beta**: 7 anchor transactions, 36 s (01.11.2026) | [1](https://explorer.solana.com/tx/2UH6jWwBEffdGcxrpaw5KVMVaxQk1WmDLX44XwLQZM998DTm6p1Hj9rfp5MARNEkRX7Hz88Wr1KVV5T2ouGQgUs4), [2](https://explorer.solana.com/tx/2o1FjPrjto1kP6vv6TFiH5hU4Tg5TJJMTrpqLo8vCqWpoB9BU2ASBGAwXnC4K7r6mdR59gi5yZCzf1RUyZcXFyYz), [3](https://explorer.solana.com/tx/2yFmaaA1Q7oBsseYG3acJDiLq68fcKMocPMK7Tt2SEF5HXBxXteagoSMFFH8sm5iy1sHHkMyh2byxQNBns8ykBJh), [4](https://explorer.solana.com/tx/3oWNNcdrcdw2C4vixjDCMNNj1HJ4mN256ww3oVdte9B6LbwsHDTDByvXxEtALBgEgb5KdzivXMJ8tB7VthyCdKCw), [5](https://explorer.solana.com/tx/4GoiNeQh6UAg5tv954WiURwNhmtjca8r6r5JLAmmnMHxP3MqHyoMobyhSGbrMnoJe3uSRXqNZLEJKrDJeqAPrRBw), [6](https://explorer.solana.com/tx/4Pvf4z6v9QyLb8WAy3n6ZNZd7PEJAPWhSD4GbUkn8Gk5h35RMBnfD4i65jQashRjnnvz7VagrRVqpWWtYn4VBAHt), [7](https://explorer.solana.com/tx/595THbD9ch46AE8M5roy6up6qKKTSttNj68Rpv6ff4JfWBTZHqZyq4UtSNsJaSjVvU4gptQ1ZpeKJo8hJRGwWtAA) | mainnet |

## Precise wording

| Word | What exactly is meant |
|---|---|
| **post-quantum** | The container file is signed with ML-DSA-65 (FIPS 204). Pages and their seals are signed with Ed25519 |
| **verifies offline** | Signatures and the seal verify offline. The time of a page comes from its anchor on a public chain; checking that time needs the anchor |
| **a copy is seen** | At the next anchor, not instantly. Base (`light`): the second copy learns it is a copy when its next anchor is refused — before any export or transfer of rights. Solana (Pro): a rolled-back file is caught when a later copy anchored through the same payer ([`after-the-demo.md`](../docs/after-the-demo.md), Known limits) |
| **anchored** | The judge-page run does not anchor to a public chain. Anchored runs are on a local Solana node (claim 17) |

## Not in this demo

- **The agent never holds the wallet** — next step: gas for the anchors is paid through μ Gate under the owner's rules, the key out of the agent's reach. On the stand the anchors on the local Solana node are paid by a throw-away payer funded from the node's own faucet.
- Keys that the product keeps away from the issuer are, on the stand, generated and stored next to the container — the full list and what comes next: [`docs/after-the-demo.md`](../docs/after-the-demo.md).
