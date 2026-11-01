# How the capsule was built

Each line is a commit of the capsule crates in the development repository (date, commit, subject); the same steps are this repository's history.

```
2026-10-26 2910a85 Capsule skeleton: capsule.rs (blocks, maps, parts), module crate (WASM boundary, host randomness), reader crate (atomic write); K1-K5 tests ignored until their days (plan v8)
2026-10-26 6700197 Capsule K1 and K2 green: blocks, map slots over the layer hand-over, scattered AEAD parts, noise; side secret file
2026-10-26 5dc3509 core-v2: internal/ paths in comments replaced by [doc:ID] labels (internal/Doc_ids.md) [skip ci]
2026-10-27 d2cd21c capsule-module: session and K4 imports test
2026-10-27 d957029 capsule-reader: wasmtime engine, session, ksg-capsule CLI, K5 offline
2026-10-27 f74d1cd G-1: client-agent ID is did:key of the client's FROST group key
2026-10-27 fb94ad7 demo track B: every Muse Spark call is a page (ksg_model_call), sam-3.1 damage mask on a page with expert recheck, judge explanation with checked page links; K5 offline fails without the module
2026-10-28 2a0bfa8 capsule module: a Pro page answers NeedsAnchor (seal, then status) and takes the network attestation back through Reanchor; light and bare stay local
2026-10-28 2cea4f2 capsule module: a Pro journal opening asks the owner's co-seal (NeedsSignature), then its anchors; a foreign signature is refused and the state is kept
2026-10-28 3ef137e capsule reader: anchor.json keeps the network settings (no keys); NeedsAnchor → Solana memo → Reanchor until Done, for initiation, journal opening and pages
2026-10-28 b079306 K5: Pro end to end through the capsule on a local Solana node — initiation and journal opening with the owner's co-seal, three anchored pages exported and ACCEPTED, tampered pages REJECTED
2026-10-28 c5006d3 capsule-module: split birth test over BeginBirth/FinishBirth wire
2026-10-28 f39647e capsule module: wire types for the remote client signing round (ClientCommit/ClientShare, NeedsClientCommit/NeedsShare); handlers refuse until the round is wired
2026-10-28 9286211 capsule-module: wire the client signing round into split birth (I4b-p)
2026-10-28 77bcce7 capsule-module: client signature in Work goes through the wire round when no half inside
2026-10-28 bc58acf capsule-module: Initiate and OpenJournal client signatures go through the wire round when no half inside
2026-10-28 6d80e6b capsule-module: wire birth reaches Done without a livelock (track I6b)
2026-10-28 fad759b capsule-reader: drive birth, work and export through the client signing round (track I-r1)
2026-10-28 9a57721 capsule-module: wrap session secrets in non-printing, wiping types (track I9)
2026-10-28 4d280db capsule-module: add secret-type tests pinning non-printing Debug and drop-wipe (track I11a)
2026-10-28 b230a67 capsule-module: add PAKE phone-reader channel by 6-digit code (track I19)
2026-10-28 9bf7c69 capsule-module: add PAKE channel tests pairing by 6-digit code (track I21a)
2026-10-28 75f5d63 capsule-module: add PAKE pairing tests, same code meets, stranger refused (track I21a)
2026-10-28 310ad01 capsule-reader: initiate through the browser page with --mobile-web (track I22)
2026-10-28 3ff759a capsule-module: PAKE channel is SPAKE2, code guessing is online-only
2026-10-28 dcdb5b7 fix clippy: backup blob parsing without panics; unused test variables
2026-10-28 b1770f6 k5 network test: default anchor wait matches the anchorer (120 s)
2026-10-28 fec7e4f capsule-module: PAKE confirmation proofs are direction-bound (no reflection)
2026-10-28 292ad7b capsule-reader: work/export through the browser page with --mobile-web (track I23)
2026-10-28 2736940 capsule-reader: scan keys are born at the recipient's, not copied from the stand (track I26)
2026-10-28 8204407 capsule-module: mark all-in-one birth path as stand/test-only with debug_asserts
2026-10-28 900238f capsule-reader: client's init scan is a recipient-born placeholder, not the stand's copy (track K4)
2026-10-30 58674e0 capsule-reader: a module-supplied length never sizes a host allocation
2026-10-30 76be867 P-12 B1: English comments and messages (no logic change)
2026-10-30 b58ca53 P-12 B2: English comments and messages (no logic change)
2026-10-31 d88b358 capsule session: signatures of parties that hold no map (Party::External, NeedsSignature -> Sign, Spec_kapsula §20 variant A); first user — E-2 ApplyPacket request (§19)
2026-10-31 d68f4cd capsule session: before initiation the status records are the issuer's (signed outside, §19–§20); E-2 ApplyPacket presses end to end through the capsule
2026-10-31 d72b712 capsule: two maps through the session and the reader — after E-4 the client's and the owner's maps (born at the reader) replace the holder's; slot v2 re-assembly carries the other party's part; v1 capsules keep opening (Spec_kapsula §21, 4b.4a)
2026-10-31 5e16279 capsule session: holder's level-1 operations — Form, FullExport, DeclareKeyLost, Freeze, DeclareSharesLost (Spec_kapsula §20, §24); the owner's signature in a client's session comes in through Sign
2026-10-31 50621d2 capsule reader: backup/restore of a side file (sealed by ksg-web-v2 backup, password only from KSG_BACKUP_PASSWORD_FILE)
2026-11-01 2b03c1f capsule phase 4b, batch 2: K2 (R-4), K3 (network commands), K4 (layer follow-ups), C4–C11
2026-11-01 adaf720 core-v2: no Cyrillic in the published tree (P-13): decision and batch marks in comments and assertion messages in Latin
```
