# `bare` — the private class of container

`bare` is one of the three emission classes of a KeysInGate container, the
smallest of them. It is meant for work that stays with its holder: a personal
journal, an agent's own record, an internal chain of hand-overs. It proves who
wrote a page and that the page has not been touched since. It never proves
**when** the page was written, because nothing of it ever reaches a chain.

In the code the class is `Class::Bare` (`crates/ksg-core-v2/src/doc/emission.rs`).
The container is born with it, and it never changes: a `bare` does not become
`light` and never becomes Pro.

## What it has, and what it does without

| | Pro (`heavy`) and `light` | `bare` |
|---|---|---|
| Signatures of the parties | Ed25519 (client key in two halves) and ML-DSA-65 | Ed25519 only |
| Post-quantum container key | ML-DSA-65 key of the container, outer signature of the whole file | none |
| Hand-over sealing | X25519 + ML-KEM-768 (hybrid) | X25519 alone |
| Anchors of the journal | every seal, or a schedule of them | none — the work journal is never anchored |
| Issuance record | packet, serial number, release record | one record of the issuance, outside the container |
| Copies | the network catches a copy at every seal | copying is allowed, a copy keeps the same identifier |
| Dispute, expert, arbitration, voluntary disclosure | present | cut |
| Class promotion, succession, lost-key death, issuer freeze | present | cut |
| Owner deletes the container with everything in it | no | yes (`delete --template ID`) |

Two consequences deserve to be said plainly:

- **Authenticity without time.** A page of a `bare` journal is signed by the
  client's Ed25519 key and bound into the journal's Merkle tree, so a forged or
  edited page is refused. Its time bound is absent: a page is not evidence that
  it existed at a date, only that it is what its author wrote.
- **A file that cannot be checked by a stranger.** Because no post-quantum key
  is made at printing, the container carries nothing that vouches for the file
  as a whole. `ksg-verify-v2 --file` answers `NOT VERIFIABLE` (exit code 3) for
  a `bare`; that is the class, not a failure. Records are checked from the
  journal exports instead.

## The ten operations

A `bare` container refuses every button outside this list — the class guard sits
before everything else (`Operation::in_bare`,
`crates/ksg-container-v2/src/operation.rs`):

| Operation | Button | What it does in `bare` |
|---|---|---|
| `PrintRelease` | D-1 | prints the release; the number is one constant for the whole release, there are no serials |
| `ApplyBuyerKey` | D-2 | takes the distributor's key, if a packet was sold through one |
| `ApplySubAgentKey` | D-2 | takes the distributor's agent's key |
| `Initiate` | D-2 | gives birth to the client's key (a half inside, a half on the phone), names the artifact, stamps the identifier |
| `OpenJournal` | D-2 | writes page 0, the opening |
| `RecordWork` | D-2 | records one step of work; never anchored, and each record moves the idle term |
| `TransferOwnership` | D-2 | changes the owner — at an attachment to a leader, or as a transfer to a new owner |
| `FullExport` | D-3 | gives the whole journal out to the owner and leaves the container working (in Pro this ends it) |
| `ExportPoint` | D-3 | gives 1 to 24 pages out at once |
| `Detach` | D-2 | cuts the container from its leader and burns this copy |

The other fourteen operations of Pro — packet, rights and dispositions,
promotion, cement, succession, lost key, issuer freeze, disclosure of shares,
dispute, expert, arbitration, settlement — are refused with `NotInClass`.

## Attachment to a leader

A `bare` is only ever the **trailer**; a leader must be Pro or `light`
(`crates/ksg-cli-v2/src/reader.rs`, `attach_to`). The attachment runs in one
command:

```
ksg-remote-panel --home DIR --mobile FILE attach-to \
    --leader-home LEADER_DIR --agent URI --new-mobile FILE
```

It does three things, in order, each refused if the previous one is missing:

1. the owner's change to the leader's owner (`TransferOwnership`, `Evidence::NewOwner`);
2. the hand-off of the client's half to the leader's agent;
3. slot 1 of the coupling — the page "attached to LEADER", the last page this
   `bare` writes.

From then on the container is **read-only**: only the two exports and `Detach`
go through (`Stopped::Attached`). The leader side records slot 2, "pulls the
trailer", at its own `RecordWork`. A leader's seal is anchored, which is what
gives the trailer's last seal a time bound it could not have on its own.

Detaching is `ksg-remote-panel --home DIR detach --former-mobile FILE`, pressed
by the owner and the former client together. It burns the copy: the journal and
the keys are wiped, every button afterwards answers `Stopped::Burned`. The
container that stays attached stays an archive.

## Limits

| | Value | Where |
|---|---|---|
| Working pages of the journal | 1 000 | `crates/ksg-core-v2/src/journal/mod.rs` |
| Pages in one pointwise export | 1 to 24 | `PAGES_PER_EXPORT` |
| Pointwise exports of a `bare` | 48 (48 × 24 covers the whole journal) | `BARE_POINT_LIMIT`, `point_limit_of` in `container.rs` |
| Idle term, nothing recorded since initiation | 730 days | `BARE_IDLE_AFTER_ISSUE_MS`, `crates/ksg-container-v2/src/timecheck.rs` |
| Idle term, records of work present | 365 days since the last record | `BARE_IDLE_AFTER_RECORD_MS` |

The idle term is a container rule, not a status: the core's statuses do not
change for `bare`. A container past its term is bricked — `Stopped::Burned` on
every press, the export buttons included. A container with work in it lives as
long as work keeps arriving. Time comes from the caller's clock; a clock moved
back lengthens the term, which is accepted for a private container.

## How to check one

A page or a set of pages, offline, with the holder's key file:

```
ksg-verify-v2 --export page.json --container MULTIHASH --class bare --keys keys.json
```

`ACCEPTED` (exit 0) means the page is signed by the client, bound into the
journal and consistent with the journal's seal; `REJECTED` (exit 1) names the
first thing that does not hold. No network, no issuer, no platform is asked.

A whole export is `ksg-remote-panel --home DIR export-page --number 1,2,3 --by owner --out F`,
or `export-final --out F` for the journal entire.

An attached pair is checked from both exports:

```
ksg-verify-v2 --pair TRAILER_EXPORT LEADER_EXPORT
```

It confirms that each side names the other, that the seal the leader carries is
the trailer's own last seal, and that the leader is Pro — with only the leader's
export the coupling is claimed, not confirmed, because any Pro may write a slot 2
naming somebody else's container.
