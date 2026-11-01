//! A session of presses over one opened capsule (`Spec_kapsula` §10 item 3).
//! Nothing is written unless the session closes: a refusal leaves the capsule
//! as it was (§14 B-6).
//!
//! # Why a session and not one call (L-1)
//!
//! The round of the client's split key and the anchoring of a Pro record need
//! the network and, in the product, another device between two steps. So the
//! reader opens the capsule once, asks for commands one by one, and closes:
//!
//! ```text
//! open(capsule, side_file, anchored) → Session
//! Session::call(Status | Keys | Work | ExportPage | Initiate | Reanchor) × N
//! Session::close() → (new capsule, outputs)
//! ```
//!
//! A command that needs the network or another party's signature answers
//! [`Answer::NeedsAnchor`] or [`Answer::NeedsSignature`] — it is not a refusal,
//! and nothing is written when it answers so.
//!
//! # The anchor protocol (Pro)
//!
//! A Pro press goes in with a placeholder anchor first, and the module answers
//! what the network owes instead of `Done`. The reader anchors each subject
//! the module names and hands the attestation back in, repeating `Reanchor`
//! after every `NeedsAnchor` until `Done`:
//!
//! ```text
//! call(Work) → NeedsAnchor { kind: seal, prev, subject }
//! call(Reanchor { attestation for the seal }) → NeedsAnchor { kind: status, … }
//! call(Reanchor { attestation for the status }) → Done
//! ```
//!
//! One command may owe two anchors — a seal and the status record pressed
//! with it — so [`Request::Initiate`] (whose press moves the status, and
//! whose journal opening, pressed by the reader's next `OpenJournal` in the
//! same session, seals page 0) may answer `NeedsAnchor` twice in a row. The
//! queue is the session's, oldest first, a seal before its status record. A
//! `Reanchor` naming anything but the head of the queue is refused. Closing
//! with anchors still owed is refused: a placeholder must never leave the
//! session as a record's anchor.
//!
//! # What lies in the capsule's parts
//!
//! The capsule (`ksg_container_v2::capsule`) is a fixed number of blocks whose
//! parts are sealed under keys a map's slot carries. This module owns the two
//! parts it must read and rewrite; the reader never parses them:
//!
//! | Part | What it holds here |
//! |---|---|
//! | `Code` | the module's own bytes — carried through untouched |
//! | `State` | the container, sealed (`Container::seal_to_bytes`) under the state key |
//! | `ClientSecrets`, `OwnerSecrets` | with two maps, the client's half and the former client's half (K2, §26); with one, empty — the halves stay in the state |
//! | `SharedSecrets` | [`Shared`]: the state key, the template's hash, the artefact, the clock, the maps' public halves |
//!
//! The state key and the maps' **public** halves live in `SharedSecrets`
//! because both maps open that part, and both are needed to re-assemble the
//! capsule (`Spec_kapsula` §10 item 1, item 2). No secret of a party is there.
//!
//! # What this module does not do
//!
//! The network. An anchor the container owes is the reader's work, and
//! [`Answer::NeedsAnchor`] is how the module asks for it. Nor does the module
//! press the commands of §5a (a command signed by a party that holds no map):
//! that queue is post-hackathon (`TODO_na_potom.md#T2-5`); an `anchored` entry
//! this module cannot read is an error at [`Session::open`], never a silent skip.

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::capsule::{self, MapPub, MapRole, Part, PartKind, Shared};
use ksg_container_v2::client_key::{
    share_commitment, Commitment, MobileHalf, MobileShare, SigningRound,
};
use ksg_container_v2::container::{Container, Evidence, JournalWrite, UnloadRoute, Writes};
use ksg_container_v2::expert::{
    entry_pieces, ExpertDisclosure, ExpertEntry, ExpertRecord, EXPERT_ENTRY_PAGE,
};
use ksg_container_v2::layers::{Level, OpenWith, SealTo, MLKEM_EK_LEN};
use ksg_container_v2::{Attachment, Event, Kind, Operation, Role, Where, Work, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, PublicKey, Signature, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::journal::{Draft, Mode, Piece, RecordKind, RecordMeta, Sealing};
use ksg_core_v2::section::StatusRecord;
use ksg_core_v2::status::{transition_for, Outcome};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use crate::secret::{OwnerKey, StateKey};

/// What a private part of a v2 capsule takes with nothing inside: the key
/// envelope, the nonce and the AEAD tag (`capsule.rs` `HANDOVER_LEN`, `NONCE`,
/// `TAG`). A carried blob longer than this holds a secret.
const EMPTY_PRIVATE_PART: usize = 32 + ksg_container_v2::layers::MLKEM_CT_LEN + 12 + 33 + 16 + 12 + 16;

/// The anchor kind of a record this module presses offline. No network
/// accepts it (`ksg-verify-v2` says so by name); the reader's anchor replaces
/// it through [`Session::call`] with [`Request::Reanchor`].
pub const LOCAL_ANCHOR: &str = "urn:ksg:anchor:local:v1";

/// A request at the panel's level (§13, §12 L-2): the five commands of the
/// demo scene, and the network's answer for a Pro anchor.
///
/// On the wire (see [`crate::abi`]) a request is one JSON object with the tag
/// `"command"`: `{"command":"status"}`, `{"command":"work","text":"…"}`,
/// `{"command":"export_page","number":1}`, `{"command":"initiate"}`,
/// `{"command":"keys"}`, `{"command":"reanchor","attestation":"<base64url>"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum Request {
    /// E-4: the client's key is born; the maps' public halves come with it.
    ///
    /// Stand/test-only (the all-in-one birth where one process holds both
    /// halves for the demo or a test): `#[doc(hidden)]` because the product
    /// wire has no `initiate` command — it splits the birth over
    /// `BeginBirth` / `FinishBirth`. One process must never hold both halves
    /// outside a stand or a test, so `debug_assert`s on the helpers below
    /// pin the invariant in debug builds.
    #[doc(hidden)]
    Initiate,
    /// E-4 split, messages 1-2: the mobile side commitment comes in, the
    /// container answer (message 2) goes out. Nothing is pressed yet.
    BeginBirth {
        /// `KeygenHello` bytes, base64url.
        #[serde(with = "b64")]
        hello: Vec<u8>,
    },
    /// E-4 split, message 3: the mobile side kept its half and sends the
    /// container share; the module presses the initiation. The mobile half
    /// never enters the module.
    FinishBirth {
        /// `KeygenFinish` bytes, base64url.
        #[serde(with = "b64")]
        fin: Vec<u8>,
        /// The client public key as the mobile side computed it
        /// (`MobileKeygen::finish` output before naming): the module names
        /// the `did:key` from its material and refuses on mismatch.
        group_key: PublicKey,
    },
    /// E-5: one step of the agent's work becomes a page.
    Work {
        /// What was done, as the agent recorded it — the page's content.
        text: String,
    },
    /// A pointwise export of one page.
    ExportPage {
        /// The page's number in the journal.
        number: u64,
    },
    /// The keys a verifier checks the pages with.
    Keys,
    /// The container's state, one line per fact.
    Status,
    /// The network's attestation for the anchor the module asked for: the JSON
    /// of a `ksg_core_v2::anchor::Attestation`.
    Reanchor {
        /// The attestation's JSON, as the reader read it from the network.
        attestation: Vec<u8>,
    },
    /// E-5: the journal is open — page 0, sealed by the client's two halves.
    OpenJournal,
    /// E-2: the packet, pressed by the issuer through the holder's map before
    /// initiation (`Spec_kapsula` §19). The issuer's signature comes from
    /// outside: [`Answer::NeedsSignature`] `{party: "issuer"}`, then
    /// [`Request::Sign`], then this request again.
    ApplyPacket,
    /// E-2 with the distributor's seat (`Spec_kapsula` §19): the distributor's
    /// key is seated in the roster, then the packet is pressed as by
    /// [`Request::ApplyPacket`]. The seat is taken before the pressing and
    /// stays if the pressing is refused (as on the stand's `packet_seating`);
    /// a repeat after a [`Answer::NeedsSignature`] with the same key goes on.
    /// A new request, not a field of `ApplyPacket`: the old requests' JSON
    /// reads as before.
    ApplyPacketSeated {
        /// The distributor's key.
        distributor: PublicKey,
    },
    /// E-3 (`Spec_kapsula` §19): the buyer's key is laid up to level 2, with
    /// the owner's consent; the holder's map gives way to the buyer's. The
    /// signatures of the buyer (`NeedsSignature {party: "buyer"}`) and of the
    /// owner come from outside. Before the initiation only, while the capsule
    /// has one map.
    ApplyBuyerKey {
        /// The buyer's key.
        buyer: PublicKey,
        /// The buyer's map, public half only: the capsule is sealed to it
        /// from the pressing on.
        holder_map: capsule::MapPub,
    },
    /// E-4 done (§21, 4б.4а): the holder's map gives way to the client's and
    /// the owner's — each born at its party's, only the public halves come
    /// in. Once, after the initiation, while the capsule has one map.
    SetMaps {
        /// The client's map and the owner's, as the shared secrets spell them.
        maps: Vec<capsule::MapPub>,
    },
    /// E-10 (`Spec_kapsula` §24): the form changes — to Pro with the owner
    /// and the issuer, back to light with the owner alone; the journal takes
    /// a page of it.
    Form {
        /// The form after it.
        to: Mode,
    },
    /// The owner and the client export everything; the container dies
    /// (`FullExport`). The export goes to the session's outputs.
    FullExport,
    /// E-15: the client's key is lost; the owner declares the container dead.
    DeclareKeyLost,
    /// E-15 by the other road (`Spec_kapsula` §24, C8): the distributor that
    /// sold the packet and the client declare the container dead in the
    /// owner's stead. The distributor holds no map: its signature comes from
    /// outside (`NeedsSignature {party: "distributor"}`, then
    /// [`Request::Sign`], then this request again). Refused before any
    /// signature is asked if no distributor is seated (a direct sale). After
    /// `Done` the container is dead.
    DeclareKeyLostByDistributor,
    /// E-23: the issuer freezes the container on the owner's application —
    /// the issuer's signature comes from outside (§20).
    Freeze,
    /// E-24: the owner declares the shares of the split key lost; the
    /// container records the declaration's digest and goes on working.
    DeclareSharesLost {
        /// The declaration's digest.
        hash: Hash,
    },
    /// E-6 (`Spec_kapsula` §20): an artefact and the data about it go into the
    /// journal. The client signs; in Pro the owner's seal on the page comes
    /// from outside (`NeedsSignature {party: "owner"}`, then
    /// [`Request::Sign`], then this request again). Only the artefact is
    /// carried so far: the rule (E-7) and the claim (E-8) need a page the
    /// session's `page` cannot write without a change to it.
    Attach {
        /// What is attached, in the wire's own type.
        what: AttachWire,
    },
    /// K4 (`Spec_kapsula` §28): the follow-ups the container holds open — the
    /// issuer's layer work after E-2, E-3, E-9 — as JSON, with the zone
    /// position each sealed write must be bound to.
    PendingTasks,
    /// K4: the issuer's sealed fields for the follow-up `index`, at the
    /// position [`Request::PendingTasks`] named.
    WriteLayer {
        /// The follow-up's index.
        index: usize,
        /// The sealed zone (`layout::ZONE_BYTES`).
        #[serde(with = "b64")]
        sealed: Vec<u8>,
    },
    /// K4: the layer key was handed over outside; the digest of the sealed
    /// hand-over.
    HandedOver {
        /// The follow-up's index.
        index: usize,
        /// The digest of the sealed hand-over.
        sealed: Hash,
    },
    /// K3 (`Spec_kapsula` §27): a command from the network — signed by a
    /// party that holds no map, anchored as `ksg:cmd:v1`, found by the reader
    /// with the scan key and handed in before the holder's own command.
    ApplyCommand {
        /// The command file's JSON ([`CommandFile`]).
        #[serde(with = "b64")]
        file: Vec<u8>,
        /// The JSON of the `ksg_core_v2::anchor::Attestation` of its anchor.
        #[serde(with = "b64")]
        attestation: Vec<u8>,
    },
    /// E-9 (`Spec_kapsula` §21): the owner hands the container over to a new
    /// owner. The owner's signature and the arriving owner's
    /// (`NeedsSignature {party: "buyer"}`) come from outside; the page of the
    /// change of owner goes into the journal. After it the owner's slot is
    /// sealed to `owner_map` — the former owner's map opens nothing (Н-3).
    ///
    /// The former owner's secrets part rides through a client's session
    /// sealed to the former map: an empty one is made again under the new map
    /// at close, a non-empty one (a `bare`'s former client's half) is a
    /// refusal — it needs the former owner's own session.
    Transfer {
        /// The arriving owner's key: it takes the owner's seat.
        new_owner: PublicKey,
        /// The arriving owner's map, public half only.
        owner_map: capsule::MapPub,
    },
    /// The other party's signature over exactly the bytes a
    /// [`Answer::NeedsSignature`] handed out (L-1: signatures are the
    /// reader's work). The JSON of a `ksg_core_v2::crypto::sign::Signature`;
    /// the container checks it when the pending command is pressed.
    Sign {
        /// The signature's JSON.
        signature: Vec<u8>,
    },
    /// `AppointExpert` (`Spec_kapsula` §23): the principals name the
    /// court's expert on a page of the journal. Signed by this session's own
    /// side — the client in a client's session, the owner in an owner's
    /// (either alone is enough); the entry itself carries its own principal's
    /// signature, made outside.
    AppointExpert {
        /// The entry naming the expert, as the core reads it.
        entry: ksg_container_v2::expert::ExpertEntry,
    },
    /// D-3 `DiscloseToExpert` (`Spec_kapsula` §23): the pages the expert
    /// demanded go out. The client and the owner sign; the owner's signature
    /// in a client's session comes through `NeedsSignature` / [`Request::Sign`].
    /// The pages go to the session's outputs, as an export does.
    Disclose {
        /// The principals' entry naming the expert (it must be on a page).
        entry: Box<ksg_container_v2::expert::ExpertEntry>,
        /// The expert's own record, as the chain carries it.
        expert_record: Box<ksg_container_v2::expert::ExpertRecord>,
        /// The anchor of the expert's record in the chain.
        record_anchor: Box<Attestation>,
        /// The principals' command, in the scope the expert demanded.
        disclosure: Box<ksg_container_v2::expert::ExpertDisclosure>,
    },
    /// Client round: mobile commitment comes in (stub until round state lands).
    ClientCommit {
        /// Mobile commitment bytes, base64url.
        #[serde(with = "b64")]
        commitment: Vec<u8>,
    },
    /// Client round: mobile share comes in (stub until round state lands).
    ClientShare {
        /// Mobile share bytes, base64url.
        #[serde(with = "b64")]
        share: Vec<u8>,
    },
    /// E-5 slot 2 of the coupling (CH-12): the leading container pulls the
    /// trailer; its last seal comes with it. Pressed as `RecordWork` by the
    /// client, like the stand's `reader.rs` `pull`.
    Pull {
        /// The trailing container.
        trailer: Hash,
        /// The trailer's last seal.
        trailer_seal: Hash,
    },
    /// The owner and the client export everything by the road of a voluntary
    /// opening (`FullExport`, st.12 — `Spec_kapsula` §17): the four parties
    /// signed the opening itself (`VoluntaryOpening`), and the gate checks it
    /// (`unload_gate.rs`, `Route::Voluntary`); the two holders' own signatures
    /// over the press come from outside, as in [`Request::FullExport`].
    /// After it the export goes to the session's outputs, and the container
    /// is dead.
    FullExportVoluntary {
        /// The opening the four parties signed.
        opening: Box<ksg_container_v2::voluntary::VoluntaryOpening>,
        /// The anchor of the opening's declaration in the chain.
        anchor: Attestation,
    },
}

/// What [`Request::Attach`] carries: the wire's own type, as `Evidence` has
/// no serde (`Spec_kapsula` §20, "Нагрузка"). On the wire a word `"what"`
/// names the case.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "what", rename_all = "snake_case", deny_unknown_fields)]
pub enum AttachWire {
    /// E-6: the artefact this container is, and the data about it. The page
    /// is the content's digest — the file stays with the client.
    Artifact {
        /// Its name. Required.
        name: String,
        /// The media type of the file.
        mime: String,
        /// The hash of the file's content.
        content_hash: Hash,
        /// Its size in bytes.
        size: u64,
        /// The offset at which the container was initiated — one of the
        /// inputs to its identifier, which the container recomputes.
        offset_ms: u64,
        /// What it was made from, by artefact URIs.
        #[serde(default)]
        derived_from: Vec<String>,
    },
    /// E-7: the rule of two seals, set or lifted (CH-19); the owner seals the
    /// page beside the client.
    Rule {
        /// The rule.
        rule: ksg_core_v2::journal::SealRule,
    },
    /// E-8: the ownership claim — the agent's ID published in the chain
    /// (step 1, made outside), recorded on a page of its own type.
    Claim {
        /// The hash of the artifact claimed.
        artifact: Hash,
        /// The publication's open ID.
        open_id: String,
        /// The agent's key the publication names.
        agent: PublicKey,
        /// The publication's signatures.
        signatures: SignatureSet,
        /// The publication's anchor in the chain.
        anchor: Attestation,
    },
}

/// What a request answers.
///
/// On the wire a word `"answer"` names the case: `{"answer":"done","bytes":…}`,
/// `{"answer":"needs_signature","party":"owner","bytes":…}`,
/// `{"answer":"needs_anchor","kind":"seal","prev":"…","subject":"…","bytes":…}`,
/// `{"answer":"refused","reason":…}`.
/// Every byte string is base64url without padding; `prev` and `subject` are
/// multihashes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "answer", rename_all = "snake_case")]
pub enum Answer {
    /// Done; `bytes` is the output, if any — the shape of each command's
    /// output is described on [`Session::call`].
    Done {
        /// The output.
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// The module needs a memo anchored: the reader sends it, then
    /// [`Request::Reanchor`] with the attestation — and repeats that after
    /// every further `NeedsAnchor` until `Done` (one command may owe a seal
    /// and a status record; the queue is oldest first, a seal before its
    /// status record).
    NeedsAnchor {
        /// What owes the anchor: a journal seal, or a status record.
        kind: AnchorKind,
        /// What the anchored record links to: the previous seal's hash for a
        /// seal (the container's identifier where there is no previous seal),
        /// the previous status record's head for a status record.
        prev: String,
        /// What the anchor must attest: the seal's or the record's hash.
        subject: String,
        /// The memo's input as JSON — `{"kind","prev","subject","period"}`,
        /// all multihashes, `period` null until the reader names the seal's
        /// scan month — as the reader's anchorer reads it.
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// The module needs a party's signature over these bytes (§14 B-3).
    NeedsSignature {
        /// Which party: `client` or `owner`.
        party: String,
        /// What it signs — the exact bytes the container will check.
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// Client round: needs mobile commitment; round holds opaque round bytes.
    NeedsClientCommit {
        /// Opaque round bytes, base64url.
        #[serde(with = "b64")]
        round: Vec<u8>,
    },
    /// Client round: needs mobile share; round holds opaque round bytes.
    NeedsShare {
        /// Opaque round bytes, base64url.
        #[serde(with = "b64")]
        round: Vec<u8>,
    },
    /// Refused; nothing is written.
    Refused {
        /// Why, in the container's or the module's own words.
        reason: String,
    },
}

/// The operations that come from the network (K3, `Spec_kapsula` §27).
/// E-14 `Succeed` joins with C10; E-15 by the orchestrator has no seat yet.
pub const COMMAND_OPS: [Operation; 4] = [
    Operation::Finalize,
    Operation::ServeDispute,
    Operation::DeclareSharesLost,
    Operation::Succeed,
];

/// A command from the network (`ksg:cmd:v1`, `Spec_kapsula` §27), as the
/// party that signed it keeps it and the reader finds it in `commands/`.
///
/// The signatures cover [`Event::subject`] of the event the file describes,
/// and its `payload` is the JSON of [`CommandFile::evidence`]: the
/// load is bound by the signatures, so a copy with another load does not
/// press.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandFile {
    /// Version: 1.
    pub v: u32,
    /// The operation.
    pub op: Operation,
    /// The container it is for, as a multihash.
    pub container: Hash,
    /// The journal head the signer saw; `None` before page 0.
    pub head: Option<CommandHead>,
    /// The load.
    pub evidence: CommandEvidence,
    /// The signatures over the event's subject.
    pub signatures: SignatureSet,
}

/// [`ksg_container_v2::event::Head`] on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandHead {
    /// The counter of the last page.
    pub counter: u64,
    /// The digest of that page.
    pub page: Hash,
}

/// The load of a network command, on the wire (`Evidence` has no serde).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandEvidence {
    /// No load (E-13 `Finalize`).
    None,
    /// E-24: the declaration's digest.
    SharesLost {
        /// The digest.
        hash: Hash,
    },
    /// The delivery of a dispute: the copy of the claim, naming the
    /// claimant's and the arbiter's keys (K1).
    Dispute {
        /// The filing.
        filing: Box<ksg_container_v2::Filing>,
    },
    /// E-14 (C10): slot 1 of the coupling — this container is attached to
    /// its successor. No load beyond the leader's hash.
    AttachedTo {
        /// The leading container.
        leader: Hash,
    },
}

impl CommandFile {
    /// The event this file presents, and its load as the container reads it.
    ///
    /// # Errors
    ///
    /// The load does not encode.
    pub fn event(&self) -> Result<(Event, Evidence), String> {
        // The load's JSON as this type writes it — the signer and the
        // container build it with the same code, field by field.
        let payload =
            serde_json::to_vec(&self.evidence).map_err(|e| format!("the load does not encode: {e}"))?;
        let mut event = Event {
            op: self.op,
            button: self.op.button(),
            container: self.container,
            payload: Wrapped::received(payload),
            signatures: self.signatures.clone(),
            covered: Vec::new(),
            head: self.head.map(|h| ksg_container_v2::event::Head {
                counter: h.counter,
                page: h.page,
            }),
        };
        event.covered = event.subject();
        let evidence = match &self.evidence {
            CommandEvidence::None => Evidence::None,
            CommandEvidence::SharesLost { hash } => Evidence::SharesLost(*hash),
            CommandEvidence::Dispute { filing } => Evidence::Dispute(filing.clone()),
            CommandEvidence::AttachedTo { leader } => Evidence::Coupling(
                ksg_core_v2::journal::CouplingRecord::AttachedTo { leader: *leader },
            ),
        };
        Ok((event, evidence))
    }

    /// The bytes the signers sign and the anchor commits to (through their
    /// hash): the event's subject.
    ///
    /// # Errors
    ///
    /// As [`CommandFile::event`].
    pub fn subject(&self) -> Result<Vec<u8>, String> {
        Ok(self.event()?.0.covered)
    }
}

/// What owes the anchor an [`Answer::NeedsAnchor`] names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorKind {
    /// A seal of the journal: the reader sends its blind memo.
    Seal,
    /// A status record: the reader sends its open memo.
    Status,
}

/// One anchor the network owes the session: a press went in with a
/// placeholder, and the reader's attestation replaces it through
/// [`Request::Reanchor`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnchorNeed {
    /// What owes the anchor.
    kind: AnchorKind,
    /// What the anchored record links to.
    prev: Hash,
    /// What the anchor must attest.
    subject: Hash,
}

/// What a press writes into the status section, if it moves the status — and
/// what that record owes the network, when it owes any.
type StatusWrite = (Option<(StatusRecord, Attestation)>, Option<AnchorNeed>);

impl AnchorNeed {
    /// The reader's answer for it: the kind, the multihashes, and the memo's
    /// input as JSON.
    fn answer(&self) -> Answer {
        let prev = self.prev.to_multihash();
        let subject = self.subject.to_multihash();
        let kind = match self.kind {
            AnchorKind::Seal => "seal",
            AnchorKind::Status => "status",
        };
        let bytes = serde_json::json!({
            "kind": kind,
            "prev": prev,
            "subject": subject,
            "period": None::<String>,
        })
        .to_string()
        .into_bytes();
        Answer::NeedsAnchor {
            kind: self.kind,
            prev,
            subject,
            bytes,
        }
    }
}

/// Which party's secret the side file carries (`Spec_kapsula` §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SideRole {
    /// The agent-client.
    Client,
    /// The owner-holder.
    Owner,
}

/// A party's one secret file, as much of it as the module reads.
///
/// The reader reads the rest (the scan key). Unknown fields are ignored on
/// purpose: a file that grows one the module does not read still opens.
#[derive(Deserialize)]
struct SideFile {
    /// Version of the file.
    v: u32,
    /// Whose file it is.
    role: SideRole,
    /// The container: its template before initiation, its identifier after.
    container: String,
    /// The party's half of signing, base64url: the client's mobile half
    /// (FROST state), or the owner's Ed25519 seed. Empty before initiation.
    half: String,
    /// The seed of the party's map, base64url (32 bytes).
    map: String,
    /// The scan key for blind anchors — the reader's, unread here.
    #[allow(dead_code)]
    scan: String,
}

/// The randomness of the module: the reader's CSPRNG inside the capsule
/// (`ksg_host.random`, §5), the operating system's outside it.
struct CspRng;

impl RngCore for CspRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CspRng {}

/// Fills `dest` from the reader's CSPRNG — the module inside the capsule.
#[cfg(target_arch = "wasm32")]
fn fill_random(dest: &mut [u8]) {
    crate::abi::random(dest);
}

/// Fills `dest` from the operating system's CSPRNG — the native side, which
/// only the tests and a host tool ever run.
#[cfg(not(target_arch = "wasm32"))]
fn fill_random(dest: &mut [u8]) {
    getrandom::getrandom(dest).expect("the operating system's CSPRNG answers");
}

/// The reader's clock inside the capsule (`ksg_host.now_ms`).
#[cfg(target_arch = "wasm32")]
fn now_ms() -> u64 {
    crate::abi::now_ms()
}

/// The system's clock — the native side.
#[cfg(not(target_arch = "wasm32"))]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Which page a press writes.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PageToWrite {
    /// No page.
    None,
    /// Page 0, the opening.
    Opening,
    /// A record of this kind, with this content.
    Record(RecordKind, Piece),
    /// The page of a change of form (E-10, CH-30).
    Form(Mode),
    /// E-7: the page of the rule of two seals (`Body::Rule`, CH-19) —
    /// `[р]` 31.10 «А».
    Rule(ksg_core_v2::journal::SealRule),
    /// A record of this kind whose page names its content type (E-8: the
    /// ownership claim, `OWNERSHIP_CLAIM_PAGE`) — `[р]` 31.10 «А».
    Typed(RecordKind, Piece, Uri),
    /// E-9: the page of a change of owner, to the owner arriving with the
    /// command (`Body::Transfer`, `OwnerChange`) — `[р]` 31.10 «А» С6/С7.
    /// Pressed by [`Request::Transfer`].
    OwnerChange(PublicKey),
    /// E-14 slot 1 / E-5 slot 2: the page of the coupling of containers
    /// (CH-12) — `[р]` 31.10 «ок А» (С10).
    Coupling(ksg_core_v2::journal::CouplingRecord),
}

/// What a repeated command still owes the press (I6b): the offsets its
/// open press already ticked. While the press stays open — a `Needs*`
/// answer — a repeat reuses them, so the wire round signs the same bytes
/// and the closed round is picked up instead of a new one. A successful,
/// refused, or anchor-owed press drops them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct PressOffsets {
    /// The text the pending `Work` press was opened with.
    work_text: Option<String>,
    /// The offset page 0 of a pending opening was ticked with.
    open_offset: Option<u64>,
    /// The offsets the pending `Work` page drafts were ticked with.
    page_offsets: Vec<u64>,
    /// The offsets the pending status records were ticked with.
    status_offsets: Vec<u64>,
}
///
/// Secrets the session holds — the state key, the client's mobile half — are
/// wiped when it drops: `Zeroizing` and the `Drop` of the halves, not a manual
/// loop over memory that a copy could leave behind.
pub struct Session {
    /// The container as it stands in memory; nothing is on disk until close.
    container: Container,
    /// Every map the capsule seals to, in slot order; re-assembly re-seals
    /// each slot to its own public halves.
    maps: Vec<(MapRole, SealTo)>,
    /// The key the container's state is sealed under: wiped when the
    /// session drops ([`StateKey`]).
    state_key: StateKey,
    /// The container's template identifier — what the state opens as.
    template: Hash,
    /// The artefact the initiation is bound to.
    artifact: Uri,
    /// The client's key identifier, for the birth.
    client_kid: Uri,
    /// The issuance's wall clock, milliseconds since the Unix epoch.
    issued_ms: u64,
    /// The greatest offset used so far.
    clock_ms: u64,
    /// The code part as it was — carried through untouched.
    code: Vec<u8>,
    /// The parts this map opened and does not rewrite.
    parts: Vec<Part>,
    /// What the reader must persist outside the capsule.
    outputs: Vec<Vec<u8>>,
    /// The client's half, while the session holds it: from the side file, or
    /// just born by [`Request::Initiate`].
    mobile: Option<MobileHalf>,
    /// The owner's key, when the side file is the owner's: wiped when
    /// the session drops ([`OwnerKey`]).
    owner: Option<OwnerKey>,
    /// A birth done in memory and not yet pressed: the client's key exists,
    /// the initiation does not. A close with one pending refuses — the birth
    /// is never stored (`Container::begin_birth`), so dropping it would lose
    /// the client's key for good.
    pending_birth: bool,
    /// The bytes the owner signs for that pending initiation, if one waits for
    /// the owner's signature: a second [`Request::Initiate`] answers the same.
    pending_bytes: Vec<u8>,
    /// The other party's signature over [`Session::pending_bytes`], handed in
    /// by [`Request::Sign`] while a birth waits for it.
    pending_owner: Option<Signature>,
    /// Signatures of parties that hold no map (`Spec_kapsula` §20), handed in
    /// by [`Request::Sign`]: who, over which bytes, the signature.
    external: Vec<(Role, Vec<u8>, Signature)>,
    /// The non-holder signature the last press asked for, if any.
    awaiting_external: Option<(Role, Vec<u8>)>,
    /// The other party's private parts, sealed (slot format v2, §21).
    carried: Vec<capsule::Carried>,
    /// The owner's signatures handed in to a client's session by
    /// [`Request::Sign`] for a holder's operation (`Request::Form`, …): over
    /// which bytes, the signature.
    owner_sigs: Vec<(Vec<u8>, Signature)>,
    /// The owner's signature the last holder's operation asked for, if any.
    awaiting_owner: Option<Vec<u8>>,
    /// Page 0 waiting for the owner's co-seal in Pro (CH-26): a client's
    /// session cannot seal the opening alone, so [`Request::OpenJournal`]
    /// answers [`Answer::NeedsSignature`] and the owner's [`Request::Sign`]
    /// presses it — the same round trip as an initiation. Never set together
    /// with `pending_birth`: a birth waits before the container is born, an
    /// opening after.
    pending_opening: bool,
    /// The opening seal's bytes the owner co-signs — the exact bytes the
    /// container checks, as on the stand.
    pending_open_bytes: Vec<u8>,
    /// The offset page 0 was ticked with: ticked once and reused while the
    /// owner's signature is missing, so a retry signs the same bytes.
    pending_open_offset: Option<u64>,
    /// The owner's co-seal over [`Session::pending_open_bytes`], handed in
    /// by [`Request::Sign`] while an opening waits for it.
    pending_open_owner: Option<Signature>,
    /// What crosses the wire while a client round is open: the message
    /// both halves sign, and the mobile side's commitment it started from.
    /// Kept until the round closes — a `ClientCommit` while one is open is
    /// refused, just as a `ClientShare` with none open is.
    client_round: Option<ClientRound>,
    /// The message a command wants the wire round to sign: set by
    /// [`Session::sign_client`] when it answers `NeedsClientCommit`, read by
    /// [`Session::client_commit`], cleared when the round opens. A
    /// commitment names no message — it answers this one.
    client_round_msg: Option<Vec<u8>>,
    /// The wire round's signatures, waiting for the command to be repeated:
    /// one entry per message the command asked the round to sign — a `Work`
    /// press signs its event and its seal, two messages, two rounds, so one
    /// slot is not enough. Entries are keyed by the message and picked up
    /// without removing: a repeated command reuses what its earlier round
    /// closed, and a successful press drops them all.
    pending_client_sigs: Vec<(Vec<u8>, Vec<Signature>)>,
    /// What a repeated command still owes the press (I6b): the offsets its
    /// open press already ticked — see [`PressOffsets`].
    press_offsets: PressOffsets,
    /// The anchors the network still owes this session, oldest first — a
    /// seal before its status record. A press in Pro queues them and answers
    /// the head; each [`Request::Reanchor`] takes the head off and answers
    /// the next, or `Done` when none is left.
    pending_anchors: std::collections::VecDeque<AnchorNeed>,
}

impl Session {
    /// Opens a capsule: the party's slot, the container, the commands the
    /// network carried.
    ///
    /// `side_file_json` is the party's one secret file (§11) as JSON;
    /// `anchored` is what the reader read from the network (§5a) — each entry
    /// the JSON of an `Attestation`, applied to the record it names before the
    /// first command.
    ///
    /// # Errors
    ///
    /// Not a capsule, another party's slot, a side file that is not version 1,
    /// a part that does not open, an anchor naming nothing here.
    pub fn open(
        capsule_bytes: &[u8],
        side_file_json: &[u8],
        anchored: Vec<Vec<u8>>,
    ) -> Result<Self, String> {
        let side: SideFile =
            serde_json::from_slice(side_file_json).map_err(|e| format!("side file: {e}"))?;
        if side.v != 1 {
            return Err(format!("side file: version {} is not 1", side.v));
        }
        let map = OpenWith::from_bytes(decode_32(&side.map, "side file: map")?);
        // Slot format v2 (§21): the other party's private part comes back
        // sealed, to be carried into the next assembly unopened.
        let split = capsule::open_split(capsule_bytes, &map).map_err(|e| format!("capsule: {e}"))?;
        let (slot_role, opened, carried) = (split.role, split.parts, split.carried);
        if !slot_matches(slot_role, side.role) {
            return Err(format!(
                "the side file is the {}'s, the slot is the {}'s: not this party's capsule",
                side_role_name(side.role),
                slot_name(slot_role)
            ));
        }

        let mut code = Vec::new();
        let mut state = None;
        let mut shared = None;
        let mut parts = Vec::with_capacity(opened.len());
        for part in opened {
            match part.kind {
                PartKind::Code => code = part.bytes,
                PartKind::State => state = Some(part.bytes),
                PartKind::SharedSecrets => shared = Some(part.bytes),
                _ => parts.push(part),
            }
        }
        let state = state.ok_or("the capsule carries no state part")?;
        let shared = shared.ok_or("the capsule carries no shared secrets part")?;
        let shared: Shared =
            serde_json::from_slice(&shared).map_err(|e| format!("shared secrets: {e}"))?;
        if shared.v != 1 {
            return Err(format!("shared secrets: version {} is not 1", shared.v));
        }
        if shared.maps.is_empty() {
            return Err("shared secrets: the capsule names no map".into());
        }
        let state_key = decode_32(&shared.state_key, "shared secrets: state key")?;
        let template =
            Hash::from_multihash(&shared.template).map_err(|e| format!("template: {e}"))?;
        // K2 (§26, Р-4): the halves come from the parties' own parts — the
        // ones this session opened; an empty part (a capsule sealed before
        // K2) leaves the half where it was, in the state.
        let own = |kind: PartKind| {
            parts
                .iter()
                .find(|p| p.kind == kind && !p.bytes.is_empty())
                .map(|p| p.bytes.as_slice())
        };
        let container = Container::open_sealed_split(
            &state,
            &template,
            &state_key,
            own(PartKind::ClientSecrets),
            own(PartKind::OwnerSecrets),
        )
        .map_err(|e| format!("the container does not open: {e}"))?;

        // The file names the container it belongs to: a side file for another
        // capsule is refused here rather than after a press.
        if let Ok(named) = Hash::from_multihash(&side.container) {
            if named != *container.id() && named != container.template_id() {
                return Err(
                    "side file: it names another container than the capsule carries".into(),
                );
            }
        }

        let maps = shared
            .maps
            .iter()
            .map(map_from)
            .collect::<Result<Vec<_>, String>>()?;
        let artifact = Uri::parse(shared.artifact.clone()).map_err(|e| format!("artifact: {e}"))?;
        let client_kid =
            Uri::parse(shared.client.clone()).map_err(|e| format!("client kid: {e}"))?;

        let mobile = if side.half.is_empty() || side.role != SideRole::Client {
            None
        } else {
            let bytes = B64
                .decode(&side.half)
                .map_err(|_| "side file: half is not base64url".to_string())?;
            Some(MobileHalf::from_bytes(&bytes).map_err(|e| format!("side file: half: {e}"))?)
        };
        if container.born() && side.role == SideRole::Client && mobile.is_none() {
            return Err(
                "side file: the container is initiated, but the file carries no mobile half".into(),
            );
        }
        // A born container opened by its client holds its half — from the
        // client's part or, before K2, from the state. Without it no page
        // could be signed: refused here, not at the first `Work`.
        if container.born() && side.role == SideRole::Client && !container.holds_client_half() {
            return Err("the capsule carries no client's half: neither its part nor its state".into());
        }
        let owner = match side.role {
            SideRole::Owner => Some(open_owner(&container, &side.half)?),
            SideRole::Client => None,
        };

        let mut session = Self {
            container,
            maps,
            state_key: StateKey::new(state_key),
            template,
            artifact,
            client_kid,
            issued_ms: shared.issued_ms,
            clock_ms: shared.clock_ms,
            code,
            parts,
            outputs: Vec::new(),
            mobile,
            owner,
            pending_birth: false,
            pending_bytes: Vec::new(),
            pending_owner: None,
            external: Vec::new(),
            awaiting_external: None,
            carried,
            owner_sigs: Vec::new(),
            awaiting_owner: None,
            pending_opening: false,
            pending_open_bytes: Vec::new(),
            pending_open_offset: None,
            pending_open_owner: None,
            client_round: None,
            client_round_msg: None,
            pending_client_sigs: Vec::new(),
            press_offsets: PressOffsets::default(),
            pending_anchors: std::collections::VecDeque::new(),
        };
        for (i, raw) in anchored.iter().enumerate() {
            let attestation: Attestation =
                serde_json::from_slice(raw).map_err(|e| format!("anchored[{i}]: {e}"))?;
            session
                .apply_anchor(attestation)
                .map_err(|e| format!("anchored[{i}]: {e}"))?;
        }
        Ok(session)
    }

    /// One panel-level request.
    ///
    /// What a `Done` carries, by command:
    ///
    /// | Command | Bytes |
    /// |---|---|
    /// | [`Request::Status`] | the state as JSON: `id`, `template`, `class`, `status`, `pages`, `top_seal`, `form`, `pending`, `born`, `views` |
    /// | [`Request::Keys`] | the keys a verifier checks the pages with, as a JSON array |
    /// | [`Request::Work`] | `{"pages": n, "seal": "<multihash>"}` |
    /// | [`Request::ExportPage`] | the page as JSON, as `ksg-verify-v2` reads it — the same bytes the session keeps in its outputs |
    /// | [`Request::Initiate`] | `{"container": "<multihash>", "share_commitment": "<base64url>"}` (stand-only; the mobile half never leaves the module) |
    /// | [`Request::BeginBirth`] | `{"reply": "<base64url>"}` (message 2 for the mobile side) |
    /// | [`Request::FinishBirth`] | `{"container": "<multihash>"}` |
    /// | [`Request::OpenJournal`] | `{"pages": n, "seal": "<multihash>"}` |
    /// | [`Request::Reanchor`] | the last owed anchor settled: `{"pages", "seal"}`, as the opening's |
    /// | [`Request::Sign`] | the same as the command whose signature was missing |
    pub fn call(&mut self, request: Request) -> Answer {
        if let Some(answer) = self.followups_first(&request) {
            return answer;
        }
        match request {
            Request::Status => Answer::Done {
                bytes: serde_json::to_vec(&self.status_json()).unwrap_or_default(),
            },
            Request::Keys => self.keys(),
            Request::Work { text } => self.work(&text),
            Request::ExportPage { number } => self.export_page(number),
            Request::Initiate => self.initiate(),
            Request::BeginBirth { hello } => self.begin_birth_request(&hello),
            Request::FinishBirth { fin, group_key } => self.finish_birth_request(&fin, group_key),
            Request::Reanchor { attestation } => self.reanchor(&attestation),
            Request::OpenJournal => self.open_journal(),
            Request::ApplyPacket => self.apply_packet(),
            Request::ApplyPacketSeated { distributor } => self.apply_packet_seated(distributor),
            Request::ApplyBuyerKey { buyer, holder_map } => {
                self.apply_buyer_key(buyer, &holder_map)
            }
            Request::SetMaps { maps } => self.set_maps(&maps),
            Request::Form { to } => self.form(to),
            Request::FullExport => self.full_export(),
            Request::DeclareKeyLost => self.holder_op(
                Operation::DeclareKeyLost,
                &[Party::Owner],
                &Evidence::None,
                PageToWrite::None,
            ),
            Request::DeclareKeyLostByDistributor => self.declare_key_lost_by_distributor(),
            Request::Freeze => self.holder_op(
                Operation::FreezeOnOwnerApplication,
                &[Party::External(Role::Issuer), Party::Owner],
                &Evidence::None,
                PageToWrite::None,
            ),
            Request::DeclareSharesLost { hash } => self.holder_op(
                Operation::DeclareSharesLost,
                &[Party::Owner],
                &Evidence::SharesLost(hash),
                // The declaration's digest is the page: the container records
                // that it was made, not the shares (CT-22).
                PageToWrite::Record(
                    RecordKind::SharesDeclaredLost,
                    Piece::Inline(hash.to_multihash().into_bytes()),
                ),
            ),
            Request::Attach { what } => self.attach(what),
            Request::ApplyCommand { file, attestation } => self.apply_command(&file, &attestation),
            Request::PendingTasks => self.pending_tasks(),
            Request::WriteLayer { index, sealed } => self.write_layer(index, sealed),
            Request::HandedOver { index, sealed } => self.handed_over(index, sealed),
            Request::Transfer { new_owner, owner_map } => self.transfer(new_owner, &owner_map),
            Request::Sign { signature } => self.sign_pending(&signature),
            Request::AppointExpert { entry } => self.appoint_expert(&entry),
            Request::Disclose {
                entry,
                expert_record,
                record_anchor,
                disclosure,
            } => self.disclose_to_expert(entry, expert_record, record_anchor, disclosure),
            Request::ClientCommit { commitment } => self.client_commit(&commitment),
            Request::ClientShare { share } => self.client_share(&share),
            Request::Pull { trailer, trailer_seal } => self.pull(trailer, trailer_seal),
            Request::FullExportVoluntary { opening, anchor } => {
                self.full_export_voluntary(*opening, anchor)
            }
        }
    }

    /// Closes the session: the new capsule and what the reader must keep
    /// outside it.
    ///
    /// `outputs` are, in order, every page an export handed out. The client's
    /// mobile half is never an output: it stays inside the module (stand-only
    /// birth) or never enters it (the split birth of I1), and the reader never
    /// needs to read it back.
    ///
    /// # Errors
    ///
    /// A birth is pending (pressing it needs another party's signature, and a
    /// birth is never stored, so it must not be dropped); an anchor the
    /// network still owes (a placeholder must never leave the session as a
    /// record's anchor — answer every `NeedsAnchor` with a `Reanchor` first);
    /// the capsule seals to
    /// more than one map — re-assembly rebuilds every part from this map's
    /// view, and the other party's `OwnerSecrets`/`ClientSecrets`, which this
    /// map cannot open, would be lost silently; the state or the capsule does
    /// not encode.
    pub fn close(&mut self) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
        if self.pending_birth {
            return Err(
                "a birth is pending: the client's key is made and not yet pressed, and a birth \
                 is never stored — press the initiation or cancel it before closing"
                    .into(),
            );
        }
        if self.pending_opening {
            return Err(
                "an opening is pending: page 0 waits for the owner's co-seal — answer the \
                 NeedsSignature with a Sign before closing"
                    .into(),
            );
        }
        if let Some(owed) = self.pending_anchors.front() {
            return Err(format!(
                "an anchor is owed: the {} {} still carries its placeholder — answer the \
                 NeedsAnchor with a Reanchor before closing",
                match owed.kind {
                    AnchorKind::Seal => "seal",
                    AnchorKind::Status => "status record",
                },
                owed.subject.to_multihash(),
            ));
        }
        let mut rng = CspRng;
        // Two maps (§21, 4б.4а): v2 — the other party's private part rides
        // through unopened. One map: as before.
        if self.maps.len() > 1 {
            // K2 (§26, Р-4): each half goes to its party's part when this
            // session writes that part (it opened it, or the capsule has none);
            // a part riding through sealed keeps its half in the state, as
            // before K2 — never lost.
            let writes = |kind: PartKind| !self.carried.iter().any(|c| c.kind == kind);
            let (to_client, to_owner) =
                (writes(PartKind::ClientSecrets), writes(PartKind::OwnerSecrets));
            let (state, secrets) = self
                .container
                .seal_to_bytes_split(self.state_key.bytes(), to_client, to_owner, &mut rng)
                .map_err(|e| format!("the state does not seal: {e}"))?;
            let mut parts = self.parts.clone();
            for (kind, write, bytes) in [
                (PartKind::ClientSecrets, to_client, secrets.client.as_deref()),
                (PartKind::OwnerSecrets, to_owner, secrets.former.as_deref()),
            ] {
                if !write {
                    continue;
                }
                let bytes = bytes.cloned().unwrap_or_default();
                match parts.iter_mut().find(|p| p.kind == kind) {
                    Some(p) => p.bytes = bytes,
                    None => parts.push(Part { kind, bytes }),
                }
            }
            let mut fill = |out: &mut [u8]| rng.fill_bytes(out);
            let capsule = capsule::seal_into_capsule_split(
                &state,
                self.state_key.bytes(),
                &self.template.to_multihash(),
                self.artifact.as_str(),
                self.client_kid.as_str(),
                self.issued_ms,
                self.clock_ms,
                &self.code,
                &parts,
                &self.carried,
                &self.maps,
                &mut fill,
            )
            .map_err(|e| format!("the capsule does not assemble: {e}"))?;
            return Ok((capsule, self.outputs.clone()));
        }
        let state = self
            .container
            .seal_to_bytes(self.state_key.bytes(), &mut rng)
            .map_err(|e| format!("the state does not seal: {e}"))?;
        let mut fill = |out: &mut [u8]| rng.fill_bytes(out);
        let capsule = seal_parts(
            &state,
            &self.state_key,
            self.template,
            self.artifact.as_str(),
            self.client_kid.as_str(),
            self.issued_ms,
            self.clock_ms,
            &self.code,
            &self.parts,
            &self.maps,
            &mut fill,
        )?;
        Ok((capsule, self.outputs.clone()))
    }

    /// The container's state, one fact per field.
    fn status_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.container.id().to_multihash(),
            // K3 (§27): the head a network command must name.
            "head": self.container.head().map(|h| serde_json::json!({
                "counter": h.counter,
                "page": h.page.to_multihash(),
            })),
            "template": self.template.to_multihash(),
            "class": format!("{:?}", self.container.class()),
            "status": format!("{:?}", self.container.status()),
            "pages": self.container.pages(),
            "top_seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
            // C9: what a `light` anchors on Base when there is no seal yet.
            "status_head": self.container.status_head().to_multihash(),
            "form": self.container.form().map(|f| format!("{f:?}")),
            "pending": self.container.pending().len(),
            "born": self.container.born(),
            "views": self.container.views().seen(),
        })
    }

    /// The keys a verifier checks the pages with, as `ksg-verify` reads them.
    fn keys(&self) -> Answer {
        let Some(agent) = self.container.agent() else {
            return Answer::Refused {
                reason: "the container is not initiated: no client's key yet".into(),
            };
        };
        match serde_json::to_vec_pretty(&[agent]) {
            Ok(bytes) => Answer::Done { bytes },
            Err(e) => Answer::Refused {
                reason: format!("the key does not serialize: {e}"),
            },
        }
    }

    /// E-5: one record of work, sealed by the client's two halves — and,
    /// with no half inside (I4v), through the wire round: the reader answers
    /// each `NeedsClientCommit`/`NeedsShare` in turn and repeats `Work`
    /// until `Done` (an event and its seal are two messages, so two rounds).
    fn work(&mut self, text: &str) -> Answer {
        if !self.container.born() {
            return Answer::Refused {
                reason: "the container is not initiated: a record of work needs the client's key \
                         (E-4 first)"
                    .into(),
            };
        }
        let mut work = Work {
            container: *self.container.id(),
            under: None,
            did: text.into(),
            signatures: SignatureSet::default(),
        };
        let subject = work.subject();
        match self.sign_client(subject.as_bytes()) {
            Ok(sigs) => work.signatures = SignatureSet::new(sigs),
            Err(answer) => return answer,
        }
        match self.press(
            Operation::RecordWork,
            &[Party::Client],
            &Evidence::Work {
                order: None,
                work: Box::new(work),
            },
            PageToWrite::Record(RecordKind::Work, Piece::Inline(text.as_bytes().to_vec())),
        ) {
            Ok(()) => Answer::Done {
                bytes: serde_json::json!({
                    "pages": self.container.pages(),
                    "seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
                })
                .to_string()
                .into_bytes(),
            },
            Err(answer) => answer,
        }
    }

    /// A pointwise export of one page, sealed by the party whose file this is.
    fn export_page(&mut self, number: u64) -> Answer {
        let party = match (self.mobile.is_some(), &self.owner) {
            (true, _) => Party::Client,
            (false, Some(_)) => Party::Owner,
            (false, None) => {
                return Answer::Refused {
                    reason: "the session holds no key of the client's and none of the owner's"
                        .into(),
                }
            }
        };
        if let Err(answer) = self.press(
            Operation::ExportPoint,
            &[party],
            &Evidence::Point { number },
            PageToWrite::None,
        ) {
            return answer;
        }
        let Some(page) = self.container.take_point() else {
            return Answer::Refused {
                reason: "no page handed out".into(),
            };
        };
        match serde_json::to_vec(&page) {
            Ok(bytes) => {
                self.outputs.push(bytes.clone());
                Answer::Done { bytes }
            }
            Err(e) => Answer::Refused {
                reason: format!("the page does not serialize: {e}"),
            },
        }
    }

    /// E-4: the client's key is born, and the container with it.
    ///
    /// Stand/test-only: the birth is three messages between two sides, both
    /// run here, because the capsule is the only place that holds the
    /// container's half and the session may hold the other. The product
    /// splits the birth over the wire (`BeginBirth` / `FinishBirth`). Builds
    /// have no `initiate`
    /// command: one process must never hold both halves outside a stand or
    /// a test, so a release binary refuses the all-in-one path at the
    /// boundary instead of pressing it.
    /// the owner's (`Operation::Initiate`), so a session that is only the
    /// client's answers [`Answer::NeedsSignature`] with the bytes the owner
    /// signs, and keeps the birth in memory until it is pressed or the session
    /// closes (a close refuses: a birth is never stored).
    ///
    /// Stand/test-only: `#[doc(hidden)]` because the wire has no `initiate`
    /// command outside the stand and tests. The `debug_assert`
    /// below pins the invariant in debug builds: the all-in-one birth runs
    /// where one process holds the half for the demo or a test — never in
    /// the product, where the halves live on two sides of the wire.
    #[doc(hidden)]
    fn initiate(&mut self) -> Answer {
        debug_assert!(
            self.mobile.is_none(),
            "all-in-one birth runs on the stand or in tests: the session must hold no half yet"
        );
        if self.container.born() {
            return Answer::Refused {
                reason: "the container is initiated already".into(),
            };
        }
        if self.pending_birth {
            // A second call while the owner's signature is still missing: the
            // same answer, the same bytes — the birth is not repeated.
            return Answer::NeedsSignature {
                party: Party::Owner.name().into(),
                bytes: self.pending_bytes.clone(),
            };
        }
        use ksg_container_v2::client_key::MobileKeygen;
        let mut rng = CspRng;
        let (keygen, hello) = match MobileKeygen::start(self.client_kid.clone(), &mut rng) {
            Ok(x) => x,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the key is not born: {e}"),
                }
            }
        };
        let reply = match self
            .container
            .begin_birth(self.client_kid.clone(), &hello, &mut rng)
        {
            Ok(x) => x,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the container does not answer the birth: {e}"),
                }
            }
        };
        let (mut mobile, mut public, fin) = match keygen.finish(&reply) {
            Ok(x) => x,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the mobile side keeps no half: {e}"),
                };
            }
        };
        // G-1: the client agent is named by the `did:key` of the group key it
        // is half of — the same name a verifier computes. The key exists only
        // now; nothing has been signed under it yet.
        let named = match ksg_core_v2::crypto::did_key::kid(&public) {
            Ok(k) => k,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the client's did:key: {e}"),
                };
            }
        };
        mobile.set_kid(named.clone());
        public.kid = named.clone();
        if let Err(e) = self.container.name_birth(named.clone()) {
            self.container.cancel_birth();
            return Answer::Refused {
                reason: format!("the container does not take the name: {e}"),
            };
        }
        let offset_ms = self.tick();
        let (born, id) = match self
            .container
            .finish_birth(&fin, self.artifact.clone(), offset_ms)
        {
            Ok(x) => x,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the container keeps no half: {e}"),
                };
            }
        };
        if born != public {
            self.container.cancel_birth();
            return Answer::Refused {
                reason: "the two sides of the birth hold halves of different keys".into(),
            };
        }
        self.mobile = Some(mobile);
        self.client_kid = named;
        self.pending_birth = true;
        let pressed = self.press(
            Operation::Initiate,
            &[Party::Client, Party::Owner],
            &Evidence::Initiation { at: Where::Inside },
            PageToWrite::None,
        );
        match pressed {
            Ok(()) => self.birth_done(id),
            Err(Answer::NeedsSignature { bytes, .. }) => {
                self.pending_bytes = bytes;
                Answer::NeedsSignature {
                    party: Party::Owner.name().into(),
                    bytes: self.pending_bytes.clone(),
                }
            }
            // A Pro press owes the network, not a refusal: the birth stays
            // queued, and the reader's `Reanchor` finishes it.
            Err(owed @ Answer::NeedsAnchor { .. }) => owed,
            Err(refused) => {
                // A refusal writes nothing, so the birth is not kept: a
                // session that cannot press this initiation is a session that
                // can still close.
                self.container.cancel_birth();
                self.pending_birth = false;
                self.mobile = None;
                refused
            }
        }
    }

    /// E-4 split, messages 1-2: the mobile side started outside
    /// (`MobileKeygen::start`) and sent its commitment (`KeygenHello`); the
    /// container answers with message 2 (`KeygenReply`). Nothing is pressed:
    /// the birth is the container keygen waiting for message 3.
    ///
    /// A second call while message 3 is still missing re-answers with a fresh
    /// message 2 — the mobile side restarts from it.
    fn begin_birth_request(&mut self, hello_bytes: &[u8]) -> Answer {
        if self.container.born() {
            return Answer::Refused {
                reason: "the container is initiated already".into(),
            };
        }
        use ksg_container_v2::client_key::KeygenHello;
        let hello = match KeygenHello::from_bytes(hello_bytes) {
            Ok(h) => h,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the birth hello does not read: {e}"),
                }
            }
        };
        let mut rng = CspRng;
        let reply = match self
            .container
            .begin_birth(self.client_kid.clone(), &hello, &mut rng)
        {
            Ok(r) => r,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the container does not answer the birth: {e}"),
                }
            }
        };
        match reply.to_bytes() {
            Ok(bytes) => Answer::Done {
                bytes: serde_json::json!({ "reply": B64.encode(bytes.as_slice()) })
                    .to_string()
                    .into_bytes(),
            },
            Err(e) => {
                self.container.cancel_birth();
                Answer::Refused {
                    reason: format!("the birth reply does not encode: {e}"),
                }
            }
        }
    }

    /// E-4 split, message 3: the mobile side checked message 2, kept its half
    /// and sends the container share (`KeygenFinish`) with the group key it
    /// computed. The module names the `did:key` from that key material,
    /// finishes the container birth, and presses the initiation — the mobile
    /// half never enters the module.
    fn finish_birth_request(&mut self, fin_bytes: &[u8], group_key: PublicKey) -> Answer {
        if self.container.born() {
            return Answer::Refused {
                reason: "the container is initiated already".into(),
            };
        }
        if self.pending_birth {
            // The press waits for a party: the signature round answers it, a
            // repeated FinishBirth re-asks the same bytes — the birth is not
            // pressed twice.
            return match self.press(
                Operation::Initiate,
                &[Party::Client, Party::Owner],
                &Evidence::Initiation { at: Where::Inside },
                PageToWrite::None,
            ) {
                // The press went in through the wire round: the birth is
                // pressed, only the queue waits.
                Ok(()) => {
                    let id = *self.container.id();
                    self.finish_birth_done(id)
                }
                // Any other answer — `NeedsClientCommit`, `NeedsShare`, a
                // stranger's refusal, the network's `NeedsAnchor` — goes back
                // to the reader as it is.
                Err(answer) => answer,
            };
        }
        use ksg_container_v2::client_key::KeygenFinish;
        let fin = match KeygenFinish::from_bytes(fin_bytes) {
            Ok(f) => f,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the birth finish does not read: {e}"),
                }
            }
        };
        // The group key exists only once both rounds are done; the mobile side
        // computed it outside. The client identifier is its `did:key` — the
        // same name the stand path derives — so name the birth before the
        // container keeps its half.
        let named = match ksg_core_v2::crypto::did_key::kid(&group_key) {
            Ok(k) => k,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the group key names no did:key: {e}"),
                }
            }
        };
        if let Err(e) = self.container.name_birth(named.clone()) {
            self.container.cancel_birth();
            return Answer::Refused {
                reason: format!("the container does not take the name: {e}"),
            };
        }
        let offset_ms = self.tick();
        let (born, id) = match self
            .container
            .finish_birth(&fin, self.artifact.clone(), offset_ms)
        {
            Ok(x) => x,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the container keeps no half: {e}"),
                };
            }
        };
        if born.key != group_key.key || born.alg != group_key.alg {
            self.container.cancel_birth();
            return Answer::Refused {
                reason: "the two sides of the birth hold halves of different keys".into(),
            };
        }
        self.client_kid = named;
        self.pending_birth = true;
        // No mobile half inside: the client signs through the round of I4 —
        // the wire answers `NeedsClientCommit`, the reader's commitment goes
        // in through `Request::ClientCommit`, the round through
        // `Answer::NeedsShare` and `Request::ClientShare`. An owner's
        // signature (`NeedsSignature { party: owner }`) is the other wait.
        let pressed = self.press(
            Operation::Initiate,
            &[Party::Client, Party::Owner],
            &Evidence::Initiation { at: Where::Inside },
            PageToWrite::None,
        );
        match pressed {
            Ok(()) => self.finish_birth_done(id),
            // The client round carries no party: only the owner names one.
            Err(needed @ Answer::NeedsClientCommit { .. })
            | Err(needed @ Answer::NeedsShare { .. }) => needed,
            Err(needs @ Answer::NeedsSignature { .. }) => {
                self.pending_bytes = match &needs {
                    Answer::NeedsSignature { bytes, .. } => bytes.clone(),
                    _ => Vec::new(),
                };
                needs
            }
            Err(owed @ Answer::NeedsAnchor { .. }) => owed,
            Err(refused) => {
                self.container.cancel_birth();
                self.pending_birth = false;
                refused
            }
        }
    }

    /// The bookkeeping of a pressed split birth: no half to hand out — the
    /// mobile side kept its own — only the container identifier goes out.
    /// The birth queue clears; the client round of I4 answers the pending
    /// signature, the network answers the pending anchor.
    fn finish_birth_done(&mut self, id: Hash) -> Answer {
        self.pending_birth = false;
        self.pending_owner = None;
        Answer::Done {
            bytes: serde_json::json!({ "container": id.to_multihash() })
                .to_string()
                .into_bytes(),
        }
    }

    /// The bookkeeping of a pressed birth: the half never leaves the
    /// module — it stays in the session, or the session forgets it at once
    /// when the owner's file is the one that pressed (the half is the
    /// client's, not the reader's to keep). Stand/test-only, paired with
    /// [`Session::initiate`]: the split birth answers through
    /// [`Session::finish_birth_done`] instead. `#[doc(hidden)]` because the
    /// wire has no `initiate` command outside the stand and tests:
    /// one process must never hold both halves outside a stand or a test.
    #[doc(hidden)]
    fn birth_done(&mut self, id: Hash) -> Answer {
        let Some(mobile) = self.mobile.take() else {
            return Answer::Refused {
                reason: "the birth was pressed, but the session holds no half".into(),
            };
        };
        let share = match mobile.share_public() {
            Ok(s) => s,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the half has no public share: {e}"),
                }
            }
        };
        // E-19: the commitment to the mobile half — the reader anchors it.
        // The half itself is no output: it never leaves the module.
        let commitment = share_commitment(&share);
        self.pending_birth = false;
        self.pending_owner = None;
        if self.owner.is_some() {
            // The owner pressed the initiation: the client's half is the
            // client's, and this session forgets it at once.
            self.mobile = None;
        } else {
            self.mobile = Some(mobile);
        }
        Answer::Done {
            bytes: serde_json::json!({
                "container": id.to_multihash(),
                "share_commitment": B64.encode(commitment),
            })
            .to_string()
            .into_bytes(),
        }
    }

    /// E-5: the journal is open — page 0, sealed by the client's two halves.
    ///
    /// With no half inside (I4g) the seal goes through the wire round: the
    /// reader answers each `NeedsClientCommit`/`NeedsShare` in turn and
    /// repeats `OpenJournal` until `Done` (or the owner's `NeedsSignature`
    /// in Pro).
    ///
    /// Pro opens with the owner's seal and the anchor (CH-26), as on the
    /// stand: a client's session answers [`Answer::NeedsSignature`] with the
    /// seal's bytes, and the owner's [`Request::Sign`] presses page 0 — the
    /// same round trip as an initiation. An owner's session seals at once.
    fn open_journal(&mut self) -> Answer {
        if !self.container.born() {
            return Answer::Refused {
                reason: "the container is not initiated: the journal opens after E-4".into(),
            };
        }
        if self.pending_opening {
            // A second call while the owner's co-seal is still missing: the
            // same answer, the same bytes — the opening is not re-ticked.
            return Answer::NeedsSignature {
                party: Party::Owner.name().into(),
                bytes: self.pending_open_bytes.clone(),
            };
        }
        match self.press(
            Operation::OpenJournal,
            &[Party::Client],
            &Evidence::None,
            PageToWrite::Opening,
        ) {
            Ok(()) => {
                self.clear_opening();
                Answer::Done {
                    bytes: serde_json::json!({
                        "pages": self.container.pages(),
                        "seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
                    })
                    .to_string()
                    .into_bytes(),
                }
            }
            Err(owed @ Answer::NeedsAnchor { .. }) => {
                self.clear_opening();
                owed
            }
            Err(still @ Answer::NeedsSignature { .. }) => still,
            Err(refused) => refused,
        }
    }

    /// The opening's pending co-seal state goes: the press went in (its
    /// anchor, if any, now lives in the queue) or with it.
    fn clear_opening(&mut self) {
        self.pending_opening = false;
        self.pending_open_bytes.clear();
        self.pending_open_offset = None;
        self.pending_open_owner = None;
    }

    /// Page 0: the opening's seal, signed by the client's two halves — and,
    /// in Pro, the owner's co-seal and the placeholder anchor (CH-26), as the
    /// stand presses it. The seal's anchor goes back with the write: in Pro
    /// the press queues it, and the reader's [`Request::Reanchor`] swaps the
    /// placeholder for the network's attestation.
    fn opening_page(
        &mut self,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = match self.pending_open_offset {
            Some(ticked) => ticked,
            None => self.tick(),
        };
        let (bytes, hash) =
            self.container
                .opening_seal(offset_ms)
                .map_err(|e| Answer::Refused {
                    reason: format!("the opening does not seal: {e}"),
                })?;
        // The offset stays ticked while the press is open (I6b): a repeated
        // `OpenJournal` re-seals the same bytes — the wire round signs them,
        // the closed round is picked up. A successful press clears it (see
        // `Session::clear_opening`); a refusal drops it below.
        let seal = match self.sign_client(&bytes) {
            Ok(seal) => seal,
            Err(needs) => {
                if Self::is_wait_answer(&needs) {
                    self.pending_open_offset = Some(offset_ms);
                } else {
                    self.pending_open_offset = None;
                }
                return Err(needs);
            }
        };
        let pro = self.container.opening_form() == ksg_core_v2::journal::Mode::Pro;
        if !pro {
            self.pending_open_offset = None;
            return Ok((
                Some(JournalWrite::Open {
                    offset_ms,
                    sealing: Box::new(Sealing {
                        seal: SignatureSet::new(seal),
                        ..Sealing::default()
                    }),
                }),
                None,
            ));
        }
        if self.pending_open_offset.is_none() {
            self.pending_open_offset = Some(offset_ms);
        }
        // The owner's session seals at once; a client's waits for the
        // co-seal handed in through `Sign` — the exact seal bytes, as the
        // container checks them.
        let owner = match self.sign_owner(&bytes) {
            Ok(s) => s,
            Err(missing @ Answer::NeedsSignature { .. }) => {
                self.pending_opening = true;
                self.pending_open_bytes = bytes;
                return Err(missing);
            }
            Err(refused) => return Err(refused),
        };
        Ok((
            Some(JournalWrite::Open {
                offset_ms,
                sealing: Box::new(Sealing {
                    seal: SignatureSet::new(seal),
                    owner: Some(SignatureSet::new(vec![owner])),
                    anchor: Some(local_anchor(hash)),
                    ..Sealing::default()
                }),
            }),
            Some(AnchorNeed {
                kind: AnchorKind::Seal,
                prev: *self.container.id(),
                subject: hash,
            }),
        ))
    }

    /// The other party's signature over the bytes a [`Answer::NeedsSignature`]
    /// handed out: the pending command is pressed with it (L-1 — the
    /// signature is made outside the module, the check is inside). An
    /// initiation's birth and a Pro opening's co-seal never wait together: a
    /// birth is made before the container is born, an opening after.
    fn sign_pending(&mut self, raw: &[u8]) -> Answer {
        // A non-holder's signature (§20): kept for the repeat of the command
        // that asked for it — the press stays open, so the repeat signs the
        // same bytes (I6b) and finds it.
        if let Some((role, bytes)) = self.awaiting_external.take() {
            return match serde_json::from_slice::<Signature>(raw) {
                Ok(signature) => {
                    self.external.push((role, bytes, signature));
                    Answer::Done {
                        bytes: br#"{"signed":true,"repeat":"the same request"}"#.to_vec(),
                    }
                }
                Err(e) => Answer::Refused {
                    reason: format!("the signature does not read: {e}"),
                },
            };
        }
        // The owner's signature for a holder's operation in a client's
        // session: kept for the repeat, as the non-holder's above.
        if let Some(bytes) = self.awaiting_owner.take() {
            return match serde_json::from_slice::<Signature>(raw) {
                Ok(signature) => {
                    self.owner_sigs.push((bytes, signature));
                    Answer::Done {
                        bytes: br#"{"signed":true,"repeat":"the same request"}"#.to_vec(),
                    }
                }
                Err(e) => Answer::Refused {
                    reason: format!("the signature does not read: {e}"),
                },
            };
        }
        if self.pending_opening {
            let signature: Signature = match serde_json::from_slice(raw) {
                Ok(s) => s,
                Err(e) => {
                    return Answer::Refused {
                        reason: format!("the signature does not read: {e}"),
                    }
                }
            };
            self.pending_open_owner = Some(signature);
            return match self.open_journal_after_sign() {
                Ok(done) => {
                    self.clear_opening();
                    done
                }
                Err(still @ Answer::NeedsSignature { .. }) => still,
                Err(refused) => {
                    self.pending_open_owner = None;
                    refused
                }
            };
        }
        if !self.pending_birth {
            return Answer::Refused {
                reason: "nothing waits for a signature".into(),
            };
        }
        let signature: Signature = match serde_json::from_slice(raw) {
            Ok(s) => s,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the signature does not read: {e}"),
                }
            }
        };
        self.pending_owner = Some(signature);
        let pressed = self.press(
            Operation::Initiate,
            &[Party::Client, Party::Owner],
            &Evidence::Initiation { at: Where::Inside },
            PageToWrite::None,
        );
        match pressed {
            Ok(()) => {
                let id = *self.container.id();
                if self.mobile.is_some() {
                    self.birth_done(id)
                } else {
                    self.finish_birth_done(id)
                }
            }
            Err(Answer::NeedsSignature { bytes, .. }) => {
                self.pending_bytes = bytes;
                Answer::NeedsSignature {
                    party: Party::Owner.name().into(),
                    bytes: self.pending_bytes.clone(),
                }
            }
            // As in [`Session::initiate`]: the birth stays queued for the
            // reader's `Reanchor`, which finishes it.
            Err(owed @ Answer::NeedsAnchor { .. }) => owed,
            Err(refused) => {
                self.pending_owner = None;
                refused
            }
        }
    }

    /// Page 0 with the owner's co-seal handed in: the press with it — `Done`,
    /// or what the network owes instead (`NeedsAnchor`, then the reader's
    /// `Reanchor`), as after an initiation.
    fn open_journal_after_sign(&mut self) -> Result<Answer, Answer> {
        match self.press(
            Operation::OpenJournal,
            &[Party::Client],
            &Evidence::None,
            PageToWrite::Opening,
        ) {
            Ok(()) => Ok(Answer::Done {
                bytes: serde_json::json!({
                    "pages": self.container.pages(),
                    "seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
                })
                .to_string()
                .into_bytes(),
            }),
            Err(owed @ Answer::NeedsAnchor { .. }) => Ok(owed),
            Err(still @ Answer::NeedsSignature { .. }) => Err(still),
            Err(refused) => Err(refused),
        }
    }

    /// The network's attestation in place of a placeholder — and the next
    /// anchor owed, if one is still queued, or `Done` when none is left.
    ///
    /// An attestation naming anything but the head of the queue is refused:
    /// the reader anchors what the module asked for, oldest first.
    fn reanchor(&mut self, raw: &[u8]) -> Answer {
        let attestation: Attestation = match serde_json::from_slice(raw) {
            Ok(a) => a,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the attestation does not read: {e}"),
                }
            }
        };
        if let Some(head) = self.pending_anchors.front() {
            if attestation.subject != head.subject {
                return Answer::Refused {
                    reason: format!(
                        "the anchor names {}, but the {} the module waits for is {}",
                        attestation.subject.to_multihash(),
                        match head.kind {
                            AnchorKind::Seal => "seal",
                            AnchorKind::Status => "status record",
                        },
                        head.subject.to_multihash(),
                    ),
                };
            }
        }
        match self.apply_anchor(attestation) {
            Ok(()) => {
                self.pending_anchors.pop_front();
                if let Some(next) = self.pending_anchors.front() {
                    return next.answer();
                }
                if self.pending_birth {
                    let id = *self.container.id();
                    if self.mobile.is_some() {
                        return self.birth_done(id);
                    }
                    return self.finish_birth_done(id);
                }
                Answer::Done {
                    bytes: serde_json::json!({
                        "pages": self.container.pages(),
                        "seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
                    })
                    .to_string()
                    .into_bytes(),
                }
            }
            Err(reason) => Answer::Refused { reason },
        }
    }

    /// Puts an attestation where it belongs: the top seal's, or the status
    /// head's. Anything else is not this container's.
    fn apply_anchor(&mut self, attestation: Attestation) -> Result<(), String> {
        let subject = attestation.subject;
        if self.container.top_seal_hash() == Some(subject) {
            return self
                .container
                .reanchor_last(Some(attestation), None)
                .map_err(|e| format!("the seal anchor is refused: {e}"));
        }
        if self.container.status_head() == subject {
            return self
                .container
                .reanchor_last(None, Some(attestation))
                .map_err(|e| format!("the status anchor is refused: {e}"));
        }
        Err("the anchor names neither the top seal nor the status head".into())
    }

    /// The client signs through both halves: the mobile one here, the
    /// container's inside. The round is opened and closed in one call — the
    /// capsule model keeps both halves in one process for the demo (L-10).
    ///
    /// The round of the client's split key is the bridge, not the
    /// signature: with no half inside ([`Session::finish_birth_request`],
    /// I4v), every client signature spans the wire — round by round, each
    /// message its own open. [`Answer::NeedsClientCommit`] carries the
    /// message both halves sign, [`Request::ClientCommit`] opens the
    /// container's side of it, [`Answer::NeedsShare`] carries the round the
    /// mobile side signs, and [`Request::ClientShare`] closes it. A session
    /// that already holds the half signs at once, as before.
    fn sign_client(&mut self, msg: &[u8]) -> Result<Vec<Signature>, Answer> {
        // The wire round's signatures wait for the repeated command: the
        // same message picks up the round it closed — another message for a
        // command whose signature was refused opens its own round; they sign
        // exactly what each round signed.
        if let Some((_, sigs)) = self.pending_client_sigs.iter().find(|(m, _)| m == msg) {
            return Ok(sigs.clone());
        }
        if self.mobile.is_some() {
            return self.sign_client_local(msg);
        }
        // No half inside: the signature comes over the wire. A round already
        // open is answered again — the same message, so the same round.
        if let Some(open) = &self.client_round {
            return Err(self.needs_share(&open.round));
        }
        self.client_round_msg = Some(msg.to_vec());
        Err(Answer::NeedsClientCommit {
            round: msg.to_vec(),
        })
    }

    /// The client's half is here: one call opens the round, answers it, and
    /// closes it — as on the stand. Stand/test-only like [`Session::initiate`]:
    /// the product path keeps no half inside and signs over the wire
    /// (`NeedsClientCommit` / `NeedsShare`), so outside the stand and tests
    /// this closes over the caller-provided half the reader holds in its own
    /// process — never over a half that crossed into the module.
    fn sign_client_local(&mut self, msg: &[u8]) -> Result<Vec<Signature>, Answer> {
        let Some(mobile) = &self.mobile else {
            return Err(self.missing(Party::Client, msg));
        };
        let mut rng = CspRng;
        let (nonces, commitment) = mobile.commit(&mut rng);
        let round = match self.container.begin_signing(msg, &commitment, &mut rng) {
            Ok(r) => r,
            Err(e) => {
                return Err(Answer::Refused {
                    reason: format!("the container opens no round: {e}"),
                })
            }
        };
        let share = match mobile.respond(nonces, &round) {
            Ok(s) => s,
            Err(e) => {
                return Err(Answer::Refused {
                    reason: format!("the mobile half answers nothing: {e}"),
                })
            }
        };
        self.container
            .finish_signing(&share, &mut rng)
            .map_err(|e| Answer::Refused {
                reason: format!("the round does not close: {e}"),
            })
    }

    /// "Sign this round": the round bytes the mobile side signs — the
    /// container's package over the waiting message.
    fn needs_share(&self, round: &SigningRound) -> Answer {
        let bytes = match round.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the round does not encode: {e}"),
                }
            }
        };
        Answer::NeedsShare { round: bytes }
    }

    /// The message the wire round signs, if a command opened one: the reader
    /// commits to it first. `None` when no command waits for a commitment.
    fn client_round_msg(&mut self) -> Option<Vec<u8>> {
        self.client_round_msg.clone()
    }

    /// The mobile side's commitment comes in: the container opens its side
    /// of the round over the message [`Answer::NeedsClientCommit`] carried.
    /// The answer carries the round the mobile side signs.
    ///
    /// A commitment with a round already open — or with no message waiting
    /// for one — is refused: one round at a time, and only for a command
    /// that asked.
    fn client_commit(&mut self, raw: &[u8]) -> Answer {
        if self.client_round.is_some() {
            return Answer::Refused {
                reason: "a client round is already open: answer it with a share".into(),
            };
        }
        let Some(open) = self.client_round_msg() else {
            return Answer::Refused {
                reason: "no client round waits for a commitment".into(),
            };
        };
        let commitment = match Commitment::from_bytes(raw) {
            Ok(c) => c,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the commitment does not read: {e}"),
                }
            }
        };
        let mut rng = CspRng;
        let round = match self.container.begin_signing(&open, &commitment, &mut rng) {
            Ok(r) => r,
            Err(e) => {
                self.client_round = None;
                return Answer::Refused {
                    reason: format!("the container opens no round: {e}"),
                };
            }
        };
        self.client_round_msg = None;
        let answer = self.needs_share(&round);
        self.client_round = Some(ClientRound {
            msg: open,
            commitment,
            round,
        });
        answer
    }

    /// The mobile side's share comes in: the container adds its own and
    /// closes the round, and the signatures wait for the command to be
    /// repeated — the reader repeats it, and [`Session::sign_client`] picks
    /// them up. A stranger's share does not verify and the round drops.
    fn client_share(&mut self, raw: &[u8]) -> Answer {
        let Some(open) = self.client_round.take() else {
            return Answer::Refused {
                reason: "no client round open".into(),
            };
        };
        let share = match MobileShare::from_bytes(raw) {
            Ok(s) => s,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the share does not read: {e}"),
                }
            }
        };
        let mut rng = CspRng;
        match self.container.finish_signing(&share, &mut rng) {
            Ok(sigs) => {
                let len = open.msg.len();
                self.pending_client_sigs.push((open.msg, sigs));
                Answer::Done {
                    bytes: serde_json::to_vec(&serde_json::json!({
                        "accepted": len,
                    }))
                    .unwrap_or_default(),
                }
            }
            Err(e) => Answer::Refused {
                reason: format!("the round does not close: {e}"),
            },
        }
    }
    /// other party, with the signature the reader handed in
    /// ([`Request::Sign`]) over exactly the bytes it was asked for.
    fn sign_owner(&self, msg: &[u8]) -> Result<Signature, Answer> {
        if let Some(signature) = &self.pending_owner {
            if msg == self.pending_bytes.as_slice() {
                return Ok(signature.clone());
            }
        }
        if let Some(signature) = &self.pending_open_owner {
            if msg == self.pending_open_bytes.as_slice() {
                return Ok(signature.clone());
            }
        }
        if let Some((_, signature)) = self.owner_sigs.iter().find(|(b, _)| b.as_slice() == msg) {
            return Ok(signature.clone());
        }
        match &self.owner {
            Some(key) => Ok(key.signer().sign(msg)),
            None => Err(self.missing(Party::Owner, msg)),
        }
    }

    /// A party that holds no map signs outside (§20): the signature handed in
    /// for exactly these bytes, or the question for it.
    fn sign_external(&mut self, msg: &[u8], role: Role) -> Result<Signature, Answer> {
        if let Some((_, _, signature)) =
            self.external.iter().find(|(r, b, _)| *r == role && b.as_slice() == msg)
        {
            return Ok(signature.clone());
        }
        self.awaiting_external = Some((role, msg.to_vec()));
        Err(self.missing(Party::External(role), msg))
    }

    /// K4 (§28, full ladder fix 1): while a follow-up that holds the container
    /// up is open — a release or packet layer to write, a layer key to hand
    /// over — a request that would move the status is refused. A move would
    /// make the follow-up stale for good (`Container::claim` wants the head it
    /// was raised at), and with it the initiation or the journal blocked for
    /// good. The chain layer (E-9) holds nothing up and is not guarded. On the
    /// paths before K4 no such follow-up is ever open (the stand discharges
    /// them at printing), so nothing there changes.
    fn followups_first(&self, request: &Request) -> Option<Answer> {
        use ksg_container_v2::{Task, Zone};
        let holds_up = self.container.pending().iter().any(|r| {
            matches!(
                r.task,
                Task::WriteLayer { zone: Zone::Release | Zone::Packet } | Task::HandOverLayer { .. }
            )
        });
        if !holds_up {
            return None;
        }
        let allowed = matches!(
            request,
            Request::Status
                | Request::Keys
                | Request::PendingTasks
                | Request::WriteLayer { .. }
                | Request::HandedOver { .. }
                | Request::Reanchor { .. }
                | Request::Sign { .. }
                | Request::ClientCommit { .. }
                | Request::ClientShare { .. }
        );
        (!allowed).then(|| Answer::Refused {
            reason: "the layers come first (K4): discharge the open follow-ups — PendingTasks, \
                     then WriteLayer / HandedOver — before the next command"
                .into(),
        })
    }

    /// K4 (§28): the open follow-ups, one JSON object each.
    fn pending_tasks(&self) -> Answer {
        use ksg_container_v2::Task;
        let mut out = Vec::new();
        for (index, raised) in self.container.pending().iter().enumerate() {
            out.push(match &raised.task {
                Task::WriteLayer { zone } => {
                    let position = (0..ksg_container_v2::layout::ZONE_POSITIONS)
                        .map_while(|nth| ksg_container_v2::layout::zone_position(*zone, nth).ok())
                        .find(|p| !self.container.sealed_zone_written(*p));
                    let owner = (*zone == ksg_container_v2::Zone::Chain)
                        .then(|| self.container.roster().holder(Role::Owner).cloned())
                        .flatten();
                    serde_json::json!({
                        "index": index,
                        "task": "write_layer",
                        "zone": zone,
                        "position": position,
                        "owner": owner,
                    })
                }
                Task::HandOverLayer { to, up_to } => serde_json::json!({
                    "index": index,
                    "task": "hand_over",
                    "to": to,
                    "up_to": up_to.0,
                }),
                Task::CarryId { .. } => serde_json::json!({ "index": index, "task": "carry_id" }),
            });
        }
        Answer::Done {
            bytes: serde_json::Value::Array(out).to_string().into_bytes(),
        }
    }

    /// K4: writes the issuer's sealed zone for the follow-up `index` and
    /// discharges it.
    fn write_layer(&mut self, index: usize, sealed: Vec<u8>) -> Answer {
        use ksg_container_v2::{Discharge, Proof, Task};
        let refused = |reason: String| Answer::Refused { reason };
        let zone = match self.container.pending().get(index).map(|r| &r.task) {
            Some(Task::WriteLayer { zone }) => *zone,
            _ => return refused(format!("follow-up {index} is not a layer to write")),
        };
        if !self.container.zones_laid() {
            let mut noise = zeroize::Zeroizing::new(vec![
                0u8;
                ksg_container_v2::layout::ZONE_POSITIONS
                    * ksg_container_v2::layout::ZONE_BYTES
            ]);
            CspRng.fill_bytes(&mut noise);
            if let Err(e) = self.container.lay_zone_noise(&noise) {
                return refused(format!("the zones' noise: {e}"));
            }
        }
        let ticket = match self.container.claim(index) {
            Ok(t) => t,
            Err(e) => return refused(format!("the follow-up: {e}")),
        };
        let digest = Hash::sha256(&sealed);
        if let Err(e) = self.container.write_zone(zone, sealed) {
            return refused(format!("the zone: {e}"));
        }
        match self.container.discharge(&Discharge {
            ticket,
            proof: Proof::LayerWritten { zone, digest },
        }) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(e) => refused(format!("the discharge: {e}")),
        }
    }

    /// K4: discharges the hand-over of the layer key made outside.
    fn handed_over(&mut self, index: usize, sealed: Hash) -> Answer {
        use ksg_container_v2::{Discharge, Proof, Task};
        let refused = |reason: String| Answer::Refused { reason };
        let (to, up_to) = match self.container.pending().get(index).map(|r| &r.task) {
            Some(Task::HandOverLayer { to, up_to }) => (to.clone(), *up_to),
            _ => return refused(format!("follow-up {index} is not a hand-over")),
        };
        let ticket = match self.container.claim(index) {
            Ok(t) => t,
            Err(e) => return refused(format!("the follow-up: {e}")),
        };
        match self.container.discharge(&Discharge {
            ticket,
            proof: Proof::HandedOver { to, up_to, sealed },
        }) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(e) => refused(format!("the discharge: {e}")),
        }
    }

    /// K3 (§27): a command from the network, pressed with the signatures it
    /// came with. Its anchor must name exactly the bytes those signatures
    /// cover; a replay carries a stale head and the container refuses it.
    fn apply_command(&mut self, command: &[u8], attestation: &[u8]) -> Answer {
        let refused = |reason: String| Answer::Refused { reason };
        let file: CommandFile = match serde_json::from_slice(command) {
            Ok(f) => f,
            Err(e) => return refused(format!("the command does not read: {e}")),
        };
        if !COMMAND_OPS.contains(&file.op) {
            return refused(format!(
                "{:?} does not come from the network (K3: Finalize, ServeDispute, DeclareSharesLost)",
                file.op
            ));
        }
        let (event, evidence) = match file.event() {
            Ok(e) => e,
            Err(e) => return refused(e),
        };
        if event.container != *self.container.id() {
            return refused("the command is another container's".into());
        }
        let attestation: Attestation = match serde_json::from_slice(attestation) {
            Ok(a) => a,
            Err(e) => return refused(format!("the attestation does not read: {e}")),
        };
        if attestation.subject != Hash::sha256(&event.covered) {
            return refused("the anchor names other bytes than the command's signatures cover".into());
        }
        let page = match &evidence {
            // The declaration's digest is the page, as the owner's E-24 (C1).
            Evidence::SharesLost(hash) => PageToWrite::Record(
                RecordKind::SharesDeclaredLost,
                Piece::Inline(hash.to_multihash().into_bytes()),
            ),
            // E-14 writes slot 1 of the coupling when the journal is open
            // (the kernel's `Operation::Succeed => journal_open && ...`):
            // without a journal the succession moves the status but writes
            // no page. A closed journal never reaches here, but the branch
            // is read against `self.container.head()` so the shape stays
            // explicit even where it is unreachable.
            Evidence::Coupling(c) if self.container.head().is_some() => {
                PageToWrite::Coupling(c.clone())
            }
            _ => PageToWrite::None,
        };
        match self.press_presigned(&event, &evidence, page) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(answer) => answer,
        }
    }

    /// [`Session::press`] for an event signed outside — the network's command
    /// (K3): its page, the status record signed by this session's party, the
    /// container's press and what Pro owes the network. `press` itself is not
    /// changed (HIGH); this is its tail without the signing.
    fn press_presigned(
        &mut self,
        event: &Event,
        evidence: &Evidence,
        page: PageToWrite,
    ) -> Result<(), Answer> {
        let (page, page_need) = match self.opening_page_or(page) {
            Ok(w) => w,
            Err(needs) => {
                if !Self::is_wait_answer(&needs) {
                    self.press_offsets = PressOffsets::default();
                }
                return Err(needs);
            }
        };
        let (status, status_need) = match self.status_record(event.op) {
            Ok(w) => w,
            Err(needs) => {
                if !Self::is_wait_answer(&needs) {
                    self.press_offsets = PressOffsets::default();
                }
                return Err(needs);
            }
        };
        let keys = self.container.roster().keys().clone();
        let at_ms = Some(self.clock_ms);
        self.container
            .press(
                event,
                evidence,
                Writes {
                    page,
                    status,
                    at_ms,
                },
                &keys,
                &Profile::default(),
            )
            .map_err(|e| Answer::Refused {
                reason: format!("refused: {e}"),
            })?;
        self.press_offsets = PressOffsets::default();
        self.pending_client_sigs.clear();
        if !self.pending_opening {
            self.pending_open_offset = None;
        }
        if self.container.is_pro() {
            if let Some(need) = page_need {
                self.pending_anchors.push_back(need);
            }
            if let Some(need) = status_need {
                self.pending_anchors.push_back(need);
            }
            if let Some(head) = self.pending_anchors.front() {
                return Err(head.answer());
            }
        }
        Ok(())
    }

    /// E-2 through the session (§19): the issuer's press on the holder's map,
    /// before initiation; `bare` has no packet.
    fn apply_packet(&mut self) -> Answer {
        if self.container.born() {
            return Answer::Refused {
                reason: "the container is initiated: the packet is before E-4".into(),
            };
        }
        match self.press(
            Operation::ApplyPacket,
            &[Party::External(Role::Issuer)],
            &Evidence::None,
            PageToWrite::None,
        ) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(answer) => answer,
        }
    }

    /// E-2 with a seat (§19): the distributor is seated before the press and
    /// stays seated if the press is refused or waits for a signature.
    fn apply_packet_seated(&mut self, distributor: PublicKey) -> Answer {
        if self.container.roster().holder(Role::Distributor) != Some(&distributor) {
            if let Err(e) = self.container.seat_distributor(distributor) {
                return Answer::Refused {
                    reason: format!("the distributor is not seated: {e}"),
                };
            }
        }
        self.apply_packet()
    }

    /// E-3 (§19): the buyer's key and the owner's consent; then the buyer's
    /// map replaces the holder's (one map before the birth).
    fn apply_buyer_key(&mut self, buyer: PublicKey, holder_map: &capsule::MapPub) -> Answer {
        self.awaiting_owner = None;
        if self.container.born() {
            return Answer::Refused {
                reason: "the container is initiated: the buyer's key is before E-4".into(),
            };
        }
        if self.maps.len() != 1 {
            return Answer::Refused {
                reason: "the capsule carries the parties' maps already".into(),
            };
        }
        let (role, seal) = match map_from(holder_map) {
            Ok(m) => m,
            Err(reason) => return Answer::Refused { reason },
        };
        if role != self.maps[0].0 {
            return Answer::Refused {
                reason: "the buyer's map takes the holder's slot: its role is the holder's".into(),
            };
        }
        let result = self.press(
            Operation::ApplyBuyerKey,
            &[Party::External(Role::Buyer), Party::Owner],
            &Evidence::KeyLaid {
                to: buyer,
                up_to: Level(2),
            },
            PageToWrite::None,
        );
        match result {
            Ok(()) => {
                self.maps[0].1 = seal;
                Answer::Done {
                    bytes: self.status_json().to_string().into_bytes(),
                }
            }
            // The press is made; the network owes an anchor (Pro): the map
            // changes all the same, the capsule closes sealed to the buyer.
            Err(answer @ Answer::NeedsAnchor { .. }) => {
                self.maps[0].1 = seal;
                answer
            }
            Err(answer) => self.note_owner_wait(answer),
        }
    }

    /// The client's and the owner's maps replace the holder's (§21).
    fn set_maps(&mut self, maps: &[capsule::MapPub]) -> Answer {
        if !self.container.born() {
            return Answer::Refused { reason: "the maps are set after the initiation (E-4)".into() };
        }
        if self.maps.len() != 1 || self.maps[0].0 != MapRole::Holder {
            return Answer::Refused { reason: "the capsule already carries the parties' maps".into() };
        }
        let parsed: Result<Vec<(MapRole, SealTo)>, String> = maps.iter().map(map_from).collect();
        let parsed = match parsed {
            Ok(p) => p,
            Err(reason) => return Answer::Refused { reason },
        };
        let roles: Vec<MapRole> = parsed.iter().map(|(r, _)| *r).collect();
        if roles != [MapRole::Client, MapRole::Owner] {
            return Answer::Refused { reason: "the maps are the client's and the owner's, in that order".into() };
        }
        self.maps = parsed;
        Answer::Done { bytes: br#"{"maps":["client","owner"]}"#.to_vec() }
    }

    /// The operations only a holder presses on a born container
    /// (`Spec_kapsula` §24): E-15, E-23, E-24. A signature of the owner that
    /// this session does not hold is asked for and handed in by
    /// [`Request::Sign`]; the container refuses what its status does not admit.
    fn holder_op(
        &mut self,
        op: Operation,
        who: &[Party],
        evidence: &Evidence,
        page: PageToWrite,
    ) -> Answer {
        self.awaiting_owner = None;
        match self.press(op, who, evidence, page) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(answer) => self.note_owner_wait(answer),
        }
    }

    /// E-15 with the distributor (`Spec_kapsula` §24): `Keys::AnyOf` takes
    /// `[Distributor, Client]`. Like the stand's `declare_dead`, the seat is
    /// checked before the press, so nobody is asked to sign for a road that
    /// does not exist.
    fn declare_key_lost_by_distributor(&mut self) -> Answer {
        if self.container.roster().holder(Role::Distributor).is_none() {
            self.awaiting_owner = None;
            return Answer::Refused {
                reason: "no distributor is seated in this container: the packet was sold \
                         directly by the issuer"
                    .into(),
            };
        }
        self.holder_op(
            Operation::DeclareKeyLost,
            &[Party::External(Role::Distributor), Party::Client],
            &Evidence::None,
            PageToWrite::None,
        )
    }

    /// E-9 through the session (`Spec_kapsula` §21): the owner and the
    /// arriving owner sign, the journal takes the page of the change of owner,
    /// and the owner's slot is sealed to the arriving owner's map from then
    /// on. Nothing changes if the press does not go in.
    fn transfer(&mut self, new_owner: PublicKey, owner_map: &capsule::MapPub) -> Answer {
        self.awaiting_owner = None;
        let seal = match map_from(owner_map) {
            Ok((MapRole::Owner, seal)) => seal,
            Ok(_) => {
                return Answer::Refused {
                    reason: "the arriving owner's map takes the owner's slot: its role is the owner's"
                        .into(),
                }
            }
            Err(reason) => return Answer::Refused { reason },
        };
        let Some(slot) = self.maps.iter().position(|(r, _)| *r == MapRole::Owner) else {
            return Answer::Refused {
                reason: "the capsule carries no owner's map: the owner's map comes with E-4".into(),
            };
        };
        // The former owner's secrets, sealed to his map, ride through this
        // session unopened. Empty — they are made again under the new map at
        // close; not empty — only the former owner's session can move them.
        let rides = self.carried.iter().position(|c| c.kind == PartKind::OwnerSecrets);
        if let Some(i) = rides {
            if self.carried[i].blob.len() > EMPTY_PRIVATE_PART {
                return Answer::Refused {
                    reason: "the former owner's secrets need his own session: they ride sealed                              to his map and would not open for the new owner"
                        .into(),
                };
            }
        }
        let result = self.press(
            Operation::TransferOwnership,
            &[Party::Owner, Party::External(Role::Buyer)],
            &Evidence::Transfer(new_owner.clone()),
            PageToWrite::OwnerChange(new_owner),
        );
        match result {
            Ok(()) => {}
            // The press is made; the network owes an anchor (Pro): the map
            // changes all the same, the capsule closes sealed to the new owner.
            Err(answer @ Answer::NeedsAnchor { .. }) => {
                self.moved_to_owner(slot, seal, rides);
                return answer;
            }
            Err(answer) => return self.note_owner_wait(answer),
        }
        self.moved_to_owner(slot, seal, rides);
        Answer::Done {
            bytes: self.status_json().to_string().into_bytes(),
        }
    }

    /// The seat and the slot of the owner have moved: seal to the new map and
    /// let go of the empty secrets part sealed to the former one.
    fn moved_to_owner(&mut self, slot: usize, seal: SealTo, rides: Option<usize>) {
        self.maps[slot].1 = seal;
        if let Some(i) = rides {
            self.carried.remove(i);
        }
    }

    /// E-10 through the session: the form changes, the journal takes a page of
    /// it. Pro (up) takes the issuer beside the owner, light (down) the owner
    /// alone.
    fn form(&mut self, to: Mode) -> Answer {
        self.awaiting_owner = None;
        let who: &[Party] = match to {
            Mode::Pro => &[Party::Owner, Party::External(Role::Issuer)],
            Mode::Local => &[Party::Owner],
        };
        match self.press(
            Operation::RaiseClass,
            who,
            &Evidence::Form { to },
            PageToWrite::Form(to),
        ) {
            Ok(()) => Answer::Done {
                bytes: self.status_json().to_string().into_bytes(),
            },
            Err(answer) => self.note_owner_wait(answer),
        }
    }

    /// E-6 through the session: the client signs, the page is the content's
    /// digest; in Pro the journal asks the owner's seal on it, and it comes
    /// in as for [`Session::form`].
    fn attach(&mut self, what: AttachWire) -> Answer {
        let (name, mime, content_hash, size, offset_ms, derived_from) = match what {
            AttachWire::Artifact {
                name,
                mime,
                content_hash,
                size,
                offset_ms,
                derived_from,
            } => (name, mime, content_hash, size, offset_ms, derived_from),
            AttachWire::Rule { rule } => {
                return self.holder_op(
                    Operation::AttachArtifactOrRights,
                    &[Party::Client],
                    &Evidence::Rule(rule.clone()),
                    PageToWrite::Rule(rule),
                )
            }
            AttachWire::Claim {
                artifact,
                open_id,
                agent,
                signatures,
                anchor,
            } => return self.attach_claim(artifact, open_id, agent, signatures, anchor),
        };
        let mut derived = Vec::with_capacity(derived_from.len());
        for uri in derived_from {
            match Uri::parse(uri) {
                Ok(u) => derived.push(u),
                Err(e) => {
                    return Answer::Refused {
                        reason: format!("derived_from does not read as a URI: {e}"),
                    }
                }
            }
        }
        let attachment = Attachment {
            artifact: self.artifact.clone(),
            kind: Kind::Media { mime },
            content_hash,
            size,
            name,
            derived_from: derived,
            offset_ms,
        };
        self.holder_op(
            Operation::AttachArtifactOrRights,
            &[Party::Client],
            &Evidence::Artifact(Box::new(attachment)),
            PageToWrite::Record(RecordKind::ArtifactOrRights, Piece::Digest(content_hash)),
        )
    }

    /// E-8 through the session: the claim's two hashes on a page of its own
    /// type; the container checks the publication (as the stand's `claim`).
    fn attach_claim(
        &mut self,
        artifact: Hash,
        open_id: String,
        agent: PublicKey,
        signatures: SignatureSet,
        anchor: Attestation,
    ) -> Answer {
        use ksg_container_v2::identity::{id_hash, OwnershipClaim, Publication, OWNERSHIP_CLAIM_PAGE};
        let claim = OwnershipClaim {
            container: *self.container.id(),
            artifact,
            agent_id: id_hash(&open_id),
        };
        let publication = Publication {
            container: *self.container.id(),
            open_id,
            agent,
            signatures,
            anchor,
        };
        let content_type = match Uri::parse(OWNERSHIP_CLAIM_PAGE.to_owned()) {
            Ok(u) => u,
            Err(e) => return Answer::Refused { reason: format!("page type: {e}") },
        };
        let page = PageToWrite::Typed(
            RecordKind::ArtifactOrRights,
            Piece::Inline(claim.page_bytes()),
            content_type,
        );
        self.holder_op(
            Operation::AttachArtifactOrRights,
            &[Party::Client],
            &Evidence::Claim {
                claim: Box::new(claim),
                publication: Box::new(publication),
            },
            page,
        )
    }

    /// `FullExport`: the owner and the client export everything and the
    /// container dies. The export goes to `outputs`, as a page does.
    fn full_export(&mut self) -> Answer {
        self.awaiting_owner = None;
        if let Err(answer) = self.press(
            Operation::FullExport,
            &[Party::Owner, Party::Client],
            &Evidence::Unload(Box::new(UnloadRoute::Principals)),
            PageToWrite::None,
        ) {
            return self.note_owner_wait(answer);
        }
        let Some(export) = self.container.take_export() else {
            return Answer::Refused {
                reason: "no export handed out".into(),
            };
        };
        match serde_json::to_vec(&export) {
            Ok(bytes) => {
                self.outputs.push(bytes.clone());
                Answer::Done { bytes }
            }
            Err(e) => Answer::Refused {
                reason: format!("the export does not serialize: {e}"),
            },
        }
    }

    /// `FullExport` by the road of a voluntary opening (st.12): the owner
    /// and the client export everything and the container dies. Like
    /// [`Session::full_export`], but the evidence carries the opening the
    /// four parties signed and its declaration's anchor — the gate checks
    /// them (`Route::Voluntary`). The export goes to `outputs`, as a page
    /// does.
    fn full_export_voluntary(
        &mut self,
        opening: ksg_container_v2::voluntary::VoluntaryOpening,
        anchor: Attestation,
    ) -> Answer {
        self.awaiting_owner = None;
        if let Err(answer) = self.press(
            Operation::FullExport,
            &[Party::Owner, Party::Client],
            &Evidence::Unload(Box::new(UnloadRoute::Voluntary {
                opening: Box::new(opening),
                anchor,
            })),
            PageToWrite::None,
        ) {
            return self.note_owner_wait(answer);
        }
        let Some(export) = self.container.take_export() else {
            return Answer::Refused {
                reason: "no export handed out".into(),
            };
        };
        match serde_json::to_vec(&export) {
            Ok(bytes) => {
                self.outputs.push(bytes.clone());
                Answer::Done { bytes }
            }
            Err(e) => Answer::Refused {
                reason: format!("the export does not serialize: {e}"),
            },
        }
    }

    /// Remembers the bytes of an owner's signature a client's session waits
    /// for, so [`Request::Sign`] can take it.
    fn note_owner_wait(&mut self, answer: Answer) -> Answer {
        if let Answer::NeedsSignature { party, bytes } = &answer {
            if party == Party::Owner.name() && self.owner.is_none() {
                self.awaiting_owner = Some(bytes.clone());
            }
        }
        answer
    }

    /// E-5 slot 2 of the coupling (CH-12): the leading container pulls the
    /// trailer; its last seal comes with it. As the stand's `pull`: the
    /// client's `RecordWork` with the coupling page.
    fn pull(&mut self, trailer: Hash, trailer_seal: Hash) -> Answer {
        let coupling = ksg_core_v2::journal::CouplingRecord::Pulls { trailer, trailer_seal };
        self.holder_op(
            Operation::RecordWork,
            &[Party::Client],
            &Evidence::Coupling(coupling.clone()),
            PageToWrite::Coupling(coupling),
        )
    }

    /// The page of a change of form, sealed the way its parties do (CH-29).
    fn form_page(
        &mut self,
        to: Mode,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = match self.press_offsets.page_offsets.pop() {
            Some(ticked) => {
                self.press_offsets.page_offsets.push(ticked);
                ticked
            }
            None => {
                let ticked = self.tick();
                self.press_offsets.page_offsets.push(ticked);
                ticked
            }
        };
        let draft = self
            .container
            .draft_form(to, offset_ms)
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        self.seal_draft(draft).map(|(w, n)| (Some(w), n))
    }

    /// The offset a page is drafted with: a repeated command reuses the one
    /// its open press ticked (I6b), as [`Session::form_page`] does.
    fn page_offset(&mut self) -> u64 {
        if let Some(ticked) = self.press_offsets.page_offsets.pop() {
            self.press_offsets.page_offsets.push(ticked);
            return ticked;
        }
        let ticked = self.tick();
        self.press_offsets.page_offsets.push(ticked);
        ticked
    }

    /// E-7: the page of the rule of two seals (`[р]` 31.10 «А»).
    fn rule_page(
        &mut self,
        rule: ksg_core_v2::journal::SealRule,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = self.page_offset();
        let draft = self
            .container
            .draft_rule(rule, offset_ms)
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        self.seal_draft(draft).map(|(w, n)| (Some(w), n))
    }

    /// E-9: the page of a change of owner to `to` (`[р]` 31.10 «А» С6/С7).
    fn owner_change_page(
        &mut self,
        to: &PublicKey,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = self.page_offset();
        let draft = self
            .container
            .draft_owner_change_to_key(to, offset_ms)
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        let transfer_bytes = draft.transfer_bytes().map_err(|e| Answer::Refused {
            reason: format!("the transfer seal does not encode: {e}"),
        })?;
        let (mut write, need) = self.seal_draft(draft)?;
        if let Some(bytes) = transfer_bytes {
            self.sign_transfer_seal(&mut write, &bytes)?;
        }
        Ok((Some(write), need))
    }

    /// The transfer seal of a change of owner (`journal::check_transfer_seal`):
    /// the agent through both halves, the owner, and the arriving owner —
    /// who signs from outside as the buyer — over the transfer seal's bytes,
    /// as the stand's `seal_draft` does. Any of them may be missing: the
    /// answer asks for it and the repeat finds it.
    fn sign_transfer_seal(&mut self, write: &mut JournalWrite, bytes: &[u8]) -> Result<(), Answer> {
        let mut sigs = self.sign_client(bytes)?;
        sigs.push(self.sign_owner(bytes)?);
        sigs.push(self.sign_external(bytes, Role::Buyer)?);
        if let JournalWrite::Record { sealing, .. } = write {
            sealing.transfer = Some(SignatureSet::new(sigs));
        }
        Ok(())
    }

    /// The page of a coupling (CH-12; `[р]` 31.10 «ок А», С10).
    fn coupling_page(
        &mut self,
        record: ksg_core_v2::journal::CouplingRecord,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = self.page_offset();
        let draft = self
            .container
            .draft_coupling(record, offset_ms)
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        self.seal_draft(draft).map(|(w, n)| (Some(w), n))
    }

    /// A record whose page names its content type (E-8; `[р]` 31.10 «А»).
    fn typed_page(
        &mut self,
        kind: RecordKind,
        content: Piece,
        content_type: Uri,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let offset_ms = self.page_offset();
        let draft = self
            .container
            .draft_record(
                vec![content],
                RecordMeta {
                    kind,
                    content_type: Some(content_type),
                    ..RecordMeta::default()
                },
                offset_ms,
            )
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        self.seal_draft(draft).map(|(w, n)| (Some(w), n))
    }

    /// "This party's signature is needed over exactly these bytes."
    fn missing(&self, party: Party, bytes: &[u8]) -> Answer {
        Answer::NeedsSignature {
            party: party.name().into(),
            bytes: bytes.to_vec(),
        }
    }

    /// The signatures a command's event carries.
    fn sign_all(&mut self, msg: &[u8], who: &[Party]) -> Result<SignatureSet, Answer> {
        let mut sigs = Vec::new();
        for party in who {
            match party {
                Party::Client => sigs.extend(self.sign_client(msg)?),
                Party::Owner => sigs.push(self.sign_owner(msg)?),
                Party::External(role) => sigs.push(self.sign_external(msg, *role)?),
            }
        }
        Ok(SignatureSet::new(sigs))
    }

    /// Presses one of the three buttons: the event, its signatures, the page,
    /// the status record — all in memory.
    ///
    /// In Pro the press goes in with placeholder anchors and queues what the
    /// network owes, oldest first — a seal before its status record — and
    /// answers the head of the queue instead of `Ok`. Light and bare press
    /// with their local anchor or none and never queue: `Ok`, as before.
    fn press(
        &mut self,
        op: Operation,
        who: &[Party],
        evidence: &Evidence,
        page: PageToWrite,
    ) -> Result<(), Answer> {
        let mut event = Event {
            op,
            button: op.button(),
            container: *self.container.id(),
            payload: Wrapped::received(b"wrapped in the capsule".to_vec()),
            signatures: SignatureSet::default(),
            covered: Vec::new(),
            head: self.container.head(),
        };
        event.covered = event.subject();
        let covered = event.covered.clone();
        match self.sign_all(&covered, who) {
            Ok(sigs) => {
                event.signatures = sigs;
            }
            Err(needs) => {
                // The press stays open, the offsets stay ticked: a repeat
                // re-signs the same bytes (I6b). A refusal drops them — its
                // press wrote nothing and opens fresh next time.
                if !Self::is_wait_answer(&needs) {
                    self.press_offsets = PressOffsets::default();
                }
                return Err(needs);
            }
        }
        let (page, page_need) = match self.opening_page_or(page) {
            Ok(w) => w,
            Err(needs) => {
                if !Self::is_wait_answer(&needs) {
                    self.press_offsets = PressOffsets::default();
                }
                return Err(needs);
            }
        };
        let (status, status_need) = match self.status_record(op) {
            Ok(w) => w,
            Err(needs) => {
                if !Self::is_wait_answer(&needs) {
                    self.press_offsets = PressOffsets::default();
                }
                return Err(needs);
            }
        };
        let keys = self.container.roster().keys().clone();
        let at_ms = Some(self.clock_ms);
        self.container
            .press(
                &event,
                evidence,
                Writes {
                    page,
                    status,
                    at_ms,
                },
                &keys,
                &Profile::default(),
            )
            .map_err(|e| Answer::Refused {
                reason: format!("refused: {e}"),
            })?;
        self.press_offsets = PressOffsets::default();
        self.pending_client_sigs.clear();
        // The opening's offset went in with the press (see
        // `Session::opening_page`): a later opening ticks fresh.
        if !self.pending_opening {
            self.pending_open_offset = None;
        }
        if self.container.is_pro() {
            if let Some(need) = page_need {
                self.pending_anchors.push_back(need);
            }
            if let Some(need) = status_need {
                self.pending_anchors.push_back(need);
            }
            if let Some(head) = self.pending_anchors.front() {
                return Err(head.answer());
            }
        }
        Ok(())
    }

    /// A `Needs*` answer that waits for the reader — the press stays open, a
    /// repeated command resumes it — rather than a refusal, which drops it.
    fn is_wait_answer(answer: &Answer) -> bool {
        matches!(
            answer,
            Answer::NeedsClientCommit { .. }
                | Answer::NeedsShare { .. }
                | Answer::NeedsSignature { .. }
                | Answer::NeedsAnchor { .. }
        )
    }

    /// The page a command writes: page 0 through its own co-seal round trip,
    /// a record through the draft's seal — and what its seal owes the
    /// network, when it owes any.
    fn opening_page_or(
        &mut self,
        spec: PageToWrite,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        match spec {
            PageToWrite::Opening => self.opening_page(),
            _ => self.page(spec),
        }
    }

    /// The page a command writes, sealed the way its parties do (CH-29) — and
    /// what its seal owes the network, when it owes any.
    fn page(
        &mut self,
        spec: PageToWrite,
    ) -> Result<(Option<JournalWrite>, Option<AnchorNeed>), Answer> {
        let (kind, content) = match spec {
            PageToWrite::None => return Ok((None, None)),
            PageToWrite::Opening => {
                return Err(Answer::Refused {
                    reason: "the opening goes through its own co-seal round trip".into(),
                })
            }
            PageToWrite::Record(kind, content) => (kind, content),
            PageToWrite::Form(to) => return self.form_page(to),
            PageToWrite::Rule(rule) => return self.rule_page(rule),
            PageToWrite::Typed(kind, content, content_type) => {
                return self.typed_page(kind, content, content_type)
            }
            PageToWrite::OwnerChange(to) => return self.owner_change_page(&to),
            PageToWrite::Coupling(record) => return self.coupling_page(record),
        };
        // A repeated command reuses the offsets its open press ticked (I6b):
        // the draft — and the seal bytes the wire round signs — stays the
        // same, so the closed round is picked up instead of a new one.
        let offset_ms = match self.press_offsets.page_offsets.pop() {
            Some(ticked) => {
                self.press_offsets.page_offsets.push(ticked);
                ticked
            }
            None => {
                let ticked = self.tick();
                self.press_offsets.page_offsets.push(ticked);
                ticked
            }
        };
        let draft = self
            .container
            .draft_record(
                vec![content],
                RecordMeta {
                    kind,
                    ..RecordMeta::default()
                },
                offset_ms,
            )
            .map_err(|e| Answer::Refused {
                reason: format!("the page is not drafted: {e}"),
            })?;
        self.seal_draft(draft).map(|(w, n)| (Some(w), n))
    }

    /// Seals a drafted record: the client's seal through both halves, the
    /// owner's where the journal asks (CH-29), the placeholder anchor in Pro.
    ///
    /// The anchor's need goes back with the write: in Pro the press queues it
    /// and answers [`Answer::NeedsAnchor`], and the reader's
    /// [`Request::Reanchor`] swaps the placeholder for the network's
    /// attestation.
    fn seal_draft(&mut self, draft: Draft) -> Result<(JournalWrite, Option<AnchorNeed>), Answer> {
        let bytes = draft.seal_bytes().map_err(|e| Answer::Refused {
            reason: format!("the seal does not encode: {e}"),
        })?;
        let hash = draft.seal_hash().map_err(|e| Answer::Refused {
            reason: format!("the seal does not hash: {e}"),
        })?;
        let mut sealing = Sealing {
            seal: SignatureSet::new(self.sign_client(&bytes)?),
            ..Sealing::default()
        };
        if draft.needs_owner() {
            sealing.owner = Some(SignatureSet::new(vec![self.sign_owner(&bytes)?]));
        }
        let need = draft.is_pro().then(|| AnchorNeed {
            kind: AnchorKind::Seal,
            prev: draft.seal().prev.unwrap_or(*self.container.id()),
            subject: hash,
        });
        if need.is_some() {
            sealing.anchor = Some(local_anchor(hash));
        }
        Ok((
            JournalWrite::Record {
                draft: Box::new(draft),
                sealing: Box::new(sealing),
            },
            need,
        ))
    }

    /// The status record of a move, if the operation moves the status at all —
    /// and what it owes the network, when it owes any.
    ///
    /// The container checks the record against the keys it pinned, not against
    /// a role: this module has no issuer's seed, so the session's own key
    /// signs here (the reader on the stand signs with the issuer's).
    fn status_record(&mut self, op: Operation) -> Result<StatusWrite, Answer> {
        let Some(event) = op.event() else {
            return Ok((None, None));
        };
        let Outcome::Moves(next) = transition_for(
            self.container.class(),
            self.container.status(),
            self.container.blocked(),
            event,
        ) else {
            return Ok((None, None));
        };
        let mut record = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: self.container.status_records() as u64,
            status: next,
            event: Some(event),
            // A repeated command reuses the offsets its open press ticked
            // (I6b) — see `Session::page`.
            offset_ms: match self.press_offsets.status_offsets.pop() {
                Some(ticked) => {
                    self.press_offsets.status_offsets.push(ticked);
                    ticked
                }
                None => {
                    let ticked = self.tick();
                    self.press_offsets.status_offsets.push(ticked);
                    ticked
                }
            },
            prev: self.container.status_head(),
            signatures: SignatureSet::default(),
        };
        let bytes = canonical_bytes(&record).map_err(|e| Answer::Refused {
            reason: format!("the status record does not encode: {e}"),
        })?;
        // The client's session signs through its halves — over the wire
        // when the half is outside (I4g: no half inside, the status move
        // answers `NeedsClientCommit` like `Work`); the owner's session
        // with its key, as before.
        // Before initiation the status records are the issuer's word (the
        // sale — E-2, E-3; `Spec_kapsula` §19): the issuer holds no map, so
        // its signature comes from outside (§20). The initiation's own record
        // is signed as before.
        record.signatures = if !self.container.born() && op != Operation::Initiate {
            SignatureSet::new(vec![self.sign_external(&bytes, Role::Issuer)?])
        } else if self.mobile.is_some() || self.owner.is_none() {
            SignatureSet::new(self.sign_client(&bytes)?)
        } else {
            SignatureSet::new(vec![self.sign_owner(&bytes)?])
        };
        let hash = record.hash().map_err(|e| Answer::Refused {
            reason: format!("the status record does not hash: {e}"),
        })?;
        let need = AnchorNeed {
            kind: AnchorKind::Status,
            prev: record.prev,
            subject: hash,
        };
        Ok((Some((record, local_anchor(hash))), Some(need)))
    }

    /// Offsets are milliseconds since issuance and grow strictly, even when
    /// the wall clock does not (`Reader::tick`).
    fn tick(&mut self) -> u64 {
        let elapsed = now_ms().saturating_sub(self.issued_ms);
        self.clock_ms = elapsed.max(self.clock_ms.saturating_add(1));
        self.clock_ms
    }
}

/// A client signature round waiting for the mobile side.
///
/// The message is what both halves sign; the commitment is the mobile side's
/// half of the round the container opened. `ClientShare` checks the share
/// against both, then the round is dropped — nonces are used once.
#[derive(Debug)]
struct ClientRound {
    /// What both halves sign.
    msg: Vec<u8>,
    /// The mobile side's commitment the container opened the round with.
    #[allow(dead_code)]
    commitment: Commitment,
    /// The container's answer: the package the mobile side signs.
    round: SigningRound,
}

/// A session's close: the shared secrets part, the code, the state, the parts
/// this map does not rewrite (`capsule::seal_into_capsule`).
#[allow(clippy::too_many_arguments)]
fn seal_parts(
    state: &[u8],
    state_key: &StateKey,
    template: Hash,
    artifact: &str,
    client: &str,
    issued_ms: u64,
    clock_ms: u64,
    code: &[u8],
    parts: &[Part],
    maps: &[(MapRole, SealTo)],
    fill: &mut dyn FnMut(&mut [u8]),
) -> Result<Vec<u8>, String> {
    capsule::seal_into_capsule(
        state,
        state_key.bytes(),
        &template.to_multihash(),
        artifact,
        client,
        issued_ms,
        clock_ms,
        code,
        parts,
        maps,
        fill,
    )
    .map_err(|e| format!("the capsule does not assemble: {e}"))
}

/// The expert's road through the session (`Spec_kapsula` §23, C7).
impl Session {
    /// `AppointExpert`: one page naming the expert, through the existing
    /// typed page (`PageToWrite::Typed`) — the core wants a `Body::Content`
    /// of type `EXPERT_ENTRY_PAGE` carrying the entry's digest.
    fn appoint_expert(&mut self, entry: &ExpertEntry) -> Answer {
        self.awaiting_owner = None;
        // The side that is here signs: the client where the mobile half is,
        // else the owner (the same choice as `export_page`).
        // A wire session holds no half either: its client's round comes over
        // the wire.
        let party = if self.mobile.is_none() && self.owner.is_some() {
            Party::Owner
        } else {
            Party::Client
        };
        let content_type = match Uri::parse(EXPERT_ENTRY_PAGE.to_owned()) {
            Ok(u) => u,
            Err(e) => return Answer::Refused { reason: format!("page type: {e}") },
        };
        let pieces = match entry_pieces(entry) {
            Ok(p) => p,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the entry does not encode: {e:?}"),
                }
            }
        };
        let [digest, _] = pieces;
        // `Work`: the kind the core's check admits here (it asks no owner's
        // seal in Pro, as the stand's `name_in_journal`).
        let page = PageToWrite::Typed(RecordKind::Work, digest, content_type);
        self.holder_op(
            Operation::AppointExpert,
            &[party],
            &Evidence::ExpertNamed(Box::new(entry.clone())),
            page,
        )
    }

    /// `DiscloseToExpert`: the client and the owner; the pages the container
    /// hands out go to `outputs`.
    fn disclose_to_expert(
        &mut self,
        entry: Box<ExpertEntry>,
        record: Box<ExpertRecord>,
        record_anchor: Box<Attestation>,
        disclosure: Box<ExpertDisclosure>,
    ) -> Answer {
        self.awaiting_owner = None;
        let evidence = Evidence::Disclose {
            entry,
            record,
            record_anchor,
            disclosure,
        };
        if let Err(answer) = self.press(
            Operation::DiscloseToExpert,
            &[Party::Client, Party::Owner],
            &evidence,
            PageToWrite::None,
        ) {
            return self.note_owner_wait(answer);
        }
        let Some(pages) = self.container.take_disclosure() else {
            return Answer::Refused {
                reason: "no pages handed out".into(),
            };
        };
        match serde_json::to_vec(&pages) {
            Ok(bytes) => {
                self.outputs.push(bytes.clone());
                Answer::Done { bytes }
            }
            Err(e) => Answer::Refused {
                reason: format!("the disclosure does not serialize: {e}"),
            },
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // The halves wipe themselves; the state key and the owner key wipe
        // through their own `Drop` — in one place a reader can point at.
        // No manual loop over memory here: a copy the loop did not see
        // would live on, while `ZeroizeOnDrop` covers the fields.
    }
}

/// The parties a command's signature set may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Party {
    /// The agent-client, through both halves of its split key.
    Client,
    /// The owner-holder, with its own key.
    Owner,
    /// A party that holds no map — the issuer, an arbiter, the former
    /// client, a sub-agent (`Spec_kapsula` §20): its signature comes from
    /// outside through [`Answer::NeedsSignature`] and [`Request::Sign`].
    External(Role),
}

impl Party {
    /// The name an [`Answer::NeedsSignature`] carries.
    const fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Owner => "owner",
            Self::External(role) => match role {
                Role::Issuer => "issuer",
                Role::Owner => "owner",
                Role::Client => "client",
                Role::SubAgent => "sub-agent",
                Role::Buyer => "buyer",
                Role::Orchestrator => "orchestrator",
                Role::Arbiter => "arbiter",
                Role::Claimant => "claimant",
                Role::Distributor => "distributor",
                Role::FormerClient => "former-client",
            },
        }
    }
}

/// A placeholder attestation, made by the capsule itself: no network accepts
/// it, and the reader replaces it through [`Request::Reanchor`].
fn local_anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: Uri::parse(LOCAL_ANCHOR).expect("the local anchor kind is a URI"),
        subject,
        proof: b"local".to_vec(),
        anchored_at: Timestamp::from_unix_ms(now_ms())
            .unwrap_or_else(|_| Timestamp::from_unix_ms(0).expect("the epoch is a moment")),
    }
}

/// Whether the slot a map opened belongs to the party whose file this is.
const fn slot_matches(slot: MapRole, side: SideRole) -> bool {
    matches!(
        (slot, side),
        (MapRole::Client, SideRole::Client)
            | (MapRole::Owner, SideRole::Owner)
            | (MapRole::Holder, _)
    )
}

/// The slot's role, for a refusal's words.
const fn slot_name(role: MapRole) -> &'static str {
    match role {
        MapRole::Holder => "holder",
        MapRole::Client => "client",
        MapRole::Owner => "owner",
    }
}

/// The side file's role, for a refusal's words.
const fn side_role_name(role: SideRole) -> &'static str {
    match role {
        SideRole::Client => "client",
        SideRole::Owner => "owner",
    }
}

/// The owner's signing key from the side file's seed.
///
/// The key's identifier is not in the file: the container's roster pins it, so
/// the roster is where it comes from — and a seed that yields another key than
/// the pinned one is refused rather than used.
fn open_owner(container: &Container, half: &str) -> Result<OwnerKey, String> {
    let pinned = container
        .roster()
        .holder(Role::Owner)
        .ok_or("side file: the capsule's roster names no owner")?
        .clone();
    let seed = decode_32(half, "side file: half")?;
    let signer = Ed25519Signer::from_seed(pinned.kid.clone(), seed);
    if signer.public() != pinned {
        return Err("side file: the half is not the owner's key the roster pinned".into());
    }
    Ok(OwnerKey::from_seed(signer, seed))
}

/// A map rebuilt from its public halves, for re-sealing its slot.
fn map_from(map: &MapPub) -> Result<(MapRole, SealTo), String> {
    let role = match map.role.as_str() {
        "holder" => MapRole::Holder,
        "client" => MapRole::Client,
        "owner" => MapRole::Owner,
        other => return Err(format!("shared secrets: unknown map role {other}")),
    };
    let x25519 = decode_32(&map.x25519, "shared secrets: map x25519")?;
    let mlkem: Vec<u8> = B64
        .decode(&map.mlkem)
        .map_err(|_| "shared secrets: map mlkem is not base64url".to_string())?;
    let mlkem: [u8; MLKEM_EK_LEN] = mlkem
        .try_into()
        .map_err(|_| "shared secrets: map mlkem is not an encapsulation key".to_string())?;
    let seal = SealTo::new(x25519_dalek::PublicKey::from(x25519), mlkem)
        .map_err(|e| format!("shared secrets: map mlkem: {e}"))?;
    Ok((role, seal))
}

/// 32 bytes of base64url.
fn decode_32(value: &str, what: &str) -> Result<[u8; 32], String> {
    let bytes = B64
        .decode(value)
        .map_err(|_| format!("{what}: not base64url"))?;
    bytes
        .try_into()
        .map_err(|_| format!("{what}: not 32 bytes"))
}

/// Base64url without padding, for the bytes of the wire format.
mod b64 {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    use serde::{Deserialize as _, Deserializer, Serializer};

    /// Encodes as one base64url string.
    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    /// Decodes one base64url string.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s).map_err(serde::de::Error::custom)
    }
}
