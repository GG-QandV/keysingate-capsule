//! A session of presses over one opened capsule (`Spec_kapsula` §10 п. 3).
//! Nothing is written unless the session closes: a refusal leaves the capsule
//! as it was (§14 Б-6).
//!
//! # Why a session and not one call (Л-1)
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
//! | `ClientSecrets`, `OwnerSecrets` | carried through untouched |
//! | `SharedSecrets` | [`Shared`]: the state key, the template's hash, the artefact, the clock, the maps' public halves |
//!
//! The state key and the maps' **public** halves live in `SharedSecrets`
//! because both maps open that part, and both are needed to re-assemble the
//! capsule (`Spec_kapsula` §10 п. 1, п. 2). No secret of a party is there.
//!
//! # What this module does not do
//!
//! The network. An anchor the container owes is the reader's work, and
//! [`Answer::NeedsAnchor`] is how the module asks for it. Nor does the module
//! press the commands of §5а (a command signed by a party that holds no map):
//! that queue is post-hackathon (`TODO_na_potom.md#Т2-5`); an `anchored` entry
//! this module cannot read is an error at [`Session::open`], never a silent skip.

#[cfg(not(target_arch = "wasm32"))]
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::capsule::{self, MapPub, MapRole, Part, PartKind, Shared};
use ksg_container_v2::client_key::{share_commitment, MobileHalf};
use ksg_container_v2::container::{Container, Evidence, JournalWrite, Writes};
use ksg_container_v2::layers::{OpenWith, SealTo, MLKEM_EK_LEN};
use ksg_container_v2::{Event, Operation, Role, Where, Work, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, PublicKey, Signature, SignatureSet};
use ksg_core_v2::doc::{Timestamp, Uri};
use ksg_core_v2::journal::{Draft, Piece, RecordKind, RecordMeta, Sealing};
use ksg_core_v2::section::StatusRecord;
use ksg_core_v2::status::{transition_for, Outcome};
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

/// The anchor kind of a record this module presses offline. No network
/// accepts it (`ksg-verify-v2` says so by name); the reader's anchor replaces
/// it through [`Session::call`] with [`Request::Reanchor`].
pub const LOCAL_ANCHOR: &str = "urn:ksg:anchor:local:v1";

/// A request at the panel's level (§13, §12 Л-2): the five commands of the
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
    /// Stand-only path: both halves are born inside the module (demo). The
    /// product splits the birth: `BeginBirth` / `FinishBirth`.
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
    /// The other party's signature over exactly the bytes a
    /// [`Answer::NeedsSignature`] handed out (Л-1: signatures are the
    /// reader's work). The JSON of a `ksg_core_v2::crypto::sign::Signature`;
    /// the container checks it when the pending command is pressed.
    Sign {
        /// The signature's JSON.
        signature: Vec<u8>,
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
    /// The module needs a party's signature over these bytes (§14 Б-3).
    NeedsSignature {
        /// Which party: `client` or `owner`.
        party: String,
        /// What it signs — the exact bytes the container will check.
        #[serde(with = "b64")]
        bytes: Vec<u8>,
    },
    /// Refused; nothing is written.
    Refused {
        /// Why, in the container's or the module's own words.
        reason: String,
    },
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
}

/// One opened capsule with the container in memory: one session per module
/// instance (`Spec_kapsula` §10 п. 3).
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
    /// The key the container's state is sealed under.
    state_key: Zeroizing<[u8; 32]>,
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
    /// The owner's key, when the side file is the owner's.
    owner: Option<Ed25519Signer>,
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
    /// `anchored` is what the reader read from the network (§5а) — each entry
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
        let (slot_role, opened) =
            capsule::open(capsule_bytes, &map).map_err(|e| format!("capsule: {e}"))?;
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
        let container = Container::open_sealed(&state, &template, &state_key)
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
        let owner = match side.role {
            SideRole::Owner => Some(open_owner(&container, &side.half)?),
            SideRole::Client => None,
        };

        let mut session = Self {
            container,
            maps,
            state_key: Zeroizing::new(state_key),
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
            pending_opening: false,
            pending_open_bytes: Vec::new(),
            pending_open_offset: None,
            pending_open_owner: None,
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
    /// | [`Request::Initiate`] | `{"container": "<multihash>", "mobile_half": "<base64url>", "share_commitment": "<base64url>"}` (stand-only) |
    /// | [`Request::BeginBirth`] | `{"reply": "<base64url>"}` (message 2 for the mobile side) |
    /// | [`Request::FinishBirth`] | `{"container": "<multihash>"}` |
    /// | [`Request::OpenJournal`] | `{"pages": n, "seal": "<multihash>"}` |
    /// | [`Request::Reanchor`] | the last owed anchor settled: `{"pages", "seal"}`, as the opening's |
    /// | [`Request::Sign`] | the same as the command whose signature was missing |
    pub fn call(&mut self, request: Request) -> Answer {
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
            Request::Sign { signature } => self.sign_pending(&signature),
        }
    }

    /// Closes the session: the new capsule and what the reader must keep
    /// outside it.
    ///
    /// `outputs` are, in order: the client's mobile half after an initiation
    /// (the reader writes it into the side file — without it the client could
    /// never sign again), and every page an export handed out.
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
        if self.maps.len() > 1 {
            return Err(
                "the capsule seals to more than one map: the parts this map does not open (the \
                 other party's secrets) cannot be carried through re-assembly, and losing them \
                 silently is worse than refusing"
                    .into(),
            );
        }
        let mut rng = CspRng;
        let state = self
            .container
            .seal_to_bytes(&self.state_key, &mut rng)
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
            "template": self.template.to_multihash(),
            "class": format!("{:?}", self.container.class()),
            "status": format!("{:?}", self.container.status()),
            "pages": self.container.pages(),
            "top_seal": self.container.top_seal_hash().map(|h| h.to_multihash()),
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

    /// E-5: one record of work, sealed by the client's two halves.
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
    /// The birth is three messages between two sides; both run here, because
    /// the capsule is the only place that holds the container's half and the
    /// session may hold the other. The signature set is the client's **and**
    /// the owner's (`Operation::Initiate`), so a session that is only the
    /// client's answers [`Answer::NeedsSignature`] with the bytes the owner
    /// signs, and keeps the birth in memory until it is pressed or the session
    /// closes (a close refuses: a birth is never stored).
    fn initiate(&mut self) -> Answer {
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
        // Г-1: the client agent is named by the `did:key` of the group key it
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
        // No mobile half inside: the client signs through the round of И4, so
        // a `NeedsSignature { party: client }` here is the bridge, not an error.
        let pressed = self.press(
            Operation::Initiate,
            &[Party::Client, Party::Owner],
            &Evidence::Initiation { at: Where::Inside },
            PageToWrite::None,
        );
        match pressed {
            Ok(()) => self.finish_birth_done(id),
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
    /// The birth queue clears; the client round of И4 answers the pending
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

    /// The bookkeeping of a pressed birth: the client's half goes to the
    /// reader, and the session forgets it when the owner's file is the one
    /// that pressed (the half is the client's).
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
        let commitment = share_commitment(&share);
        let half = match mobile.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the half does not encode: {e}"),
                };
            }
        };
        self.pending_birth = false;
        self.pending_owner = None;
        self.outputs.push(half.to_vec());
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
                "mobile_half": B64.encode(half.as_slice()),
                "share_commitment": B64.encode(commitment),
            })
            .to_string()
            .into_bytes(),
        }
    }

    /// E-5: the journal opens — page 0, sealed by the client's two halves.
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
        let seal = self.sign_client(&bytes)?;
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
    /// handed out: the pending command is pressed with it (Л-1 — the
    /// signature is made outside the module, the check is inside). An
    /// initiation's birth and a Pro opening's co-seal never wait together: a
    /// birth is made before the container is born, an opening after.
    fn sign_pending(&mut self, raw: &[u8]) -> Answer {
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
    /// capsule model keeps both halves in one process for the demo (Л-10).
    fn sign_client(&mut self, msg: &[u8]) -> Result<Vec<Signature>, Answer> {
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

    /// The owner signs with its own key — or, while a command waits for the
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
        match &self.owner {
            Some(signer) => Ok(signer.sign(msg)),
            None => Err(self.missing(Party::Owner, msg)),
        }
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
        event.signatures = self.sign_all(&covered, who)?;
        let (page, page_need) = self.opening_page_or(page)?;
        let (status, status_need) = self.status_record(op)?;
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
        };
        let offset_ms = self.tick();
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
            offset_ms: self.tick(),
            prev: self.container.status_head(),
            signatures: SignatureSet::default(),
        };
        let bytes = canonical_bytes(&record).map_err(|e| Answer::Refused {
            reason: format!("the status record does not encode: {e}"),
        })?;
        record.signatures = if self.mobile.is_some() {
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

/// A session's close: the shared secrets part, the code, the state, the parts
/// this map does not rewrite (`capsule::seal_into_capsule`).
#[allow(clippy::too_many_arguments)]
fn seal_parts(
    state: &[u8],
    state_key: &[u8; 32],
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
        state_key,
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

impl Drop for Session {
    fn drop(&mut self) {
        // The halves wipe themselves; the state key goes here, in one place a
        // reader can point at.
        self.state_key.zeroize();
    }
}

/// The parties a command's signature set may name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Party {
    /// The agent-client, through both halves of its split key.
    Client,
    /// The owner-holder, with its own key.
    Owner,
}

impl Party {
    /// The name an [`Answer::NeedsSignature`] carries.
    const fn name(self) -> &'static str {
        match self {
            Self::Client => "client",
            Self::Owner => "owner",
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
fn open_owner(container: &Container, half: &str) -> Result<Ed25519Signer, String> {
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
    Ok(signer)
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
