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
use ksg_container_v2::capsule::{self, MapRole, Part, PartKind};
use ksg_container_v2::client_key::{share_commitment, MobileHalf};
use ksg_container_v2::container::{Container, Evidence, JournalWrite, Writes};
use ksg_container_v2::layers::{OpenWith, SealTo, MLKEM_EK_LEN};
use ksg_container_v2::{Event, Operation, Role, Where, Work, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::canonical_bytes;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{Ed25519Signer, Profile, Signature, SignatureSet};
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
    Initiate,
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
}

/// What a request answers.
///
/// On the wire a word `"answer"` names the case: `{"answer":"done","bytes":…}`,
/// `{"answer":"needs_signature","party":"owner","bytes":…}`,
/// `{"answer":"needs_anchor","bytes":…}`, `{"answer":"refused","reason":…}`.
/// Every byte string is base64url without padding.
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
    /// [`Request::Reanchor`] with the attestation.
    NeedsAnchor {
        /// The memo, as the reader's anchorer reads it.
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

/// The `SharedSecrets` part: what both maps must read to carry the capsule on.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Shared {
    /// Version of this layout.
    v: u32,
    /// The key the container's state is sealed under, base64url (32 bytes).
    state_key: String,
    /// The container's template identifier, as a multihash.
    template: String,
    /// The artefact the container was initiated on.
    artifact: String,
    /// The client's key identifier, for the birth (E-4).
    client: String,
    /// The wall clock of the issuance, milliseconds since the Unix epoch:
    /// the offsets in the journal run from it.
    issued_ms: u64,
    /// The greatest offset already used: offsets grow strictly, even when the
    /// wall clock does not.
    clock_ms: u64,
    /// Every map the capsule seals to, in slot order (`Spec_kapsula` §10 п. 2).
    maps: Vec<MapPub>,
}

/// One map's public halves, enough to re-seal its slot.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct MapPub {
    /// `holder`, `client` or `owner`.
    role: String,
    /// The X25519 public half, base64url (32 bytes).
    x25519: String,
    /// The ML-KEM-768 encapsulation key, base64url.
    mlkem: String,
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

        let mobile = if side.half.is_empty() {
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
    /// | [`Request::Initiate`] | `{"container": "<multihash>", "mobile_half": "<base64url>", "share_commitment": "<base64url>"}` |
    /// | [`Request::Reanchor`] | empty |
    pub fn call(&mut self, request: Request) -> Answer {
        match request {
            Request::Status => Answer::Done {
                bytes: serde_json::to_vec(&self.status_json()).unwrap_or_default(),
            },
            Request::Keys => self.keys(),
            Request::Work { text } => self.work(&text),
            Request::ExportPage { number } => self.export_page(number),
            Request::Initiate => self.initiate(),
            Request::Reanchor { attestation } => self.reanchor(&attestation),
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
    /// birth is never stored, so it must not be dropped); the capsule seals to
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
        let shared = Shared {
            v: 1,
            state_key: B64.encode(self.state_key.as_ref()),
            template: self.template.to_multihash(),
            artifact: self.artifact.as_str().to_string(),
            client: self.client_kid.as_str().to_string(),
            issued_ms: self.issued_ms,
            clock_ms: self.clock_ms,
            maps: self
                .maps
                .iter()
                .map(|(role, map)| MapPub {
                    role: map_role_name(*role).to_string(),
                    x25519: B64.encode(map.public().as_bytes()),
                    mlkem: B64.encode(map.mlkem()),
                })
                .collect(),
        };
        let shared = serde_json::to_vec(&shared).map_err(|e| format!("shared secrets: {e}"))?;
        let mut parts = self.parts.clone();
        parts.push(Part {
            kind: PartKind::Code,
            bytes: self.code.clone(),
        });
        parts.push(Part {
            kind: PartKind::State,
            bytes: state,
        });
        parts.push(Part {
            kind: PartKind::SharedSecrets,
            bytes: shared,
        });
        let mut fill = |out: &mut [u8]| rng.fill_bytes(out);
        let capsule = capsule::assemble(&parts, &self.maps, &mut fill)
            .map_err(|e| format!("the capsule does not assemble: {e}"))?;
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
            Some((RecordKind::Work, Piece::Inline(text.as_bytes().to_vec()))),
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
            None,
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
        let (mobile, public, fin) = match keygen.finish(&reply) {
            Ok(x) => x,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the mobile side keeps no half: {e}"),
                };
            }
        };
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
        let share = match mobile.share_public() {
            Ok(s) => s,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the half has no public share: {e}"),
                };
            }
        };
        // E-19: the commitment to the mobile half — the reader anchors it.
        let commitment = share_commitment(&share);
        let half = match mobile.to_bytes() {
            Ok(b) => b,
            Err(e) => {
                self.container.cancel_birth();
                return Answer::Refused {
                    reason: format!("the half does not encode: {e}"),
                };
            }
        };
        self.mobile = Some(mobile);
        self.pending_birth = true;
        let pressed = self.press(
            Operation::Initiate,
            &[Party::Client, Party::Owner],
            &Evidence::Initiation { at: Where::Inside },
            None,
        );
        match pressed {
            Ok(()) => {
                self.pending_birth = false;
                self.outputs.push(half.to_vec());
                let owned = self.owner.is_some();
                if owned {
                    // The owner pressed the initiation: the client's half is
                    // the client's, and this session forgets it at once.
                    self.mobile = None;
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
            Err(Answer::NeedsSignature { bytes, .. }) => {
                self.pending_bytes = bytes;
                Answer::NeedsSignature {
                    party: Party::Owner.name().into(),
                    bytes: self.pending_bytes.clone(),
                }
            }
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

    /// The network's attestation in place of a placeholder.
    fn reanchor(&mut self, raw: &[u8]) -> Answer {
        let attestation: Attestation = match serde_json::from_slice(raw) {
            Ok(a) => a,
            Err(e) => {
                return Answer::Refused {
                    reason: format!("the attestation does not read: {e}"),
                }
            }
        };
        match self.apply_anchor(attestation) {
            Ok(()) => Answer::Done { bytes: Vec::new() },
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

    /// The owner signs with its own key.
    fn sign_owner(&self, msg: &[u8]) -> Result<Signature, Answer> {
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
    fn press(
        &mut self,
        op: Operation,
        who: &[Party],
        evidence: &Evidence,
        page: Option<(RecordKind, Piece)>,
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
        let page = self.page(page)?;
        let status = self.status_record(op)?;
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
        Ok(())
    }

    /// The page a command writes, sealed the way its parties do (CH-29).
    fn page(&mut self, spec: Option<(RecordKind, Piece)>) -> Result<Option<JournalWrite>, Answer> {
        let Some((kind, content)) = spec else {
            return Ok(None);
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
        self.seal_draft(draft).map(Some)
    }

    /// Seals a drafted record: the client's seal through both halves, the
    /// owner's where the journal asks (CH-29), the placeholder anchor in Pro.
    fn seal_draft(&mut self, draft: Draft) -> Result<JournalWrite, Answer> {
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
        if draft.is_pro() {
            sealing.anchor = Some(local_anchor(hash));
        }
        Ok(JournalWrite::Record {
            draft: Box::new(draft),
            sealing: Box::new(sealing),
        })
    }

    /// The status record of a move, if the operation moves the status at all.
    ///
    /// The container checks the record against the keys it pinned, not against
    /// a role: this module has no issuer's seed, so the session's own key
    /// signs here (the reader on the stand signs with the issuer's).
    fn status_record(
        &mut self,
        op: Operation,
    ) -> Result<Option<(StatusRecord, Attestation)>, Answer> {
        let Some(event) = op.event() else {
            return Ok(None);
        };
        let Outcome::Moves(next) = transition_for(
            self.container.class(),
            self.container.status(),
            self.container.blocked(),
            event,
        ) else {
            return Ok(None);
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
        Ok(Some((record, local_anchor(hash))))
    }

    /// Offsets are milliseconds since issuance and grow strictly, even when
    /// the wall clock does not (`Reader::tick`).
    fn tick(&mut self) -> u64 {
        let elapsed = now_ms().saturating_sub(self.issued_ms);
        self.clock_ms = elapsed.max(self.clock_ms.saturating_add(1));
        self.clock_ms
    }
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

/// A map's role as [`Shared`] spells it.
const fn map_role_name(role: MapRole) -> &'static str {
    match role {
        MapRole::Holder => "holder",
        MapRole::Client => "client",
        MapRole::Owner => "owner",
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
