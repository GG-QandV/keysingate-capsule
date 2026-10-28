//! The tests' stand: a container of the light class, initiated, its journal
//! open, and a capsule around it — assembled the way the reader will.
//!
//! It is deliberately small: only what the session's criteria need. Every
//! press goes through [`Container::press`] (the three buttons), as on the
//! crate's own stand.

#![allow(dead_code)]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::capsule::{self, MapRole, Part, PartKind};
use ksg_container_v2::client_key::{split, MobileHalf};
use ksg_container_v2::container::{Container, Evidence, JournalWrite, Release, Writes};
use ksg_container_v2::followup::{Discharge, Proof, Task};
use ksg_container_v2::layers::{Level, OpenWith};
use ksg_container_v2::{Event, Operation, Role, Roster, Where, Wrapped};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{derive_container_id, Class, MemoFormat, Serial, Timestamp, Uri};
use ksg_core_v2::journal::Sealing;
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::{transition_for, Outcome, Status};
use rand_core::{CryptoRng, Error as RngError, RngCore};

/// The emission every test container belongs to.
pub const EMISSION: &str = "ksg:em:000001";
/// The serial every test container occupies.
pub const SERIAL: Serial = Serial(7);
/// The artefact initiation binds.
pub const ARTIFACT: &str = "ksg:artifact:the-one";
/// The offset initiation records.
pub const OFFSET: u64 = 1_000;

/// A deterministic generator for the tests only: splitmix64. Its quality is
/// irrelevant — what the tests check is the session, not the keys.
pub struct TestRng(pub u64);

impl TestRng {
    fn next_byte_block(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl RngCore for TestRng {
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
        self.next_byte_block(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RngError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}

/// A URI, or a panic: a test's literals are URIs.
pub fn uri(s: &str) -> Uri {
    Uri::parse(s).expect("a uri")
}

/// A moment, or a panic.
pub fn ts(s: &str) -> Timestamp {
    Timestamp::parse(s).expect("a timestamp")
}

/// The client's key identifier.
pub fn client_kid() -> Uri {
    uri("did:key:zAgent#a1")
}

/// A placeholder anchor, as the stand makes it.
pub fn anchor(subject: Hash) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject,
        proof: b"stand".to_vec(),
        anchored_at: ts("2026-09-12T00:00:00.000Z"),
    }
}

/// A network's attestation for a subject named by its multihash — what the
/// reader hands back in through `Reanchor` in the tests. The module checks
/// the subject, not the kind: a test attestation stands in for the network's.
pub fn attestation_for(subject_multihash: &str) -> Attestation {
    Attestation {
        kind: uri("urn:ksg:anchor:test"),
        subject: Hash::from_multihash(subject_multihash).expect("a multihash"),
        proof: b"test".to_vec(),
        anchored_at: ts("2026-09-12T00:00:00.000Z"),
    }
}

/// The parties a test needs: the issuer's word and the owner's signature.
pub struct Parties {
    /// The issuer signs the status records and lays the packet.
    pub issuer: Ed25519Signer,
    /// The owner signs the initiation beside the client.
    pub owner: Ed25519Signer,
    /// The buyer's key takes the third status on the way to initiation.
    pub buyer: Ed25519Signer,
}

impl Parties {
    /// The stand's keys, from fixed seeds.
    #[must_use]
    pub fn new() -> Self {
        Self {
            issuer: Ed25519Signer::from_seed(uri("did:key:zIssuer#i1"), [11; 32]),
            owner: Ed25519Signer::from_seed(uri("did:key:zOwner#o1"), [44; 32]),
            buyer: Ed25519Signer::from_seed(uri("did:key:zBuyer#b1"), [12; 32]),
        }
    }
}

/// A container ready for a session: born, initiated, its journal open.
pub struct Fixture {
    /// The container itself.
    pub container: Container,
    /// The client's mobile half — what the side file carries.
    pub mobile: MobileHalf,
    /// The seed of the client's map.
    pub map_seed: [u8; 32],
    /// The key the container's state is sealed under.
    pub state_key: [u8; 32],
    /// The container's template identifier.
    pub template: Hash,
    /// The clock the journal's offsets run from.
    pub issued_ms: u64,
    /// The greatest offset used by the presses below.
    pub clock_ms: u64,
    /// The parties' keys.
    pub parties: Parties,
    /// The randomness of the stand.
    pub rng: TestRng,
}

impl Fixture {
    /// A light container, initiated, with page 0 written.
    #[must_use]
    pub fn started() -> Self {
        let mut f = Self::printed(Class::Light, Parties::new(), TestRng(7));
        f.press_packet();
        f.press_buyer_key();
        f.press_initiate();
        f.press_opening();
        f
    }

        /// A heavy (Pro) container, initiated, NOT yet opened: `OpenJournal` goes
    /// through the module's own co-seal round trip.
    #[must_use]
    pub fn started_heavy_unopened() -> Self {
        let mut f = Self::printed(Class::Heavy, Parties::new(), TestRng(7));
        f.press_packet();
        f.press_buyer_key();
        f.press_initiate();
        f
    }

    /// A heavy (Pro) container, initiated, with page 0 written: page 0
    /// carries the owner's seal and a placeholder anchor (CH-26), the status
    /// records their placeholder anchors.
    #[must_use]
    pub fn started_heavy() -> Self {
        let mut f = Self::printed(Class::Heavy, Parties::new(), TestRng(7));
        f.press_packet();
        f.press_buyer_key();
        f.press_initiate();
        f.press_opening();
        f
    }

    fn printed(class: Class, parties: Parties, rng: TestRng) -> Self {
        let mut rng = rng;
        let (inside, mobile) = split(client_kid(), &mut rng).expect("the client's key splits");
        let client = inside.public().clone();
        let template = section_root(EMISSION, SERIAL);
        let issued_at = ts("2026-09-01T00:00:00.000Z");
        let id = derive_container_id(
            EMISSION,
            &issued_at,
            SERIAL,
            &client,
            &uri(ARTIFACT),
            OFFSET,
        );

        let mut r0 = StatusRecord {
            context: ksg_core_v2::doc::Context,
            doc_type: "StatusRecord".into(),
            v: 3,
            number: 0,
            status: Status::Printed,
            event: None,
            offset_ms: 0,
            prev: template,
            signatures: SignatureSet::default(),
        };
        r0.signatures = SignatureSet::new(vec![
            sign_doc(&r0, &parties.issuer).expect("the issuer's word")
        ]);
        let a0 = anchor(r0.hash().expect("record 0 hashes"));
        let issuer_keys: KeySet = [parties.issuer.public()].into_iter().collect();
        let section =
            StatusSection::start(EMISSION, SERIAL, r0, a0, &issuer_keys, &Profile::default())
                .expect("the section starts");

        let roster = Roster::of([
            (parties.issuer.public(), Role::Issuer),
            (parties.owner.public(), Role::Owner),
            (parties.buyer.public(), Role::Buyer),
            (client.clone(), Role::Client),
        ]);
        let release = Release {
            id: EMISSION.into(),
            issued_at,
            class,
        };
        let pq = ksg_container_v2::pq_key::ContainerPqKey::generate(
            uri("did:key:zContainer#pq"),
            &mut rng,
        )
        .expect("the container's post-quantum key");
        let mut container = Container::assemble(
            id,
            release,
            SERIAL,
            client,
            MemoFormat::Controlled,
            section,
            roster,
        )
        .with_pq_key(pq);
        container
            .integrate_client_key(inside)
            .expect("the container's half");

        Self {
            container,
            mobile,
            map_seed: [7; 32],
            state_key: [9; 32],
            template,
            issued_ms: 0,
            clock_ms: 50_000,
            parties,
            rng,
        }
    }

    /// The client signs through both halves, as the reader does.
    pub fn client_signs(&mut self, msg: &[u8]) -> Vec<ksg_core_v2::crypto::sign::Signature> {
        let (nonces, commitment) = self.mobile.commit(&mut self.rng);
        let round = self
            .container
            .begin_signing(msg, &commitment, &mut self.rng)
            .expect("the container opens a round");
        let share = self
            .mobile
            .respond(nonces, &round)
            .expect("the mobile half answers");
        self.container
            .finish_signing(&share, &mut self.rng)
            .expect("the round closes")
    }

    fn sign_all(&mut self, msg: &[u8], who: &[Who]) -> SignatureSet {
        let mut sigs = Vec::new();
        for w in who {
            match w {
                Who::Client => sigs.extend(self.client_signs(msg)),
                Who::Issuer => sigs.push(self.parties.issuer.sign(msg)),
                Who::Owner => sigs.push(self.parties.owner.sign(msg)),
                Who::Buyer => sigs.push(self.parties.buyer.sign(msg)),
            }
        }
        SignatureSet::new(sigs)
    }

    fn tick(&mut self) -> u64 {
        self.clock_ms = self.clock_ms.saturating_add(1_000);
        self.clock_ms
    }

    fn status_record(&mut self, op: Operation) -> Option<(StatusRecord, Attestation)> {
        let event = op.event()?;
        let Outcome::Moves(next) = transition_for(
            self.container.class(),
            self.container.status(),
            self.container.blocked(),
            event,
        ) else {
            return None;
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
        record.signatures = SignatureSet::new(vec![
            sign_doc(&record, &self.parties.issuer).expect("a word")
        ]);
        let a = anchor(record.hash().expect("the record hashes"));
        Some((record, a))
    }

    fn press(&mut self, op: Operation, who: &[Who], evidence: &Evidence, page: Page) {
        let mut event = Event {
            op,
            button: op.button(),
            container: *self.container.id(),
            payload: Wrapped::received(b"wrapped at the stand".to_vec()),
            signatures: SignatureSet::default(),
            covered: Vec::new(),
            head: self.container.head(),
        };
        event.covered = event.subject();
        let covered = event.covered.clone();
        event.signatures = self.sign_all(&covered, who);
        let page: Option<JournalWrite> = match page {
            Page::None => None,
            Page::Opening => {
                let offset_ms = self.tick();
                let (bytes, hash) = self.container.opening_seal(offset_ms).expect("page 0");
                let mut sealing = Sealing {
                    seal: SignatureSet::new(self.client_signs(&bytes)),
                    ..Sealing::default()
                };
                // CH-26: page 0 of a Pro journal carries the owner's seal
                // and an anchor. The stand's placeholder stands in for the
                // network's attestation here, as the module's does inside.
                if self.container.opening_form() == ksg_core_v2::journal::Mode::Pro {
                    sealing.owner = Some(SignatureSet::new(vec![self.parties.owner.sign(&bytes)]));
                    sealing.anchor = Some(anchor(hash));
                }
                Some(JournalWrite::Open {
                    offset_ms,
                    sealing: Box::new(sealing),
                })
            }
        };
        let status = self.status_record(op);
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
            .expect("the press goes in");
        self.work_off();
    }

    /// The follow-up worker: discharges what it can prove (the packet's layer
    /// and the buyer's hand-over), as the reader does after every press.
    fn work_off(&mut self) {
        while let Some(i) =
            self.container.pending().iter().position(|r| {
                matches!(r.task, Task::WriteLayer { .. } | Task::HandOverLayer { .. })
            })
        {
            let ticket = self.container.claim(i).expect("claimable");
            let proof = match &ticket.task {
                Task::WriteLayer { zone } => Proof::LayerWritten {
                    zone: *zone,
                    digest: Hash::sha256(b"fields written by the stand"),
                },
                Task::HandOverLayer { to, up_to } => Proof::HandedOver {
                    to: to.clone(),
                    up_to: *up_to,
                    sealed: Hash::sha256(b"a sealed hand-over"),
                },
                Task::CarryId { .. } => unreachable!("filtered above"),
            };
            self.container
                .discharge(&Discharge { ticket, proof })
                .expect("the worker's proof");
        }
    }

    fn press_packet(&mut self) {
        self.press(
            Operation::ApplyPacket,
            &[Who::Issuer],
            &Evidence::None,
            Page::None,
        );
    }

    fn press_buyer_key(&mut self) {
        let to = self.parties.buyer.public();
        self.press(
            Operation::ApplyBuyerKey,
            &[Who::Buyer, Who::Owner],
            &Evidence::KeyLaid {
                to,
                up_to: Level(2),
            },
            Page::None,
        );
    }

    fn press_initiate(&mut self) {
        self.press(
            Operation::Initiate,
            &[Who::Client, Who::Owner],
            &Evidence::Initiation { at: Where::Inside },
            Page::None,
        );
    }

    fn press_opening(&mut self) {
        self.press(
            Operation::OpenJournal,
            &[Who::Client],
            &Evidence::None,
            Page::Opening,
        );
    }

    /// The party's side file, as the reader hands it to the module.
    #[must_use]
    pub fn side_file(&self) -> Vec<u8> {
        let half = self.mobile.to_bytes().expect("the half encodes");
        serde_json::json!({
            "v": 1,
            "role": "client",
            "container": self.container.id().to_multihash(),
            "half": B64.encode(half.as_slice()),
            "map": B64.encode(self.map_seed),
            "scan": B64.encode([3u8; 32]),
        })
        .to_string()
        .into_bytes()
    }

    /// The capsule around the container as it stands now.
    pub fn capsule(&mut self) -> Vec<u8> {
        let map = OpenWith::from_bytes(self.map_seed).seal_to();
        let state = self
            .container
            .seal_to_bytes(&self.state_key, &mut self.rng)
            .expect("the state seals");
        let shared = serde_json::json!({
            "v": 1,
            "state_key": B64.encode(self.state_key),
            "template": self.template.to_multihash(),
            "artifact": ARTIFACT,
            "client": client_kid().as_str(),
            "issued_ms": self.issued_ms,
            "clock_ms": self.clock_ms,
            "maps": [{
                "role": "client",
                "x25519": B64.encode(map.public().as_bytes()),
                "mlkem": B64.encode(map.mlkem()),
            }],
        })
        .to_string()
        .into_bytes();
        let parts = [
            Part {
                kind: PartKind::Code,
                bytes: b"\0asm-test".to_vec(),
            },
            Part {
                kind: PartKind::State,
                bytes: state,
            },
            Part {
                kind: PartKind::SharedSecrets,
                bytes: shared,
            },
        ];
        let mut rng = TestRng(self.rng.0.wrapping_add(1));
        let mut fill = |out: &mut [u8]| rng.fill_bytes(out);
        capsule::assemble(&parts, &[(MapRole::Client, map)], &mut fill).expect("the capsule")
    }
}

/// Who signs a command on the stand.
#[derive(Clone, Copy, Debug)]
pub enum Who {
    /// The client, through both halves.
    Client,
    /// The issuer.
    Issuer,
    /// The owner.
    Owner,
    /// The buyer.
    Buyer,
}

/// Which page a press writes.
pub enum Page {
    /// No page.
    None,
    /// Page 0.
    Opening,
}
