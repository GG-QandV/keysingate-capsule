//! C11 (`Spec_kapsula` §17, st.12): the export by the road of a voluntary
//! opening through the session (`FullExportVoluntary`).
//!
//! Sample: `sc_export_by_voluntary_opening` in the container stand
//! (`ksg-container-v2/tests/e2e_stand.rs`) and the `FullExport` session path
//! in `tests/holder_ops.rs`.

mod kit;

use ksg_capsule_module::session::{
    Answer, Request, Session,
};
use ksg_container_v2::voluntary::{ArbiterAttestation, OpeningDeclaration, VoluntaryOpening};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, Signature, SignatureSet};
use ksg_core_v2::doc::Context;

/// A born, working capsule and its session.
fn open(stand: &mut kit::Fixture) -> Session {
    let side = stand.side_file();
    let capsule = stand.capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the capsule opens")
}

/// Repeats `request`, answering each `NeedsSignature` with the owner's
/// signature; the last answer.
fn drive_owner(session: &mut Session, request: Request, owner: &Ed25519Signer) -> Answer {
    for _ in 0..8 {
        match session.call(request.clone()) {
            Answer::NeedsSignature { party, bytes } if party == "owner" => {
                let signature =
                    serde_json::to_vec(&owner.sign(&bytes)).expect("the signature is JSON");
                match session.call(Request::Sign { signature }) {
                    Answer::Done { .. } => {}
                    other => return other,
                }
            }
            other => return other,
        }
    }
    panic!("the request keeps asking");
}

fn uri(s: &str) -> ksg_core_v2::doc::Uri {
    ksg_core_v2::doc::Uri::parse(s).expect("a uri")
}

fn arbiter_a() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArbA#j1"), [70u8; 32])
}

fn arbiter_b() -> Ed25519Signer {
    Ed25519Signer::from_seed(uri("did:key:zArbB#j1"), [71u8; 32])
}

fn client_sigs(stand: &mut kit::Fixture, bytes: &[u8]) -> Vec<Signature> {
    stand.client_signs(bytes)
}

/// The client's first seal-side signature, as the stand's `client_ed25519`:
/// the reader gives both halves and the container's ML-DSA, and a document
/// whose key set names only the client's Ed25519 key takes the first.
fn client_ed25519(stand: &mut kit::Fixture, bytes: &[u8]) -> Signature {
    client_sigs(stand, bytes).remove(0)
}

/// The opening the four parties signed, with its declaration's anchor — by
/// the shape of `voluntary_opening` on the container's stand.
fn opening(stand: &mut kit::Fixture) -> (VoluntaryOpening, Attestation) {
    let id = *stand.container.id();
    let client = stand.container.agent().cloned().expect("a born container");
    let owner = stand.parties.owner.public();
    let (a, b) = (arbiter_a(), arbiter_b());

    let mut decl = OpeningDeclaration {
        context: Context,
        doc_type: "OpeningDeclaration".into(),
        v: 3,
        container: id,
        client: client.clone(),
        owner: owner.clone(),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&decl).expect("canonical");
    decl.signatures = SignatureSet::new(vec![
        client_ed25519(stand, &bytes),
        sign_doc(&decl, &stand.parties.owner).expect("owner"),
    ]);

    let mut attestations = Vec::new();
    for (arbiter, other) in [(&a.public(), &b), (&b.public(), &a)] {
        let base = ArbiterAttestation {
            context: Context,
            doc_type: "ArbiterAttestation".into(),
            v: 3,
            container: id,
            attestor: client.kid.clone(),
            arbiter: arbiter.clone(),
            signatures: SignatureSet::default(),
        };
        let mut by_client = base.clone();
        let bytes = ksg_core_v2::canonical::canonical_bytes(&by_client).expect("canonical");
        by_client.signatures = SignatureSet::new(vec![client_ed25519(stand, &bytes)]);
        let mut by_owner = ArbiterAttestation {
            attestor: owner.kid.clone(),
            ..base.clone()
        };
        by_owner.signatures =
            SignatureSet::new(vec![sign_doc(&by_owner, &stand.parties.owner).expect("o")]);
        let mut by_other = ArbiterAttestation {
            attestor: other.public().kid.clone(),
            ..base
        };
        by_other.signatures = SignatureSet::new(vec![sign_doc(&by_other, other).expect("a")]);
        attestations.extend([by_client, by_owner, by_other]);
    }

    let mut doc = VoluntaryOpening {
        context: Context,
        doc_type: "VoluntaryOpening".into(),
        v: 3,
        container: id,
        client,
        owner,
        arbiters: [a.public(), b.public()],
        attestations,
        declaration: decl.clone(),
        signatures: SignatureSet::default(),
    };
    let bytes = ksg_core_v2::canonical::canonical_bytes(&doc).expect("canonical");
    doc.signatures = SignatureSet::new(vec![
        client_ed25519(stand, &bytes),
        sign_doc(&doc, &stand.parties.owner).expect("owner"),
        sign_doc(&doc, &a).expect("a"),
        sign_doc(&doc, &b).expect("b"),
    ]);
    let anchor = Attestation {
        kind: uri("urn:ksg:anchor:stand"),
        subject: ksg_core_v2::canonical::doc_hash(&decl).expect("hash"),
        proof: b"stand".to_vec(),
        anchored_at: kit::ts("2026-09-12T00:00:00.000Z"),
    };
    (doc, anchor)
}

fn request(doc: &VoluntaryOpening, anchor: &Attestation) -> Request {
    Request::FullExportVoluntary {
        opening: Box::new(doc.clone()),
        anchor: anchor.clone(),
    }
}

fn export_pages(bytes: &[u8]) -> usize {
    let export: ksg_core_v2::journal::BoundExport =
        serde_json::from_slice(bytes).expect("the export is JSON");
    export.pages.len()
}

/// A forged opening (its signatures wiped) is refused, and nothing leaves.
#[test]
fn a_forged_opening_is_refused_and_hands_out_nothing() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let (doc, anchor) = opening(&mut stand);
    let mut forged = doc;
    forged.signatures = SignatureSet::default();
    let answer = drive_owner(&mut session, request(&forged, &anchor), &stand.parties.owner);
    assert!(
        matches!(answer, Answer::Refused { .. }),
        "a forged opening exports: {answer:?}"
    );
}

/// The real opening exports everything to the outputs.
#[test]
fn the_opening_exports_everything_to_the_outputs() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let (doc, anchor) = opening(&mut stand);
    let answer = drive_owner(&mut session, request(&doc, &anchor), &stand.parties.owner);
    let Answer::Done { bytes } = answer else {
        panic!("the opening does not export: {answer:?}");
    };
    assert!(!bytes.is_empty());
    assert_eq!(export_pages(&bytes), 1, "page 0 only: the stand did no work");
    let (_, outputs) = session.close().expect("the capsule closes");
    assert_eq!(outputs, vec![bytes], "the export is an output");
}

/// After the export the container is dead: work is refused.
#[test]
fn after_the_export_through_the_opening_work_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let (doc, anchor) = opening(&mut stand);
    let answer = drive_owner(&mut session, request(&doc, &anchor), &stand.parties.owner);
    assert!(matches!(answer, Answer::Done { .. }), "{answer:?}");
    let work = session.call(Request::Work { text: "after the export".into() });
    assert!(matches!(work, Answer::Refused { .. }), "a dead container works: {work:?}");
}
