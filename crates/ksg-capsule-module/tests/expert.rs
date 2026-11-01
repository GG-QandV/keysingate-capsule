//! `Spec_kapsula` §23, C7: the court's expert through the session —
//! `AppointExpert` (the principals name the expert on a page of the journal)
//! and `DiscloseToExpert` (the client and the owner hand the demanded pages
//! out). The session here is the client's: the owner's signature comes from
//! outside (`NeedsSignature` → `Sign` → repeat).

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_container_v2::expert::{
    ExpertDisclosure, ExpertEntry, ExpertRecord, Scope,
};
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::canonical::{canonical_bytes, doc_hash};
use ksg_core_v2::crypto::sign::{sign_doc, Ed25519Signer, Signature, SignatureSet};

fn open(stand: &mut kit::Fixture) -> Session {
    let side = stand.side_file();
    let capsule = stand.capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the capsule opens")
}

fn status(session: &mut Session) -> serde_json::Value {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("the status is JSON"),
        other => panic!("status is not done: {other:?}"),
    }
}

fn pages(session: &mut Session) -> u64 {
    status(session)["pages"].as_u64().expect("pages")
}

fn expert_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(kit::uri("did:key:zExpert#e1"), [80u8; 32])
}

/// Who signs the entry: the owner, or the client through both halves.
#[derive(Clone, Copy)]
enum Principal {
    Owner,
    Client,
}

fn entry(stand: &mut kit::Fixture, by: Principal, case: &str) -> ExpertEntry {
    let mut entry = ExpertEntry {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertEntry".into(),
        v: 3,
        container: *stand.container.id(),
        expert: expert_signer().public(),
        appointment: case.into(),
        signatures: SignatureSet::default(),
    };
    let bytes = canonical_bytes(&entry).expect("canonical");
    entry.signatures = match by {
        Principal::Owner => SignatureSet::new(vec![sign_doc(&entry, &stand.parties.owner)
            .expect("owner")]),
        Principal::Client => SignatureSet::new(stand.client_signs(&bytes)),
    };
    entry
}

fn expert_record(stand: &kit::Fixture, demanded: Scope) -> (ExpertRecord, Attestation) {
    let mut record = ExpertRecord {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertRecord".into(),
        v: 3,
        container: *stand.container.id(),
        expert: expert_signer().public(),
        parameters: "page 1 only".into(),
        demanded,
        signatures: SignatureSet::default(),
    };
    record.signatures =
        SignatureSet::new(vec![sign_doc(&record, &expert_signer()).expect("expert")]);
    let anchor = kit::anchor(doc_hash(&record).expect("hash"));
    (record, anchor)
}

fn disclosure(stand: &mut kit::Fixture, scope: Scope) -> ExpertDisclosure {
    let mut disclosure = ExpertDisclosure {
        context: ksg_core_v2::doc::Context,
        doc_type: "ExpertDisclosure".into(),
        v: 3,
        container: *stand.container.id(),
        expert: expert_signer().public(),
        scope,
        signatures: SignatureSet::default(),
    };
    let bytes = canonical_bytes(&disclosure).expect("canonical");
    let mut sigs = stand.client_signs(&bytes);
    sigs.push(sign_doc(&disclosure, &stand.parties.owner).expect("owner"));
    disclosure.signatures = SignatureSet::new(sigs);
    disclosure
}

/// Repeats `request`, answering each `NeedsSignature` with `sign(party, bytes)`.
fn drive(
    session: &mut Session,
    request: &Request,
    sign: &dyn Fn(&str, &[u8]) -> Signature,
) -> Answer {
    for _ in 0..8 {
        match session.call(request.clone()) {
            Answer::NeedsSignature { party, bytes } => {
                let signature = serde_json::to_vec(&sign(&party, &bytes)).expect("JSON");
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

fn work(session: &mut Session, text: &str) {
    match session.call(Request::Work { text: text.into() }) {
        Answer::Done { .. } => {}
        other => panic!("work is not done: {other:?}"),
    }
}

fn appoint(session: &mut Session, entry: &ExpertEntry) -> Answer {
    session.call(Request::AppointExpert {
        entry: entry.clone(),
    })
}

fn disclose(
    stand: &mut kit::Fixture,
    entry: &ExpertEntry,
    scope: Scope,
) -> Request {
    let (record, anchor) = expert_record(stand, Scope::Pages(vec![1]));
    Request::Disclose {
        entry: Box::new(entry.clone()),
        expert_record: Box::new(record),
        record_anchor: Box::new(anchor),
        disclosure: Box::new(disclosure(stand, scope)),
    }
}

#[test]
fn the_client_appoints_the_expert() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let entry = entry(&mut stand, Principal::Client, "urn:court:ua:case-1");
    let before = pages(&mut session);
    let answer = appoint(&mut session, &entry);
    assert!(matches!(answer, Answer::Done { .. }), "not appointed: {answer:?}");
    assert_eq!(pages(&mut session), before + 1, "the expert's page is written");
}

#[test]
fn the_owner_appoints_the_expert() {
    // The owner names the expert (the entry carries the owner's signature);
    // the client's session presses it with its own side's signature.
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-2");
    let before = pages(&mut session);
    let answer = appoint(&mut session, &entry);
    assert!(matches!(answer, Answer::Done { .. }), "not appointed: {answer:?}");
    assert_eq!(pages(&mut session), before + 1, "the expert's page is written");
}

#[test]
fn a_stranger_s_entry_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let mut entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-3");
    entry.signatures = SignatureSet::new(vec![
        sign_doc(&entry, &stand.parties.buyer).expect("the stranger"),
    ]);
    let before = pages(&mut session);
    let answer = appoint(&mut session, &entry);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger names: {answer:?}");
    assert_eq!(pages(&mut session), before, "nothing is written");
}

#[test]
fn disclosure_waits_for_the_owner_and_then_hands_the_pages_out() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    work(&mut session, "work before the court");
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-4");
    let answer = appoint(&mut session, &entry);
    assert!(matches!(answer, Answer::Done { .. }), "not appointed: {answer:?}");

    let request = disclose(&mut stand, &entry, Scope::Pages(vec![1]));
    // Without the owner's second signature: the question for it.
    match session.call(request.clone()) {
        Answer::NeedsSignature { party, .. } => assert_eq!(party, "owner"),
        other => panic!("the owner's signature is asked for: {other:?}"),
    }
    let answer = drive(&mut session, &request, &|party, bytes| {
        assert_eq!(party, "owner");
        stand.parties.owner.sign(bytes)
    });
    let Answer::Done { bytes } = answer else {
        panic!("the disclosure is not done: {answer:?}");
    };
    let shown: serde_json::Value = serde_json::from_slice(&bytes).expect("JSON");
    assert_eq!(shown.as_array().map(Vec::len), Some(1), "one page, as demanded");
    let (_, outputs) = session.close().expect("the capsule closes");
    assert_eq!(outputs, vec![bytes], "the disclosure is an output");
}

#[test]
fn disclosure_refuses_a_stranger_for_the_owner() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    work(&mut session, "work before the court");
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-5");
    assert!(matches!(appoint(&mut session, &entry), Answer::Done { .. }));
    let request = disclose(&mut stand, &entry, Scope::Pages(vec![1]));
    let answer = drive(&mut session, &request, &|_, bytes| stand.stranger_signs(bytes));
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("Exactly(Owner)")),
        "a stranger discloses: {answer:?}"
    );
}

#[test]
fn disclosure_without_an_appointed_expert_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    work(&mut session, "work before the court");
    // The entry exists, but it was never named on a page of the journal.
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-6");
    let request = disclose(&mut stand, &entry, Scope::Pages(vec![1]));
    let answer = drive(&mut session, &request, &|_, bytes| stand.parties.owner.sign(bytes));
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("AppointExpert")),
        "no expert, yet disclosed: {answer:?}"
    );
}

#[test]
fn disclosure_wider_than_the_expert_demanded_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    work(&mut session, "work before the court");
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-7");
    assert!(matches!(appoint(&mut session, &entry), Answer::Done { .. }));
    let request = disclose(&mut stand, &entry, Scope::Pages(vec![0, 1]));
    let answer = drive(&mut session, &request, &|_, bytes| stand.parties.owner.sign(bytes));
    assert!(matches!(answer, Answer::Refused { .. }), "wider than demanded: {answer:?}");
}

#[test]
fn the_requests_read_from_json() {
    let mut stand = kit::Fixture::started();
    let entry = entry(&mut stand, Principal::Owner, "urn:court:ua:case-8");
    let request = Request::AppointExpert { entry };
    let json = serde_json::to_vec(&request).expect("encodes");
    assert!(String::from_utf8_lossy(&json).contains("\"command\":\"appoint_expert\""));
    let back: Request = serde_json::from_slice(&json).expect("reads");
    assert_eq!(back, request);
}
