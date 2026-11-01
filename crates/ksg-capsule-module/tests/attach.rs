//! `Spec_kapsula` §20: E-6 through the session — `Request::Attach` with an
//! artefact. The session is the client's: the owner's seal on the page in Pro
//! comes from outside (`NeedsSignature` → `Sign` → repeat), and the anchors it
//! owes from the reader (`NeedsAnchor` → `Reanchor`).

mod kit;

use ksg_capsule_module::session::{Answer, AttachWire, Request, Session};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Signature;

fn open(stand: &mut kit::Fixture) -> Session {
    let side = stand.side_file();
    let capsule = stand.capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the capsule opens")
}

fn pages(session: &mut Session) -> u64 {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice::<serde_json::Value>(&bytes)
            .expect("the status is JSON")["pages"]
            .as_u64()
            .expect("pages"),
        other => panic!("status is not done: {other:?}"),
    }
}

fn artifact(offset_ms: u64) -> Request {
    Request::Attach {
        what: AttachWire::Artifact {
            name: "report.pdf".into(),
            mime: "application/pdf".into(),
            content_hash: Hash::sha256(b"the report"),
            size: 10,
            offset_ms,
            derived_from: Vec::new(),
        },
    }
}

/// Repeats `request`: the owner signs with `owner`, each anchor is answered.
/// The last answer.
fn drive(session: &mut Session, request: &Request, owner: &dyn Fn(&[u8]) -> Signature) -> Answer {
    let mut next = request.clone();
    for _ in 0..12 {
        match session.call(next.clone()) {
            Answer::NeedsSignature { party, bytes } => {
                assert_eq!(party, "owner", "only the owner's seal is asked for");
                let signature = serde_json::to_vec(&owner(&bytes)).expect("JSON");
                match session.call(Request::Sign { signature }) {
                    Answer::Done { .. } => next = request.clone(),
                    other => return other,
                }
            }
            Answer::NeedsAnchor { subject, .. } => {
                next = Request::Reanchor {
                    attestation: serde_json::to_vec(&kit::attestation_for(&subject))
                        .expect("JSON"),
                };
            }
            other => return other,
        }
    }
    panic!("the request keeps asking");
}

#[test]
fn the_artifact_goes_in_with_the_clients_signature_in_light() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let owner = |b: &[u8]| stand.parties.owner.sign(b);
    let answer = drive(&mut session, &artifact(kit::OFFSET), &owner);
    assert!(matches!(answer, Answer::Done { .. }), "not attached: {answer:?}");
    assert_eq!(pages(&mut session), before + 1, "the artefact's page is written");
}

#[test]
fn the_artifact_of_another_container_is_refused_and_writes_nothing() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let owner = |b: &[u8]| stand.parties.owner.sign(b);
    let answer = drive(&mut session, &artifact(kit::OFFSET + 1), &owner);
    assert!(
        matches!(&answer, Answer::Refused { reason } if !reason.is_empty()),
        "another offset gives another container: {answer:?}"
    );
    assert_eq!(pages(&mut session), before, "nothing is written");
}

#[test]
fn in_pro_the_page_waits_for_the_owners_seal() {
    let mut stand = kit::Fixture::started_heavy_sealed();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    // Without the owner's seal the request stays a question.
    let asked = session.call(artifact(kit::OFFSET));
    let Answer::NeedsSignature { party, .. } = asked else {
        panic!("Pro asks the owner's seal on the page: {asked:?}");
    };
    assert_eq!(party, "owner");
    assert_eq!(pages(&mut session), before, "nothing is written without it");
}

#[test]
fn in_pro_the_owners_seal_writes_the_page() {
    let mut stand = kit::Fixture::started_heavy_sealed();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let owner = |b: &[u8]| stand.parties.owner.sign(b);
    let answer = drive(&mut session, &artifact(kit::OFFSET), &owner);
    assert!(matches!(answer, Answer::Done { .. }), "not attached: {answer:?}");
    assert_eq!(pages(&mut session), before + 1, "the artefact's page is written");
}

#[test]
fn in_pro_a_strangers_seal_is_refused() {
    let mut stand = kit::Fixture::started_heavy_sealed();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let stranger = |b: &[u8]| stand.stranger_signs(b);
    let answer = drive(&mut session, &artifact(kit::OFFSET), &stranger);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger seals: {answer:?}");
    assert_eq!(pages(&mut session), before, "nothing is written");
}

#[test]
fn a_wire_that_does_not_read_is_refused_with_a_reason() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    // Bytes that are not a hash, an unknown case, a stray field: no `Request`
    // (the module's boundary answers these with its own error, `abi.rs`).
    let zero = format!("1220{}", "0".repeat(64));
    let stray = format!(
        r#"{{"attach":{{"what":{{"what":"artifact","name":"a","mime":"x/y","content_hash":"{zero}","size":1,"offset_ms":1000,"extra":1}}}}}}"#
    );
    for bad in [
        r#"{"attach":{"what":{"what":"artifact","name":"a","mime":"x/y","content_hash":"nope","size":1,"offset_ms":1000}}}"#,
        r#"{"attach":{"what":{"what":"rule","rule":{"scope":"all"}}}}"#,
        stray.as_str(),
    ] {
        assert!(
            serde_json::from_str::<Request>(bad).is_err(),
            "a wire that must not read: {bad}"
        );
    }
    // A URI that is not one, past the wire: the session's own refusal.
    let answer = session.call(Request::Attach {
        what: AttachWire::Artifact {
            name: "a".into(),
            mime: "x/y".into(),
            content_hash: Hash::sha256(b"a"),
            size: 1,
            offset_ms: kit::OFFSET,
            derived_from: vec!["not a uri".into()],
        },
    });
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("derived_from")),
        "{answer:?}"
    );
    // An empty name: the container's refusal, with its words.
    let answer = session.call(Request::Attach {
        what: AttachWire::Artifact {
            name: String::new(),
            mime: "x/y".into(),
            content_hash: Hash::sha256(b"a"),
            size: 1,
            offset_ms: kit::OFFSET,
            derived_from: Vec::new(),
        },
    });
    assert!(matches!(&answer, Answer::Refused { reason } if !reason.is_empty()), "{answer:?}");
}

// --- E-7 and E-8: the two page kinds `Session::page` gained (`[р]` 31.10 «А»)

fn rule(scope: ksg_core_v2::journal::RuleScope) -> Request {
    Request::Attach {
        what: AttachWire::Rule {
            rule: ksg_core_v2::journal::SealRule { scope },
        },
    }
}

#[test]
fn the_rule_of_two_seals_goes_in_with_the_owners_seal_beside_in_light_and_pro() {
    for mut stand in [kit::Fixture::started(), kit::Fixture::started_heavy_sealed()] {
        let mut session = open(&mut stand);
        let before = pages(&mut session);
        let owner = |b: &[u8]| stand.parties.owner.sign(b);
        let answer = drive(&mut session, &rule(ksg_core_v2::journal::RuleScope::All), &owner);
        assert!(matches!(answer, Answer::Done { .. }), "the rule is not set: {answer:?}");
        assert_eq!(pages(&mut session), before + 1, "the rule's page is written");
    }
}

#[test]
fn a_rule_sealed_by_a_stranger_beside_the_client_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let stranger = |b: &[u8]| stand.stranger_signs(b);
    let answer = drive(&mut session, &rule(ksg_core_v2::journal::RuleScope::All), &stranger);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger's seal sets the rule: {answer:?}");
    assert_eq!(pages(&mut session), before, "nothing is written");
}

/// The claim, its publication signed by the container's agent — the client's
/// key, both halves (step 1, made outside the capsule).
fn claim(stand: &mut kit::Fixture, container: Hash, open_id: &str) -> Request {
    use ksg_container_v2::identity::Publication;
    let agent = stand.container.agent().cloned().expect("a born container has its agent");
    let subject = Publication::subject(&container, open_id, &agent);
    let signatures = ksg_core_v2::crypto::sign::SignatureSet::new(stand.client_signs(subject.as_bytes()));
    Request::Attach {
        what: AttachWire::Claim {
            artifact: Hash::sha256(b"the artifact claimed"),
            open_id: open_id.into(),
            agent,
            signatures,
            anchor: kit::anchor(subject),
        },
    }
}

#[test]
fn the_ownership_claim_goes_in_on_its_own_page_type() {
    let mut stand = kit::Fixture::started();
    let id = *stand.container.id();
    let request = claim(&mut stand, id, "ksg:agent:zAgent-public-identifier");
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let owner = |b: &[u8]| stand.parties.owner.sign(b);
    let answer = drive(&mut session, &request, &owner);
    assert!(matches!(answer, Answer::Done { .. }), "the claim is not recorded: {answer:?}");
    assert_eq!(pages(&mut session), before + 1, "the claim's page is written");
}

#[test]
fn a_claim_published_for_another_container_is_refused() {
    let mut stand = kit::Fixture::started();
    let elsewhere = Hash::sha256(b"another container");
    let request = claim(&mut stand, elsewhere, "ksg:agent:zAgent-public-identifier");
    let mut session = open(&mut stand);
    let before = pages(&mut session);
    let owner = |b: &[u8]| stand.parties.owner.sign(b);
    let answer = drive(&mut session, &request, &owner);
    assert!(matches!(answer, Answer::Refused { .. }), "a claim of elsewhere is recorded: {answer:?}");
    assert_eq!(pages(&mut session), before, "nothing is written");
}
