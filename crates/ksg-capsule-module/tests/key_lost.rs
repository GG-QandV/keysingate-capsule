//! `Spec_kapsula` §24 (E-15): the distributor and the client declare the
//! container dead in the owner's stead. The session is the client's; the
//! distributor holds no map, so its signature comes from outside
//! (`NeedsSignature {party: "distributor"}` -> `Sign` -> repeat).

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_core_v2::crypto::sign::{Ed25519Signer, Signature};

fn distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(kit::uri("did:key:zDistributor#d1"), [21; 32])
}

fn open(stand: &mut kit::Fixture) -> Session {
    let side = stand.side_file();
    let capsule = stand.capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the capsule opens")
}

/// Repeats `request`, answering each `NeedsSignature` with `sign(party, bytes)`;
/// the last answer, and the parties that were asked, in order.
fn drive(
    session: &mut Session,
    request: &Request,
    sign: &dyn Fn(&str, &[u8]) -> Signature,
) -> (Answer, Vec<String>) {
    let mut asked = Vec::new();
    for _ in 0..8 {
        match session.call(request.clone()) {
            Answer::NeedsSignature { party, bytes } => {
                asked.push(party.clone());
                let signature = serde_json::to_vec(&sign(&party, &bytes)).expect("JSON");
                match session.call(Request::Sign { signature }) {
                    Answer::Done { .. } => {}
                    other => return (other, asked),
                }
            }
            other => return (other, asked),
        }
    }
    panic!("the request keeps asking");
}

fn right(party: &str, bytes: &[u8]) -> Signature {
    match party {
        "distributor" => distributor().sign(bytes),
        other => panic!("nobody was expected to sign as {other}"),
    }
}

fn is_refused(answer: &Answer) -> bool {
    matches!(answer, Answer::Refused { .. })
}

#[test]
fn the_distributor_and_the_client_declare_the_container_dead() {
    let mut stand = kit::Fixture::started_with_distributor(distributor().public());
    let mut session = open(&mut stand);
    let (answer, asked) = drive(&mut session, &Request::DeclareKeyLostByDistributor, &right);
    assert!(matches!(answer, Answer::Done { .. }), "the declaration is not pressed: {answer:?}");
    assert!(!asked.is_empty(), "the distributor was never asked");
    assert!(asked.iter().all(|p| p == "distributor"), "asked for another party: {asked:?}");
    // Dead is final: the session works on nothing.
    let work = session.call(Request::Work { text: "after death".into() });
    assert!(is_refused(&work), "a dead container works: {work:?}");
}

#[test]
fn without_a_seated_distributor_the_declaration_is_refused_before_a_signature() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = session.call(Request::DeclareKeyLostByDistributor);
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("no distributor")),
        "a direct sale declares through a distributor: {answer:?}"
    );
    let work = session.call(Request::Work { text: "still alive".into() });
    assert!(matches!(work, Answer::Done { .. }), "a refused declaration kills: {work:?}");
}

#[test]
fn somebody_elses_signature_for_the_distributor_is_refused() {
    let mut stand = kit::Fixture::started_with_distributor(distributor().public());
    let mut session = open(&mut stand);
    let stranger = |_: &str, bytes: &[u8]| stand.stranger_signs(bytes);
    let (answer, _) = drive(&mut session, &Request::DeclareKeyLostByDistributor, &stranger);
    assert!(is_refused(&answer), "a stranger is the distributor: {answer:?}");
    let work = session.call(Request::Work { text: "still alive".into() });
    assert!(matches!(work, Answer::Done { .. }), "a refused declaration kills: {work:?}");
}

#[test]
fn another_distributors_key_is_not_the_seated_one() {
    let mut stand = kit::Fixture::started_with_distributor(distributor().public());
    let mut session = open(&mut stand);
    let other = Ed25519Signer::from_seed(kit::uri("did:key:zDistributorTwo#d2"), [22; 32]);
    let sign = |_: &str, bytes: &[u8]| other.sign(bytes);
    let (answer, _) = drive(&mut session, &Request::DeclareKeyLostByDistributor, &sign);
    assert!(is_refused(&answer), "an unseated distributor declares death: {answer:?}");
}

#[test]
fn the_request_has_its_own_wire_tag() {
    let json = serde_json::to_string(&Request::DeclareKeyLostByDistributor).expect("writes");
    assert!(json.contains("declare_key_lost_by_distributor"), "{json}");
    let old: Request = serde_json::from_str(r#"{"command":"declare_key_lost"}"#).expect("reads");
    assert_eq!(old, Request::DeclareKeyLost);
}
