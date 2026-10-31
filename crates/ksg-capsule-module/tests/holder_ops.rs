//! `Spec_kapsula` §20, §24: the holder's operations of level 1 through the
//! session — `Form`, `FullExport`, `DeclareKeyLost`, `Freeze`,
//! `DeclareSharesLost`. The session here is the client's: the owner's and the
//! issuer's signatures come from outside (`NeedsSignature` → `Sign` → repeat).

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Signature;
use ksg_core_v2::journal::Mode;

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

/// Repeats `request`, answering each `NeedsSignature` with `sign(party, bytes)`;
/// the last answer.
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

/// Everybody signs as they should.
fn right(stand: &kit::Fixture) -> impl Fn(&str, &[u8]) -> Signature + '_ {
    move |party, bytes| match party {
        "owner" => stand.parties.owner.sign(bytes),
        "issuer" => stand.issuer_signs(bytes),
        other => panic!("nobody was expected to sign as {other}"),
    }
}

/// Everybody who signs is somebody else (the buyer's key).
fn wrong(stand: &kit::Fixture) -> impl Fn(&str, &[u8]) -> Signature + '_ {
    move |_, bytes| stand.stranger_signs(bytes)
}

fn is_refused(answer: &Answer) -> bool {
    matches!(answer, Answer::Refused { .. })
}

#[test]
fn the_form_goes_to_pro_with_the_owner_and_the_issuer() {
    let mut stand = kit::Fixture::started_sealed();
    let mut session = open(&mut stand);
    let before = status(&mut session)["pages"].as_u64().expect("pages");
    let answer = drive(&mut session, &Request::Form { to: Mode::Pro }, &right(&stand));
    assert!(
        matches!(answer, Answer::Done { .. } | Answer::NeedsAnchor { .. }),
        "the form is not pressed: {answer:?}"
    );
    let after = status(&mut session)["pages"].as_u64().expect("pages");
    assert_eq!(after, before + 1, "the form's page is written");
}

#[test]
fn the_form_to_pro_refuses_a_stranger_for_the_issuer_and_the_owner() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::Form { to: Mode::Pro }, &wrong(&stand));
    assert!(is_refused(&answer), "a stranger raises the form: {answer:?}");
}

#[test]
fn the_form_back_to_light_needs_the_owner_alone() {
    let mut stand = kit::Fixture::started_heavy();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::Form { to: Mode::Local }, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the form is not lowered: {answer:?}");
    let refused = drive(&mut session, &Request::Form { to: Mode::Local }, &right(&stand));
    assert!(is_refused(&refused), "the same form twice: {refused:?}");
}

#[test]
fn declare_key_lost_kills_the_container() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::DeclareKeyLost, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the declaration is not pressed: {answer:?}");
    let work = session.call(Request::Work { text: "after death".into() });
    assert!(is_refused(&work), "a dead container works: {work:?}");
}

#[test]
fn declare_key_lost_refuses_a_stranger() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::DeclareKeyLost, &wrong(&stand));
    assert!(is_refused(&answer), "a stranger declares death: {answer:?}");
    let work = session.call(Request::Work { text: "still alive".into() });
    assert!(matches!(work, Answer::Done { .. }), "a refused declaration kills: {work:?}");
}

#[test]
fn full_export_hands_everything_out_and_the_container_dies() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::FullExport, &right(&stand));
    let Answer::Done { bytes } = answer else {
        panic!("the export is not done: {answer:?}");
    };
    assert!(!bytes.is_empty());
    let (_, outputs) = session.close().expect("the capsule closes");
    assert_eq!(outputs, vec![bytes], "the export is an output");
}

#[test]
fn full_export_refuses_a_stranger_and_after_it_work_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::FullExport, &wrong(&stand));
    assert!(is_refused(&answer), "a stranger exports: {answer:?}");

    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let done = drive(&mut session, &Request::FullExport, &right(&stand));
    assert!(matches!(done, Answer::Done { .. }), "{done:?}");
    let work = session.call(Request::Work { text: "after the export".into() });
    assert!(is_refused(&work), "a dead container works: {work:?}");
}

#[test]
fn freeze_needs_the_issuer_and_the_owner() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::Freeze, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the freeze is not pressed: {answer:?}");
    let work = session.call(Request::Work { text: "while frozen".into() });
    assert!(is_refused(&work), "a frozen container works: {work:?}");
}

#[test]
fn freeze_refuses_a_stranger() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let answer = drive(&mut session, &Request::Freeze, &wrong(&stand));
    assert!(is_refused(&answer), "a stranger freezes: {answer:?}");
}

#[test]
fn shares_lost_is_declared_by_the_owner_and_the_container_goes_on() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let hash = Hash::from_multihash(&format!("1220{}", "ab".repeat(32))).expect("a hash");
    let answer = drive(&mut session, &Request::DeclareSharesLost { hash }, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the declaration is not pressed: {answer:?}");
    let work = session.call(Request::Work { text: "still working".into() });
    assert!(matches!(work, Answer::Done { .. }), "the container stops: {work:?}");
}

#[test]
fn shares_lost_refuses_a_stranger() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let hash = Hash::from_multihash(&format!("1220{}", "cd".repeat(32))).expect("a hash");
    let answer = drive(&mut session, &Request::DeclareSharesLost { hash }, &wrong(&stand));
    assert!(is_refused(&answer), "a stranger declares: {answer:?}");
}
