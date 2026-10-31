//! `Spec_kapsula` §19–§20: a party that holds no map signs outside. The
//! packet (E-2) is the issuer's press through the holder's map: the capsule
//! asks for the issuer's signature — over the event, then over the status
//! record — the reader hands each in, the repeat presses.

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};

fn status(session: &mut Session) -> serde_json::Value {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("the status is JSON"),
        other => panic!("status is not done: {other:?}"),
    }
}

fn open_printed() -> (kit::Fixture, Session) {
    let mut stand = kit::Fixture::printed_only();
    let side = stand.side_file_empty();
    let capsule = stand.capsule();
    let session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    (stand, session)
}

/// Presses the packet, answering every `NeedsSignature {party: "issuer"}`
/// with `sign`; the last answer.
fn packet_with(session: &mut Session, sign: impl Fn(&[u8]) -> Vec<u8>) -> Answer {
    for _ in 0..4 {
        match session.call(Request::ApplyPacket) {
            Answer::NeedsSignature { party, bytes } => {
                assert_eq!(party, "issuer");
                let signature = sign(&bytes);
                assert!(matches!(session.call(Request::Sign { signature }), Answer::Done { .. }));
            }
            other => return other,
        }
    }
    panic!("the packet keeps asking");
}

#[test]
fn the_packet_presses_after_the_issuers_signatures() {
    let (stand, mut session) = open_printed();
    let before = status(&mut session)["status"].clone();
    let answer = packet_with(&mut session, |b| {
        serde_json::to_vec(&stand.issuer_signs(b)).expect("a signature is JSON")
    });
    assert!(matches!(answer, Answer::Done { .. }), "the packet is not pressed: {answer:?}");
    assert_ne!(status(&mut session)["status"], before, "the packet moved the status");
    let (capsule, _) = session.close().expect("the capsule closes");
    assert_eq!(capsule.len(), ksg_container_v2::capsule::CAPSULE_SIZE);
}

#[test]
fn a_signature_by_somebody_else_is_refused_by_the_container() {
    let (stand, mut session) = open_printed();
    let wrong = |b: &[u8]| serde_json::to_vec(&stand.stranger_signs(b)).expect("a signature is JSON");
    let answer = packet_with(&mut session, wrong);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger's signature presses: {answer:?}");
}

#[test]
fn a_sign_with_nothing_waiting_is_refused() {
    let (_, mut session) = open_printed();
    let signature = b"{}".to_vec();
    assert!(matches!(session.call(Request::Sign { signature }), Answer::Refused { .. }));
}

#[test]
fn an_initiated_container_refuses_the_packet() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    assert!(matches!(session.call(Request::ApplyPacket), Answer::Refused { .. }));
}
