//! `Spec_kapsula` §19–§20: a party that holds no map signs outside. The
//! packet (E-2) is the issuer's press through the holder's map: the capsule
//! asks for the issuer's signature and takes it for the repeat. (The press
//! itself also needs the status record signed by the issuer before E-4 —
//! `Session::status_record`, pending the owner's word, §20.)

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};

fn open_printed() -> (kit::Fixture, Session) {
    let mut stand = kit::Fixture::printed_only();
    let side = stand.side_file_empty();
    let capsule = stand.capsule();
    let session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    (stand, session)
}

#[test]
fn the_packet_asks_for_the_issuer_and_takes_its_signature() {
    let (stand, mut session) = open_printed();
    let bytes = match session.call(Request::ApplyPacket) {
        Answer::NeedsSignature { party, bytes } => {
            assert_eq!(party, "issuer");
            bytes
        }
        other => panic!("the packet does not ask for the issuer: {other:?}"),
    };
    let signature = serde_json::to_vec(&stand.issuer_signs(&bytes)).expect("a signature is JSON");
    match session.call(Request::Sign { signature }) {
        Answer::Done { .. } => {}
        other => panic!("the issuer's signature is not taken: {other:?}"),
    }
    // The repeat signs the same event bytes and finds the issuer's signature:
    // it no longer asks for the issuer.
    if let Answer::NeedsSignature { party, .. } = session.call(Request::ApplyPacket) {
        assert_ne!(party, "issuer");
    }
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
