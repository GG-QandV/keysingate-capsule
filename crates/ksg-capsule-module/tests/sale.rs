//! `Spec_kapsula` §19: the sale before the initiation through the session —
//! E-2 with the distributor's seat (`ApplyPacketSeated`) and E-3, the buyer's
//! key with the owner's consent (`ApplyBuyerKey`), after which the holder's
//! map gives way to the buyer's.

mod kit;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_container_v2::capsule::MapPub;
use ksg_container_v2::layers::OpenWith;
use ksg_core_v2::crypto::sign::{Ed25519Signer, PublicKey, Signature};

fn open_printed() -> (kit::Fixture, Session) {
    let mut stand = kit::Fixture::printed_only();
    let side = stand.side_file_empty();
    let capsule = stand.capsule();
    let session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    (stand, session)
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

fn right(stand: &kit::Fixture) -> impl Fn(&str, &[u8]) -> Signature + '_ {
    move |party, bytes| match party {
        "issuer" => stand.issuer_signs(bytes),
        "owner" => stand.parties.owner.sign(bytes),
        "buyer" => stand.parties.buyer.sign(bytes),
        other => panic!("nobody was expected to sign as {other}"),
    }
}

fn distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(kit::uri("did:key:zDistributor#d1"), [21; 32])
}

fn other_distributor() -> Ed25519Signer {
    Ed25519Signer::from_seed(kit::uri("did:key:zDistributorTwo#d2"), [22; 32])
}

fn map_pub(seed: [u8; 32]) -> MapPub {
    let to = OpenWith::from_bytes(seed).seal_to();
    MapPub {
        role: "client".into(),
        x25519: B64.encode(to.public().as_bytes()),
        mlkem: B64.encode(to.mlkem()),
    }
}

fn seated(key: PublicKey) -> Request {
    Request::ApplyPacketSeated { distributor: key }
}

fn buyer_key(stand: &kit::Fixture, seed: [u8; 32]) -> Request {
    Request::ApplyBuyerKey {
        buyer: stand.parties.buyer.public(),
        holder_map: map_pub(seed),
    }
}

/// The packet pressed (E-2) so that the buyer's key may follow.
/// K4 (§28): the issuer's layer work after a sale press, in the same session
/// — the container checks the zone's width and the hand-over's recipient,
/// not the issuer's keys, so test bytes stand for the sealed work.
fn work_off(session: &mut Session) {
    for _ in 0..8 {
        let tasks = match session.call(Request::PendingTasks) {
            Answer::Done { bytes } => serde_json::from_slice::<Vec<serde_json::Value>>(&bytes).expect("JSON"),
            other => panic!("pending tasks: {other:?}"),
        };
        let Some(t) = tasks.iter().find(|t| t["task"] != "carry_id") else { return };
        let index = t["index"].as_u64().expect("index") as usize;
        let answer = match t["task"].as_str() {
            Some("write_layer") => session.call(Request::WriteLayer {
                index,
                sealed: vec![7u8; ksg_container_v2::layout::ZONE_BYTES],
            }),
            Some("hand_over") => session.call(Request::HandedOver {
                index,
                sealed: ksg_core_v2::crypto::hash::Hash::sha256(b"the sealed hand-over"),
            }),
            other => panic!("unknown task {other:?}"),
        };
        assert!(matches!(answer, Answer::Done { .. }), "the follow-up is not discharged: {answer:?}");
    }
    panic!("the follow-ups do not end");
}

fn press_packet(stand: &kit::Fixture, session: &mut Session) {
    let answer = drive(session, &Request::ApplyPacket, &right(stand));
    assert!(matches!(answer, Answer::Done { .. }), "the packet is not pressed: {answer:?}");
    work_off(session);
}

/// The side file of the client for a capsule sealed to the map `seed`.
fn side_with_map(stand: &kit::Fixture, seed: [u8; 32]) -> Vec<u8> {
    let mut side: serde_json::Value =
        serde_json::from_slice(&stand.side_file_empty()).expect("the side file is JSON");
    side["map"] = serde_json::Value::String(B64.encode(seed));
    side.to_string().into_bytes()
}

#[test]
fn a_packet_with_a_distributor_seats_it() {
    let (stand, mut session) = open_printed();
    let before = status(&mut session)["status"].clone();
    let answer = drive(&mut session, &seated(distributor().public()), &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the packet is not pressed: {answer:?}");
    assert_ne!(status(&mut session)["status"], before, "the packet moved the status");
    work_off(&mut session);
    // The seat is taken: another distributor does not take it.
    let answer = session.call(seated(other_distributor().public()));
    match answer {
        Answer::Refused { reason } => {
            assert!(reason.contains("seated already"), "another reason: {reason}");
        }
        other => panic!("a second distributor is seated: {other:?}"),
    }
    let (capsule, _) = session.close().expect("the capsule closes");
    assert_eq!(capsule.len(), ksg_container_v2::capsule::CAPSULE_SIZE);
}

#[test]
fn the_seat_stays_when_the_press_is_refused() {
    let (stand, mut session) = open_printed();
    let wrong = |_: &str, b: &[u8]| stand.stranger_signs(b);
    let answer = drive(&mut session, &seated(distributor().public()), &wrong);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger's signature presses: {answer:?}");
    // The distributor sits all the same (as on the stand's `packet_seating`).
    let answer = session.call(seated(other_distributor().public()));
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("seated already")),
        "the seat is gone: {answer:?}"
    );
}

#[test]
fn an_initiated_container_refuses_the_seat() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    let answer = session.call(seated(distributor().public()));
    assert!(matches!(answer, Answer::Refused { .. }), "the seat after the birth: {answer:?}");
}

#[test]
fn the_old_request_reads_as_before() {
    // The JSON of `ApplyPacket` is unchanged; the new requests are new tags.
    let old: Request = serde_json::from_str(r#"{"command":"apply_packet"}"#).expect("reads");
    assert_eq!(old, Request::ApplyPacket);
    let new = serde_json::to_string(&seated(distributor().public())).expect("writes");
    assert!(new.contains("apply_packet_seated"), "{new}");
}

#[test]
fn the_buyer_key_waits_for_the_owner() {
    let (stand, mut session) = open_printed();
    press_packet(&stand, &mut session);
    // The buyer signs; the owner's signature is not at hand.
    let mut owner_asked = false;
    let sign = |party: &str, bytes: &[u8]| match party {
        "buyer" => stand.parties.buyer.sign(bytes),
        other => panic!("unexpected {other}"),
    };
    for _ in 0..4 {
        match session.call(buyer_key(&stand, [31; 32])) {
            Answer::NeedsSignature { party, bytes } if party == "buyer" => {
                let signature = serde_json::to_vec(&sign(&party, &bytes)).expect("JSON");
                assert!(matches!(session.call(Request::Sign { signature }), Answer::Done { .. }));
            }
            Answer::NeedsSignature { party, .. } => {
                assert_eq!(party, "owner");
                owner_asked = true;
                break;
            }
            other => panic!("not the owner's turn: {other:?}"),
        }
    }
    assert!(owner_asked, "the owner was never asked");
}

#[test]
fn somebody_elses_signature_for_the_owner_is_refused() {
    let (stand, mut session) = open_printed();
    press_packet(&stand, &mut session);
    let sign = |party: &str, bytes: &[u8]| match party {
        "buyer" => stand.parties.buyer.sign(bytes),
        _ => stand.stranger_signs(bytes),
    };
    let answer = drive(&mut session, &buyer_key(&stand, [31; 32]), &sign);
    assert!(matches!(answer, Answer::Refused { .. }), "a stranger is the owner: {answer:?}");
}

#[test]
fn after_the_buyer_key_the_old_map_does_not_open_the_capsule() {
    let (stand, mut session) = open_printed();
    press_packet(&stand, &mut session);
    let before = status(&mut session)["status"].clone();
    let answer = drive(&mut session, &buyer_key(&stand, [31; 32]), &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the buyer's key is not laid: {answer:?}");
    assert_ne!(status(&mut session)["status"], before, "E-3 moved the status");
    let (capsule, _) = session.close().expect("the capsule closes");
    assert_eq!(capsule.len(), ksg_container_v2::capsule::CAPSULE_SIZE);

    // The holder's map (the issuer's): the capsule stays shut.
    let old = Session::open(&capsule, &stand.side_file_empty(), Vec::new());
    assert!(old.is_err(), "the old map still opens the capsule");
    // The buyer's map opens it, and the state is the pressed one.
    let mut session = Session::open(&capsule, &side_with_map(&stand, [31; 32]), Vec::new())
        .expect("the buyer's map opens the capsule");
    assert_ne!(status(&mut session)["status"], before);
}

#[test]
fn a_buyer_key_after_the_birth_is_refused() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    let answer = session.call(buyer_key(&stand, [31; 32]));
    assert!(matches!(answer, Answer::Refused { .. }), "E-3 after E-4: {answer:?}");
}

// --- K4 (§28): the layers come first ------------------------------------------

#[test]
fn a_status_move_over_an_open_layer_follow_up_is_refused() {
    let (stand, mut session) = open_printed();
    let answer = drive(&mut session, &Request::ApplyPacket, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "the packet is not pressed: {answer:?}");
    // The packet's layer is open: E-3 over it would make it stale for good.
    let answer = session.call(buyer_key(&stand, [31; 32]));
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("layers come first")),
        "a status move over an open layer: {answer:?}"
    );
    // The status, the follow-ups and their discharge stay open to it.
    assert!(matches!(session.call(Request::Status), Answer::Done { .. }));
    work_off(&mut session);
    let answer = drive(&mut session, &buyer_key(&stand, [31; 32]), &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "E-3 after the layer: {answer:?}");
    work_off(&mut session);
    match session.call(Request::PendingTasks) {
        Answer::Done { bytes } => {
            let tasks: Vec<serde_json::Value> = serde_json::from_slice(&bytes).expect("JSON");
            assert!(tasks.iter().all(|t| t["task"] == "carry_id"), "follow-ups left: {tasks:?}");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_follow_up_of_the_wrong_kind_or_width_is_refused() {
    let (stand, mut session) = open_printed();
    let answer = drive(&mut session, &Request::ApplyPacket, &right(&stand));
    assert!(matches!(answer, Answer::Done { .. }), "{answer:?}");
    // The packet's layer is follow-up 0: a hand-over answer does not fit it.
    let answer = session.call(Request::HandedOver {
        index: 0,
        sealed: ksg_core_v2::crypto::hash::Hash::sha256(b"x"),
    });
    assert!(matches!(&answer, Answer::Refused { reason } if reason.contains("not a hand-over")), "{answer:?}");
    // A zone of another width.
    let answer = session.call(Request::WriteLayer { index: 0, sealed: vec![7u8; 10] });
    assert!(matches!(&answer, Answer::Refused { reason } if reason.contains("width")), "{answer:?}");
}
