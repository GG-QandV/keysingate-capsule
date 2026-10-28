//! The birth automaton split across the wire (E-4, CH-5b): the mobile
//! side starts outside the module (`MobileKeygen::start`), the container
//! answers through [`Request::BeginBirth`], the mobile side keeps its half
//! and sends the container share through [`Request::FinishBirth`] — the
//! mobile half never enters the module.
//!
//! The client's signature round (track И4) is still the bridge: a correct
//! finish answers `NeedsClientCommit`, the commitment goes in through
//! [`Request::ClientCommit`], back comes the round the mobile side signs
//! (`NeedsShare`), the share goes in through [`Request::ClientShare`] — and
//! the finish repeated presses the initiation, which still owes the owner.

mod kit;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_container_v2::client_key::{
    KeygenFinish, KeygenHello, KeygenReply, MobileKeygen, SigningRound,
};

/// A template capsule and the client's half-less side file.
fn unborn_capsule() -> (Vec<u8>, Vec<u8>) {
    let mut stand = kit::Fixture::unborn();
    let side = stand.side_file_empty();
    let capsule = stand.capsule();
    (capsule, side)
}

fn open_unborn() -> Session {
    let (capsule, side) = unborn_capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the template capsule opens with no half")
}

/// Message 2 out of `BeginBirth`, decoded from the answer.
fn begin(session: &mut Session, hello: &[u8]) -> Vec<u8> {
    match session.call(Request::BeginBirth {
        hello: hello.to_vec(),
    }) {
        Answer::Done { bytes } => {
            let v: serde_json::Value =
                serde_json::from_slice(&bytes).expect("the reply is JSON");
            let r = v["reply"].as_str().expect("a reply field");
            B64.decode(r).expect("a base64url reply")
        }
        other => panic!("BeginBirth is not done: {other:?}"),
    }
}

fn is_refused(answer: Answer) -> bool {
    matches!(answer, Answer::Refused { .. })
}

/// Message 3 in, the client's round out: the finish asks the mobile side
/// for its commitment over the message both halves sign.
fn finish_to_commit(
    session: &mut Session,
    fin: Vec<u8>,
    group: ksg_core_v2::crypto::sign::PublicKey,
) -> Vec<u8> {
    match session.call(Request::FinishBirth { fin, group_key: group }) {
        Answer::NeedsClientCommit { round } => {
            assert!(!round.is_empty(), "there are bytes to sign");
            round
        }
        other => panic!("a correct finish waits for the client round: {other:?}"),
    }
}

/// One full client round: the mobile half commits, the container answers
/// the round, the mobile half shares, the share goes in — then the repeated
/// finish presses the initiation, which still owes the owner.
fn close_round(
    session: &mut Session,
    round_msg: &[u8],
    half: &ksg_container_v2::client_key::MobileHalf,
    rng: &mut kit::TestRng,
    fin: Vec<u8>,
    group: ksg_core_v2::crypto::sign::PublicKey,
) {
    let (nonces, commitment) = half.commit(rng);
    let round = match session.call(Request::ClientCommit {
        commitment: commitment.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => {
            let round = SigningRound::from_bytes(&round).expect("the round reads");
            assert_eq!(
                round.message(),
                round_msg,
                "the round signs what the finish asked for"
            );
            round
        }
        other => panic!("the commitment opens the round: {other:?}"),
    };
    let share = half.respond(nonces, &round).expect("the mobile side answers");
    match session.call(Request::ClientShare {
        share: share.to_bytes(),
    }) {
        Answer::Done { .. } => {}
        other => panic!("the share closes the round: {other:?}"),
    }
    // Nothing was pressed yet: the container is still a template — the
    // signatures wait for the finish repeated.
    match session.call(Request::Status) {
        Answer::Done { bytes } => {
            let v: serde_json::Value =
                serde_json::from_slice(&bytes).expect("the status is JSON");
            assert_eq!(v["born"], false, "no birth pressed: {v}");
        }
        other => panic!("the status is not done: {other:?}"),
    }
    // The repeated finish picks the signatures up and presses the
    // initiation — which still owes the owner's co-seal.
    match session.call(Request::FinishBirth {
        fin,
        group_key: group,
    }) {
        Answer::NeedsSignature { party, bytes } => {
            assert_eq!(party, "owner", "the initiation still owes the owner");
            assert!(!bytes.is_empty(), "there are bytes to sign");
        }
        other => panic!("the repeated finish waits for the owner: {other:?}"),
    }
}

#[test]
fn begin_answers_and_a_correct_finish_waits_for_the_client_round() {
    let mut session = open_unborn();
    let mut rng = kit::TestRng(41);
    let (keygen, hello) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    // The wire form survives the trip, both ways.
    let hello = hello.to_bytes().expect("the hello encodes");
    let hello = KeygenHello::from_bytes(&hello)
        .expect("the hello reads")
        .to_bytes()
        .expect("the hello re-encodes");
    let reply_bytes = begin(&mut session, &hello);
    let reply = KeygenReply::from_bytes(&reply_bytes).expect("the reply reads");
    let (half, group, fin) = keygen.finish(&reply).expect("the mobile side keeps its half");
    let fin = KeygenFinish::from_bytes(&fin.to_bytes().expect("the finish encodes"))
        .expect("the finish reads")
        .to_bytes()
        .expect("the finish re-encodes")
        .to_vec();
    let round_msg = finish_to_commit(&mut session, fin.clone(), group.clone());
    close_round(&mut session, &round_msg, &half, &mut rng, fin, group);
}

#[test]
fn a_second_begin_re_answers_and_the_mobile_side_restarts_from_it() {
    let mut session = open_unborn();
    let mut rng = kit::TestRng(43);
    let (_first, hello1) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    let reply1 = begin(&mut session, &hello1.to_bytes().expect("bytes"));
    let (second, hello2) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    let reply2 = begin(&mut session, &hello2.to_bytes().expect("bytes"));
    assert_ne!(reply1, reply2, "every answer is fresh");
    let reply = KeygenReply::from_bytes(&reply2).expect("the second reply reads");
    let (half, group, fin) = second.finish(&reply).expect("the mobile side keeps its half");
    let fin = fin.to_bytes().expect("the finish encodes").to_vec();
    let round_msg = finish_to_commit(&mut session, fin.clone(), group.clone());
    close_round(&mut session, &round_msg, &half, &mut rng, fin, group);
}

#[test]
fn garbage_and_a_stranger_key_are_refused() {
    // A hello that reads as nothing.
    let mut session = open_unborn();
    assert!(
        is_refused(session.call(Request::BeginBirth {
            hello: b"nothing".to_vec(),
        })),
        "a bad hello is refused"
    );
    // A finish with no keygen open under it.
    let mut session = open_unborn();
    let stranger = kit::Parties::new().owner.public();
    assert!(
        is_refused(session.call(Request::FinishBirth {
            fin: b"nothing".to_vec(),
            group_key: stranger,
        })),
        "a finish with no keygen open is refused"
    );
    // The container share of this birth under another key: the two sides
    // hold halves of different keys.
    let mut session = open_unborn();
    let mut rng = kit::TestRng(47);
    let (keygen, hello) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    let reply = begin(&mut session, &hello.to_bytes().expect("bytes"));
    let reply = KeygenReply::from_bytes(&reply).expect("the reply reads");
    let (_half, _group, fin) = keygen.finish(&reply).expect("the mobile side keeps its half");
    let stranger = kit::Parties::new().owner.public();
    match session.call(Request::FinishBirth {
        fin: fin.to_bytes().expect("the finish encodes").to_vec(),
        group_key: stranger,
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("different keys"),
            "the halves must match, got: {reason}"
        ),
        other => panic!("a stranger's key is refused: {other:?}"),
    }
}

#[test]
fn a_born_container_answers_no_birth() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session =
        Session::open(&capsule, &side, Vec::new()).expect("the born capsule opens");
    let mut rng = kit::TestRng(53);
    let (_keygen, hello) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    assert!(
        is_refused(session.call(Request::BeginBirth {
            hello: hello.to_bytes().expect("bytes"),
        })),
        "a born container refuses BeginBirth"
    );
}
