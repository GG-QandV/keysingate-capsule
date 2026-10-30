//! The client signing round across the wire (track I4): with no half
//! inside, every client signature spans `NeedsClientCommit` / `ClientCommit`
//! / `NeedsShare` / `ClientShare` — one round per message — and the command
//! repeated picks the closed rounds up until `Done`.
//!
//! The session below is born over the wire (as in `birth.rs`), so its
//! container is initiated but the mobile half stays outside: a `Work` signs
//! round by round. Garbage, double commits, and a stranger's share are
//! refused, and a refused round drops without breaking the next one.

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_container_v2::client_key::{KeygenReply, MobileHalf, MobileKeygen, SigningRound};

/// A session born over the wire: the container initiated, the mobile half
/// outside, the owner's signer still at hand.
struct WireBorn {
    stand: kit::Fixture,
    session: Session,
    half: MobileHalf,
    rng: kit::TestRng,
}

/// Message 2 out of `BeginBirth`, decoded from the answer.
fn begin(session: &mut Session, hello: &[u8]) -> Vec<u8> {
    match session.call(Request::BeginBirth {
        hello: hello.to_vec(),
    }) {
        Answer::Done { bytes } => {
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("the reply is JSON");
            use base64::Engine as _;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v["reply"].as_str().expect("a reply field"))
                .expect("a base64url reply")
        }
        other => panic!("BeginBirth is not done: {other:?}"),
    }
}

/// One client round closed: the mobile half commits, the container answers
/// the round, the mobile half shares, the share goes in.
fn close_round(session: &mut Session, round_msg: &[u8], half: &MobileHalf, rng: &mut kit::TestRng) {
    let (nonces, commitment) = half.commit(rng);
    let round = match session.call(Request::ClientCommit {
        commitment: commitment.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => {
            let round = SigningRound::from_bytes(&round).expect("the round reads");
            assert_eq!(
                round.message(),
                round_msg,
                "the round signs what was asked for"
            );
            round
        }
        other => panic!("the commitment opens the round: {other:?}"),
    };
    let share = half
        .respond(nonces, &round)
        .expect("the mobile side answers");
    match session.call(Request::ClientShare {
        share: share.to_bytes(),
    }) {
        Answer::Done { .. } => {}
        other => panic!("the share closes the round: {other:?}"),
    }
}

/// The birth pressed over the wire, owner included: a born session with no
/// half inside.
fn wire_born() -> WireBorn {
    let mut stand = kit::Fixture::unborn();
    let side = stand.side_file_empty();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the template opens");
    let mut rng = kit::TestRng(101);
    let (keygen, hello) = MobileKeygen::start(kit::client_kid(), &mut rng).expect("start");
    let reply = begin(&mut session, &hello.to_bytes().expect("the hello encodes"));
    let reply = KeygenReply::from_bytes(&reply).expect("the reply reads");
    let (half, group, fin) = keygen
        .finish(&reply)
        .expect("the mobile side keeps its half");
    let fin = fin.to_bytes().expect("the finish encodes").to_vec();
    let round_msg = match session.call(Request::FinishBirth {
        fin: fin.clone(),
        group_key: group.clone(),
    }) {
        Answer::NeedsClientCommit { round } => {
            assert!(!round.is_empty(), "there are bytes to sign");
            round
        }
        other => panic!("a correct finish waits for the client round: {other:?}"),
    };
    close_round(&mut session, &round_msg, &half, &mut rng);
    // The repeated finish re-presses: its press breaks off at the
    // owner's check, whose signature goes in through `Sign` — and the
    // final `Sign` re-presses the same event + status record to done.
    // The client round only spans the first repeat (the event); after it
    // the signature waits in `pending_client_sigs`, so the loop closes
    // every `NeedsClientCommit` exactly once and answers the press again.
    let mut owner_bytes = Vec::new();
    for _ in 0..20 {
        match session.call(Request::FinishBirth {
            fin: fin.clone(),
            group_key: group.clone(),
        }) {
            Answer::Done { .. } => {
                return WireBorn {
                    stand,
                    session,
                    half,
                    rng,
                };
            }
            Answer::NeedsClientCommit { round } => {
                close_round(&mut session, &round, &half, &mut rng);
            }
            Answer::NeedsShare { round } => {
                panic!("a share with no commitment open: {round:?}");
            }
            Answer::NeedsSignature { party, bytes } => {
                assert_eq!(party, "owner", "the initiation still owes the owner");
                owner_bytes = bytes;
                break;
            }
            other => panic!("the repeated finish presses the birth: {other:?}"),
        }
    }
    assert!(!owner_bytes.is_empty(), "the press reached the owner");
    let sig = stand.parties.owner.sign(&owner_bytes);
    // The owner's seal goes in through `Sign`; the loop below answers
    // whatever the press still owes until `Done`. One subtlety: this
    // session has no half, but the stand-path bytes we hand to the owner
    // were signed by the kit's owner, while `Session::open` refused the
    // owner's side file — the press signs the client first, and the client
    // round for the right message (`pending bytes` trip) opens fresh each
    // time until both signatures are in the press together. Every answer
    // means the press broke off again; the same press goes back in until
    // done.
    let mut cmd: Request = Request::Sign {
        signature: serde_json::to_vec(&sig).expect("the signature encodes"),
    };
    let mut done = false;
    let mut n_rounds = 0u32;
    let mut cmd_label = String::from("sign");
    let mut last = String::from("no answer yet");
    let mut seen: Vec<String> = Vec::new();
    for i in 0..60 {
        seen.push(cmd_label.clone());
        let label_before = cmd_label.clone();
        let answer = session.call(cmd);
        last = format!("{label_before} loop {i}: {answer:?}");
        match answer {
            Answer::Done { .. } => {
                done = true;
                break;
            }
            Answer::NeedsClientCommit { round } => {
                n_rounds += 1;
                assert!(
                    n_rounds <= 6,
                    "the press closes a few rounds, then moves: {last}"
                );
                close_round(&mut session, &round, &half, &mut rng);
                cmd_label = String::from("sign_after_round");
                cmd = Request::Sign {
                    signature: serde_json::to_vec(&sig).expect("the signature encodes"),
                };
            }
            Answer::NeedsShare { round } => {
                panic!("a share with no commitment open: {round:?}");
            }
            Answer::NeedsSignature { party, bytes } => {
                assert_eq!(party, "owner", "the initiation still owes the owner");
                assert_eq!(bytes, owner_bytes, "the same bytes");
                cmd_label = String::from("sign_again");
                cmd = Request::Sign {
                    signature: serde_json::to_vec(&sig).expect("the signature encodes"),
                };
            }
            Answer::NeedsAnchor { subject, .. } => {
                let attestation = kit::attestation_for(&subject);
                cmd_label = String::from("reanchor");
                cmd = Request::Reanchor {
                    attestation: serde_json::to_vec(&attestation).expect("the attestation encodes"),
                };
            }
            _other => {
                cmd_label = String::from("refused-or-more");
                cmd = Request::FinishBirth {
                    fin: fin.clone(),
                    group_key: group.clone(),
                };
            }
        }
    }
    assert!(done, "the press went to done, last: {last}, seen: {seen:?}");
    // The birth pressed the initiation; the journal opens next (page 0),
    // as on the stand — through the same wire round (I4g).
    drive_opening(&mut session, &half, &mut rng);
    WireBorn {
        stand,
        session,
        half,
        rng,
    }
}

fn pages_of(session: &mut Session) -> u64 {
    match session.call(Request::Status) {
        Answer::Done { bytes } => {
            let v: serde_json::Value = serde_json::from_slice(&bytes).expect("the status is JSON");
            assert_eq!(v["born"], true, "the wire birth pressed: {v}");
            v["pages"].as_u64().expect("a page count")
        }
        other => panic!("the status is not done: {other:?}"),
    }
}

/// A `Work` driven to `Done` through the wire round, one round per message.
/// Returns the round messages it signed and the closing `Done` payload.
fn drive_opening(session: &mut Session, half: &MobileHalf, rng: &mut kit::TestRng) {
    loop {
        match session.call(Request::OpenJournal) {
            Answer::Done { .. } => return,
            Answer::NeedsClientCommit { round } => {
                close_round(session, &round, half, rng);
            }
            other => panic!("the opening drives the wire round: {other:?}"),
        }
    }
}
fn drive_work(
    session: &mut Session,
    text: &str,
    half: &MobileHalf,
    rng: &mut kit::TestRng,
) -> (Vec<Vec<u8>>, serde_json::Value) {
    let mut msgs = Vec::new();
    loop {
        assert!(msgs.len() < 10, "the work does not loop forever");
        match session.call(Request::Work { text: text.into() }) {
            Answer::Done { bytes } => {
                let v: serde_json::Value =
                    serde_json::from_slice(&bytes).expect("the work answer is JSON");
                for i in 0..msgs.len() {
                    for j in (i + 1)..msgs.len() {
                        assert_ne!(msgs[i], msgs[j], "every round signs its own message");
                    }
                }
                return (msgs, v);
            }
            Answer::NeedsClientCommit { round } => {
                assert!(!round.is_empty(), "there are bytes to sign");
                close_round(session, &round, half, rng);
                msgs.push(round);
            }
            other => panic!("the work drives the wire round: {other:?}"),
        }
    }
}

#[test]
fn work_without_a_half_signs_round_by_round_until_done() {
    let wb = wire_born();
    let mut session = wb.session;
    let half = wb.half;
    let mut rng = wb.rng;
    let before = pages_of(&mut session);
    let (msgs, done) = drive_work(&mut session, "a line of work", &half, &mut rng);
    assert!(
        msgs.len() >= 2,
        "the event and its seal are two messages, so two rounds: {}",
        msgs.len()
    );
    assert_eq!(
        done["pages"].as_u64().expect("a page count"),
        before + 1,
        "the record of work is a page: {done}"
    );
}

#[test]
fn commit_and_share_with_no_round_waiting_are_refused() {
    let WireBorn {
        stand: _stand,
        mut session,
        half,
        mut rng,
    } = wire_born();
    match session.call(Request::ClientCommit {
        commitment: b"nothing".to_vec(),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("no client round waits"),
            "nothing asked: {reason}"
        ),
        other => panic!("a lone commitment is refused: {other:?}"),
    }
    match session.call(Request::ClientShare {
        share: b"nothing".to_vec(),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("no client round open"),
            "nothing open: {reason}"
        ),
        other => panic!("a lone share is refused: {other:?}"),
    }
    // The refusals broke nothing: the work still drives to done.
    let (msgs, _) = drive_work(&mut session, "after refusals", &half, &mut rng);
    assert!(!msgs.is_empty(), "rounds still open");
}

#[test]
fn a_second_commit_while_open_is_refused_and_the_round_survives() {
    let wb = wire_born();
    let mut session = wb.session;
    let mut rng = wb.rng;
    let round_msg = match session.call(Request::Work {
        text: "double commit".into(),
    }) {
        Answer::NeedsClientCommit { round } => round,
        other => panic!("the work waits for a commitment: {other:?}"),
    };
    let (nonces, first) = wb.half.commit(&mut rng);
    let round = match session.call(Request::ClientCommit {
        commitment: first.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => round,
        other => panic!("the first commitment opens the round: {other:?}"),
    };
    let (_, second) = wb.half.commit(&mut rng);
    match session.call(Request::ClientCommit {
        commitment: second.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("already open"),
            "one round at a time: {reason}"
        ),
        other => panic!("a second commitment is refused: {other:?}"),
    }
    // The open round survived the refusal: its share still closes it.
    let round = SigningRound::from_bytes(&round).expect("the round reads");
    assert_eq!(round.message(), round_msg.as_slice());
    let share = wb
        .half
        .respond(nonces, &round)
        .expect("the mobile side answers");
    match session.call(Request::ClientShare {
        share: share.to_bytes(),
    }) {
        Answer::Done { .. } => {}
        other => panic!("the surviving round closes: {other:?}"),
    }
    let (msgs, _) = drive_work(&mut session, "double commit", &wb.half, &mut rng);
    assert!(!msgs.is_empty(), "the work still drives to done");
}

#[test]
fn garbage_commitment_is_refused_then_a_good_one_opens() {
    let wb = wire_born();
    let mut session = wb.session;
    let mut rng = wb.rng;
    let round_msg = match session.call(Request::Work {
        text: "bad commitment".into(),
    }) {
        Answer::NeedsClientCommit { round } => round,
        other => panic!("the work waits for a commitment: {other:?}"),
    };
    match session.call(Request::ClientCommit {
        commitment: b"nothing".to_vec(),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("does not read"),
            "garbage reads as nothing: {reason}"
        ),
        other => panic!("garbage is refused: {other:?}"),
    }
    // The message still waits: a good commitment opens its round.
    close_round(&mut session, &round_msg, &wb.half, &mut rng);
    let (msgs, _) = drive_work(&mut session, "bad commitment", &wb.half, &mut rng);
    assert!(!msgs.is_empty(), "the work still drives to done");
}

#[test]
fn a_strangers_share_does_not_close_and_a_fresh_round_does() {
    let wb = wire_born();
    let mut session = wb.session;
    let mut rng = wb.rng;
    let round_msg = match session.call(Request::Work {
        text: "stranger share".into(),
    }) {
        Answer::NeedsClientCommit { round } => round,
        other => panic!("the work waits for a commitment: {other:?}"),
    };
    // Garbage instead of a share: refused, and the round drops with it.
    let (nonces_old, commitment_old) = wb.half.commit(&mut rng);
    let round_old = match session.call(Request::ClientCommit {
        commitment: commitment_old.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => round,
        other => panic!("the commitment opens the round: {other:?}"),
    };
    match session.call(Request::ClientShare {
        share: b"nothing".to_vec(),
    }) {
        Answer::Refused { .. } => {}
        other => panic!("garbage is refused: {other:?}"),
    }
    match session.call(Request::ClientShare {
        share: b"nothing".to_vec(),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("no client round open"),
            "the refused round dropped: {reason}"
        ),
        other => panic!("nothing open now: {other:?}"),
    }
    // A fresh round over the same message: its package differs (fresh
    // nonces), so the old package's share is a stranger's — refused.
    let round_msg2 = match session.call(Request::Work {
        text: "stranger share".into(),
    }) {
        Answer::NeedsClientCommit { round } => round,
        other => panic!("the work waits again: {other:?}"),
    };
    assert_eq!(
        round_msg2, round_msg,
        "the same work asks for the same bytes"
    );
    let (_, commitment_new) = wb.half.commit(&mut rng);
    let round_new = match session.call(Request::ClientCommit {
        commitment: commitment_new.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => round,
        other => panic!("the fresh commitment opens: {other:?}"),
    };
    assert_ne!(round_new, round_old, "fresh nonces, a fresh package");
    let old_package = SigningRound::from_bytes(&round_old).expect("the old round reads");
    let stranger = wb
        .half
        .respond(nonces_old, &old_package)
        .expect("the old package answers");
    match session.call(Request::ClientShare {
        share: stranger.to_bytes(),
    }) {
        Answer::Refused { reason } => assert!(
            reason.contains("does not close"),
            "a stranger's share does not verify: {reason}"
        ),
        other => panic!("the stranger's share is refused: {other:?}"),
    }
    // The refused round dropped; a fresh one drives the work to done.
    let (msgs, _) = drive_work(&mut session, "stranger share", &wb.half, &mut rng);
    assert!(!msgs.is_empty(), "the work still drives to done");
}

#[test]
fn a_repeat_while_open_repeats_the_same_round() {
    let wb = wire_born();
    let mut session = wb.session;
    let mut rng = wb.rng;
    let round_msg = match session.call(Request::Work {
        text: "same round".into(),
    }) {
        Answer::NeedsClientCommit { round } => round,
        other => panic!("the work waits for a commitment: {other:?}"),
    };
    let (nonces, commitment) = wb.half.commit(&mut rng);
    let round = match session.call(Request::ClientCommit {
        commitment: commitment.to_bytes().expect("the commitment encodes"),
    }) {
        Answer::NeedsShare { round } => round,
        other => panic!("the commitment opens the round: {other:?}"),
    };
    // The command repeated while the round is open: the same round again,
    // not a second one.
    match session.call(Request::Work {
        text: "same round".into(),
    }) {
        Answer::NeedsShare { round: again } => {
            assert_eq!(again, round, "the open round is answered again")
        }
        other => panic!("the repeat answers the open round: {other:?}"),
    }
    let round = SigningRound::from_bytes(&round).expect("the round reads");
    assert_eq!(round.message(), round_msg.as_slice());
    let share = wb
        .half
        .respond(nonces, &round)
        .expect("the mobile side answers");
    match session.call(Request::ClientShare {
        share: share.to_bytes(),
    }) {
        Answer::Done { .. } => {}
        other => panic!("the round closes: {other:?}"),
    }
    let (msgs, _) = drive_work(&mut session, "same round", &wb.half, &mut rng);
    assert!(!msgs.is_empty(), "the work still drives to done");
}

#[test]
fn the_round_speaks_json_on_the_wire() {
    let commit = Request::ClientCommit {
        commitment: vec![1, 2, 3],
    };
    let json = serde_json::to_value(&commit).expect("the request encodes");
    assert_eq!(json["command"], "client_commit");
    let back: Request = serde_json::from_value(json).expect("the request reads");
    assert_eq!(back, commit, "the commitment survives the wire");

    let share = Request::ClientShare { share: vec![4, 5] };
    let json = serde_json::to_value(&share).expect("the request encodes");
    assert_eq!(json["command"], "client_share");
    let back: Request = serde_json::from_value(json).expect("the request reads");
    assert_eq!(back, share, "the share survives the wire");

    let needs = Answer::NeedsClientCommit { round: vec![6, 7] };
    let json = serde_json::to_value(&needs).expect("the answer encodes");
    assert_eq!(json["answer"], "needs_client_commit");
    let back: Answer = serde_json::from_value(json).expect("the answer reads");
    assert_eq!(back, needs, "the round message survives the wire");

    let needs = Answer::NeedsShare { round: vec![8, 9] };
    let json = serde_json::to_value(&needs).expect("the answer encodes");
    assert_eq!(json["answer"], "needs_share");
    let back: Answer = serde_json::from_value(json).expect("the answer reads");
    assert_eq!(back, needs, "the round survives the wire");
}
