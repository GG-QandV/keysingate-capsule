//! K3 (`Spec_kapsula` §27): a command from the network — signed by a party
//! that holds no map, anchored, handed in through `Request::ApplyCommand`.

mod kit;

use ksg_capsule_module::session::{
    Answer, CommandEvidence, CommandFile, CommandHead, Request, Session,
};
use ksg_container_v2::Operation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::SignatureSet;

fn status(session: &mut Session) -> serde_json::Value {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("the status is JSON"),
        other => panic!("status is not done: {other:?}"),
    }
}

/// A born, working capsule and its session.
fn open() -> (kit::Fixture, Session) {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    (stand, session)
}

/// A command for the fixture's container, signed by `sign`.
fn command(
    stand: &kit::Fixture,
    op: Operation,
    evidence: CommandEvidence,
    sign: impl Fn(&[u8]) -> ksg_core_v2::crypto::sign::Signature,
) -> CommandFile {
    let mut file = CommandFile {
        v: 1,
        op,
        container: *stand.container.id(),
        head: stand.container.head().map(|h| CommandHead { counter: h.counter, page: h.page }),
        evidence,
        signatures: SignatureSet::default(),
    };
    let subject = file.subject().expect("a subject");
    file.signatures = SignatureSet::new(vec![sign(&subject)]);
    file
}

fn apply(session: &mut Session, file: &CommandFile, anchored: &[u8]) -> Answer {
    let attestation = serde_json::to_vec(&kit::anchor(Hash::sha256(anchored))).expect("JSON");
    session.call(Request::ApplyCommand {
        file: serde_json::to_vec(file).expect("JSON"),
        attestation,
    })
}

#[test]
fn the_issuers_finalize_from_the_network_presses_once() {
    let (stand, mut session) = open();
    let before = status(&mut session)["status"].clone();
    let file = command(&stand, Operation::Finalize, CommandEvidence::None, |m| stand.issuer_signs(m));
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(matches!(answer, Answer::Done { .. }), "the command is not pressed: {answer:?}");
    assert_ne!(status(&mut session)["status"], before, "Finalize moved the status");
    // The same command again: refused — the container is past it.
    let again = apply(&mut session, &file, &subject);
    assert!(matches!(again, Answer::Refused { .. }), "a replay presses: {again:?}");
}

#[test]
fn the_issuers_e24_writes_its_page_and_a_replay_is_stale() {
    let (stand, mut session) = open();
    let pages = status(&mut session)["pages"].as_u64().expect("pages");
    let hash = Hash::sha256(b"declaration of lost shares");
    let file = command(&stand, Operation::DeclareSharesLost, CommandEvidence::SharesLost { hash }, |m| {
        stand.issuer_signs(m)
    });
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(matches!(answer, Answer::Done { .. }), "E-24 is not pressed: {answer:?}");
    assert_eq!(status(&mut session)["pages"].as_u64(), Some(pages + 1), "the declaration is a page");
    let again = apply(&mut session, &file, &subject);
    assert!(
        matches!(&again, Answer::Refused { reason } if reason.contains("head")),
        "a replay with a stale head presses: {again:?}"
    );
}

#[test]
fn a_command_that_does_not_hold_is_refused() {
    let (stand, mut session) = open();
    // Signed by somebody who is not the issuer.
    let file = command(&stand, Operation::Finalize, CommandEvidence::None, |m| stand.stranger_signs(m));
    let subject = file.subject().expect("a subject");
    assert!(matches!(apply(&mut session, &file, &subject), Answer::Refused { .. }), "a stranger finalizes");

    // An anchor of other bytes.
    let file = command(&stand, Operation::Finalize, CommandEvidence::None, |m| stand.issuer_signs(m));
    let answer = apply(&mut session, &file, b"other bytes");
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("anchor")),
        "an anchor of other bytes: {answer:?}"
    );

    // The load changed under the same signatures, with an anchor of the new
    // bytes: the signatures cover the load, the container refuses.
    let mut file = command(&stand, Operation::DeclareSharesLost, CommandEvidence::SharesLost {
        hash: Hash::sha256(b"one"),
    }, |m| stand.issuer_signs(m));
    file.evidence = CommandEvidence::SharesLost { hash: Hash::sha256(b"another") };
    let subject = file.subject().expect("a subject");
    assert!(matches!(apply(&mut session, &file, &subject), Answer::Refused { .. }), "a changed load presses");

    // An operation that does not come from the network.
    let file = command(&stand, Operation::RecordWork, CommandEvidence::None, |m| stand.issuer_signs(m));
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(
        matches!(&answer, Answer::Refused { reason } if reason.contains("does not come from the network")),
        "{answer:?}"
    );

    // Another container's command.
    let mut file = command(&stand, Operation::Finalize, CommandEvidence::None, |m| stand.issuer_signs(m));
    file.container = Hash::sha256(b"another container");
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(matches!(&answer, Answer::Refused { reason } if reason.contains("another container")), "{answer:?}");
}
