//! The session natively (`Spec_kapsula` §10 item 3): open the capsule, drive a
//! command, close, open again — the work is still there.
//!
//! The container is a real one of the light class, initiated and with its
//! journal open; the capsule is assembled by the stand (`kit`) the way the
//! reader will assemble it.

mod kit;

use ksg_capsule_module::session::{Answer, Request, Session};
use ksg_container_v2::capsule::CAPSULE_SIZE;

/// The state a `Status` answers with.
fn status_of(session: &mut Session) -> serde_json::Value {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("the status is JSON"),
        other => panic!("status is not done: {other:?}"),
    }
}

#[test]
fn a_page_written_in_a_session_survives_the_capsule() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();

    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    let before = status_of(&mut session);
    assert_eq!(before["born"], true);
    // Page 0 is the journal's opening, written by the stand.
    assert_eq!(before["pages"], 1, "page 0, the opening: {before}");
    assert_eq!(before["status"], "InWork");

    match session.call(Request::Work { text: "x".into() }) {
        Answer::Done { .. } => {}
        other => panic!("work is not done: {other:?}"),
    }
    let after = status_of(&mut session);
    assert_eq!(after["pages"], 2, "the record of work is a page: {after}");

    let (capsule, outputs) = session.close().expect("the capsule closes");
    assert_eq!(capsule.len(), CAPSULE_SIZE, "a capsule is one size");
    assert!(
        outputs.is_empty(),
        "no export, no initiation: nothing outside"
    );

    let mut again = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens again");
    let reopened = status_of(&mut again);
    assert_eq!(
        reopened["pages"], 2,
        "the page survived the capsule: {reopened}"
    );
    assert_eq!(reopened["id"], after["id"], "the same container");
}

#[test]
fn the_keys_are_the_clients_and_an_uninitiated_capsule_has_none() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    match session.call(Request::Keys) {
        Answer::Done { bytes } => {
            let keys: Vec<serde_json::Value> =
                serde_json::from_slice(&bytes).expect("the keys are JSON");
            assert_eq!(keys.len(), 1, "one client's key");
        }
        other => panic!("keys are not done: {other:?}"),
    }
}

#[test]
fn another_party_s_map_does_not_open_the_capsule() {
    let mut stand = kit::Fixture::started();
    let capsule = stand.capsule();
    let mut file: serde_json::Value =
        serde_json::from_slice(&stand.side_file()).expect("the side file is JSON");
    // The same file with another map's seed (32 zero bytes): not this
    // capsule's party, so no slot opens.
    file["map"] = serde_json::Value::String("A".repeat(43));
    let side = serde_json::to_vec(&file).expect("the side file encodes");
    let refused = Session::open(&capsule, &side, Vec::new());
    assert!(
        refused.is_err(),
        "another party's map opens no slot of this capsule"
    );
}

#[test]
fn a_side_file_of_another_container_is_refused() {
    let mut stand = kit::Fixture::started();
    let capsule = stand.capsule();
    let mut file: serde_json::Value =
        serde_json::from_slice(&stand.side_file()).expect("the side file is JSON");
    // A well-formed multihash of another container.
    file["container"] = serde_json::Value::String(format!("1220{}", "ab".repeat(32)));
    let side = serde_json::to_vec(&file).expect("the side file encodes");
    let refused = Session::open(&capsule, &side, Vec::new());
    assert!(
        refused.is_err(),
        "a side file naming another container does not open this one"
    );
}

/// A Pro `work` owes the network: the module presses with a placeholder and
/// answers `NeedsAnchor` with the seal's subject, and the reader's
/// `Reanchor` swaps the placeholder for the attestation — then `Done`.
#[test]
fn a_pro_work_owes_its_seal_to_the_network() {
    let mut stand = kit::Fixture::started_heavy();
    let side = stand.side_file();
    let capsule = stand.capsule();

    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    let before = status_of(&mut session);
    assert_eq!(before["pages"], 1, "page 0, the opening: {before}");

    let top = before["top_seal"]
        .as_str()
        .expect("the status names the top seal")
        .to_string();
    match session.call(Request::Work { text: "x".into() }) {
        Answer::NeedsAnchor {
            kind,
            prev,
            subject,
            bytes,
        } => {
            assert_eq!(kind, ksg_capsule_module::session::AnchorKind::Seal);
            assert_eq!(prev, top, "the seal links to the seal before it");
            let after_press = status_of(&mut session);
            assert_eq!(
                after_press["top_seal"].as_str(),
                Some(subject.as_str()),
                "the subject is the seal just pressed"
            );
            assert_ne!(subject, top, "the press moved the top seal");
            let memo: serde_json::Value =
                serde_json::from_slice(&bytes).expect("the memo's input is JSON");
            assert_eq!(memo["kind"], "seal");
            assert_eq!(memo["subject"], subject);

            // A stranger's attestation is refused: the module waits for this
            // seal's anchor, not just any anchor.
            let stranger = kit::attestation_for(&format!("1220{}", "cd".repeat(32)));
            match session.call(Request::Reanchor {
                attestation: serde_json::to_vec(&stranger).expect("the attestation encodes"),
            }) {
                Answer::Refused { .. } => {}
                other => panic!("a stranger's anchor is refused: {other:?}"),
            }

            // The network's attestation for the subject: the placeholder
            // goes, the press stays, the answer is `Done`.
            let attestation = kit::attestation_for(&subject);
            match session.call(Request::Reanchor {
                attestation: serde_json::to_vec(&attestation).expect("the attestation encodes"),
            }) {
                Answer::Done { .. } => {}
                other => panic!("the reanchor is done: {other:?}"),
            }
        }
        other => panic!("a Pro work owes its anchor: {other:?}"),
    }
    let after = status_of(&mut session);
    assert_eq!(after["pages"], 2, "the record of work is a page: {after}");

    let (capsule, _) = session
        .close()
        .expect("the capsule closes with no anchor owed");
    let mut again = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens again");
    let reopened = status_of(&mut again);
    assert_eq!(
        reopened["pages"], 2,
        "the page survived the capsule: {reopened}"
    );
}

/// A Pro `open_journal` needs the owner's co-seal (CH-26): the module
/// answers `NeedsSignature { party: owner }` over the seal's bytes, the
/// kit-owner's `Sign` presses page 0 with a placeholder, and the reader's
/// `Reanchor` swaps it for the attestation — then `Done`. A stranger's
/// signature over the same bytes is refused by the container.
#[test]
fn a_pro_opening_needs_the_owners_seal() {
    use ksg_core_v2::crypto::sign::Ed25519Signer;

    let mut stand = kit::Fixture::started_heavy_unopened();
    let side = stand.side_file();
    let capsule = stand.capsule();

    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    let before = status_of(&mut session);
    assert_eq!(before["born"], true);
    assert_eq!(before["pages"], 0, "the journal is not open yet: {before}");
    assert_eq!(before["status"], "Initiated");

    let bytes = match session.call(Request::OpenJournal) {
        Answer::NeedsSignature { party, bytes } => {
            assert_eq!(party, "owner");
            bytes
        }
        other => panic!("a Pro opening waits for the owner: {other:?}"),
    };
    // A second call while the co-seal is missing: the same bytes.
    match session.call(Request::OpenJournal) {
        Answer::NeedsSignature { party, bytes: again } => {
            assert_eq!(party, "owner");
            assert_eq!(again, bytes, "the opening is not re-ticked");
        }
        other => panic!("the same wait: {other:?}"),
    }
    // A stranger's signature over the same bytes is refused: the container
    // checks the co-seal against the owner's pinned key.
    let stranger = Ed25519Signer::from_seed(kit::uri("did:key:zStranger#s1"), [99; 32]);
    match session.call(Request::Sign {
        signature: serde_json::to_vec(&stranger.sign(&bytes)).expect("the signature encodes"),
    }) {
        Answer::Refused { .. } => {}
        other => panic!("a stranger's co-seal is refused: {other:?}"),
    }
    assert!(
        session.close().is_err(),
        "a close with an opening pending is refused"
    );

    // The kit-owner's co-seal presses page 0: Pro owes the seal's anchor.
    let id = before["id"].as_str().expect("the status names the id");
    match session.call(Request::Sign {
        signature: serde_json::to_vec(&stand.parties.owner.sign(&bytes))
            .expect("the signature encodes"),
    }) {
        Answer::NeedsAnchor {
            kind,
            prev,
            subject,
            bytes: memo,
        } => {
            assert_eq!(kind, ksg_capsule_module::session::AnchorKind::Seal);
            assert_eq!(prev, id, "page 0 links to the container");
            assert_ne!(subject, prev, "the press moved the top seal");
            let memo: serde_json::Value =
                serde_json::from_slice(&memo).expect("the memo's input is JSON");
            assert_eq!(memo["kind"], "seal");
            assert_eq!(memo["subject"], subject);

            // The seal's attestation: the press stays, the status record
            // owes its own anchor next.
            let seal_attestation = kit::attestation_for(&subject);
            match session.call(Request::Reanchor {
                attestation: serde_json::to_vec(&seal_attestation)
                    .expect("the attestation encodes"),
            }) {
                Answer::NeedsAnchor {
                    kind,
                    subject: status_subject,
                    bytes: _,
                    ..
                } => {
                    assert_eq!(kind, ksg_capsule_module::session::AnchorKind::Status);
                    let status_attestation = kit::attestation_for(&status_subject);
                    match session.call(Request::Reanchor {
                        attestation: serde_json::to_vec(&status_attestation)
                            .expect("the attestation encodes"),
                    }) {
                        Answer::Done { .. } => {}
                        other => panic!("the opening is done: {other:?}"),
                    }
                }
                other => panic!("the status record owes its anchor: {other:?}"),
            }
        }
        other => panic!("the owner's co-seal presses page 0: {other:?}"),
    }
    let after = status_of(&mut session);
    assert_eq!(after["pages"], 1, "page 0, the opening: {after}");
    assert_eq!(after["status"], "InWork");

    let (capsule, _) = session
        .close()
        .expect("the capsule closes with no anchor owed");
    let mut again = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens again");
    let reopened = status_of(&mut again);
    assert_eq!(
        reopened["pages"], 1,
        "page 0 survived the capsule: {reopened}"
    );
}

/// A light `work` still presses with its local anchor and answers `Done` —
/// no network is owed.
#[test]
fn a_light_work_owes_nothing() {
    let mut stand = kit::Fixture::started();
    let side = stand.side_file();
    let capsule = stand.capsule();
    let mut session = Session::open(&capsule, &side, Vec::new()).expect("the capsule opens");
    match session.call(Request::Work { text: "x".into() }) {
        Answer::Done { .. } => {}
        other => panic!("a light work is done at once: {other:?}"),
    }
    session.close().expect("the capsule closes");
}
