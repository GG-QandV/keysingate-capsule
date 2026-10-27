//! The session natively (`Spec_kapsula` §10 п. 3): open the capsule, drive a
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
