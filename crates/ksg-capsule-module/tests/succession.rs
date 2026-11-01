//! C10 (`Spec_kapsula`, CH-12): E-14 succession from the network and
//! slot 2 of the coupling (`Pull`). Light only — the kit's stand builds no
//! `bare`: the `bare` pull refusal is pinned against the kernel directly
//! through the fixture's container, no session between.
//!
//! Samples: `tests/command.rs` (a command from the network), `tests/sale.rs`
//! (a session).

mod kit;

use ksg_capsule_module::session::{
    Answer, CommandEvidence, CommandFile, CommandHead, Request, Session,
};
use ksg_container_v2::client_key::split;
use ksg_container_v2::{Container, Event, Operation, Release, Role, Wrapped};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::{sign_doc, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::{derive_container_id, Class, Context, MemoFormat};
use ksg_core_v2::section::{section_root, StatusRecord, StatusSection};
use ksg_core_v2::status::Status;

fn status(session: &mut Session) -> serde_json::Value {
    match session.call(Request::Status) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("the status is JSON"),
        other => panic!("status is not done: {other:?}"),
    }
}

/// A born, working capsule and its session.
fn open(stand: &mut kit::Fixture) -> Session {
    let side = stand.side_file();
    let capsule = stand.capsule();
    Session::open(&capsule, &side, Vec::new()).expect("the capsule opens")
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
        head: stand
            .container
            .head()
            .map(|h| CommandHead { counter: h.counter, page: h.page }),
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

fn pending(session: &mut Session) -> Vec<serde_json::Value> {
    match session.call(Request::PendingTasks) {
        Answer::Done { bytes } => serde_json::from_slice(&bytes).expect("pending tasks are JSON"),
        other => panic!("pending tasks are not done: {other:?}"),
    }
}

/// E-14 with no heir: the container succeeds to nobody. The press moves the
/// status to `Done`, and `PendingTasks` holds a `carry_id` case for the
/// successor outside — one that blocks nothing.
#[test]
fn e14_without_an_heir_is_done_and_leaves_a_carry_id() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let before = status(&mut session)["status"].clone();
    let file = command(&stand, Operation::Succeed, CommandEvidence::None, |m| {
        stand.issuer_signs(m)
    });
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(matches!(answer, Answer::Done { .. }), "E-14 is not pressed: {answer:?}");
    assert_ne!(status(&mut session)["status"], before, "the status did not move");
    let tasks = pending(&mut session);
    assert!(
        tasks.iter().any(|t| t["task"] == "carry_id"),
        "no carry_id after E-14: {tasks:?}"
    );
}

/// E-14 with an heir: the issuer's command carries slot 1 of the coupling,
/// and the journal grows by one page.
#[test]
fn e14_with_an_heir_writes_its_page() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let pages = status(&mut session)["pages"].as_u64().expect("pages");
    let leader = Hash::sha256(b"the successor");
    let file = command(
        &stand,
        Operation::Succeed,
        CommandEvidence::AttachedTo { leader },
        |m| stand.issuer_signs(m),
    );
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(matches!(answer, Answer::Done { .. }), "E-14 is not pressed: {answer:?}");
    assert_eq!(
        status(&mut session)["pages"].as_u64(),
        Some(pages + 1),
        "the coupling is no page"
    );
}

/// E-14 to itself: the kernel refuses — the leader is never this container.
#[test]
fn e14_to_itself_is_refused() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let pages = status(&mut session)["pages"].as_u64().expect("pages");
    let leader = *stand.container.id();
    let file = command(
        &stand,
        Operation::Succeed,
        CommandEvidence::AttachedTo { leader },
        |m| stand.issuer_signs(m),
    );
    let subject = file.subject().expect("a subject");
    let answer = apply(&mut session, &file, &subject);
    assert!(
        matches!(answer, Answer::Refused { .. }),
        "a succession to itself presses: {answer:?}"
    );
    assert_eq!(status(&mut session)["pages"].as_u64(), Some(pages), "a refusal wrote a page");
}

/// E-5 slot 2 through the session's `Pull`: `light` pulls the trailer and
/// the journal grows by one page.
#[test]
fn pull_in_light_writes_its_page() {
    let mut stand = kit::Fixture::started();
    let mut session = open(&mut stand);
    let pages = status(&mut session)["pages"].as_u64().expect("pages");
    let answer = session.call(Request::Pull {
        trailer: Hash::sha256(b"the trailer"),
        trailer_seal: Hash::sha256(b"the trailer's seal"),
    });
    assert!(matches!(answer, Answer::Done { .. }), "Pull is not pressed: {answer:?}");
    assert_eq!(
        status(&mut session)["pages"].as_u64(),
        Some(pages + 1),
        "the pull is no page"
    );
}

/// Slot 2 in `bare`: the kernel refuses — `bare` never pulls a trailer
/// ("bare is a follower only"). The kit's stand builds no `bare` session: the
/// same container the fixture holds, in the `bare` class, refuses the same
/// pull through `Container::press` directly — the check is the kernel's, the
/// session only carries it through.
#[test]
fn pull_in_bare_is_refused_by_the_kernel() {
    use ksg_container_v2::container::{Evidence, Writes};
    use ksg_container_v2::Roster;

    let mut light = kit::Fixture::started();
    let trailer = Hash::sha256(b"the trailer");
    let trailer_seal = Hash::sha256(b"the trailer's seal");
    let evidence =
        ksg_core_v2::journal::CouplingRecord::Pulls { trailer, trailer_seal };
    let evidence = Evidence::Coupling(evidence);

    // The same container's key material, in the `bare` class: printed the way
    // the kit prints, then born and opened like the fixture.
    let (inside, mobile) = split(kit::client_kid(), &mut kit::TestRng(7)).expect("split");
    let client = inside.public().clone();
    let template = section_root(kit::EMISSION, kit::SERIAL);
    let issued_at = kit::ts("2026-09-01T00:00:00.000Z");
    let id = derive_container_id(
        kit::EMISSION,
        &issued_at,
        kit::SERIAL,
        &client,
        &kit::uri(kit::ARTIFACT),
        kit::OFFSET,
    );
    let mut r0 = StatusRecord {
        context: Context,
        doc_type: "StatusRecord".into(),
        v: 3,
        number: 0,
        status: Status::Printed,
        event: None,
        offset_ms: 0,
        prev: template,
        signatures: SignatureSet::default(),
    };
    r0.signatures =
        SignatureSet::new(vec![sign_doc(&r0, &light.parties.issuer).expect("the issuer's word")]);
    let a0 = kit::anchor(r0.hash().expect("record 0 hashes"));
    let issuer_keys: KeySet = [light.parties.issuer.public()].into_iter().collect();
    let section = StatusSection::start(
        kit::EMISSION,
        kit::SERIAL,
        r0,
        a0,
        &issuer_keys,
        &Profile::default(),
    )
    .expect("the section starts");
    let roster = Roster::of([
        (light.parties.issuer.public(), Role::Issuer),
        (light.parties.owner.public(), Role::Owner),
        (light.parties.buyer.public(), Role::Buyer),
        (client.clone(), Role::Client),
    ]);
    let release = Release {
        id: kit::EMISSION.into(),
        issued_at,
        class: Class::Bare,
    };
    let mut bare = Container::assemble(
        id,
        release,
        kit::SERIAL,
        client,
        MemoFormat::Controlled,
        section,
        roster,
    );
    bare.integrate_client_key(inside).expect("the container's half");

    let mut event = Event {
        op: Operation::RecordWork,
        button: Operation::RecordWork.button(),
        container: *bare.id(),
        payload: Wrapped::received(b"a pull from the stand".to_vec()),
        signatures: SignatureSet::default(),
        covered: Vec::new(),
        head: bare.head(),
    };
    event.covered = event.subject();
    let covered = event.covered.clone();
    let (nonces, commitment) = mobile.commit(&mut kit::TestRng(7));
    let round = bare
        .begin_signing(&covered, &commitment, &mut kit::TestRng(7))
        .expect("the container opens a round");
    let share = mobile.respond(nonces, &round).expect("the mobile half");
    event.signatures = SignatureSet::new(bare.finish_signing(&share, &mut kit::TestRng(7)).expect("signs"));
    let keys = bare.roster().keys().clone();
    let refused = bare.press(&event, &evidence, Writes { page: None, status: None, at_ms: Some(1) }, &keys, &Profile::default());
    assert!(refused.is_err(), "a bare pulls: {refused:?}");
    let _ = &mut light;
}
