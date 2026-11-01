//! `Spec_kapsula` §21, E-9 (C6): the owner hands the container over to a new
//! owner through the capsule. N-3: after the transfer the former owner's map
//! opens nothing, the new owner's opens the owner's slot, the client works on.

use ksg_capsule_module::session::{Answer, Request};
use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print};
use ksg_capsule_reader::side::SideFile;
use ksg_container_v2::capsule::{assemble_split, open_split, MapRole, Part, PartKind};
use ksg_container_v2::layers::SealTo;
use ksg_core_v2::doc::Class;
use rand_core::{OsRng, RngCore as _};

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-transfer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

/// A printed and initiated capsule of `class`, or `None` where the module is
/// not built (`KSG_SKIP_K5=1`).
fn initiated(name: &str, class: Class) -> Option<Layout> {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(
            std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"),
            "build the module for wasm32 first"
        );
        return None;
    }
    let layout = Layout::new(home(name));
    flow::init(&layout, &Print { class, wasm, ..Print::default() }).expect("prints");
    flow::initiate(&layout).expect("initiates");
    Some(layout)
}

fn pages(layout: &Layout) -> u64 {
    flow::status(layout).expect("status")["pages"].as_u64().expect("pages")
}

#[test]
fn after_the_transfer_the_former_owners_map_opens_nothing() {
    let Some(layout) = initiated("light", Class::Light) else { return };
    flow::work(&layout, "a page before the transfer").expect("the client works");
    let former = SideFile::read(&layout.owner_side()).expect("the owner's file");
    let former_json = std::fs::read(layout.owner_side()).expect("the owner's file");
    let client = SideFile::read(&layout.client_side()).expect("the client's file");
    let before = pages(&layout);

    flow::transfer(&layout).expect("the transfer");

    let new = SideFile::read(&layout.owner_side()).expect("the owner's file");
    assert_ne!(new.map, former.map, "the owner's map seed is the new one");
    assert_ne!(new.half, former.half, "the owner's key is the new owner's");
    assert_eq!(new.container, former.container);
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    // N-3: the former owner's map opens nothing; the new one opens the
    // owner's slot; the client's map is the one it was.
    assert!(
        open_split(&capsule, &former.map().expect("a map")).is_err(),
        "N-3: the former owner's map still opens the capsule"
    );
    let opened = open_split(&capsule, &new.map().expect("a map")).expect("the new owner opens");
    assert_eq!(opened.role, MapRole::Owner);
    assert_eq!(client.map, SideFile::read(&layout.client_side()).expect("file").map);
    assert!(open_split(&capsule, &client.map().expect("a map")).is_ok());
    // The former owner's file opens no session any more.
    assert!(
        ksg_capsule_reader::Session::open(&capsule, &former_json, Vec::new()).is_err(),
        "the former owner's file opens a session"
    );

    // The page of the change of owner is in the journal; the client works on.
    assert_eq!(pages(&layout), before + 1, "the transfer's page");
    flow::work(&layout, "a page after the transfer").expect("the client works on");
    // The new owner works: its session opens and exports a page.
    flow::export_page(&layout, 1, Party::Owner).expect("the new owner exports");
    std::fs::remove_dir_all(&layout.home).ok();
}

#[test]
fn without_the_new_owners_signature_the_press_waits() {
    let Some(layout) = initiated("nosign", Class::Light) else { return };
    let before = std::fs::read(layout.capsule()).expect("the capsule");
    let owner_file = std::fs::read(layout.owner_side()).expect("the owner's file");
    let mut session = ksg_capsule_reader::Session::open(
        &before,
        &std::fs::read(layout.client_side()).expect("the client's file"),
        Vec::new(),
    )
    .expect("opens");
    let map = {
        let seed = [9u8; 32];
        let to = ksg_container_v2::layers::OpenWith::from_bytes(seed).seal_to();
        ksg_container_v2::capsule::MapPub {
            role: "owner".into(),
            x25519: base64_url(to.public().as_bytes()),
            mlkem: base64_url(to.mlkem()),
        }
    };
    let new_owner = {
        let seeds: ksg_cli_v2::home::Seeds = serde_json::from_slice(
            &std::fs::read(layout.stand().join("parties.json")).expect("parties"),
        )
        .expect("parties.json");
        ksg_cli_v2::home::Parties::from_seeds(&seeds).expect("parties").buyer.public()
    };
    let request = Request::Transfer { new_owner, owner_map: map };
    // The first signature asked for is the owner's, the second the new
    // owner's; the press does not go in without it.
    let Answer::NeedsSignature { party, bytes } = session.call(&request).expect("a call") else {
        panic!("the transfer asked for no signature");
    };
    assert_eq!(party, "owner");
    let owner = ksg_cli_v2::home::Parties::from_seeds(
        &serde_json::from_slice(&std::fs::read(layout.stand().join("parties.json")).expect("p"))
            .expect("parties.json"),
    )
    .expect("parties")
    .owner;
    let signature = serde_json::to_vec(&owner.sign(&bytes)).expect("JSON");
    assert!(matches!(
        session.call(&Request::Sign { signature }).expect("a call"),
        Answer::Done { .. }
    ));
    match session.call(&request).expect("a call") {
        Answer::NeedsSignature { party, .. } => assert_eq!(party, "buyer"),
        other => panic!("the new owner's signature was not asked for: {other:?}"),
    }
    drop(session);
    // Nothing was written: the capsule and the owner's file are as they were.
    assert_eq!(std::fs::read(layout.capsule()).expect("the capsule"), before);
    assert_eq!(std::fs::read(layout.owner_side()).expect("file"), owner_file);
    std::fs::remove_dir_all(&layout.home).ok();
}

fn base64_url(bytes: &[u8]) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use base64::Engine as _;
    B64.encode(bytes)
}

/// A `bare` with nothing in the former owner's part changes owner as a light
/// does (`Evidence::Transfer` in every class, `container.rs` E-9).
#[test]
fn a_bare_without_a_former_half_changes_owner() {
    let Some(layout) = initiated("bare-ok", Class::Bare) else { return };
    let former = SideFile::read(&layout.owner_side()).expect("the owner's file");
    flow::transfer(&layout).expect("the transfer");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    assert!(open_split(&capsule, &former.map().expect("a map")).is_err(), "N-3 in a bare");
    let new = SideFile::read(&layout.owner_side()).expect("the owner's file");
    assert!(open_split(&capsule, &new.map().expect("a map")).is_ok());
    flow::export_page(&layout, 1, Party::Owner).expect("the new owner exports");
    std::fs::remove_dir_all(&layout.home).ok();
}

/// A `bare` whose former owner's secrets part is not empty (the former
/// client's half after an attachment): a client's session cannot move it to
/// the new owner's map, so the transfer is refused with the reason — not a
/// silent loss — and nothing changes.
#[test]
fn a_bare_with_a_former_half_refuses_with_the_reason() {
    let Some(layout) = initiated("bare", Class::Bare) else { return };
    let client = SideFile::read(&layout.client_side()).expect("the client's file");
    let owner = SideFile::read(&layout.owner_side()).expect("the owner's file");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");

    // Put a secret into the owner's part, as the former half would be, and
    // assemble the capsule again with the maps it had.
    let opened = open_split(&capsule, &owner.map().expect("a map")).expect("the owner opens");
    let parts: Vec<Part> = opened
        .parts
        .iter()
        .map(|p| Part {
            kind: p.kind,
            bytes: if p.kind == PartKind::OwnerSecrets {
                b"the former client's half".to_vec()
            } else {
                p.bytes.clone()
            },
        })
        .collect();
    let maps: Vec<(MapRole, SealTo)> = vec![
        (MapRole::Client, client.map().expect("a map").seal_to()),
        (MapRole::Owner, owner.map().expect("a map").seal_to()),
    ];
    let mut random = |out: &mut [u8]| OsRng.fill_bytes(out);
    let crafted = assemble_split(&parts, &opened.carried, &maps, &mut random).expect("assembles");
    std::fs::write(layout.capsule(), &crafted).expect("the capsule");
    let owner_file = std::fs::read(layout.owner_side()).expect("the owner's file");

    let refused = flow::transfer(&layout).expect_err("the transfer passed");
    assert!(refused.contains("former owner's secrets"), "another reason: {refused}");
    assert_eq!(std::fs::read(layout.capsule()).expect("the capsule"), crafted);
    assert_eq!(std::fs::read(layout.owner_side()).expect("file"), owner_file);
    std::fs::remove_dir_all(&layout.home).ok();
}
