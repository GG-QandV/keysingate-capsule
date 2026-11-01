//! `Spec_kapsula` §21, 4b.4a: after the initiation the client and the owner
//! open the capsule with maps of their own, born at the reader; the holder's
//! map (the issuer's printing stand knows it) opens nothing any more.

use ksg_capsule_reader::flow::{self, default_wasm, Layout, Print};
use ksg_capsule_reader::side::SideFile;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::capsule::{open_split, PartKind};
use ksg_container_v2::Container;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Class;

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-two-maps-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

#[test]
fn after_the_initiation_each_party_has_its_own_map() {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"), "build the module for wasm32 first");
        return;
    }
    let layout = Layout::new(home("own"));
    flow::init(&layout, &Print { class: Class::Light, wasm, ..Print::default() }).expect("prints");
    let holder = SideFile::read(&layout.client_side()).expect("the client's file").map().expect("a map");
    flow::initiate(&layout).expect("initiates");

    let client = SideFile::read(&layout.client_side()).expect("the client's file");
    let owner = SideFile::read(&layout.owner_side()).expect("the owner's file");
    assert_ne!(client.map, owner.map, "two maps, not two copies of one");

    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    assert!(open_split(&capsule, &holder).is_err(), "the holder's map opens nothing after E-4");
    let by_client = open_split(&capsule, &client.map().expect("a map")).expect("the client opens");
    let by_owner = open_split(&capsule, &owner.map().expect("a map")).expect("the owner opens");
    assert_eq!(by_client.role, ksg_container_v2::capsule::MapRole::Client);
    assert_eq!(by_owner.role, ksg_container_v2::capsule::MapRole::Owner);

    // The client works; the owner's session opens the client's capsule.
    flow::work(&layout, "a page after the maps split").expect("the client works");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    let owner_json = std::fs::read(layout.owner_side()).expect("the owner's file");
    let mut session = ksg_capsule_reader::session::Session::open(&capsule, &owner_json, Vec::new())
        .expect("the owner's session opens the client's capsule");
    let status = match session.call(&ksg_capsule_module::session::Request::Status).expect("a call") {
        ksg_capsule_module::session::Answer::Done { bytes } => {
            serde_json::from_slice::<serde_json::Value>(&bytes).expect("JSON")
        }
        other => panic!("status: {other:?}"),
    };
    assert!(status["pages"].as_u64().unwrap_or(0) >= 2, "the owner sees the client's page: {status}");

    // K2 (§26, R-4): what the owner's map opens — the state — carries no
    // half of the client's key; the client's part does.
    let opened = open_split(&capsule, &owner.map().expect("a map")).expect("the owner opens");
    let part = |kind| {
        opened.parts.iter().find(|p| p.kind == kind).map(|p| p.bytes.clone()).expect("a part")
    };
    let shared: ksg_container_v2::capsule::Shared =
        serde_json::from_slice(&part(PartKind::SharedSecrets)).expect("shared secrets");
    let key: [u8; 32] = B64.decode(&shared.state_key).expect("base64").try_into().expect("32 bytes");
    let template = Hash::from_multihash(&shared.template).expect("template");
    let state = Container::open_sealed(&part(PartKind::State), &template, &key).expect("the state");
    assert!(state.born());
    assert!(!state.holds_client_half(), "R-4: the owner's map gives no client's half");
    assert!(
        opened.parts.iter().all(|p| p.kind != PartKind::ClientSecrets),
        "R-4: the client's part is not the owner's"
    );
    let by_client = open_split(&capsule, &client.map().expect("a map")).expect("the client opens");
    assert!(
        by_client.parts.iter().any(|p| p.kind == PartKind::ClientSecrets && !p.bytes.is_empty()),
        "the client's half lives in the client's part"
    );

    // The owner's session closes the capsule; the client works on after it
    // (the half rode through in the client's part, sealed).
    let (closed, _) = session.close().expect("the owner's session closes");
    std::fs::write(layout.capsule(), closed).expect("the capsule");
    flow::work(&layout, "a page after the owner's session").expect("the client works on");
    std::fs::remove_dir_all(&layout.home).ok();
}
