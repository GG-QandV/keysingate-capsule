//! `Spec_kapsula` §19: E-3 through the capsule — the buyer's key with the
//! owner's consent, after which the holder's map opens nothing and the
//! buyer's does. The initiation after it is NOT covered: see the last test.

use ksg_capsule_reader::flow::{self, default_wasm, Layout};
use ksg_capsule_reader::session::compress_code;
use ksg_capsule_reader::side::{Role, SideFile};
use ksg_capsule_reader::write_capsule;
use ksg_cli_v2::home::{owner_seed, Seeds};
use ksg_cli_v2::InitOptions;
use ksg_container_v2::capsule::open_split;
use ksg_core_v2::doc::{Class, Uri};

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-buyer-key-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

/// A capsule printed and nothing else (status 0): `flow::init` lays E-2 and
/// E-3 on the stand itself, which is just what these tests must not have.
/// Returns `None` where the module is not built (`KSG_SKIP_K5=1`).
fn printed_only(name: &str, stand_packet: bool) -> Option<Layout> {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(
            std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"),
            "build the module for wasm32 first"
        );
        return None;
    }
    let layout = Layout::new(home(name));
    let opts = InitOptions {
        class: Class::Light,
        emission: "ksg:em:test:000001".into(),
        serial: 7,
        artifact: Uri::parse("ksg:artifact:the-one".to_owned()).expect("a URI"),
        anchor: None,
        channel: None,
        base: None,
    };
    let meta = ksg_cli_v2::init(&layout.stand(), &opts).expect("the stand prints");
    if stand_packet {
        // E-2 on the stand: the packet and its layer (the stand's follow-up
        // worker writes it); the buyer's key is left for the session.
        let mut stand = ksg_cli_v2::Reader::open(&layout.stand(), Box::new(ksg_cli_v2::mobile::NoMobile))
            .expect("the stand opens");
        stand.packet().expect("the packet");
    }
    let code = compress_code(&std::fs::read(&wasm).expect("the module")).expect("compresses");
    let capsule = ksg_cli_v2::reader::home_to_capsule(&layout.stand(), &code).expect("a capsule");
    write_capsule(&layout.capsule(), &capsule).expect("written");

    let map: [u8; 32] = std::fs::read(layout.stand().join("layer.key"))
        .expect("layer.key")
        .try_into()
        .expect("32 bytes");
    let seeds = seeds(&layout);
    let owner = owner_seed(&seeds).expect("the owner's seed");
    SideFile::new(Role::Client, &meta.id, &[], &map, &[3u8; 32])
        .write(&layout.client_side())
        .expect("the client's file");
    SideFile::new(Role::Owner, &meta.id, owner.as_slice(), &map, &[4u8; 32])
        .write(&layout.owner_side())
        .expect("the owner's file");
    Some(layout)
}

fn seeds(layout: &Layout) -> Seeds {
    serde_json::from_slice(&std::fs::read(layout.stand().join("parties.json")).expect("parties"))
        .expect("parties.json")
}

#[test]
fn the_holders_map_opens_nothing_after_the_buyers_key() {
    let Some(layout) = printed_only("flow", true) else { return };
    let holder = SideFile::read(&layout.client_side()).expect("file").map().expect("a map");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    assert!(open_split(&capsule, &holder).is_ok(), "the holder's map opens the printed capsule");

    flow::buyer_key(&layout).expect("the buyer's key is laid");

    let client = SideFile::read(&layout.client_side()).expect("file");
    let owner = SideFile::read(&layout.owner_side()).expect("file");
    assert_eq!(client.map, owner.map, "before the birth the capsule has one map");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    assert!(open_split(&capsule, &holder).is_err(), "the old holder's map still opens the capsule");
    assert!(
        open_split(&capsule, &client.map().expect("a map")).is_ok(),
        "the buyer's map does not open the capsule"
    );
}

#[test]
fn the_buyer_key_needs_the_packet_first() {
    let Some(layout) = printed_only("nopacket", false) else { return };
    let before = std::fs::read(layout.capsule()).expect("the capsule");
    let files = (
        std::fs::read(layout.client_side()).expect("file"),
        std::fs::read(layout.owner_side()).expect("file"),
    );
    assert!(flow::buyer_key(&layout).is_err(), "E-3 passed without E-2");
    // Nothing moved: the capsule and the files are as they were.
    assert_eq!(std::fs::read(layout.capsule()).expect("the capsule"), before);
    assert_eq!(std::fs::read(layout.client_side()).expect("file"), files.0);
    assert_eq!(std::fs::read(layout.owner_side()).expect("file"), files.1);
}

/// K4 (`Spec_kapsula` §28) closed the gap C4 pinned here: the buyer's key is
/// laid through the session, the issuer's layer work is handed in in the same
/// session, and the initiation goes through.
#[test]
fn after_the_buyers_key_through_the_session_the_initiation_goes_through() {
    let Some(layout) = printed_only("handover", true) else { return };
    flow::buyer_key(&layout).expect("the buyer's key is laid");
    flow::initiate(&layout).expect("the initiation goes through after K4");
    flow::work(&layout, "a page after the sale through the capsule").expect("the client works");
}
