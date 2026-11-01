//! `Spec_kapsula` §22, "code-level detail — C9": a `light` capsule anchors on
//! Base Sepolia (a node in a thread — `ksg-cli-v2/tests/mock_base`): after
//! initiation, before a value goes out, past the ten offline records; a copy
//! learns it is one and does nothing but the full export; a transfer hands
//! the writer's seat to the new owner's key. Without `--base` nothing changes.

#[path = "mock_base/mod.rs"]
mod mock_base;

use std::path::{Path, PathBuf};

use ksg_capsule_reader::base::{BaseFile, BaseSpec};
use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::solana::HttpRpc;
use mock_base::MockBase;

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("ksg-base-light-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("a temporary directory");
    d
}

/// A key file of 64 hex characters (the stand's `--evm-key`).
fn key_file(d: &Path, name: &str, byte: u8) -> PathBuf {
    let path = d.join(name);
    std::fs::write(&path, hex::encode([byte; 32])).expect("a key file");
    path
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).expect("a directory");
    for e in std::fs::read_dir(from).expect("a listing") {
        let e = e.expect("an entry");
        let target = to.join(e.file_name());
        if e.file_type().expect("a type").is_dir() {
            copy_dir(&e.path(), &target);
        } else {
            std::fs::copy(e.path(), target).expect("a copy");
        }
    }
}

/// The module is built; else `None` under `KSG_SKIP_K5=1`.
fn built() -> Option<PathBuf> {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(
            std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"),
            "build the module for wasm32 first"
        );
        return None;
    }
    Some(wasm)
}

fn print(node: &MockBase, key: &Path, wasm: PathBuf) -> Print {
    Print {
        class: Class::Light,
        wasm,
        base: Some(BaseSpec {
            rpc: node.url.clone(),
            contract: node.contract(),
            key: key.to_path_buf(),
        }),
        ..Print::default()
    }
}

/// How many anchors the chain holds for this capsule.
fn count(node: &MockBase, layout: &Layout) -> u64 {
    let status = flow::status(layout).expect("status");
    let template = Hash::from_multihash(status["template"].as_str().expect("template")).expect("hash");
    let file = BaseFile::read(layout).expect("base.json").expect("a Base capsule");
    let salt: [u8; 32] = ksg_anchor_v2::evm::unhex(file.cfg.salt.as_deref().expect("salt"))
        .expect("hex")
        .try_into()
        .expect("32 bytes");
    let key = ksg_verify_v2::base::anchor_key(template.as_bytes(), &salt);
    let contract: [u8; 20] = ksg_anchor_v2::evm::unhex(&node.contract())
        .expect("hex")
        .try_into()
        .expect("20 bytes");
    let rpc = HttpRpc::new(&node.url).expect("rpc");
    ksg_verify_v2::base::head(&rpc, &contract, &key).expect("head").count
}

fn since(layout: &Layout) -> u32 {
    BaseFile::read(layout).expect("base.json").expect("a Base capsule").cfg.since
}

/// A printed and initiated capsule on `node`, with `key` as the sender.
fn initiated(name: &str, node: &MockBase) -> Option<(Layout, PathBuf)> {
    let wasm = built()?;
    let d = dir(name);
    let key = key_file(&d, "evm.key", 0x42);
    let layout = Layout::new(d.join("home"));
    flow::init(&layout, &print(node, &key, wasm)).expect("prints");
    flow::initiate(&layout).expect("initiates");
    Some((layout, d))
}

#[test]
fn the_status_names_the_head_of_the_statuses() {
    let Some(wasm) = built() else { return };
    let d = dir("status");
    let layout = Layout::new(d.join("home"));
    flow::init(&layout, &Print { wasm, ..Print::default() }).expect("prints");
    let status = flow::status(&layout).expect("status");
    let head = status["status_head"].as_str().expect("status_head");
    assert!(Hash::from_multihash(head).is_ok(), "a multihash: {head}");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_print_with_base_then_initiation_puts_the_first_anchor_and_the_eleventh_record_waits() {
    let node = MockBase::start();
    let Some((layout, d)) = initiated("schedule", &node) else { return };
    assert_eq!(count(&node, &layout), 1, "Ya-2: the anchor after the initiation");
    assert_eq!(since(&layout), 0);

    // base.json keeps the path to the key, never the key.
    let text = std::fs::read_to_string(layout.base()).expect("base.json");
    assert!(!text.contains(&hex::encode([0x42u8; 32])), "the key is in base.json");
    assert!(text.contains("evm.key"), "the path to the key: {text}");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(layout.base()).expect("meta").permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "base.json is 0600");
    }

    // Ten records go on with no anchor…
    for i in 0..10 {
        flow::work(&layout, &format!("step {i}")).expect("a record");
    }
    assert_eq!(count(&node, &layout), 1);
    assert_eq!(since(&layout), 10);

    // …the eleventh needs the network: it is down, nothing is written.
    let before = std::fs::read(layout.capsule()).expect("the capsule");
    node.chain.lock().unwrap().down = true;
    let e = flow::work(&layout, "the eleventh").expect_err("the network is down");
    assert!(e.contains("Base Sepolia"), "{e}");
    assert!(std::fs::read(layout.capsule()).expect("the capsule") == before, "the capsule changed");
    node.chain.lock().unwrap().down = false;

    // …and goes once the network is back, on a fresh anchor.
    flow::work(&layout, "the eleventh").expect("the eleventh");
    assert_eq!(count(&node, &layout), 2);
    assert_eq!(since(&layout), 1, "the anchor reset the count, the record made it one");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_page_goes_out_only_on_a_fresh_anchor() {
    let node = MockBase::start();
    let Some((layout, d)) = initiated("value", &node) else { return };
    flow::work(&layout, "a record").expect("a record");
    assert_eq!(count(&node, &layout), 1);

    // The network is down: the page does not go.
    node.chain.lock().unwrap().down = true;
    flow::export_page(&layout, 1, Party::Client).expect_err("no fresh anchor");
    node.chain.lock().unwrap().down = false;

    flow::export_page(&layout, 1, Party::Client).expect("the page");
    assert_eq!(count(&node, &layout), 2, "the page went out on an anchor of the record");
    // Nothing new since: the same head, no second anchor.
    flow::export_page(&layout, 1, Party::Owner).expect("the owner's page");
    assert_eq!(count(&node, &layout), 2);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_copy_learns_it_is_one_and_does_only_the_full_export() {
    let node = MockBase::start();
    let Some((first, d)) = initiated("copy", &node) else { return };
    // The second file of the same capsule, taken right after the first anchor.
    let second = Layout::new(d.join("copy"));
    copy_dir(&first.home, &second.home);

    // Each goes on writing; the first anchors first.
    flow::work(&first, "on the first file").expect("a record");
    flow::work(&second, "on the second file").expect("a record");
    for l in [&first, &second] {
        let mut f = BaseFile::read(l).expect("base.json").expect("Base");
        f.cfg.since = 10;
        f.write(l).expect("base.json");
    }
    flow::work(&first, "the first anchors").expect("the first goes on");
    assert_eq!(count(&node, &first), 2);

    // The second is refused by the contract when its anchor is due: a copy.
    let before = std::fs::read(second.capsule()).expect("the capsule");
    let e = flow::work(&second, "the second anchors").expect_err("a copy");
    assert!(e.contains("copy"), "{e}");
    assert!(BaseFile::read(&second).expect("base.json").expect("Base").copy);
    assert!(std::fs::read(second.capsule()).expect("the capsule") == before, "the capsule changed");
    assert_eq!(count(&node, &second), 2, "the copy put nothing on the chain");
    // (`status` seals the capsule afresh: the comparison starts from here.)
    let before = std::fs::read(second.capsule()).expect("the capsule");

    // From here on every flow of the copy is refused before anything is written…
    for e in [
        flow::work(&second, "again").expect_err("work"),
        flow::export_page(&second, 1, Party::Client).expect_err("export"),
        flow::transfer(&second).expect_err("transfer"),
        flow::initiate(&second).expect_err("initiate"),
    ] {
        assert!(e.contains("copy"), "{e}");
    }
    assert!(std::fs::read(second.capsule()).expect("the capsule") == before, "the capsule changed");
    // …but it still reads: the state, the keys. The reader has no flow of the
    // full export of its own (`Request::FullExport` is the module's): nothing
    // in the reader stands in its way.
    flow::status(&second).expect("the status still reads");
    flow::keys(&second).expect("the keys still read");
    // The first file is not touched by any of it.
    flow::work(&first, "the first goes on").expect("the first goes on");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_transfer_goes_on_an_anchor_and_the_new_owners_key_takes_the_writers_seat() {
    let node = MockBase::start();
    let Some((layout, d)) = initiated("transfer", &node) else { return };
    let new_key = key_file(&d, "new-owner.key", 0x43);
    flow::work(&layout, "a record before the transfer").expect("a record");
    assert_eq!(count(&node, &layout), 1);

    // A Base capsule without a key for the new owner: refused before any write.
    let before = std::fs::read(layout.capsule()).expect("the capsule");
    flow::transfer(&layout).expect_err("no key for the new owner");
    assert!(std::fs::read(layout.capsule()).expect("the capsule") == before, "the capsule changed");

    flow::transfer_with_evm_key(&layout, Some(&new_key)).expect("the transfer");
    assert_eq!(count(&node, &layout), 2, "the transfer went out on a fresh anchor");
    let file = BaseFile::read(&layout).expect("base.json").expect("Base");
    assert!(file.cfg.hand_to.is_none(), "the hand-over landed");
    assert_eq!(file.cfg.key, new_key, "anchors go from the new owner's key now");
    let text = std::fs::read_to_string(layout.base()).expect("base.json");
    assert!(!text.contains(&hex::encode([0x43u8; 32])), "the key is in base.json");

    // The new owner's key anchors: the old key is no longer the writer.
    let mut f = file;
    f.cfg.since = 10;
    f.write(&layout).expect("base.json");
    flow::work(&layout, "a record after the transfer").expect("a record");
    flow::work(&layout, "one more").expect("one more");
    assert_eq!(count(&node, &layout), 3, "the new owner's key anchored");
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn a_hand_over_the_network_did_not_take_waits_for_the_next_anchor() {
    let node = MockBase::start();
    let Some((layout, d)) = initiated("owed", &node) else { return };
    let new_key = key_file(&d, "new-owner.key", 0x43);
    flow::work(&layout, "a record").expect("a record");
    // The network drops right after the anchor of the transfer.
    node.chain.lock().unwrap().drop =
        Some(ksg_anchor_v2::evm::selector("handOver(bytes32,address)"));
    flow::transfer_with_evm_key(&layout, Some(&new_key)).expect("the transfer");
    let file = BaseFile::read(&layout).expect("base.json").expect("Base");
    assert!(file.cfg.hand_to.is_some(), "the hand-over is owed");
    assert_ne!(file.cfg.key, new_key, "still the old key");

    node.chain.lock().unwrap().drop = None;
    let mut f = file;
    f.cfg.since = 10;
    f.write(&layout).expect("base.json");
    flow::work(&layout, "a record after the transfer").expect("the hand-over goes first");
    let file = BaseFile::read(&layout).expect("base.json").expect("Base");
    assert!(file.cfg.hand_to.is_none());
    assert_eq!(file.cfg.key, new_key);
    std::fs::remove_dir_all(&d).ok();
}

#[test]
fn only_a_light_capsule_takes_base_and_without_it_nothing_changes() {
    let Some(wasm) = built() else { return };
    let node = MockBase::start();
    let d = dir("plain");
    let key = key_file(&d, "evm.key", 0x42);
    // A heavy capsule with --base: refused, nothing printed.
    let heavy = Layout::new(d.join("heavy"));
    let mut p = print(&node, &key, wasm.clone());
    p.class = Class::Heavy;
    flow::init(&heavy, &p).expect_err("only light");
    assert!(!heavy.capsule().exists());
    // A key file that is not a key: refused before the capsule is written.
    let bad = d.join("bad.key");
    std::fs::write(&bad, "not a key").expect("a file");
    let broken = Layout::new(d.join("broken"));
    flow::init(&broken, &print(&node, &bad, wasm.clone())).expect_err("not a key");

    // Without --base: no base.json, no network, ten and more records go on.
    let plain = Layout::new(d.join("plain"));
    flow::init(&plain, &Print { wasm, ..Print::default() }).expect("prints");
    flow::initiate(&plain).expect("initiates");
    for i in 0..11 {
        flow::work(&plain, &format!("step {i}")).expect("a record");
    }
    flow::export_page(&plain, 1, Party::Client).expect("a page");
    flow::transfer(&plain).expect("a transfer");
    assert!(!plain.base().exists());
    std::fs::remove_dir_all(&d).ok();
}
