//! K5, the offline half: print → initiate → work ×3 → export ×3 → the
//! verifier says ACCEPTED; one flipped byte of an export → REJECTED; the
//! capsule is 6 MiB after every session; another party's file does not open it
//! (`Spec_kapsula` §6, plan v8, K5).
//!
//! The module must be built for `wasm32` first:
//!
//! ```text
//! cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release
//! ```
//!
//! The test reads `target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm`
//! (or `KSG_CAPSULE_WASM`); without it the test **fails** — a machine without the
//! artifact proves nothing about the capsule. A machine that cannot build the
//! module says so on purpose: `KSG_SKIP_K5=1`.

use base64::Engine as _;
use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print};
use ksg_capsule_reader::side::SideFile;
use ksg_container_v2::capsule::CAPSULE_SIZE;
use ksg_core_v2::anchor::AttestationVerifier;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::solana::{HttpRpc, SEAL_KIND, SealScanKey, SolanaReader, LOCALNET};
use ksg_verify_v2::{keys_from_json, verify_bytes, Expected};

/// The temporary home of one test.
fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-k5-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

/// The module's bytes, or `None` when the run skips K5 on purpose.
///
/// A missing module fails the test: a green run of a machine that never built
/// the module would prove nothing about the capsule. `KSG_SKIP_K5=1` is the one
/// deliberate way to say "this machine cannot build wasm32".
fn wasm() -> Option<std::path::PathBuf> {
    let path = std::env::var("KSG_CAPSULE_WASM").map_or_else(|_| default_wasm(), std::path::PathBuf::from);
    if path.exists() {
        return Some(path);
    }
    if std::env::var("KSG_SKIP_K5").as_deref() == Ok("1") {
        eprintln!(
            "K5 is skipped on purpose (KSG_SKIP_K5=1): {} is missing",
            path.display()
        );
        return None;
    }
    panic!(
        "K5 cannot run: {} is missing — build the module for wasm32 first \
         (cargo build -p ksg-capsule-module --target wasm32-unknown-unknown --release), \
         or set KSG_SKIP_K5=1 to skip K5 on purpose",
        path.display()
    );
}

/// A capsule is one size, always.
fn assert_capsule_size(layout: &Layout, when: &str) {
    let len = std::fs::metadata(layout.capsule())
        .unwrap_or_else(|e| panic!("{when}: {}: {e}", layout.capsule().display()))
        .len();
    assert_eq!(
        len,
        CAPSULE_SIZE as u64,
        "{when}: a capsule is {CAPSULE_SIZE} bytes, not {len}"
    );
}

#[test]
fn k5_offline_a_printed_capsule_verifies_page_by_page() {
    let Some(wasm) = wasm() else {
        return;
    };
    let dir = home("offline");
    let layout = Layout::new(&dir);
    let print = Print {
        class: Class::Light,
        wasm,
        ..Print::default()
    };
    flow::init(&layout, &print).expect("the capsule prints");
    assert_capsule_size(&layout, "after init");

    let initiated = flow::initiate(&layout).expect("the initiation goes through");
    assert!(
        initiated.get("mobile_half").and_then(serde_json::Value::as_str).is_some(),
        "the client's half is handed to the reader: {initiated}"
    );
    assert_capsule_size(&layout, "after initiate");

    for text in [
        "input: claim 4417, water damage, policy P-88 (synthetic)",
        "tool call: policy_lookup(P-88) -> exclusion 7.2 gradual leak",
        "result: claim rejected, exclusion 7.2",
    ] {
        let receipt = flow::work(&layout, text).expect("the page goes in");
        assert!(receipt.get("pages").is_some(), "a receipt names the pages: {receipt}");
        assert_capsule_size(&layout, "after work");
    }

    let status = flow::status(&layout).expect("the status reads");
    let container = Hash::from_multihash(
        status
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("the status names the container"),
    )
    .expect("a multihash");
    assert_eq!(status["pages"], 4, "page 0 and three pages of work: {status}");

    let keys = ksg_verify_v2::keys_from_json(&flow::keys(&layout).expect("the keys read"))
        .expect("the keys are a key set");
    let anchors = ksg_verify_v2::NoReader;
    let expected = Expected {
        container,
        class: Class::Light,
        keys,
        // The keys are the ones the reader itself wrote: the client is named
        // by the `did:key` of its group key (Г-1).
        client_id_from_key: true,
        anchors: &anchors,
    };

    for number in 1..=3 {
        let page = flow::export_page(&layout, number, Party::Client).expect("the page exports");
        assert_capsule_size(&layout, "after export-page");
        let report = verify_bytes(&page, &expected);
        assert!(
            report.accepted,
            "page {number} is ACCEPTED: {:?}",
            report.reason
        );

        // One byte of the page's content, flipped: the seal no longer holds.
        let mut value: serde_json::Value =
            serde_json::from_slice(&page).expect("the page is JSON");
        let inline = value
            .pointer_mut("/page/body/content/content/inline")
            .expect("the page's content is inline base64")
            .as_str()
            .expect("the content is a string")
            .to_string();
        let mut raw = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &inline,
        )
        .expect("the content is base64url");
        raw[0] ^= 0x01;
        let bad = base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &raw,
        );
        *value
            .pointer_mut("/page/body/content/content/inline")
            .expect("the same field") = serde_json::Value::String(bad);
        let tampered = serde_json::to_vec(&value).expect("the page encodes");
        let report = verify_bytes(&tampered, &expected);
        assert!(
            !report.accepted,
            "a flipped byte of page {number} is REJECTED"
        );
    }

    // Another party's file: another map, so no slot of this capsule opens.
    let other = Layout::new(home("offline-other"));
    flow::init(
        &other,
        &Print {
            class: Class::Light,
            wasm: print.wasm.clone(),
            ..Print::default()
        },
    )
    .expect("a second capsule prints");
    let foreign = std::fs::read(other.client_side()).expect("the other client's file");
    let capsule = std::fs::read(layout.capsule()).expect("the capsule");
    let refused =
        ksg_capsule_reader::session::Session::open(&capsule, &foreign, Vec::new());
    assert!(
        refused.is_err(),
        "another party's file opens no slot of this capsule"
    );

    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(other.home.clone()).ok();
}

#[test]
fn a_side_file_of_the_owner_opens_the_holders_slot_before_initiation() {
    let Some(wasm) = wasm() else {
        return;
    };
    let dir = home("owner");
    let layout = Layout::new(&dir);
    flow::init(
        &layout,
        &Print {
            class: Class::Light,
            wasm,
            ..Print::default()
        },
    )
    .expect("the capsule prints");
    use ksg_capsule_reader::side::Role as SideRole;
    // Before initiation the slot is the holder's: both files carry its map.
    let owner = SideFile::read(&layout.owner_side()).expect("the owner's file");
    assert_eq!(owner.role, SideRole::Owner);
    let status = flow::status(&layout).expect("the owner's session reads the state");
    assert_eq!(status["born"], false);
    std::fs::remove_dir_all(&dir).ok();
}

/// K5 with the network: Pro pages anchored on the owner's own Solana node.
///
/// Not run in the cloud: it needs `solana-test-validator`, a funded payer and
/// the reader's anchoring, which is not wired into `ksg-capsule` yet (see the
/// report). On the owner's machine:
///
/// ```text
/// solana-test-validator --ledger /tmp/ksg-ledger --reset --quiet &
/// solana-keygen new --no-bip39-passphrase --silent --outfile /tmp/ksg-payer.json
/// solana airdrop 10 "$(solana-keygen pubkey /tmp/ksg-payer.json)" --url http://127.0.0.1:8899
/// KSG_CAPSULE_WASM=target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm \
///   cargo test -p ksg-capsule-reader -- --ignored k5_network
/// ```
///
/// The test then prints the capsule with `--class heavy --anchor solana:localnet
/// --payer ...`, works three pages, and checks them against the node with
/// `ksg-verify-v2 --rpc http://127.0.0.1:8899`.
#[test]
#[ignore = "the network half of K5: an own Solana node, run on the owner's machine"]
fn k5_network_pro_through_the_capsule() {
    let Ok(wasm) = std::env::var("KSG_CAPSULE_WASM") else {
        panic!("set KSG_CAPSULE_WASM to the module built for wasm32");
    };
    let payer = std::env::var("KSG_PAYER").expect("set KSG_PAYER to a funded key file");
    let rpc = std::env::var("KSG_RPC").unwrap_or_else(|_| "http://127.0.0.1:8899".into());
    // The anchor wait is 120 s by default in the anchorer: the test names its
    // own 20 s unless the caller set `KSG_ANCHOR_WAIT_S` already.
    if std::env::var("KSG_ANCHOR_WAIT_S").is_err() {
        std::env::set_var("KSG_ANCHOR_WAIT_S", "20");
    }
    let dir = home("network");
    let layout = Layout::new(&dir);
    let print = Print {
        class: Class::Heavy,
        anchor: Some(ksg_cli_v2::anchoring::AnchorCfg {
            cluster: "localnet".into(),
            rpc: rpc.clone(),
            payer: Some(std::path::PathBuf::from(payer)),
            service: None,
            last_signature: None,
            pending: Vec::new(),
            rotate_scan: true,
            scan_periods: Vec::new(),
        }),
        wasm: std::path::PathBuf::from(wasm),
        ..Print::default()
    };
    flow::init(&layout, &print).expect("the capsule prints on the node");
    flow::initiate(&layout).expect("the initiation through the capsule");
    for text in [
        "one: claim 4417, water damage, policy P-88 (synthetic)",
        "two: tool call policy_lookup(P-88) -> exclusion 7.2 gradual leak",
        "three: result claim rejected, exclusion 7.2",
    ] {
        flow::work(&layout, text).expect("a page through the capsule");
    }
    assert_capsule_size(&layout, "after work on the node");

    let status = flow::status(&layout).expect("the status reads");
    let container = Hash::from_multihash(
        status
            .get("id")
            .and_then(serde_json::Value::as_str)
            .expect("the status names the container"),
    )
    .expect("a multihash");
    assert_eq!(status["pages"], 4, "page 0 and three pages of work: {status}");

    let keys = keys_from_json(&flow::keys(&layout).expect("the keys read"))
        .expect("the keys are a key set");
    assert!(
        keys.keys().next().is_some(),
        "the keys are a non-empty set"
    );

    // The holder's scan key is in the client's side file — the third party's
    // `scan-key`, which the verifier needs to read blind seal anchors. A
    // rotated container blinds each month's memos under that month's key:
    // `scan_periods` of `anchor.json` names the months used.
    let side = SideFile::read(&layout.client_side()).expect("the client's file");
    let master = {
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&side.scan)
            .expect("the file's scan key is base64url");
        let bytes: [u8; 32] = raw
            .as_slice()
            .try_into()
            .expect("the file's scan key is 32 bytes");
        SealScanKey::new(bytes)
    };
    let cfg: ksg_cli_v2::anchoring::AnchorCfg =
        serde_json::from_slice(&std::fs::read(layout.anchor()).expect("anchor.json"))
            .expect("anchor.json reads");
    let mut scan_keys: Vec<SealScanKey> = cfg
        .scan_periods
        .iter()
        .map(|p| master.for_period(p))
        .collect();
    if scan_keys.is_empty() {
        scan_keys.push(master.clone());
    }

    // The anchors are read from the node's RPC — the same path
    // `ksg-verify-v2 --rpc URL` takes (`HttpRpc`, then `SolanaReader`
    // with the scan key; see `ksg-verify-v2/src/main.rs` and
    // `ksg-remote-panel scan-key --out` there).
    let rpc_url = rpc.clone();
    let rpc = HttpRpc::new(&rpc_url).expect("the node's RPC");
    let reader = scan_keys
        .into_iter()
        .fold(SolanaReader::connect(&rpc, LOCALNET), |acc, key| {
            acc.map(|r| r.with_scan_key(key))
        })
        .expect("the node proves it is localnet");
    assert!(
        reader.handles(&ksg_core_v2::doc::Uri::parse(SEAL_KIND).expect("a kind")),
        "the reader handles Solana anchors"
    );
    let expected = Expected {
        container,
        class: Class::Heavy,
        keys,
        client_id_from_key: true,
        anchors: &reader,
    };

    for number in 1..=3u64 {
        let page = flow::export_page(&layout, number, Party::Client).expect("an export");
        assert_capsule_size(&layout, "after export-page");
        let report = verify_bytes(&page, &expected);
        assert!(
            report.accepted,
            "page {number} is ACCEPTED: {:?}",
            report.reason
        );

        // One byte of the page's seal, flipped: the seal no longer holds.
        let mut value: serde_json::Value =
            serde_json::from_slice(&page).expect("the page is JSON");
        let signatures = value
            .pointer_mut("/seal/signatures")
            .expect("the page carries the seal's signatures")
            .as_array_mut()
            .expect("the signatures are an array");
        assert!(
            !signatures.is_empty(),
            "the seal carries signatures to flip"
        );
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(
                signatures[0]
                    .get("value")
                    .and_then(serde_json::Value::as_str)
                    .expect("the signature value is a string"),
            )
            .expect("the signature is base64url");
        let mut bytes = bytes;
        bytes[0] ^= 0x01;
        signatures[0]["value"] = serde_json::Value::String(
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes),
        );
        let tampered = serde_json::to_vec(&value).expect("the page encodes");
        let report = verify_bytes(&tampered, &expected);
        assert!(
            !report.accepted,
            "a flipped byte of a page {number} signature is REJECTED"
        );
    }

    std::fs::remove_dir_all(&dir).ok();
}
