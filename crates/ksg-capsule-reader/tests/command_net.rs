//! K3 (`Spec_kapsula` §27, `[decision]` 31.10 «B»): the issuer's command goes out
//! as a blind memo under the command key; the client's reader finds it among
//! the payer's transactions and applies it — once.

use std::cell::RefCell;
use std::collections::BTreeMap;

use ksg_capsule_module::session::CommandEvidence;
use ksg_capsule_reader::command;
use ksg_capsule_reader::flow::{self, default_wasm, Layout, Party, Print};
use ksg_container_v2::Operation;
use ksg_core_v2::doc::Class;
use ksg_verify_v2::solana::{Rpc, MEMO_PROGRAM};
use serde_json::{json, Value};

const PAYER: &str = "Payer1111111111111111111111111111111111111";

/// A node that knows some memo transactions of one payer.
struct Node(RefCell<BTreeMap<String, (u64, String)>>);

impl Node {
    fn add(&self, sig: &str, slot: u64, memo: &str) {
        self.0.borrow_mut().insert(sig.into(), (slot, memo.into()));
    }
}

impl Rpc for Node {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let txs = self.0.borrow();
        match method {
            "getSignaturesForAddress" => {
                assert_eq!(params[0], PAYER, "the reader looks through the payer's account");
                Ok(Value::Array(txs.keys().rev().map(|s| json!({"signature": s})).collect()))
            }
            "getTransaction" => {
                let sig = params[0].as_str().unwrap_or_default();
                Ok(txs.get(sig).map_or(Value::Null, |(slot, memo)| {
                    json!({
                        "slot": slot,
                        "blockTime": 1_790_000_000,
                        "meta": {"err": null},
                        "transaction": {"message": {
                            "accountKeys": [PAYER, MEMO_PROGRAM],
                            "instructions": [{"programIdIndex": 1, "data": bs58::encode(memo).into_string()}],
                        }},
                    })
                }))
            }
            other => Err(format!("unexpected {other}")),
        }
    }
}

fn home(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("ksg-cmd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("a temporary directory");
    dir
}

#[test]
fn the_issuers_finalize_from_the_network_is_found_and_applied_once() {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"), "build the module for wasm32 first");
        return;
    }
    let layout = Layout::new(home("finalize"));
    flow::init(&layout, &Print { class: Class::Light, wasm, ..Print::default() }).expect("prints");
    flow::initiate(&layout).expect("initiates");
    flow::work(&layout, "a page before the command").expect("works");

    // The issuer signs and saves its command; the memo goes out (here: the
    // fake node), and the signature lies next to the file.
    let file = command::issue(&layout, Operation::Finalize, CommandEvidence::None).expect("issued");
    let (memo, path) = command::save(&layout, &file).expect("saved");
    assert!(memo.starts_with("ksg:cmd:v1 "), "{memo}");
    let node = Node(RefCell::new(BTreeMap::new()));
    node.add("sigFinalize", 100, &memo);
    node.add("sigOther", 90, "ksg:bs:v1 00 11");
    std::fs::write(path.with_extension("tx"), "sigFinalize").expect("tx");

    let report = command::apply_with(&layout, Party::Client, &node, "localnet").expect("applied");
    assert_eq!(report.applied, vec!["Finalize".to_owned()], "{report:?}");
    assert!(report.unmatched.is_empty() && report.unpublished.is_empty(), "{report:?}");

    // The next look: the container is past it — refused, not applied twice.
    let again = command::apply_with(&layout, Party::Client, &node, "localnet").expect("looked again");
    assert!(again.applied.is_empty(), "{again:?}");
    assert_eq!(again.refused.len(), 1, "{again:?}");

    // The owner's reader holds the same command key and finds the same memo.
    let by_owner = command::apply_with(&layout, Party::Owner, &node, "localnet").expect("the owner looks");
    assert!(by_owner.applied.is_empty() && by_owner.refused.len() == 1, "{by_owner:?}");
    std::fs::remove_dir_all(&layout.home).ok();
}

#[test]
fn an_anchor_without_a_file_and_a_file_without_an_anchor_are_named() {
    let wasm = default_wasm();
    if !wasm.exists() {
        assert!(std::env::var("KSG_SKIP_K5").as_deref() == Ok("1"), "build the module for wasm32 first");
        return;
    }
    let layout = Layout::new(home("unmatched"));
    flow::init(&layout, &Print { class: Class::Light, wasm, ..Print::default() }).expect("prints");
    flow::initiate(&layout).expect("initiates");

    // A command anchored, then its file lost: the anchor is the proof.
    let lost = command::issue(&layout, Operation::Finalize, CommandEvidence::None).expect("issued");
    let (memo, path) = command::save(&layout, &lost).expect("saved");
    std::fs::remove_file(&path).expect("the file is gone");
    let node = Node(RefCell::new(BTreeMap::new()));
    node.add("sigLost", 50, &memo);
    // A second command saved and never anchored.
    let hash = ksg_core_v2::crypto::hash::Hash::sha256(b"declaration");
    let kept = command::issue(&layout, Operation::DeclareSharesLost, CommandEvidence::SharesLost { hash })
        .expect("issued");
    let (_, kept_path) = command::save(&layout, &kept).expect("saved");
    std::fs::write(kept_path.with_extension("tx"), "sigLost").expect("the payer is known");

    let report = command::apply_with(&layout, Party::Client, &node, "localnet").expect("looked");
    assert!(report.applied.is_empty(), "{report:?}");
    assert_eq!(report.unmatched.len(), 1, "the anchor without a file: {report:?}");
    assert_eq!(report.unpublished, vec!["DeclareSharesLost".to_owned()], "{report:?}");
    std::fs::remove_dir_all(&layout.home).ok();
}
