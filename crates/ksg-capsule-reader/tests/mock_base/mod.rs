//! A Base Sepolia in a thread: a JSON-RPC server over plain HTTP on 127.0.0.1
//! whose state is an EVM (`revm`) with the `KsgAnchors` contract deployed.
//!
//! Strict where the real one is: a raw transaction must be type 2, signed
//! (the sender is recovered from the signature, never taken on trust), on
//! chain 84532, with the sender's next nonce. A call the contract refuses
//! still lands — status 0 in its receipt, as on a real chain.
//!
//! The same address answers as the sponsor's bundler and paymaster
//! (ERC-4337, EntryPoint 0.6): the account factory's `getAddress`, the
//! EntryPoint's `getNonce`, `pm_getPaymasterStubData` / `pm_getPaymasterData`,
//! `eth_estimateUserOperationGas`, `eth_sendUserOperation` and its receipt. A
//! UserOperation is checked as the account would check it — the owner's
//! signature over its hash, the account's nonce, `initCode` only while the
//! account has no code, the paymaster's final data — and its `execute` runs
//! with the account as the caller.

#![allow(dead_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use ksg_anchor_v2::evm::{address_of, keccak, unhex, KSG_ANCHORS_BYTECODE};
use revm::db::{CacheDB, EmptyDB};
use revm::primitives::{Address, Bytes, ExecutionResult, Output, TxKind, U256};
use revm::Evm;
use serde_json::{json, Value};

pub const CHAIN_ID: u64 = 84_532;

#[derive(Clone, Debug)]
pub struct Receipt {
    pub hash: [u8; 32],
    pub ok: bool,
    pub block: u64,
    pub from: [u8; 20],
    pub logs: Vec<(Vec<[u8; 32]>, Vec<u8>)>,
}

pub struct Chain {
    db: CacheDB<EmptyDB>,
    pub contract: [u8; 20],
    pub nonces: BTreeMap<[u8; 20], u64>,
    pub receipts: Vec<Receipt>,
    pub block: u64,
    pub time: u64,
    /// The node answers nothing: the network is down.
    pub down: bool,
    /// Calls opening with this selector find the network down: the network
    /// drops between two transactions of one command.
    pub drop: Option<[u8; 4]>,
    /// How many such calls are dropped before the network is back; none —
    /// every one.
    pub drop_left: Option<u32>,
    /// Confirmations are not given (the node errs on
    /// `eth_getTransactionReceipt`), while transactions still land: a sender
    /// sees its transaction go and never sees it land.
    pub lose_confirmations: bool,
    /// Smart accounts the factory named, and their owners.
    pub accounts: BTreeMap<[u8; 20], [u8; 20]>,
    /// Smart accounts with code: created by their first UserOperation.
    pub deployed: BTreeSet<[u8; 20]>,
    /// The EntryPoint's nonces.
    pub op_nonces: BTreeMap<[u8; 20], u64>,
    /// UserOperations carried: their hash, the transaction, success.
    pub ops: Vec<([u8; 32], [u8; 32], bool)>,
    /// Calls the paymaster answered.
    pub pm_calls: u32,
    /// The longest `eth_getLogs` range answered, blocks — a free node's
    /// limit (the live run of 16.10); `Some(0)` refuses every log question.
    pub log_span: Option<u64>,
}

/// The paymaster of the mock: what it puts in `paymasterAndData`, followed
/// by 0 on the stub and 1 on the final data.
pub const PAYMASTER: [u8; 20] = [0x99; 20];

/// The mock factory's address for an owner's account.
pub fn account_of(owner: &[u8; 20]) -> [u8; 20] {
    let mut b = b"mock-cb-account".to_vec();
    b.extend_from_slice(owner);
    keccak(&b)[12..].try_into().unwrap()
}

fn h(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

fn hexnum(v: u64) -> String {
    format!("0x{v:x}")
}

// RLP, enough to read a type-2 transaction.
enum Item {
    Bytes(Vec<u8>),
    List(Vec<Item>),
}

fn rlp(b: &[u8]) -> Option<(Item, &[u8])> {
    let p = *b.first()?;
    match p {
        0..=0x7f => Some((Item::Bytes(vec![p]), &b[1..])),
        0x80..=0xb7 => {
            let n = (p - 0x80) as usize;
            let (d, r) = b[1..].split_at_checked(n)?;
            Some((Item::Bytes(d.to_vec()), r))
        }
        0xb8..=0xbf => {
            let ll = (p - 0xb7) as usize;
            let (l, r) = b[1..].split_at_checked(ll)?;
            let n = l.iter().fold(0usize, |a, x| a * 256 + *x as usize);
            let (d, r) = r.split_at_checked(n)?;
            Some((Item::Bytes(d.to_vec()), r))
        }
        0xc0..=0xf7 => {
            let n = (p - 0xc0) as usize;
            let (d, r) = b[1..].split_at_checked(n)?;
            Some((Item::List(list(d)?), r))
        }
        _ => {
            let ll = (p - 0xf7) as usize;
            let (l, r) = b[1..].split_at_checked(ll)?;
            let n = l.iter().fold(0usize, |a, x| a * 256 + *x as usize);
            let (d, r) = r.split_at_checked(n)?;
            Some((Item::List(list(d)?), r))
        }
    }
}

fn list(mut d: &[u8]) -> Option<Vec<Item>> {
    let mut out = Vec::new();
    while !d.is_empty() {
        let (i, r) = rlp(d)?;
        out.push(i);
        d = r;
    }
    Some(out)
}

fn bytes(i: &Item) -> Option<&[u8]> {
    match i {
        Item::Bytes(b) => Some(b),
        Item::List(_) => None,
    }
}

fn num(i: &Item) -> Option<u64> {
    let b = bytes(i)?;
    (b.len() <= 8).then(|| b.iter().fold(0u64, |a, x| a * 256 + u64::from(*x)))
}

fn enc(i: &Item) -> Vec<u8> {
    match i {
        Item::Bytes(b) => ksg_anchor_v2::evm::rlp_bytes(b),
        Item::List(l) => ksg_anchor_v2::evm::rlp_list(&l.iter().map(enc).collect::<Vec<_>>()),
    }
}

fn reencode(items: &[&Item]) -> Vec<u8> {
    ksg_anchor_v2::evm::rlp_list(&items.iter().map(|i| enc(i)).collect::<Vec<_>>())
}

impl Chain {
    fn new() -> Self {
        let mut db = CacheDB::new(EmptyDB::default());
        let code = unhex(KSG_ANCHORS_BYTECODE).unwrap();
        let r = Evm::builder()
            .with_db(&mut db)
            .modify_tx_env(|tx| {
                tx.caller = Address::repeat_byte(0xee);
                tx.transact_to = TxKind::Create;
                tx.data = Bytes::from(code);
                tx.gas_limit = 5_000_000;
                tx.gas_price = U256::ZERO;
            })
            .build()
            .transact_commit()
            .unwrap();
        let contract = match r {
            ExecutionResult::Success {
                output: Output::Create(_, Some(a)),
                ..
            } => a.into_array(),
            other => panic!("deploy failed: {other:?}"),
        };
        Self {
            db,
            contract,
            nonces: BTreeMap::new(),
            receipts: Vec::new(),
            block: 1,
            time: 1_760_000_000,
            down: false,
            drop: None,
            drop_left: None,
            lose_confirmations: false,
            accounts: BTreeMap::new(),
            deployed: BTreeSet::new(),
            op_nonces: BTreeMap::new(),
            ops: Vec::new(),
            pm_calls: 0,
            log_span: None,
        }
    }

    fn exec(
        &mut self,
        from: [u8; 20],
        to: [u8; 20],
        data: Vec<u8>,
        commit: bool,
    ) -> ExecutionResult {
        let b = Evm::builder().with_db(&mut self.db).modify_tx_env(|tx| {
            tx.caller = Address::from(from);
            tx.transact_to = TxKind::Call(Address::from(to));
            tx.data = Bytes::from(data);
            tx.gas_limit = 1_000_000;
            tx.gas_price = U256::ZERO;
        });
        let mut evm = b.build();
        if commit {
            evm.transact_commit().unwrap()
        } else {
            evm.transact().unwrap().result
        }
    }

    fn send_raw(&mut self, raw: &[u8]) -> Result<[u8; 32], String> {
        let (ty, body) = raw.split_first().ok_or("empty")?;
        if *ty != 2 {
            return Err("only type-2 transactions".into());
        }
        let (Item::List(f), rest) = rlp(body).ok_or("bad rlp")? else {
            return Err("not a list".into());
        };
        if !rest.is_empty() || f.len() != 12 {
            return Err("bad transaction".into());
        }
        if num(&f[0]) != Some(CHAIN_ID) {
            return Err("wrong chain id".into());
        }
        let unsigned: Vec<&Item> = f[..9].iter().collect();
        let mut msg = vec![2u8];
        msg.extend_from_slice(&reencode(&unsigned));
        let digest = keccak(&msg);
        let y = num(&f[9]).ok_or("v")?;
        let mut rs = [0u8; 64];
        let r = bytes(&f[10]).ok_or("r")?;
        let s = bytes(&f[11]).ok_or("s")?;
        rs[32 - r.len()..32].copy_from_slice(r);
        rs[64 - s.len()..].copy_from_slice(s);
        let sig = Signature::from_slice(&rs).map_err(|_| "bad signature")?;
        if sig.normalize_s().is_some() {
            return Err("high-s signature".into());
        }
        let rec = RecoveryId::new(y == 1, false);
        let key =
            VerifyingKey::recover_from_prehash(&digest, &sig, rec).map_err(|_| "no signer")?;
        let from = address_of(&key);
        let nonce = num(&f[1]).ok_or("nonce")?;
        let want = self.nonces.get(&from).copied().unwrap_or(0);
        if nonce != want {
            return Err(format!("nonce {nonce}, expected {want}"));
        }
        let to: [u8; 20] = bytes(&f[5]).ok_or("to")?.try_into().map_err(|_| "to")?;
        let data = bytes(&f[7]).ok_or("data")?.to_vec();
        self.nonces.insert(from, want + 1);
        self.block += 1;
        self.time += 2;
        let hash = keccak(raw);
        let res = self.exec(from, to, data, true);
        let (ok, logs) = match res {
            ExecutionResult::Success { logs, .. } => (
                true,
                logs.into_iter()
                    .map(|l| {
                        (
                            l.data.topics().iter().map(|t| t.0).collect(),
                            l.data.data.to_vec(),
                        )
                    })
                    .collect(),
            ),
            _ => (false, Vec::new()),
        };
        self.receipts.push(Receipt {
            hash,
            ok,
            block: self.block,
            from,
            logs,
        });
        Ok(hash)
    }

    fn word(v: &[u8]) -> String {
        let mut w = [0u8; 32];
        w[32 - v.len()..].copy_from_slice(v);
        h(&w)
    }

    fn user_op(&mut self, j: &Value) -> Result<[u8; 32], String> {
        use ksg_anchor_v2::user_op::{decode_execute, init_code, UserOp, ENTRY_POINT_V06};
        let b = |k: &str| unhex(j[k].as_str().unwrap_or("")).map_err(|e| format!("{k}: {e}"));
        let n = |k: &str| {
            u128::from_str_radix(j[k].as_str().unwrap_or("").trim_start_matches("0x"), 16)
                .map_err(|_| format!("{k}: not a number"))
        };
        let sender: [u8; 20] = b("sender")?.try_into().map_err(|_| "sender")?;
        let mut nonce = [0u8; 32];
        nonce[16..].copy_from_slice(&n("nonce")?.to_be_bytes());
        let op = UserOp {
            sender,
            nonce,
            init_code: b("initCode")?,
            call_data: b("callData")?,
            call_gas_limit: n("callGasLimit")?,
            verification_gas_limit: n("verificationGasLimit")?,
            pre_verification_gas: n("preVerificationGas")?,
            max_fee_per_gas: n("maxFeePerGas")?,
            max_priority_fee_per_gas: n("maxPriorityFeePerGas")?,
            paymaster_and_data: b("paymasterAndData")?,
            signature: b("signature")?,
        };
        let owner = *self.accounts.get(&sender).ok_or("AA: unknown account")?;
        let want = self.op_nonces.get(&sender).copied().unwrap_or(0);
        if n("nonce")? != u128::from(want) {
            return Err(format!("AA25 invalid account nonce: {want} expected"));
        }
        let deployed = self.deployed.contains(&sender);
        if deployed != op.init_code.is_empty() || (!deployed && op.init_code != init_code(&owner)) {
            return Err("AA10/AA14: initCode does not fit the account".into());
        }
        let mut pm_final = PAYMASTER.to_vec();
        pm_final.push(1);
        if op.paymaster_and_data != pm_final {
            return Err("AA33: not the paymaster's final data".into());
        }
        // The account's check: the wrapped signature, owner 0, recovers to
        // the owner over the operation's hash.
        let hash = op.hash(&ENTRY_POINT_V06, CHAIN_ID);
        let sig = op
            .signature
            .get(128..128 + 65)
            .ok_or("AA23: signature shape")?;
        if op
            .signature
            .get(..128)
            .map(|w| w[31] == 0x20 && w[63] == 0 && w[95] == 0x40 && w[127] == 65)
            != Some(true)
        {
            return Err("AA23: signature wrapper".into());
        }
        let rs = Signature::from_slice(&sig[..64]).map_err(|_| "AA23: bad signature")?;
        let rec = RecoveryId::new(sig[64] == 28, false);
        let key =
            VerifyingKey::recover_from_prehash(&hash, &rs, rec).map_err(|_| "AA23: no signer")?;
        if address_of(&key) != owner {
            return Err("AA24 signature error".into());
        }
        let (target, data) = decode_execute(&op.call_data).ok_or("not execute")?;
        self.deployed.insert(sender);
        self.op_nonces.insert(sender, want + 1);
        self.block += 1;
        self.time += 2;
        let tx = keccak(&[hash.as_slice(), b"tx"].concat());
        let res = self.exec(sender, target, data, true);
        let (ok, logs) = match res {
            ExecutionResult::Success { logs, .. } => (
                true,
                logs.into_iter()
                    .map(|l| {
                        (
                            l.data.topics().iter().map(|t| t.0).collect(),
                            l.data.data.to_vec(),
                        )
                    })
                    .collect(),
            ),
            _ => (false, Vec::new()),
        };
        self.receipts.push(Receipt {
            hash: tx,
            ok,
            block: self.block,
            from: sender,
            logs,
        });
        self.ops.push((hash, tx, ok));
        Ok(hash)
    }

    pub fn call(&mut self, method: &str, p: &Value) -> Result<Value, String> {
        if self.down {
            return Err("the network is down".into());
        }
        if let Some(sel) = self.drop {
            if method == "eth_call"
                && p[0]["data"]
                    .as_str()
                    .and_then(|d| unhex(d).ok())
                    .is_some_and(|d| d.starts_with(&sel))
            {
                match &mut self.drop_left {
                    Some(0) => {}
                    Some(n) => {
                        *n -= 1;
                        return Err("the network is down".into());
                    }
                    None => return Err("the network is down".into()),
                }
            }
        }
        match method {
            "eth_chainId" => Ok(json!(hexnum(CHAIN_ID))),
            "eth_blockNumber" => Ok(json!(hexnum(self.block))),
            "eth_getBlockByNumber" => Ok(
                json!({"number": hexnum(self.block), "timestamp": hexnum(self.time), "baseFeePerGas": "0x1"}),
            ),
            "eth_maxPriorityFeePerGas" | "eth_gasPrice" => Ok(json!("0x1")),
            "eth_getTransactionCount" => {
                let a: [u8; 20] = unhex(p[0].as_str().unwrap_or(""))
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "address")?;
                Ok(json!(hexnum(self.nonces.get(&a).copied().unwrap_or(0))))
            }
            "eth_estimateGas" => Ok(json!(hexnum(100_000))),
            "eth_getCode" => {
                let a: [u8; 20] = unhex(p[0].as_str().unwrap_or(""))
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "address")?;
                Ok(json!(if self.deployed.contains(&a) || a == self.contract {
                    "0x01"
                } else {
                    "0x"
                }))
            }
            "eth_call"
                if p[0]["to"].as_str().and_then(|t| unhex(t).ok()).as_deref()
                    == Some(ksg_anchor_v2::user_op::CB_FACTORY.as_slice()) =>
            {
                let d = unhex(p[0]["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                if d != ksg_anchor_v2::user_op::get_address_data(
                    &d[d.len() - 20..].try_into().unwrap(),
                ) {
                    return Err("factory: not getAddress of one owner".into());
                }
                let owner: [u8; 20] = d[d.len() - 20..].try_into().unwrap();
                let a = account_of(&owner);
                self.accounts.insert(a, owner);
                Ok(json!(Self::word(&a)))
            }
            "eth_call"
                if p[0]["to"].as_str().and_then(|t| unhex(t).ok()).as_deref()
                    == Some(ksg_anchor_v2::user_op::ENTRY_POINT_V06.as_slice()) =>
            {
                let d = unhex(p[0]["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                let a: [u8; 20] = d.get(16..36).ok_or("getNonce")?.try_into().unwrap();
                if d != ksg_anchor_v2::user_op::get_nonce_data(&a) {
                    return Err("EntryPoint: not getNonce".into());
                }
                Ok(json!(Self::word(
                    &self.op_nonces.get(&a).copied().unwrap_or(0).to_be_bytes()
                )))
            }
            "pm_getPaymasterStubData" | "pm_getPaymasterData" => {
                if p[1].as_str().map(str::to_lowercase)
                    != Some(h(&ksg_anchor_v2::user_op::ENTRY_POINT_V06))
                    || p[2] != json!(hexnum(CHAIN_ID))
                {
                    return Err("paymaster: wrong EntryPoint or chain".into());
                }
                self.pm_calls += 1;
                let mut d = PAYMASTER.to_vec();
                d.push(u8::from(method == "pm_getPaymasterData"));
                Ok(json!({"paymasterAndData": h(&d)}))
            }
            "eth_estimateUserOperationGas" => Ok(json!({
                "callGasLimit": hexnum(100_000),
                "verificationGasLimit": hexnum(150_000),
                "preVerificationGas": hexnum(50_000),
            })),
            "eth_sendUserOperation" => Ok(json!(h(&self.user_op(&p[0])?))),
            "eth_getUserOperationReceipt" => {
                let want = unhex(p[0].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                Ok(self
                    .ops
                    .iter()
                    .find(|o| o.0.as_slice() == want.as_slice())
                    .map_or(
                        Value::Null,
                        |o| json!({"success": o.2, "receipt": {"transactionHash": h(&o.1)}}),
                    ))
            }
            "eth_call" => {
                let to: [u8; 20] = unhex(p[0]["to"].as_str().unwrap_or(""))
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "to")?;
                let from: [u8; 20] = p[0]["from"].as_str().map_or(Ok([1u8; 20]), |f| {
                    unhex(f)
                        .map_err(|e| e.to_string())?
                        .try_into()
                        .map_err(|_| "from".to_string())
                })?;
                let data = unhex(p[0]["data"].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                match self.exec(from, to, data, false) {
                    ExecutionResult::Success { output, .. } => Ok(json!(h(output.data()))),
                    ExecutionResult::Revert { output, .. } => {
                        Err(format!("execution reverted: {}", h(&output)))
                    }
                    ExecutionResult::Halt { reason, .. } => Err(format!("halt: {reason:?}")),
                }
            }
            "eth_sendRawTransaction" => {
                let raw = unhex(p[0].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                Ok(json!(h(&self.send_raw(&raw)?)))
            }
            "eth_getTransactionReceipt" if self.lose_confirmations => {
                Err("the network is down".into())
            }
            "eth_getTransactionReceipt" => {
                let want = unhex(p[0].as_str().unwrap_or("")).map_err(|e| e.to_string())?;
                Ok(self
                    .receipts
                    .iter()
                    .find(|r| r.hash.as_slice() == want.as_slice())
                    .map_or(Value::Null, |r| {
                        json!({"transactionHash": h(&r.hash), "status": if r.ok {"0x1"} else {"0x0"},
                               "blockNumber": hexnum(r.block), "from": h(&r.from)})
                    }))
            }
            "eth_getLogs" => {
                let f = &p[0];
                let block = |k: &str| match f[k].as_str() {
                    Some("latest") | None => Some(self.block),
                    Some(b) => u64::from_str_radix(b.trim_start_matches("0x"), 16).ok(),
                };
                let (lo, hi) = (
                    block("fromBlock").unwrap_or(0),
                    block("toBlock").unwrap_or(self.block),
                );
                if let Some(span) = self.log_span {
                    if span == 0 || hi.saturating_sub(lo) + 1 > span {
                        return Err(format!("eth_getLogs is limited to a {span} block range"));
                    }
                }
                // A topic position is one topic or a list of them (any
                // one matches), as on a real node.
                let topics: Vec<Vec<Vec<u8>>> = f["topics"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|t| match t {
                                Value::Array(any) => any
                                    .iter()
                                    .filter_map(|x| x.as_str().and_then(|s| unhex(s).ok()))
                                    .collect(),
                                _ => t.as_str().and_then(|s| unhex(s).ok()).into_iter().collect(),
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut out = Vec::new();
                for r in self
                    .receipts
                    .iter()
                    .filter(|r| (lo..=hi).contains(&r.block))
                {
                    for (ts, data) in &r.logs {
                        if topics
                            .iter()
                            .zip(ts)
                            .all(|(want, have)| want.iter().any(|w| w.as_slice() == have.as_slice()))
                        {
                            out.push(json!({"address": h(&self.contract), "topics": ts.iter().map(|t| h(t)).collect::<Vec<_>>(),
                                            "data": h(data), "blockNumber": hexnum(r.block)}));
                        }
                    }
                }
                Ok(Value::Array(out))
            }
            other => Err(format!("{other}: not answered")),
        }
    }
}

fn serve(stream: TcpStream, chain: Arc<Mutex<Chain>>) {
    let mut r = BufReader::new(stream.try_clone().expect("clone"));
    let mut w = stream;
    loop {
        let mut len = None;
        let mut line = String::new();
        loop {
            line.clear();
            if r.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line == "\r\n" {
                break;
            }
            let l = line.to_ascii_lowercase();
            if let Some(v) = l.strip_prefix("content-length:") {
                len = v.trim().parse::<usize>().ok();
            }
        }
        let mut body = vec![0u8; len.unwrap_or(0)];
        if r.read_exact(&mut body).is_err() {
            return;
        }
        let req: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        let method = req["method"].as_str().unwrap_or_default().to_owned();
        let answer = match chain.lock().unwrap().call(&method, &req["params"]) {
            Ok(v) => json!({"jsonrpc": "2.0", "id": req["id"], "result": v}),
            Err(e) => {
                json!({"jsonrpc": "2.0", "id": req["id"], "error": {"code": 3, "message": e}})
            }
        };
        let out = serde_json::to_vec(&answer).unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
            out.len()
        );
        if w.write_all(head.as_bytes())
            .and_then(|()| w.write_all(&out))
            .is_err()
        {
            return;
        }
    }
}

pub struct MockBase {
    pub url: String,
    pub chain: Arc<Mutex<Chain>>,
}

impl MockBase {
    pub fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().unwrap());
        let chain = Arc::new(Mutex::new(Chain::new()));
        let c = chain.clone();
        std::thread::spawn(move || {
            for s in listener.incoming().flatten() {
                let c = c.clone();
                std::thread::spawn(move || serve(s, c));
            }
        });
        Self { url, chain }
    }

    pub fn contract(&self) -> String {
        h(&self.chain.lock().unwrap().contract)
    }
}
