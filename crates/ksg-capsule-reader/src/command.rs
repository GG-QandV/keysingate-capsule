//! K3 (`Spec_kapsula` §27, `[decision]` 31.10 «B»): commands from the network.
//!
//! A party that holds no map (the issuer for E-13 `Finalize` and E-24, the
//! claimant for the delivery of a dispute) signs a [`CommandFile`] and
//! anchors it as a memo `ksg:cmd:v1 <link> <commit>`: `link` is blind over
//! the container under the **command key** the issuer born at printing and
//! gave both parties (`SideFile::cmd`), `commit` is blind over the hash of
//! the bytes the signatures cover. The reader of either party finds the memo
//! among the transactions of the accounts that paid the container's anchors,
//! matches it with a file in `commands/`, and hands both in through
//! `Request::ApplyCommand` before the holder's own command.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{Answer, CommandEvidence, CommandFile, CommandHead, Request};
use ksg_container_v2::Operation;
use ksg_core_v2::anchor::Attestation;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::SignatureSet;
use ksg_core_v2::doc::Uri;
use ksg_verify_v2::solana::{get_transaction, signatures_for, AnchorProof, Rpc, SealScanKey};
use zeroize::Zeroizing;

use crate::flow::{self, Layout, Party};
use crate::side::SideFile;

/// The memo's tag.
pub const CMD_MEMO_TAG: &str = "ksg:cmd:v1";

/// The attestation kind the reader gives a command's anchor.
pub const CMD_KIND: &str = "urn:ksg:anchor:solana:cmd:v1";

/// How many transactions per paying account the reader looks through.
pub const SCAN_LIMIT: u32 = 200;

/// The folder of command files next to the capsule.
#[must_use]
pub fn dir(layout: &Layout) -> PathBuf {
    layout.home.join("commands")
}

/// The blind link of `container`'s commands under the command key: the
/// seal-link function over a hash no seal ever has (a seal's link is over
/// a seal or the container's own identifier).
#[must_use]
pub fn link(key: &SealScanKey, container: &Hash) -> Vec<u8> {
    key.link(&Hash::sha256(&[CMD_MEMO_TAG.as_bytes(), container.as_bytes()].concat()))
        .to_vec()
}

/// The blind commit of a command: over the hash of what its signatures cover.
#[must_use]
pub fn commit(key: &SealScanKey, subject: &[u8]) -> Vec<u8> {
    key.commit(&Hash::sha256(subject)).to_vec()
}

/// The memo of a command.
#[must_use]
pub fn memo(key: &SealScanKey, container: &Hash, subject: &[u8]) -> String {
    format!(
        "{CMD_MEMO_TAG} {} {}",
        hex::encode(link(key, container)),
        hex::encode(commit(key, subject))
    )
}

/// `(link, commit)` of a command memo; `None` for any other memo.
#[must_use]
pub fn parse(memo: &str) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut parts = memo.split_whitespace();
    if parts.next() != Some(CMD_MEMO_TAG) {
        return None;
    }
    let link = hex::decode(parts.next()?).ok()?;
    let commit = hex::decode(parts.next()?).ok()?;
    parts.next().is_none().then_some((link, commit))
}

/// Writes 32 secret bytes to `path`, mode `0600`.
///
/// # Errors
///
/// The file does not write.
pub fn write_secret(path: &Path, bytes: &[u8; 32]) -> Result<(), String> {
    use std::io::Write as _;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(&B64.encode(bytes).into_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))
}

fn key_of(b64: &str, what: &str) -> Result<SealScanKey, String> {
    let v = Zeroizing::new(B64.decode(b64.trim()).map_err(|_| format!("{what}: not base64url"))?);
    let k: [u8; 32] = v.as_slice().try_into().map_err(|_| format!("{what}: not 32 bytes"))?;
    Ok(SealScanKey::new(k))
}

/// The command key at the issuer's stand.
fn stand_key(layout: &Layout) -> Result<SealScanKey, String> {
    let raw = std::fs::read_to_string(layout.stand().join("cmd.key"))
        .map_err(|e| format!("stand/cmd.key: {e}"))?;
    key_of(&raw, "stand/cmd.key")
}

/// The command key in `party`'s file.
fn party_key(layout: &Layout, party: Party) -> Result<SealScanKey, String> {
    let file = SideFile::read(&layout.side(party))?;
    if file.cmd.is_empty() {
        return Err("the side file carries no command key (printed before K3)".into());
    }
    key_of(&file.cmd, "side file: cmd")
}

/// The container's identifier and head, as the capsule says now.
fn container_and_head(layout: &Layout, party: Party) -> Result<(Hash, Option<CommandHead>), String> {
    let mut session = flow::open(layout, party)?;
    let status = match session.call(&Request::Status)? {
        Answer::Done { bytes } => serde_json::from_slice::<serde_json::Value>(&bytes)
            .map_err(|e| format!("status: {e}"))?,
        other => return Err(format!("status: {other:?}")),
    };
    let id = Hash::from_multihash(status["id"].as_str().ok_or("status: no id")?)
        .map_err(|e| format!("status: id: {e}"))?;
    let head = match &status["head"] {
        serde_json::Value::Null => None,
        h => Some(CommandHead {
            counter: h["counter"].as_u64().ok_or("status: head counter")?,
            page: Hash::from_multihash(h["page"].as_str().ok_or("status: head page")?)
                .map_err(|e| format!("status: head page: {e}"))?,
        }),
    };
    Ok((id, head))
}

/// The issuer's command for the capsule as it is now, signed with the
/// stand's issuer key (a stand key, `[decision]` 25.10).
///
/// # Errors
///
/// The capsule or the stand does not read.
pub fn issue(layout: &Layout, op: Operation, evidence: CommandEvidence) -> Result<CommandFile, String> {
    let seeds: ksg_cli_v2::home::Seeds = serde_json::from_slice(
        &std::fs::read(layout.stand().join("parties.json")).map_err(|e| format!("parties.json: {e}"))?,
    )
    .map_err(|e| format!("parties.json: {e}"))?;
    let issuer = ksg_cli_v2::home::Parties::from_seeds(&seeds)?.issuer;
    let (container, head) = container_and_head(layout, Party::Client)?;
    let mut file = CommandFile {
        v: 1,
        op,
        container,
        head,
        evidence,
        signatures: SignatureSet::default(),
    };
    let subject = file.subject()?;
    file.signatures = SignatureSet::new(vec![issuer.sign(&subject)]);
    Ok(file)
}

/// Saves a command file in `commands/` under its blind commit, and returns
/// its memo (under the stand's command key) and the file's path.
///
/// # Errors
///
/// The stand's command key does not read, the file does not write.
pub fn save(layout: &Layout, file: &CommandFile) -> Result<(String, PathBuf), String> {
    let key = stand_key(layout)?;
    let subject = file.subject()?;
    let memo = memo(&key, &file.container, &subject);
    std::fs::create_dir_all(dir(layout)).map_err(|e| format!("commands/: {e}"))?;
    let path = dir(layout).join(format!("{}.json", hex::encode(commit(&key, &subject))));
    std::fs::write(&path, serde_json::to_vec_pretty(file).map_err(|e| e.to_string())?)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok((memo, path))
}

/// Anchors a saved command: the memo goes out through the container's
/// anchorer (its payer); the transaction's signature is kept next to the
/// file, so its payer is among the accounts the readers look through.
///
/// # Errors
///
/// No anchor config, the memo does not go out.
pub fn publish(layout: &Layout, file: &CommandFile) -> Result<String, String> {
    let (memo, path) = save(layout, file)?;
    let cfg = flow::anchor_cfg(layout)?.ok_or("commands need --anchor: reprint with an anchor")?;
    let rpc = ksg_verify_v2::solana::HttpRpc::new(&cfg.rpc)?;
    let anchorer = ksg_cli_v2::anchoring::Anchorer::with_rpc(Box::new(rpc), &cfg)?;
    let subject = Hash::sha256(&file.subject()?);
    // The kind is only a label for the anchoring service.
    let (sig, _, _) =
        anchorer.send_memo(ksg_cli_v2::anchoring::MemoKind::Seal, &subject, &memo)?;
    std::fs::write(path.with_extension("tx"), sig.as_bytes())
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(sig)
}

/// What one look through the network found.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    /// Commands applied, by operation.
    pub applied: Vec<String>,
    /// Commands the container refused, with the reason (a replay among them).
    pub refused: Vec<String>,
    /// Anchors of this container's commands with no file: not applied, and
    /// the anchor is the proof that they exist (§5a, P-10).
    pub unmatched: Vec<String>,
    /// Files with no anchor found: not published, not applied.
    pub unpublished: Vec<String>,
}

/// Looks for `party`'s container's commands through `rpc` and applies the
/// ones with a file, oldest first.
///
/// # Errors
///
/// The side file, the commands folder or the network does not read; the
/// capsule does not write.
pub fn apply_with(layout: &Layout, party: Party, rpc: &dyn Rpc, cluster: &str) -> Result<Report, String> {
    let key = party_key(layout, party)?;
    // The container's identifier as the capsule names it (the side file may
    // still name the template it was printed from).
    let (container, _) = container_and_head(layout, party)?;
    let our_link = link(&key, &container);

    // The files, by their blind commit; the payers of their anchors.
    let mut files: Vec<(Vec<u8>, Vec<u8>, String)> = Vec::new(); // commit, json, op
    let mut payers: Vec<String> = Vec::new();
    let add_payer = |sig: &str, payers: &mut Vec<String>| -> Result<(), String> {
        if let Some(tx) = get_transaction(rpc, sig)? {
            if !payers.contains(&tx.fee_payer) {
                payers.push(tx.fee_payer);
            }
        }
        Ok(())
    };
    if let Ok(entries) = std::fs::read_dir(dir(layout)) {
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) == Some("json") {
                let json = std::fs::read(&path).map_err(|x| format!("{}: {x}", path.display()))?;
                let file: CommandFile = serde_json::from_slice(&json)
                    .map_err(|x| format!("{}: {x}", path.display()))?;
                files.push((commit(&key, &file.subject()?), json, format!("{:?}", file.op)));
            } else if path.extension().and_then(|x| x.to_str()) == Some("tx") {
                let sig = std::fs::read_to_string(&path).map_err(|x| format!("{}: {x}", path.display()))?;
                add_payer(sig.trim(), &mut payers)?;
            }
        }
    }
    if let Some(cfg) = flow::anchor_cfg(layout)? {
        if let Some(sig) = &cfg.last_signature {
            add_payer(sig, &mut payers)?;
        }
    }

    // The anchors with our link, oldest first.
    let mut found: Vec<(u64, String, Option<i64>, Vec<u8>)> = Vec::new(); // slot, sig, time, commit
    for payer in &payers {
        for sig in signatures_for(rpc, payer, None, SCAN_LIMIT)? {
            let Some(tx) = get_transaction(rpc, &sig)? else { continue };
            for (l, c) in tx.memos.iter().filter_map(|m| parse(m)) {
                if l == our_link && !found.iter().any(|f| f.3 == c) {
                    found.push((tx.slot, sig.clone(), tx.block_time, c));
                }
            }
        }
    }
    found.sort_by_key(|f| f.0);

    let mut report = Report::default();
    let mut session = flow::open(layout, party)?;
    let mut changed = false;
    for (slot, sig, time, c) in &found {
        let Some((_, json, op)) = files.iter().find(|f| &f.0 == c) else {
            report.unmatched.push(format!("{sig} (commit {})", hex::encode(c)));
            continue;
        };
        let file: CommandFile = serde_json::from_slice(json).map_err(|e| e.to_string())?;
        let attestation = Attestation {
            kind: Uri::parse(CMD_KIND).map_err(|e| e.to_string())?,
            subject: Hash::sha256(&file.subject()?),
            proof: AnchorProof { signature: sig.clone(), slot: *slot, cluster: cluster.to_owned() }
                .to_bytes()
                .map_err(|e| e.to_string())?,
            anchored_at: ksg_verify_v2::clock::utc(u64::try_from(time.unwrap_or(0)).unwrap_or(0) * 1000),
        };
        let request = Request::ApplyCommand {
            file: json.clone(),
            attestation: serde_json::to_vec(&attestation).map_err(|e| e.to_string())?,
        };
        let mut answer = session.call(&request)?;
        if matches!(answer, Answer::NeedsAnchor { .. }) {
            answer = flow::anchor_and_reanchor(layout, &mut session, answer, party)?;
        }
        match answer {
            Answer::Done { .. } => {
                changed = true;
                report.applied.push(op.clone());
            }
            Answer::Refused { reason } => report.refused.push(format!("{op}: {reason}")),
            other => report.refused.push(format!("{op}: {other:?}")),
        }
    }
    for (c, _, op) in &files {
        if !found.iter().any(|f| &f.3 == c) {
            report.unpublished.push(op.clone());
        }
    }
    if changed {
        flow::finish(layout, session)?;
    }
    Ok(report)
}

/// [`apply_with`] through the node of the container's anchor config.
///
/// # Errors
///
/// No anchor config; as [`apply_with`].
pub fn apply(layout: &Layout, party: Party) -> Result<Report, String> {
    let cfg = flow::anchor_cfg(layout)?.ok_or("no anchor config: commands come through the network")?;
    let rpc = ksg_verify_v2::solana::HttpRpc::new(&cfg.rpc)?;
    apply_with(layout, party, &rpc, &cfg.cluster)
}

/// How many records a capsule writes without the network having been asked
/// for its commands (`[decision]` 01.11 «V»: the same window as `light`'s ten
/// records off the anchors, `ksg_cli_v2::base_anchor::OFFLINE_RECORDS`).
pub const OFFLINE_CHECKS: u32 = 10;

fn offline_path(layout: &Layout) -> PathBuf {
    dir(layout).join("offline.json")
}

fn offline_since(layout: &Layout) -> u32 {
    std::fs::read(offline_path(layout))
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| v["since"].as_u64())
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(0)
}

fn set_offline_since(layout: &Layout, since: u32) -> Result<(), String> {
    std::fs::create_dir_all(dir(layout)).map_err(|e| format!("commands/: {e}"))?;
    std::fs::write(offline_path(layout), serde_json::json!({ "since": since }).to_string())
        .map_err(|e| format!("commands/offline.json: {e}"))
}

fn note(layout: &Layout, line: &str) {
    use std::io::Write as _;
    eprintln!("{line}");
    if std::fs::create_dir_all(dir(layout)).is_ok() {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir(layout).join("report.log"))
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// K3 (`Spec_kapsula` §27, «auto-apply», `[decision]` 01.11 «V»): the network's
/// commands go in **before** the holder's own — a holder's page first would
/// leave a command signed over the old head stale for good. Skipped for a
/// capsule without `anchor.json` (no Solana: commands are neither published
/// nor found) and for a side file without a command key (printed before K3).
/// With no answer from the network, an action that writes a page (`writes`)
/// is counted; past [`OFFLINE_CHECKS`] it is refused until the network
/// answers. A command found stale is written to `commands/report.log`: the
/// issuer has to sign it again.
///
/// # Errors
///
/// Past [`OFFLINE_CHECKS`] records without the network; the counter does not
/// write.
pub fn before_holder(layout: &Layout, party: Party, writes: bool) -> Result<(), String> {
    if flow::anchor_cfg(layout)?.is_none() {
        return Ok(());
    }
    before_holder_with(layout, party, writes, || apply(layout, party))
}

/// [`before_holder`] with the look through the network given (`look`), for a
/// capsule that has the network: the counting and the refusal past
/// [`OFFLINE_CHECKS`].
///
/// # Errors
///
/// As [`before_holder`].
pub fn before_holder_with(
    layout: &Layout,
    party: Party,
    writes: bool,
    look: impl FnOnce() -> Result<Report, String>,
) -> Result<(), String> {
    match SideFile::read(&layout.side(party)) {
        Ok(f) if !f.cmd.is_empty() => {}
        _ => return Ok(()),
    }
    match look() {
        Ok(report) => {
            set_offline_since(layout, 0)?;
            for op in &report.applied {
                eprintln!("a command from the network applied before this action: {op}");
            }
            for r in &report.refused {
                if r.contains("head") {
                    note(
                        layout,
                        &format!("a command from the network is stale (written over by records made without it): {r} — the issuer has to sign it again"),
                    );
                }
            }
            for u in &report.unmatched {
                note(layout, &format!("a command anchored in the network has no file here, not applied: {u}"));
            }
            Ok(())
        }
        Err(e) => {
            let since = offline_since(layout);
            if writes {
                if since >= OFFLINE_CHECKS {
                    return Err(format!(
                        "{since} records were written without asking the network for its commands \
                         (the limit is {OFFLINE_CHECKS}): the next one waits for the network ({e})"
                    ));
                }
                set_offline_since(layout, since + 1)?;
            }
            eprintln!(
                "the network's commands were not checked ({e}); records without the check: {}",
                if writes { since + 1 } else { since }
            );
            Ok(())
        }
    }
}
