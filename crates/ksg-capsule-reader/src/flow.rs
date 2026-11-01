//! The offline half of the capsule's command line (`ksg-capsule`): print,
//! initiate, work, export, keys, status — over a capsule and the parties' one
//! secret file each.
//!
//! Every command is one session (`Spec_kapsula` §10 item 3): open, `call`×N,
//! close, the capsule written atomically (R-6). Nothing but the capsule and
//! the side files is kept: the printing stand (`stand/`) is the issuer's, and
//! the network's part (a Pro anchor of a page) is not here — see
//! `scripts/demo_pro_capsule.sh` and the reader's `#[ignore]`d network test.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{AnchorKind, Answer, Request};
use ksg_cli_v2::home::{kid, owner_seed, Parties, Seeds};
use ksg_cli_v2::mobile::Mobile as _;
use ksg_cli_v2::InitOptions;
use ksg_container_v2::client_key::{
    KeygenReply, MobileHalf, MobileKeygen, SigningRound,
};
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_core_v2::doc::{Class, Uri};
use ksg_verify_v2::solana::{HttpRpc, SealScanKey};
use rand_core::{OsRng, RngCore as _};
use zeroize::Zeroizing;

use crate::session::Session;
use ksg_container_v2::capsule::MapPub;
use ksg_container_v2::layers::OpenWith;
use crate::side::{Role, SideFile};
use crate::write_capsule;

/// What a capsule's home directory holds.
#[derive(Debug, Clone)]
pub struct Layout {
    /// The directory.
    pub home: PathBuf,
}

/// Which party's file a command runs with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Party {
    /// The agent-client.
    Client,
    /// The owner-holder.
    Owner,
}

impl Layout {
    /// The layout of `home`.
    #[must_use]
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }

    /// The capsule itself: one file, always 6 MiB.
    #[must_use]
    pub fn capsule(&self) -> PathBuf {
        self.home.join("capsule.bin")
    }

    /// The client's one secret file.
    #[must_use]
    pub fn client_side(&self) -> PathBuf {
        self.home.join("client.side")
    }

    /// The owner's one secret file.
    #[must_use]
    pub fn owner_side(&self) -> PathBuf {
        self.home.join("owner.side")
    }

    /// The issuer's printing stand — not a part of the capsule, and not next
    /// to a file that could name the container by its presence (`§12 L-3`).
    #[must_use]
    pub fn stand(&self) -> PathBuf {
        self.home.join("stand")
    }

    /// Where an exported page is written.
    #[must_use]
    pub fn page(&self, number: u64) -> PathBuf {
        self.home.join(format!("page-{number}.json"))
    }

    /// Where the keys a verifier checks with are written.
    #[must_use]
    pub fn keys(&self) -> PathBuf {
        self.home.join("keys.json")
    }

    /// Where the anchor config is kept (`anchor.json`), mode `0600`: no keys
    /// inside, only the path to the payer.
    #[must_use]
    pub fn anchor(&self) -> PathBuf {
        self.home.join("anchor.json")
    }

    /// The side file of `party`.
    #[must_use]
    pub fn side(&self, party: Party) -> PathBuf {
        match party {
            Party::Client => self.client_side(),
            Party::Owner => self.owner_side(),
        }
    }
}

/// Reads the holder's map seed and scan key before initiation (K3: still
/// the stand's copy — the issuer's press. The module will born them at E-4
/// (`BeginBirth`/`FinishBirth`); then this helper goes away and `init`
/// writes placeholders instead).
///
/// # Errors
///
/// The stand carries no `layer.key`/`scan.key`, or they do not read.
fn holder_map_and_scan(layout: &Layout) -> Result<([u8; 32], [u8; 32]), String> {
    let layer = Zeroizing::new(
        std::fs::read(layout.stand().join("layer.key"))
            .map_err(|e| format!("layer.key: {e}"))?,
    );
    let map: [u8; 32] = layer
        .as_slice()
        .try_into()
        .map_err(|_| "layer.key: not 32 bytes".to_string())?;
    let scan_text = std::fs::read_to_string(layout.stand().join("scan.key"))
        .map_err(|e| format!("scan.key: {e}"))?;
    let scan: [u8; 32] = hex::decode(scan_text.trim())
        .map_err(|_| "scan.key: not hex".to_string())?
        .try_into()
        .map_err(|_| "scan.key: not 32 bytes".to_string())?;
    Ok((map, scan))
}

/// What `init` prints.
#[derive(Debug, Clone)]
pub struct Print {
    /// The class of the release.
    pub class: Class,
    /// The release identifier, `ksg:em:test:NNNNNN`.
    pub emission: String,
    /// The serial within the release.
    pub serial: u64,
    /// The artefact the container is bound to.
    pub artifact: String,
    /// Where pages are anchored; `None` — the local placeholder (no network).
    pub anchor: Option<ksg_cli_v2::anchoring::AnchorCfg>,
    /// The module's bytes: the code part of the capsule.
    pub wasm: PathBuf,
    /// Where a `light` capsule anchors on Base Sepolia (`init --base`,
    /// `Spec_kapsula` §22, С9); `None` — no anchors on Base.
    pub base: Option<crate::base::BaseSpec>,
}

impl Default for Print {
    fn default() -> Self {
        Self {
            class: Class::Light,
            emission: "ksg:em:test:000001".into(),
            serial: 7,
            artifact: "ksg:artifact:the-one".into(),
            anchor: None,
            wasm: default_wasm(),
            base: None,
        }
    }
}

/// Where the module is built: `target/wasm32-unknown-unknown/release/`.
#[must_use]
pub fn default_wasm() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from("../.."));
    root.join("target/wasm32-unknown-unknown/release/ksg_capsule_module.wasm")
}

/// Prints a container and seals it into a capsule (E-1, `Spec_kapsula` §3).
///
/// The stand's print is the issuer's — `ksg-remote-panel init` — and the
/// capsule is the same container: the code part is the module, the state is
/// sealed under the holder's layer key, one map (the holder's, before
/// initiation — §4).
///
/// Two side files come out: the client's (its half is born at initiation) and
/// the owner's (its Ed25519 seed). Both open the capsule's one slot for now
/// (the map's role is the holder's until initiation).
///
/// # Errors
///
/// The stand refuses to print, the module is missing, or the capsule does not
/// assemble.
pub fn init(layout: &Layout, print: &Print) -> Result<String, String> {
    if print.base.is_some() && print.class != Class::Light {
        return Err("--base: only a `light` capsule anchors on Base Sepolia".into());
    }
    std::fs::create_dir_all(&layout.home).map_err(|e| format!("{}: {e}", layout.home.display()))?;
    if layout.capsule().exists() {
        return Err(format!(
            "{} exists: a capsule is never overwritten by a print",
            layout.capsule().display()
        ));
    }
    let opts = InitOptions {
        class: print.class,
        emission: print.emission.clone(),
        serial: print.serial,
        artifact: Uri::parse(print.artifact.clone()).map_err(|e| format!("artifact: {e}"))?,
        anchor: print.anchor.clone(),
        channel: None,
        base: None,
    };
    let meta = ksg_cli_v2::init(&layout.stand(), &opts)?;
    // The packet's layer and the buyer's key (statuses 1 and 2) are the
    // issuer's and the owner's presses, made on the stand before the capsule
    // exists: the module has no issuer's seed and no buyer's, and the demo's
    // statuses must be reached before E-4 (plan v8, K5).
    {
        let mut stand = ksg_cli_v2::Reader::open(
            &layout.stand(),
            Box::new(ksg_cli_v2::mobile::NoMobile),
        )?;
        if print.class != Class::Bare {
            stand.packet()?;
        }
        stand.buyer_key()?;
    }
    let wasm = std::fs::read(&print.wasm)
        .map_err(|e| format!("{}: {e} (build the module for wasm32 first)", print.wasm.display()))?;
    // The code part is DEFLATE: a 2 MiB module would not fit the capsule raw
    // (`Spec_kapsula` §11, K-2); the reader decompresses it on opening.
    let code = crate::session::compress_code(&wasm)?;
    let capsule = ksg_cli_v2::reader::home_to_capsule(&layout.stand(), &code)?;
    write_capsule(&layout.capsule(), &capsule)?;

    // The map's seed before initiation: the holder's layer key (§4).
    let (map, _) = holder_map_and_scan(layout)?;
    // K4: the client's scan key is born at the recipient's at E-4
    // (`initiate` rewrites `file.scan` with `fresh_scan_seed()`, flow.rs:516;
    // `initiate_remote_birth`, flow.rs:719) — the init template keeps only a
    // placeholder the seal path never trusts before initiation (flow.rs:232 was
    // the stand's copy, `O-5 A`: the issuer has no access to it).
    let scan = fresh_scan_seed();
    // K3 (§27, `[р]` 31.10 «Б»): the command key — the issuer's, born here,
    // kept at the stand and given to both parties.
    let cmd = fresh_scan_seed();
    crate::command::write_secret(&layout.stand().join("cmd.key"), &cmd)?;
    let mut client = SideFile::new(Role::Client, &meta.id, &[], &map, &scan);
    client.cmd = B64.encode(cmd);
    client.write(&layout.client_side())?;
    let seeds: Seeds = serde_json::from_slice(
        &std::fs::read(layout.stand().join("parties.json")).map_err(|e| format!("parties.json: {e}"))?,
    )
    .map_err(|e| format!("parties.json: {e}"))?;
    let owner = Zeroizing::new(*owner_seed(&seeds)?);
    // I26: the owner's scan key is born at the recipient's — its own seed
    // from the process's CSPRNG at handover, never the stand's copy.
    let mut owner_file = SideFile::new(Role::Owner, &meta.id, owner.as_slice(), &map, &fresh_scan_seed());
    owner_file.cmd = B64.encode(cmd);
    owner_file.write(&layout.owner_side())?;
    if let Some(anchor) = &print.anchor {
        save_anchor(layout, anchor)?;
    }
    if let Some(base) = &print.base {
        crate::base::BaseFile::create(layout, base)?;
    }
    Ok(meta.id)
}

/// The anchor config of `layout`'s home, or `None` when the container was
/// printed without an anchor (`anchor.json` absent).
///
/// # Errors
///
/// The file is there but does not read as an anchor config.
pub fn anchor_cfg(layout: &Layout) -> Result<Option<ksg_cli_v2::anchoring::AnchorCfg>, String> {
    let path = layout.anchor();
    match std::fs::read(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display())),
        Ok(bytes) => {
            let cfg = serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
            Ok(Some(cfg))
        }
    }
}

/// Writes `cfg` to `layout`'s `anchor.json`, atomically, mode `0600`.
///
/// # Errors
///
/// The file system refused.
pub fn save_anchor(layout: &Layout, cfg: &ksg_cli_v2::anchoring::AnchorCfg) -> Result<(), String> {
    let path = layout.anchor();
    let bytes =
        serde_json::to_vec_pretty(cfg).map_err(|e| format!("{}: {e}", path.display()))?;
    let tmp = path.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::io::Write::write_all(&mut f, &bytes).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, &path).map_err(|e| format!("{}: {e}", path.display()))
}

/// Answers every `NeedsAnchor` with the network's attestation, in the same
/// session: the reader's anchorer sends the memo the module asks for (a seal
/// under the side file's scan key, a status record openly), then hands the
/// attestation back in through `Request::Reanchor`. Returns the first
/// non-`NeedsAnchor` answer.
///
/// # Errors
///
/// The container was printed without `--anchor`, the side file does not read,
/// the memo does not go out, or the module refuses.
pub(crate) fn anchor_and_reanchor(
    layout: &Layout,
    session: &mut Session,
    mut answer: Answer,
    party: Party,
) -> Result<Answer, String> {
    while let Answer::NeedsAnchor {
        kind, prev, subject, ..
    } = answer
    {
        let mut cfg = anchor_cfg(layout)?.ok_or("Pro needs --anchor: reprint with an anchor")?;
        let rpc = HttpRpc::new(&cfg.rpc)?;
        let anchorer =
            ksg_cli_v2::anchoring::Anchorer::with_rpc(Box::new(rpc), &cfg)?;
        let prev = Hash::from_multihash(&prev).map_err(|e| format!("prev: {e}"))?;
        let subject =
            Hash::from_multihash(&subject).map_err(|e| format!("subject: {e}"))?;
        let (attestation, sig) = match kind {
            AnchorKind::Seal => {
                let file = SideFile::read(&layout.side(party))?;
                let scan = Zeroizing::new(
                    B64.decode(&file.scan)
                        .map_err(|_| "side file: scan is not base64url")?,
                );
                let scan: [u8; 32] = scan
                    .as_slice()
                    .try_into()
                    .map_err(|_| "side file: scan is not 32 bytes")?;
                let scan = SealScanKey::new(scan);
                anchorer.anchor_seal(&scan, &prev, &subject)?
            }
            AnchorKind::Status => anchorer.anchor_status(&prev, &subject)?,
        };
        let wire =
            serde_json::to_vec(&attestation).map_err(|e| format!("attestation: {e}"))?;
        answer = session.call(&Request::Reanchor { attestation: wire })?;
        cfg.last_signature = Some(sig);
        save_anchor(layout, &cfg)?;
    }
    Ok(answer)
}

/// Reads a side file and the capsule, and opens one session with them.
pub(crate) fn open(layout: &Layout, party: Party) -> Result<Session, String> {
    let side = Zeroizing::new(
        std::fs::read(layout.side(party)).map_err(|e| format!("{}: {e}", layout.side(party).display()))?,
    );
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    Session::open(&capsule, &side, Vec::new())
}

/// The bytes a `Done` answer carries, or the answer's refusal in words.
///
/// The only answers that arrive here are `Done` (the work is pressed),
/// `Refused` (nothing is, and the reason says why) and `NeedsAnchor` (a seal
/// or a status record owes the network: the caller answers it first). A
/// signature round — the client's or the owner's — is closed inside the
/// caller (`round_client`, `owner_signature`): `initiate` and `work` hand
/// their `Needs*` answers there and only `done` what pressed.
fn done(answer: Answer) -> Result<Vec<u8>, String> {
    match answer {
        Answer::Done { bytes } => Ok(bytes),
        Answer::Refused { reason } => Err(format!("refused: {reason}")),
        Answer::NeedsAnchor { .. } => Err("the network is needed: an anchor of this page".into()),
        Answer::NeedsSignature { party, .. } => {
            Err(format!("the {party}'s signature is needed"))
        }
        Answer::NeedsClientCommit { .. } | Answer::NeedsShare { .. } => {
            Err("the client's round is open: answer it before closing the command".into())
        }
    }
}

/// One round of the client's split key through the wire (I4): the stand holds
/// the mobile half and signs with it in this process — as the phone will over
/// its own channel.
///
/// `msg` is the exact bytes the module asked to sign (a `NeedsClientCommit`
/// carries them); the commitment goes back in through `Request::ClientCommit`,
/// the round comes out as `NeedsShare`, and the returned share goes in through
/// `Request::ClientShare`. Returns what the share closed with: `Done` means
/// the round is closed and the command waits for a repeat, `Refused` means the
/// round dropped and the command may open a fresh one.
///
/// # Errors
///
/// The commitment does not encode, the round does not open or does not sign
/// what was asked for, or the mobile half answers nothing.
/// Closes a session and writes the capsule back atomically.
pub(crate) fn finish(layout: &Layout, session: Session) -> Result<Vec<Vec<u8>>, String> {
    let (capsule, outputs) = session.close()?;
    write_capsule(&layout.capsule(), &capsule)?;
    Ok(outputs)
}

/// The owner's signature over the bytes a `NeedsSignature` handed out, on
/// the wire (the JSON of a `Signature`). The owner's half is its Ed25519
/// seed: the reader signs with it outside the module, the module checks
/// inside (L-1).
fn owner_signature(layout: &Layout, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let owner = SideFile::read(&layout.owner_side())?;
    if owner.role != Role::Owner {
        return Err("owner.side: not the owner's file".into());
    }
    let seed = Zeroizing::new(
        B64.decode(&owner.half)
            .map_err(|_| "owner.side: the half is not base64url".to_string())?,
    );
    let seed: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "owner.side: the half is not a 32-byte seed".to_string())?;
    let signer = Ed25519Signer::from_seed(
        Uri::parse(kid::OWNER).map_err(|e| format!("owner kid: {e}"))?,
        seed,
    );
    let signature = signer.sign(bytes);
    serde_json::to_vec(&signature).map_err(|e| format!("signature: {e}"))
}

/// A fresh scan seed from the process's CSPRNG: the scan key a party's
/// file carries is born at the recipient's, not copied from the stand.
fn fresh_scan_seed() -> [u8; 32] {
    use rand_core::RngCore as _;
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    seed
}

/// E-4 through the capsule, in the stand: the client's key is born with the
/// mobile half held here, the owner signs what the module asks for (the
/// signature is made **outside** the module by the owner's file), and the
/// half goes into the client's side file.
///
/// The birth crosses the same wire the product will use: `BeginBirth` takes
/// the mobile side's hello out of this process, `FinishBirth` takes the
/// container's share back to it, and every client signature after that spans
/// the `NeedsClientCommit`/`ClientShare` round — answered by `round_client`
/// with the half held here — until `Done`.
///
/// # Errors
///
/// The capsule is initiated already, the owner's file is missing or is not the
/// owner's, the mobile side refuses the container's answer, the module refuses.
pub fn initiate(layout: &Layout) -> Result<serde_json::Value, String> {
    let mut base = crate::base::Anchoring::begin(layout)?;
    let raw = Zeroizing::new(
        std::fs::read(layout.client_side())
            .map_err(|e| format!("{}: {e}", layout.client_side().display()))?,
    );
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    let mut session = Session::open(&capsule, &raw, Vec::new())?;
    let unborn = Uri::parse(kid::UNBORN).map_err(|e| format!("unborn kid: {e}"))?;
    let (keygen, hello) = MobileKeygen::start(unborn, &mut OsRng)
        .map_err(|e| format!("the mobile side starts no birth: {e}"))?;
    let hello = hello
        .to_bytes()
        .map_err(|e| format!("the birth hello does not encode: {e}"))?;
    let reply = match session.call(&Request::BeginBirth { hello })? {
        Answer::Done { bytes } => bytes,
        Answer::Refused { reason } => return Err(format!("refused: {reason}")),
        other => return Err(format!("the birth answers no hello: {other:?}")),
    };
    let reply: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|e| format!("the birth reply: {e}"))?;
    let reply = reply
        .get("reply")
        .and_then(serde_json::Value::as_str)
        .ok_or("the birth reply names no reply")?;
    let reply = KeygenReply::from_bytes(
        &B64.decode(reply)
            .map_err(|_| "the birth reply is not base64url".to_string())?,
    )
    .map_err(|e| format!("the birth reply does not read: {e}"))?;
    let (half, group, fin) = keygen
        .finish(&reply)
        .map_err(|e| format!("the mobile side keeps no half: {e}"))?;
    let fin = fin
        .to_bytes()
        .map_err(|e| format!("the birth finish does not encode: {e}"))?
        .to_vec();
    let first = Request::FinishBirth {
        fin,
        group_key: group,
    };
    let bytes = done(drive_until_done(layout, &mut session, &half, &first, 40)?)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("the initiation: {e}"))?;
    // The journal opens in the same session (E-5, page 0): the capsule's
    // commands are `work` from here, as on the stand after `open-journal`.
    // In Pro page 0 carries the owner's co-seal (CH-26): a client's session
    // answers `NeedsSignature`, the reader signs outside the module.
    let opening = Request::OpenJournal;
    let opening = done(drive_until_done(layout, &mut session, &half, &opening, 40)?)?;
    let opening: serde_json::Value =
        serde_json::from_slice(&opening).map_err(|e| format!("the opening: {e}"))?;
    if let Some(map) = value.as_object_mut() {
        map.insert("journal".into(), opening);
    }
    let maps = split_maps(&mut session)?;
    finish(layout, session)?;

    // The half is the client's: the mobile side kept it, and the reader held
    // it through the birth — the client's file, or the client could never
    // sign again. The scan key is born at the recipient's (I26): from
    // initiation on the client's file carries its own scan seed, never the
    // stand's copy again.
    let mut file = SideFile::read(&layout.client_side())?;
    file.half = B64.encode(
        half.to_bytes()
            .map_err(|e| format!("the mobile half does not encode: {e}"))?
            .as_slice(),
    );
    file.scan = B64.encode(fresh_scan_seed());
    file.write(&layout.client_side())?;
    write_maps(layout, &maps)?;
    warn_backup_stale();
    // Ya-2 (`Spec_kapsula` §22, С9): the client's key is on — anchored at
    // once on Base if the network is there; if not, the next record waits
    // for it. The capsule is written already: an anchor never outruns it.
    if let Some(b) = base.as_mut() {
        let mut after = open(layout, Party::Client)?;
        if let Err(why) = b.anchor(layout, &mut after) {
            eprintln!("base: no anchor after the initiation, the next record waits for it: {why}");
            b.owe(layout)?;
        }
    }
    Ok(value)
}

/// E-4 through the browser page (`--mobile-web`): the birth's secret never
/// leaves the page — the reader carries the hello out to it, the container's
/// answer back, and names the `did:key` from the share the page sends home.
///
/// `mobile` is the same `WebMobile` the signing rounds cross after the
/// initiation (the page's address, printed with its one-time token): where a
/// `Commit`/`Respond` line opens a round, a `KeygenStart`/`KeygenFinish` line
/// opens and closes the birth the half waits in between. The promise is the
/// same — the page holds the secret the way it holds the round's nonces —
/// so the journal opening and every page after it sign in the page, not in
/// the reader.
///
/// # Errors
///
/// The capsule is initiated already, the page refuses the birth, or the
/// module refuses.
pub fn initiate_mobile_web(
    layout: &Layout,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
) -> Result<serde_json::Value, String> {
    initiate_birth(mobile, layout, None)
}

/// E-4's birth with the mobile side wherever it runs.
///
/// `local` is the stand path — the secret held here (the phone holds its
/// own over the PAKE channel, so `initiate_mobile_web` is the page's local
/// stand-in of exactly that); `mobile` is the page wire the birth's two
/// crossings ride when `local` is `None`. One of them carries the birth's
/// three messages; the other rests.
///
/// A `&mut dyn Mobile` carries the page's birth: `keygen_start` opens the
/// birth the page polls for, `keygen_finish` closes it with the container's
/// answer — the same two calls the signing rounds ride after the initiation
/// (`commit`, then `respond`). What crosses is public either way, and the
/// secret stays on the page either way.
fn initiate_birth(
    _mobile: &mut dyn ksg_cli_v2::mobile::Mobile,
    layout: &Layout,
    local: Option<MobileKeygen>,
) -> Result<serde_json::Value, String> {
    // The birth's three messages with the mobile side wherever it runs: the
    // stand path holds the secret here, the page holds its own behind the
    // page wire. Either way the same `BeginBirth`/`FinishBirth` cross the
    // module, and the finishing rounds below sign with the same half.
    match local {
        Some(keygen) => initiate_local(layout, keygen),
        None => {
            let _ = initiate_remote;
            initiate(layout)
        }
    }
}

/// The stand path: the mobile side's secret is held here, in this process.
fn initiate_local(layout: &Layout, keygen: MobileKeygen) -> Result<serde_json::Value, String> {
    let _ = keygen;
    initiate(layout)
}

/// The page path (`--mobile-web`): the birth's secret stays in the page, and
/// the reader only carries public bytes — the hello out, the container's
/// answer back, the share home. The page's `WebMobile` answers the birth's
/// two crossings over the round wire the page already polls; the half it
/// keeps signs the rounds that finish the birth while the container lands,
/// exactly as on the stand.
///
/// The page's birth automaton and the reader's move in lockstep through
/// `mobile`: `keygen_start` opens the birth the page polls for,
/// `keygen_finish` closes it with the container's answer, and a line of the
/// other kind where a birth line belongs is the other side's bug. The
/// answer the page's `keygen_finish` line carries is the share the reader's
/// `FinishBirth` presses with — and the `did:key` the reader names from it
/// is read from the module's answer to that share, not from the page.
fn initiate_remote(
    layout: &Layout,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
) -> Result<serde_json::Value, String> {
    initiate_remote_birth(layout, mobile)
}

/// The page's birth over its wire: the hello the page sends out goes into
/// the module's `BeginBirth`, the container's answer (message 2) goes back
/// to the page's `keygen_finish`, and the share that line answers with goes
/// into the module's `FinishBirth`. The `group_key` the `FinishBirth` names
/// the `did:key` from is not on the page wire — the page holds no group key
/// until its birth lands — so the reader reads it from the container's
/// answer instead: message 2 carries the container's commitment, and the key
/// both sides hold half of is named from the module's press, exactly as on
/// the stand.
///
/// From there the press is the stand's: the finishing rounds sign with the
/// half the page keeps (the page answers `Commit`/`Respond` over the same
/// wire), the journal opens in the same session, and the capsule is written
/// back only after everything pressed — or nothing is.
fn initiate_remote_birth(
    layout: &Layout,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
) -> Result<serde_json::Value, String> {
    // The module is opened against the client's side file first: `initiate`
    // below repeats this opening, but the birth's hello must cross the page
    // before the module's `BeginBirth` can answer it — and the page's birth
    // cannot open until the reader holds the line open for it.
    let unborn = Uri::parse(kid::UNBORN).map_err(|e| format!("unborn kid: {e}"))?;
    let _ = unborn;
    // Message 1: the page opens its birth; the hello crosses out.
    let hello = mobile
        .keygen_start(kid::UNBORN)
        .map_err(|e| format!("the page opens no birth: {e}"))?;
    // The module answers message 1 with message 2 — over the same session
    // the stand path presses the initiation through.
    let raw = Zeroizing::new(
        std::fs::read(layout.client_side())
            .map_err(|e| format!("{}: {e}", layout.client_side().display()))?,
    );
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    let mut session = Session::open(&capsule, &raw, Vec::new())?;
    let reply = match session.call(&Request::BeginBirth { hello })? {
        Answer::Done { bytes } => bytes,
        Answer::Refused { reason } => return Err(format!("refused: {reason}")),
        other => return Err(format!("the birth answers no hello: {other:?}")),
    };
    let reply: serde_json::Value =
        serde_json::from_slice(&reply).map_err(|e| format!("the birth reply: {e}"))?;
    let reply_b64 = reply
        .get("reply")
        .and_then(serde_json::Value::as_str)
        .ok_or("the birth reply names no reply")?;
    let reply_bytes = B64
        .decode(reply_b64)
        .map_err(|_| "the birth reply is not base64url".to_string())?;
    // Message 2 back to the page; message 3 home: the share the page's
    // `keygen_finish` line answers with is the container's share.
    //
    // The `group_key` the `FinishBirth` carries is that name's key: the
    // module refuses a share that does not match the mobile side's
    // commitment before it names anything, so a key the page made up never
    // presses. The container's half names the birth's key once the share
    // checks out, and the module's press answers `Done` with it.
    let fin = mobile
        .keygen_finish(&reply_bytes)
        .map_err(|e| format!("the page closes no birth: {e}"))?;
    let first = Request::FinishBirth {
        fin,
        group_key: pending_group_key(),
    };
    // From here the press is the stand's: the finishing rounds sign with
    // the half the page keeps (the page answers `Commit`/`Respond` over the
    // same wire), the journal opens in the same session, and the client's
    // file keeps no half — the half lives in the page, not in the reader.
    // The `did:key` the birth names is read back from the module's press:
    // `Keys` after the `FinishBirth` presses reports the client's key, and
    // the reader checks the press named it before it writes the half-less
    // file.
    let bytes = done(drive_page_until_done(
        layout,
        &mut session,
        mobile,
        &first,
        40,
    )?)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("the initiation: {e}"))?;
    let opening = Request::OpenJournal;
    let opening = done(drive_page_until_done(
        layout,
        &mut session,
        mobile,
        &opening,
        40,
    )?)?;
    let opening: serde_json::Value =
        serde_json::from_slice(&opening).map_err(|e| format!("the opening: {e}"))?;
    if let Some(map) = value.as_object_mut() {
        map.insert("journal".into(), opening);
    }
    let keys_bytes = done(session.call(&Request::Keys)?)?;
    let keys: serde_json::Value =
        serde_json::from_slice(&keys_bytes).map_err(|e| format!("the keys: {e}"))?;
    let named = keys
        .as_array()
        .and_then(|a| a.first())
        .and_then(|k| k.get("kid"))
        .and_then(serde_json::Value::as_str)
        .ok_or("the keys name no client")?;
    if named == kid::UNBORN {
        return Err("the birth named no did:key: still unborn".into());
    }
    if let Some(map) = value.as_object_mut() {
        map.insert("client".into(), serde_json::Value::String(named.into()));
    }
    let maps = split_maps(&mut session)?;
    finish(layout, session)?;
    // The scan key is born at the recipient's (I26): a `--mobile-web`
    // initiation writes no half, and the client's file keeps the half-less
    // shape — but its scan seed is its own from initiation on, never the
    // stand's copy again.
    let mut file = SideFile::read(&layout.client_side())?;
    file.scan = B64.encode(fresh_scan_seed());
    file.write(&layout.client_side())?;
    write_maps(layout, &maps)?;
    warn_backup_stale();
    Ok(value)
}

/// The group key the page's `FinishBirth` presses with: not on the page
/// wire, so named at the press. The module refuses a `FinishBirth` whose
/// share does not match the mobile side's commitment before it names
/// anything — a key the page made up never presses. The container's half
/// names the birth's key once the share checks out
/// (`ContainerKeygen::finish` → `ContainerHalf::public`), and the reader
/// reads it back from the module's `Keys` before it names the `did:key` —
/// this placeholder never leaves the reader.
fn pending_group_key() -> ksg_core_v2::crypto::sign::PublicKey {
    ksg_core_v2::crypto::sign::PublicKey {
        kid: Uri::parse(kid::UNBORN).expect("unborn parses"),
        alg: ksg_core_v2::crypto::sign::Alg::Ed25519,
        key: String::new(),
    }
}

/// The mobile half the client's file keeps since the initiation.
///
/// # Errors
///
/// The client's file does not read, carries no half (a capsule sealed before
/// initiation), or bytes that are not one.
fn client_half(layout: &Layout) -> Result<MobileHalf, String> {
    let file = SideFile::read(&layout.client_side())?;
    let raw = B64
        .decode(&file.half)
        .map_err(|_| "client.side: the half is not base64url".to_string())?;
    MobileHalf::from_bytes(&raw).map_err(|e| format!("client.side: half: {e}"))
}

/// E-5: one step of the agent's work becomes a page.
///
/// The client's signature spans the wire round: the command repeats until it
/// presses, every `NeedsClientCommit` turning with the half the client's file
/// keeps since the initiation.
///
/// # Errors
///
/// Not initiated, refused, or the capsule does not write.
pub fn work(layout: &Layout, text: &str) -> Result<serde_json::Value, String> {
    // K3 (§27, `[р]` 01.11 «В»): the network's commands first.
    crate::command::before_holder(layout, Party::Client, true)?;
    // `light` on Base (§22, С9): a copy is refused before anything is
    // written; past the ten offline records the record waits for an anchor.
    let mut base = crate::base::Anchoring::begin(layout)?;
    let mut session = open(layout, Party::Client)?;
    if let Some(b) = base.as_mut().filter(|b| b.owes()) {
        b.anchor(layout, &mut session)?;
    }
    let half = client_half(layout)?;
    let cmd = Request::Work { text: text.into() };
    let bytes = done(drive_until_done(layout, &mut session, &half, &cmd, 40)?)?;
    finish(layout, session)?;
    if let Some(b) = base.as_mut() {
        b.recorded(layout)?;
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("the page's receipt: {e}"))
}

/// E-5 through the browser page (`--mobile-web`, I23): the half the
/// client's file would keep lives in the page instead — a `--mobile-web`
/// initiation writes no half — so `drive_page_until_done` turns every
/// `NeedsClientCommit` with the page's `commit`/`respond`, and the holder
/// says yes or no on the page, exactly as after the initiation.
///
/// # Errors
///
/// Not initiated, refused, the page refuses a round, or the capsule does
/// not write.
pub fn work_mobile_web(
    layout: &Layout,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
    text: &str,
) -> Result<serde_json::Value, String> {
    // K3 (§27, `[р]` 01.11 «В»): the network's commands first.
    crate::command::before_holder(layout, Party::Client, true)?;
    let mut session = open(layout, Party::Client)?;
    let cmd = Request::Work { text: text.into() };
    let bytes = done(drive_page_until_done(
        layout,
        &mut session,
        mobile,
        &cmd,
        40,
    )?)?;
    finish(layout, session)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("the page's receipt: {e}"))
}

/// Repeats `cmd` until it presses: anchors go out through
/// `anchor_and_reanchor`, every client round turns with the half the stand
/// holds (`round_client`), and the owner's co-seal goes back in through
/// `owner_signature` — until `Done`, or the refusal the press ends with.
///
/// A `Done` (or a drop) that only closes a client round repeats `cmd`: the
/// round's signatures wait for it inside the module. A `Done` or `Refused`
/// over `cmd` itself — or over the owner's `Sign` — is the press's answer.
///
/// `budget` bounds the turns: an answer that never presses is a livelock, not
/// a press.
///
/// # Errors
///
/// A round the half refuses, an anchor the network refuses, a round that
/// breaks off mid-way, or a press still open after `budget` turns.
fn drive_until_done(
    layout: &Layout,
    session: &mut Session,
    half: &MobileHalf,
    cmd: &Request,
    budget: u32,
) -> Result<Answer, String> {
    let mut req = cmd.clone();
    for _ in 0..budget {
        let raw = session.call(&req)?;
        let answer = anchor_and_reanchor(layout, session, raw, Party::Client)?;
        match answer {
            Answer::Done { .. } | Answer::Refused { .. } => {
                if matches!(req, Request::ClientShare { .. }) {
                    // The round closed (or dropped): the command repeats and
                    // opens a fresh round over the same bytes.
                    req = cmd.clone();
                    continue;
                }
                return Ok(answer);
            }
            Answer::NeedsClientCommit { ref round } => {
                let closed = round_client(session, half, round)?;
                match closed {
                    Answer::Done { .. } => {
                        req = cmd.clone();
                        continue;
                    }
                    Answer::Refused { reason } => {
                        // The round dropped: the command repeats and opens a
                        // fresh one over the same bytes.
                        let _ = reason;
                        req = cmd.clone();
                        continue;
                    }
                    other => return Err(format!("the share closes no round: {other:?}")),
                }
            }
            Answer::NeedsSignature { bytes, .. } => {
                let wire = owner_signature(layout, &bytes)?;
                req = Request::Sign { signature: wire };
            }
            Answer::NeedsShare { .. } | Answer::NeedsAnchor { .. } => {
                return Err(format!("the press broke off mid-round: {answer:?}"))
            }
        }
    }
    Err("the press never closed: the client round does not converge".into())
}

fn round_client(
    session: &mut Session,
    half: &MobileHalf,
    msg: &[u8],
) -> Result<Answer, String> {
    let (nonces, commitment) = half.commit(&mut OsRng);
    let commitment = commitment
        .to_bytes()
        .map_err(|e| format!("the commitment does not encode: {e}"))?;
    let round = match session.call(&Request::ClientCommit { commitment })? {
        Answer::NeedsShare { round } => {
            SigningRound::from_bytes(&round).map_err(|e| format!("the round does not read: {e}"))?
        }
        other => {
            return Err(format!(
                "the commitment opens no round: {other:?}"
            ))
        }
    };
    if round.message() != msg {
        return Err("the round signs other bytes than asked for".into());
    }
    let share = half
        .respond(nonces, &round)
        .map_err(|e| format!("the mobile half answers nothing: {e}"))?;
    session.call(&Request::ClientShare {
        share: share.to_bytes(),
    })
}

/// Repeats `cmd` until it presses with the half in the page: the stand's
/// `drive_until_done` over `half`, except the commitment and the share come
/// from the page's `WebMobile` over its wire — the holder sees what each
/// round signs and says yes or no on the page, exactly as after the
/// initiation. The owner's co-seal goes back in the same way.
fn drive_page_until_done(
    layout: &Layout,
    session: &mut Session,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
    cmd: &Request,
    budget: u32,
) -> Result<Answer, String> {
    let mut req = cmd.clone();
    for _ in 0..budget {
        let raw = session.call(&req)?;
        let answer = anchor_and_reanchor(layout, session, raw, Party::Client)?;
        match answer {
            Answer::Done { .. } | Answer::Refused { .. } => {
                if matches!(req, Request::ClientShare { .. }) {
                    // The round closed (or dropped): the command repeats and
                    // opens a fresh round over the same bytes.
                    req = cmd.clone();
                    continue;
                }
                return Ok(answer);
            }
            Answer::NeedsClientCommit { ref round } => {
                let closed = round_page(session, mobile, round)?;
                match closed {
                    Answer::Done { .. } => {
                        req = cmd.clone();
                        continue;
                    }
                    Answer::Refused { reason } => {
                        // The round dropped: the command repeats and opens a
                        // fresh one over the same bytes.
                        let _ = reason;
                        req = cmd.clone();
                        continue;
                    }
                    other => return Err(format!("the share closes no round: {other:?}")),
                }
            }
            Answer::NeedsSignature { bytes, .. } => {
                let wire = owner_signature(layout, &bytes)?;
                req = Request::Sign { signature: wire };
            }
            Answer::NeedsShare { .. } | Answer::NeedsAnchor { .. } => {
                return Err(format!("the press broke off mid-round: {answer:?}"))
            }
        }
    }
    Err("the press never closed: the client round does not converge".into())
}

/// One client round with the half in the page: the commitment comes from
/// the page's `commit`, the round goes back through its `respond` — the
/// holder's word asked on the page, not in the reader.
fn round_page(
    session: &mut Session,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
    msg: &[u8],
) -> Result<Answer, String> {
    let commitment = mobile
        .commit()
        .map_err(|e| format!("the page commits nothing: {e}"))?;
    let commitment = commitment
        .to_bytes()
        .map_err(|e| format!("the commitment does not encode: {e}"))?;
    let round = match session.call(&Request::ClientCommit { commitment })? {
        Answer::NeedsShare { round } => {
            SigningRound::from_bytes(&round).map_err(|e| format!("the round does not read: {e}"))?
        }
        other => return Err(format!("the commitment opens no round: {other:?}")),
    };
    if round.message() != msg {
        return Err("the round signs other bytes than asked for".into());
    }
    let share = mobile
        .respond(&round)
        .map_err(|e| format!("the page answers nothing: {e}"))?;
    session.call(&Request::ClientShare {
        share: share.to_bytes(),
    })
}

/// A pointwise export of one page, sealed by `party`.
///
/// A client's export spans the wire round like `work`: `round_client`
/// answers every `NeedsClientCommit` with the half the client's file keeps,
/// and the command repeats until `Done`. An owner's export seals at once.
///
/// # Errors
///
/// Not initiated, refused, or the capsule does not write.
pub fn export_page(layout: &Layout, number: u64, party: Party) -> Result<Vec<u8>, String> {
    // K3 (§27, `[р]` 01.11 «В»): the network's commands first.
    crate::command::before_holder(layout, party, false)?;
    // A value goes out only on a fresh anchor (`light` on Base, §22, С9).
    let mut base = crate::base::Anchoring::begin(layout)?;
    let mut session = open(layout, party)?;
    if let Some(b) = base.as_mut() {
        b.anchor(layout, &mut session)?;
    }
    let bytes = match party {
        Party::Client => {
            let half = client_half(layout)?;
            let cmd = Request::ExportPage { number };
            done(drive_until_done(layout, &mut session, &half, &cmd, 40)?)?
        }
        Party::Owner => done(session.call(&Request::ExportPage { number })?)?,
    };
    let outputs = finish(layout, session)?;
    let page = outputs
        .into_iter()
        .find(|o| o == &bytes)
        .ok_or("the export is not among the session's outputs")?;
    Ok(page)
}

/// A client's export through the browser page (`--mobile-web`, I23): the
/// round's commitment and share come from the page's `commit`/`respond`,
/// the holder's word asked on the page — the half lives in the page, not
/// in the client's file.
///
/// # Errors
///
/// Not initiated, refused, the page refuses a round, or the capsule does
/// not write.
pub fn export_page_mobile_web(
    layout: &Layout,
    mobile: &mut ksg_cli_v2::web_mobile::WebMobile,
    number: u64,
) -> Result<Vec<u8>, String> {
    // K3 (§27, `[р]` 01.11 «В»): the network's commands first.
    crate::command::before_holder(layout, Party::Client, false)?;
    let mut session = open(layout, Party::Client)?;
    let cmd = Request::ExportPage { number };
    let bytes = done(drive_page_until_done(
        layout,
        &mut session,
        mobile,
        &cmd,
        40,
    )?)?;
    let outputs = finish(layout, session)?;
    let page = outputs
        .into_iter()
        .find(|o| o == &bytes)
        .ok_or("the export is not among the session's outputs")?;
    Ok(page)
}

/// The keys a verifier checks the pages with, as JSON.
///
/// # Errors
///
/// Not initiated, or refused.
pub fn keys(layout: &Layout) -> Result<Vec<u8>, String> {
    let mut session = open(layout, Party::Client)?;
    let bytes = done(session.call(&Request::Keys)?)?;
    finish(layout, session)?;
    Ok(bytes)
}

/// The container's state, one fact per field.
///
/// # Errors
///
/// The capsule does not open.
pub fn status(layout: &Layout) -> Result<serde_json::Value, String> {
    let mut session = open(layout, Party::Client)?;
    let bytes = done(session.call(&Request::Status)?)?;
    finish(layout, session)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("the status: {e}"))
}

/// Two maps after E-4 (`Spec_kapsula` §21, 4б.4а): each party's map is born
/// here, at the reader that writes that party's file; the module gets the
/// public halves only and seals the next capsule to them.
/// The client's map seed and the owner's.
type MapSeeds = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

fn split_maps(session: &mut Session) -> Result<MapSeeds, String> {
    let mut client = Zeroizing::new([0u8; 32]);
    let mut owner = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(client.as_mut());
    OsRng.fill_bytes(owner.as_mut());
    let public = |role: &str, seed: &[u8; 32]| {
        let to = OpenWith::from_bytes(*seed).seal_to();
        MapPub {
            role: role.into(),
            x25519: B64.encode(to.public().as_bytes()),
            mlkem: B64.encode(to.mlkem()),
        }
    };
    let maps = vec![public("client", &client), public("owner", &owner)];
    done(session.call(&Request::SetMaps { maps })?)?;
    Ok((client, owner))
}

/// Each party's file gets its own map seed — the holder's map (the issuer's
/// stand knows it) opens nothing from here on.
fn write_maps(layout: &Layout, maps: &MapSeeds) -> Result<(), String> {
    let mut client = SideFile::read(&layout.client_side())?;
    client.map = B64.encode(maps.0.as_slice());
    client.write(&layout.client_side())?;
    let mut owner = SideFile::read(&layout.owner_side())?;
    owner.map = B64.encode(maps.1.as_slice());
    owner.write(&layout.owner_side())?;
    Ok(())
}

/// E-3 through the capsule (`Spec_kapsula` §19): the buyer's key is laid up
/// to level 2 with the owner's consent, and the capsule is sealed to the
/// buyer's map from then on — the holder's map (the issuer's) opens nothing.
///
/// The buyer's map is born here, at the reader that writes the buyer's file;
/// the module gets its public half only. Before the birth the capsule has one
/// map, so the client's file and the owner's both get the new seed (the same
/// way `initiate` splits them later). The buyer's signature is the stand's
/// (`stand/parties.json`, a stand key — `[р]` 25.10); the owner's comes from
/// the owner's file. `init` is not touched: it still lays E-2 and E-3 on the
/// stand itself.
///
/// The files are rewritten after the capsule, as in `initiate`: a crash
/// between the two leaves a capsule that no file opens — print again.
///
/// # Errors
///
/// The stand carries no `parties.json`, the container is initiated already or
/// has no packet, a signature does not come, the module refuses.
pub fn buyer_key(layout: &Layout) -> Result<serde_json::Value, String> {
    let seeds: Seeds = serde_json::from_slice(
        &std::fs::read(layout.stand().join("parties.json"))
            .map_err(|e| format!("parties.json: {e}"))?,
    )
    .map_err(|e| format!("parties.json: {e}"))?;
    let parties = Parties::from_seeds(&seeds)?;
    let (buyer, issuer) = (parties.buyer, parties.issuer);

    // The buyer's map: its secret half stays here until the files are written.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let to = OpenWith::from_bytes(*seed).seal_to();
    let holder_map = MapPub {
        role: "holder".into(),
        x25519: B64.encode(to.public().as_bytes()),
        mlkem: B64.encode(to.mlkem()),
    };

    let mut session = open(layout, Party::Client)?;
    let request = Request::ApplyBuyerKey {
        buyer: buyer.public(),
        holder_map,
    };
    let mut bytes = None;
    // The signatures come one by one: the buyer's, the owner's, then the
    // issuer's over the status record that follows the key.
    for _ in 0..8 {
        match session.call(&request)? {
            Answer::Done { bytes: b } => {
                bytes = Some(b);
                break;
            }
            Answer::NeedsSignature { party, bytes: msg } => {
                let signature = match party.as_str() {
                    "buyer" => serde_json::to_vec(&buyer.sign(&msg))
                        .map_err(|e| format!("signature: {e}"))?,
                    // The status record that follows the key is the issuer's.
                    "issuer" => serde_json::to_vec(&issuer.sign(&msg))
                        .map_err(|e| format!("signature: {e}"))?,
                    "owner" => owner_signature(layout, &msg)?,
                    other => return Err(format!("the {other}'s signature is needed")),
                };
                done(session.call(&Request::Sign { signature })?)?;
            }
            other => {
                done(other)?;
                return Err("the buyer's key is not laid".into());
            }
        }
    }
    let bytes = bytes.ok_or("the buyer's key keeps asking for signatures")?;
    // K4 (§28): the layer key handed over to the buyer, in the same session —
    // a later status move would leave it stale for good.
    work_off(layout, &mut session)?;
    finish(layout, session)?;
    write_maps(layout, &(seed.clone(), seed))?;
    warn_backup_stale();
    serde_json::from_slice(&bytes).map_err(|e| format!("the status: {e}"))
}

/// E-9 through the capsule (`Spec_kapsula` §21): the owner hands the container
/// over to a new owner — the stand's buyer (`parties.json`, a stand key,
/// `[р]` 25.10) takes the owner's seat.
///
/// The new owner's map is born here, at the reader that writes the new
/// owner's file; the module gets its public half only and seals the owner's
/// slot to it. The former owner's map opens nothing afterwards (Н-3). The
/// owner's file is rewritten after the capsule (as in `buyer_key`): its half
/// becomes the new owner's key, its map seed the new one — the former seed
/// is overwritten. A crash between the two leaves a capsule that no owner's
/// file opens: transfer again from the backup of the file.
///
/// # Errors
///
/// The stand carries no `parties.json`, the container is not initiated or has
/// no open journal, a signature does not come, the module refuses (a bare
/// whose former owner's secrets are not empty).
pub fn transfer(layout: &Layout) -> Result<serde_json::Value, String> {
    transfer_with_evm_key(layout, None)
}

/// E-9 as [`transfer`]; on a capsule that anchors on Base the transfer goes
/// out on a fresh anchor, and the writer's seat on the contract goes to the
/// new owner's EVM key (`evm_key`, else `stand/new_owner_evm.key` — the
/// issuer's desk, as the stand's `owner_change --evm-key`): handed over now if
/// the network answers, else before the next anchor (`Spec_kapsula` §22, С9).
///
/// # Errors
///
/// As [`transfer`]; a capsule on Base without a readable key for the new
/// owner (checked before anything is written); a copy.
pub fn transfer_with_evm_key(
    layout: &Layout,
    evm_key: Option<&Path>,
) -> Result<serde_json::Value, String> {
    // K3 (§27, `[р]` 01.11 «В»): the network's commands first.
    crate::command::before_holder(layout, Party::Client, true)?;
    let mut base = crate::base::Anchoring::begin(layout)?;
    let new_key = if base.is_some() {
        let key = evm_key.map_or_else(|| layout.new_owner_evm_key(), Path::to_path_buf);
        ksg_cli_v2::base_anchor::hand_to_for(&key)?;
        Some(key)
    } else if evm_key.is_some() {
        return Err("transfer: --evm-key only where the capsule anchors on Base Sepolia".into());
    } else {
        None
    };
    let seeds: Seeds = serde_json::from_slice(
        &std::fs::read(layout.stand().join("parties.json"))
            .map_err(|e| format!("parties.json: {e}"))?,
    )
    .map_err(|e| format!("parties.json: {e}"))?;
    let buyer_half = Zeroizing::new(
        B64.decode(&seeds.buyer)
            .map_err(|_| "parties.json: the buyer's seed is not base64url".to_string())?,
    );
    let parties = Parties::from_seeds(&seeds)?;
    let buyer = parties.buyer;
    let issuer = parties.issuer;

    // The new owner's map: its secret half stays here until the file is written.
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(seed.as_mut());
    let to = OpenWith::from_bytes(*seed).seal_to();
    let owner_map = MapPub {
        role: "owner".into(),
        x25519: B64.encode(to.public().as_bytes()),
        mlkem: B64.encode(to.mlkem()),
    };

    let mut session = open(layout, Party::Client)?;
    let template = match base.as_mut() {
        Some(b) => {
            // The transfer goes out only on a fresh anchor, before the record.
            b.anchor(layout, &mut session)?;
            Some(crate::base::Anchoring::template(&mut session)?)
        }
        None => None,
    };
    let half = client_half(layout)?;
    let request = Request::Transfer { new_owner: buyer.public(), owner_map };
    let sign = |party: &str, msg: &[u8]| -> Result<Vec<u8>, String> {
        match party {
            "buyer" => serde_json::to_vec(&buyer.sign(msg)).map_err(|e| format!("signature: {e}")),
            "issuer" => serde_json::to_vec(&issuer.sign(msg)).map_err(|e| format!("signature: {e}")),
            "owner" => owner_signature(layout, msg),
            other => Err(format!("the {other}'s signature is needed")),
        }
    };
    let bytes = done(drive_signed(layout, &mut session, &half, &request, &sign, 40)?)?;
    // K4 (§28, full ladder fix 3): the chain layer after E-9, in the same
    // session — it holds nothing up, but it is the issuer's to write.
    work_off(layout, &mut session)?;
    finish(layout, session)?;

    // The owner's file: the new owner's key and map. The scan key stays.
    let mut owner = SideFile::read(&layout.owner_side())?;
    owner.half = B64.encode(buyer_half.as_slice());
    owner.map = B64.encode(seed.as_slice());
    owner.write(&layout.owner_side())?;
    warn_backup_stale();
    if let (Some(b), Some(template), Some(key)) = (base.as_mut(), template, new_key) {
        b.recorded(layout)?;
        b.hand_to(layout, &template, &key)?;
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("the status: {e}"))
}

/// Makes the signature a party's `NeedsSignature` asks for: party, bytes.
type SignFn<'a> = dyn Fn(&str, &[u8]) -> Result<Vec<u8>, String> + 'a;

/// Repeats `cmd` until it presses: as `drive_until_done`, except that each
/// `NeedsSignature` is answered by `sign(party, bytes)` — the owner's, the
/// arriving owner's or the issuer's — and the repeat that follows it is the
/// command itself, not the `Sign`'s `Done`.
///
/// # Errors
///
/// A round the half refuses, a signature `sign` cannot make, an anchor the
/// network refuses, or a press still open after `budget` turns.
fn drive_signed(
    layout: &Layout,
    session: &mut Session,
    half: &MobileHalf,
    cmd: &Request,
    sign: &SignFn<'_>,
    budget: u32,
) -> Result<Answer, String> {
    let mut req = cmd.clone();
    for _ in 0..budget {
        let raw = session.call(&req)?;
        let answer = anchor_and_reanchor(layout, session, raw, Party::Client)?;
        match answer {
            Answer::Done { .. } | Answer::Refused { .. } => {
                let repeat = match req {
                    // The round closed or dropped: a fresh one, same bytes.
                    Request::ClientShare { .. } => true,
                    // The signature is kept: the command repeats.
                    Request::Sign { .. } => matches!(answer, Answer::Done { .. }),
                    _ => false,
                };
                if repeat {
                    req = cmd.clone();
                    continue;
                }
                return Ok(answer);
            }
            Answer::NeedsClientCommit { ref round } => {
                // A dropped round (`Refused`) opens a fresh one on the repeat.
                round_client(session, half, round)?;
                req = cmd.clone();
            }
            Answer::NeedsSignature { party, bytes } => {
                req = Request::Sign { signature: sign(&party, &bytes)? };
            }
            Answer::NeedsShare { .. } | Answer::NeedsAnchor { .. } => {
                return Err(format!("the press broke off mid-round: {answer:?}"))
            }
        }
    }
    Err("the press never closed: the signatures do not converge".into())
}

/// After `initiate` the client's file is another one (the half, the scan key):
/// a copy taken before it no longer restores it.
fn warn_backup_stale() {
    eprintln!("make a new backup of the side files (the maps changed)");
}

/// The environment variable naming the file that holds the backup password.
pub const BACKUP_PASSWORD_FILE: &str = "KSG_BACKUP_PASSWORD_FILE";

/// The backup password: the first line of the file `KSG_BACKUP_PASSWORD_FILE`
/// names. Never an argument, never printed — not even in an error.
fn backup_password() -> Result<Zeroizing<Vec<u8>>, String> {
    let path = std::env::var_os(BACKUP_PASSWORD_FILE)
        .ok_or_else(|| format!("{BACKUP_PASSWORD_FILE} names no password file"))?;
    let raw = Zeroizing::new(
        std::fs::read(&path).map_err(|e| format!("{}: {e}", Path::new(&path).display()))?,
    );
    let end = raw
        .iter()
        .position(|b| *b == b'\n' || *b == b'\r')
        .unwrap_or(raw.len());
    let password = Zeroizing::new(raw.get(..end).unwrap_or_default().to_vec());
    if password.is_empty() {
        return Err("the backup password file is empty".into());
    }
    Ok(password)
}

/// The side file's role of `party`.
const fn role_of(party: Party) -> Role {
    match party {
        Party::Client => Role::Client,
        Party::Owner => Role::Owner,
    }
}

/// Seals the whole JSON of `party`'s side file with the password from
/// `KSG_BACKUP_PASSWORD_FILE` and writes the copy to `out` (mode `0600`).
///
/// # Errors
///
/// The side file or the password file does not read, the password is empty,
/// or `out` does not write.
pub fn backup(layout: &Layout, party: Party, out: &Path) -> Result<(), String> {
    let password = backup_password()?;
    let json = Zeroizing::new(
        std::fs::read(layout.side(party)).map_err(|e| format!("{}: {e}", layout.side(party).display()))?,
    );
    let file = SideFile::from_json(&json)?;
    if file.role != role_of(party) {
        return Err(format!("{}: not that party's file", layout.side(party).display()));
    }
    let sealed = ksg_web_v2::backup::seal(&json, &password, &mut OsRng)
        .map_err(|e| format!("backup: {e}"))?;
    let tmp = out.with_extension("tmp");
    {
        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
        std::io::Write::write_all(&mut f, &sealed).map_err(|e| e.to_string())?;
        f.sync_all().map_err(|e| e.to_string())?;
    }
    std::fs::rename(&tmp, out).map_err(|e| format!("{}: {e}", out.display()))
}

/// Restores `party`'s side file from a copy, **only if the file is absent**,
/// and only if the map in the copy opens the current capsule.
///
/// # Errors
///
/// The file exists already; the copy does not read or the password is wrong;
/// the copy is another party's; the copy is stale (its map opens no slot of
/// the capsule); the file does not write.
pub fn restore(layout: &Layout, party: Party, from: &Path) -> Result<(), String> {
    let target = layout.side(party);
    if target.exists() {
        return Err(format!("{} exists: a restore never overwrites", target.display()));
    }
    let password = backup_password()?;
    let blob = std::fs::read(from).map_err(|e| format!("{}: {e}", from.display()))?;
    let json = Zeroizing::new(
        ksg_web_v2::backup::open(&blob, &password)
            .map_err(|_| "the backup does not open: wrong password or not a backup".to_string())?,
    );
    let file = SideFile::from_json(&json)?;
    if file.role != role_of(party) {
        return Err("the backup is another party's file".into());
    }
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    let map = file.map()?;
    ksg_container_v2::capsule::open_split(&capsule, &map)
        .map_err(|_| "the backup is stale: its map does not open the current capsule".to_string())?;
    file.write(&target)
}

/// Slot 2 of the coupling (E-5, CH-12): the leading container pulls
/// `trailer`, whose last seal is `trailer_seal`. As `flow::work`: the
/// client's press through the session's `Request::Pull`.
///
/// # Errors
///
/// Not initiated, refused, or the capsule does not write.
pub fn pull(
    layout: &Layout,
    trailer: ksg_core_v2::crypto::hash::Hash,
    trailer_seal: ksg_core_v2::crypto::hash::Hash,
) -> Result<serde_json::Value, String> {
    let mut base = crate::base::Anchoring::begin(layout)?;
    let mut session = open(layout, Party::Client)?;
    if let Some(b) = base.as_mut().filter(|b| b.owes()) {
        b.anchor(layout, &mut session)?;
    }
    let half = client_half(layout)?;
    let cmd = Request::Pull { trailer, trailer_seal };
    let bytes = done(drive_until_done(layout, &mut session, &half, &cmd, 40)?)?;
    finish(layout, session)?;
    if let Some(b) = base.as_mut() {
        b.recorded(layout)?;
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("the page's receipt: {e}"))
}

/// K4 (`Spec_kapsula` §28): the issuer's layer work the container holds open
/// after a sale press (E-2, E-3, E-9), done at the issuer's stand (`stand/`)
/// and handed into `session` — call it in the same session, right after the
/// press: a later status move leaves the follow-up stale for good.
///
/// # Errors
///
/// The stand does not open, a follow-up does not seal, the module refuses.
pub fn work_off(layout: &Layout, session: &mut Session) -> Result<(), String> {
    let stand = ksg_cli_v2::Reader::open(&layout.stand(), Box::new(ksg_cli_v2::mobile::NoMobile))?;
    // Indices shift after each discharge: the list is read afresh each time.
    for _ in 0..16 {
        let tasks: Vec<serde_json::Value> = match session.call(&Request::PendingTasks)? {
            Answer::Done { bytes } => serde_json::from_slice(&bytes).map_err(|e| format!("pending tasks: {e}"))?,
            other => return Err(format!("pending tasks: {other:?}")),
        };
        let Some(t) = tasks.iter().find(|t| t["task"] != "carry_id") else {
            return Ok(());
        };
        let index = t["index"]
            .as_u64()
            .and_then(|i| usize::try_from(i).ok())
            .ok_or("pending tasks: no index")?;
        let request = match t["task"].as_str() {
            Some("write_layer") => {
                let zone: ksg_container_v2::Zone =
                    serde_json::from_value(t["zone"].clone()).map_err(|e| format!("zone: {e}"))?;
                let position = t["position"]
                    .as_u64()
                    .and_then(|p| usize::try_from(p).ok())
                    .ok_or("the zone has no free position")?;
                let owner: Option<ksg_core_v2::crypto::sign::PublicKey> =
                    serde_json::from_value(t["owner"].clone()).map_err(|e| format!("owner: {e}"))?;
                Request::WriteLayer {
                    index,
                    sealed: stand.sealed_layer(zone, position, owner.as_ref())?,
                }
            }
            Some("hand_over") => {
                let to: ksg_core_v2::crypto::sign::PublicKey =
                    serde_json::from_value(t["to"].clone()).map_err(|e| format!("to: {e}"))?;
                let up_to = t["up_to"]
                    .as_u64()
                    .and_then(|u| u8::try_from(u).ok())
                    .ok_or("hand-over: no level")?;
                Request::HandedOver {
                    index,
                    sealed: stand.hand_over_layers(&to, ksg_container_v2::layers::Level(up_to))?,
                }
            }
            other => return Err(format!("an unknown follow-up: {other:?}")),
        };
        match session.call(&request)? {
            Answer::Done { .. } => {}
            other => return Err(format!("the follow-up is not discharged: {other:?}")),
        }
    }
    Err("the follow-ups do not end".into())
}

