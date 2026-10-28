//! The offline half of the capsule's command line (`ksg-capsule`): print,
//! initiate, work, export, keys, status — over a capsule and the parties' one
//! secret file each.
//!
//! Every command is one session (`Spec_kapsula` §10 п. 3): open, `call`×N,
//! close, the capsule written atomically (Р-6). Nothing but the capsule and
//! the side files is kept: the printing stand (`stand/`) is the issuer's, and
//! the network's part (a Pro anchor of a page) is not here — see
//! `scripts/demo_pro_capsule.sh` and the reader's `#[ignore]`d network test.

use std::path::{Path, PathBuf};

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{AnchorKind, Answer, Request};
use ksg_cli_v2::home::{kid, owner_seed, Seeds};
use ksg_cli_v2::InitOptions;
use ksg_core_v2::crypto::hash::Hash;
use ksg_core_v2::crypto::sign::Ed25519Signer;
use ksg_core_v2::doc::{Class, Uri};
use ksg_verify_v2::solana::{HttpRpc, SealScanKey};
use zeroize::Zeroizing;

use crate::session::Session;
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
    /// to a file that could name the container by its presence (`§12 Л-3`).
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
    let client = SideFile::new(Role::Client, &meta.id, &[], &map, &scan);
    client.write(&layout.client_side())?;
    let seeds: Seeds = serde_json::from_slice(
        &std::fs::read(layout.stand().join("parties.json")).map_err(|e| format!("parties.json: {e}"))?,
    )
    .map_err(|e| format!("parties.json: {e}"))?;
    let owner = Zeroizing::new(*owner_seed(&seeds)?);
    let owner_file = SideFile::new(Role::Owner, &meta.id, owner.as_slice(), &map, &scan);
    owner_file.write(&layout.owner_side())?;
    if let Some(anchor) = &print.anchor {
        save_anchor(layout, anchor)?;
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
fn anchor_and_reanchor(
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
fn open(layout: &Layout, party: Party) -> Result<Session, String> {
    let side = Zeroizing::new(
        std::fs::read(layout.side(party)).map_err(|e| format!("{}: {e}", layout.side(party).display()))?,
    );
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    Session::open(&capsule, &side, Vec::new())
}

/// The bytes a `Done` answer carries, or the answer's refusal in words.
fn done(answer: Answer) -> Result<Vec<u8>, String> {
    match answer {
        Answer::Done { bytes } => Ok(bytes),
        Answer::Refused { reason } => Err(format!("refused: {reason}")),
        Answer::NeedsAnchor { .. } => Err("the network is needed: an anchor of this page".into()),
        Answer::NeedsSignature { party, .. } => {
            Err(format!("the {party}'s signature is needed"))
        }
    }
}

/// Closes a session and writes the capsule back atomically.
fn finish(layout: &Layout, session: Session) -> Result<Vec<Vec<u8>>, String> {
    let (capsule, outputs) = session.close()?;
    write_capsule(&layout.capsule(), &capsule)?;
    Ok(outputs)
}

/// The owner's signature over the bytes a `NeedsSignature` handed out, on
/// the wire (the JSON of a `Signature`). The owner's half is its Ed25519
/// seed: the reader signs with it outside the module, the module checks
/// inside (Л-1).
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

/// E-4 through the capsule: the client's key is born, the owner signs the
/// bytes the module asks for (the signature is made **outside** the module by
/// the owner's file), the half goes into the client's side file.
///
/// # Errors
///
/// The capsule is initiated already, the owner's file is missing or is not the
/// owner's, the module refuses.
pub fn initiate(layout: &Layout) -> Result<serde_json::Value, String> {
    let raw = Zeroizing::new(
        std::fs::read(layout.client_side())
            .map_err(|e| format!("{}: {e}", layout.client_side().display()))?,
    );
    let capsule = std::fs::read(layout.capsule())
        .map_err(|e| format!("{}: {e}", layout.capsule().display()))?;
    let mut session = Session::open(&capsule, &raw, Vec::new())?;
    let first = session.call(&Request::Initiate)?;
    let answer = anchor_and_reanchor(layout, &mut session, first, Party::Client)?;
    let answer = match answer {
        Answer::NeedsSignature { bytes, .. } => {
            let wire = owner_signature(layout, &bytes)?;
            let signed = session.call(&Request::Sign { signature: wire })?;
            anchor_and_reanchor(layout, &mut session, signed, Party::Client)?
        }
        other => other,
    };
    let bytes = done(answer)?;
    let mut value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("the initiation: {e}"))?;
    // The journal opens in the same session (E-5, page 0): the capsule's
    // commands are `work` from here, as on the stand after `open-journal`.
    // In Pro page 0 carries the owner's co-seal (CH-26): a client's session
    // answers `NeedsSignature`, the reader signs outside the module.
    let first = session.call(&Request::OpenJournal)?;
    let opening = match anchor_and_reanchor(layout, &mut session, first, Party::Client)? {
        Answer::NeedsSignature { bytes, .. } => {
            let wire = owner_signature(layout, &bytes)?;
            let signed = session.call(&Request::Sign { signature: wire })?;
            done(anchor_and_reanchor(
                layout,
                &mut session,
                signed,
                Party::Client,
            )?)?
        }
        other => done(other)?,
    };
    let opening: serde_json::Value =
        serde_json::from_slice(&opening).map_err(|e| format!("the opening: {e}"))?;
    if let Some(map) = value.as_object_mut() {
        map.insert("journal".into(), opening);
    }
    finish(layout, session)?;

    // The half is the client's: it goes into the client's file, or the client
    // could never sign again.
    if let Some(half) = value.get("mobile_half").and_then(serde_json::Value::as_str) {
        let mut file = SideFile::read(&layout.client_side())?;
        file.half = half.to_string();
        file.write(&layout.client_side())?;
    }
    Ok(value)
}

/// E-5: one step of the agent's work becomes a page.
///
/// # Errors
///
/// Not initiated, refused, or the capsule does not write.
pub fn work(layout: &Layout, text: &str) -> Result<serde_json::Value, String> {
    let mut session = open(layout, Party::Client)?;
    let first = session.call(&Request::Work { text: text.into() })?;
    let answer = anchor_and_reanchor(layout, &mut session, first, Party::Client)?;
    let bytes = done(answer)?;
    finish(layout, session)?;
    serde_json::from_slice(&bytes).map_err(|e| format!("the page's receipt: {e}"))
}

/// A pointwise export of one page, sealed by `party`.
///
/// # Errors
///
/// Not initiated, refused, or the capsule does not write.
pub fn export_page(layout: &Layout, number: u64, party: Party) -> Result<Vec<u8>, String> {
    let mut session = open(layout, party)?;
    let bytes = done(session.call(&Request::ExportPage { number })?)?;
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
