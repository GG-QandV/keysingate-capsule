//! Base Sepolia anchors of a `light` capsule (`Spec_kapsula` §22, "Уточнение
//! по коду — С9"): the module asks for none (`a_light_work_owes_nothing`), so
//! the schedule of the stand — before a value goes out, every ten records,
//! right after initiation — is the reader's work, run through
//! [`ksg_cli_v2::base_anchor::anchor_due`].
//!
//! `base.json` in the capsule's home keeps the config: where the node and the
//! contract are, the path to the sender's key file (never the key), the last
//! anchor, the records since it, the salt of the blind anchor key. `copy`
//! marks a file the contract refused as a stale predecessor: from then on
//! every flow but the full export is refused.

use std::path::{Path, PathBuf};

use ksg_capsule_module::session::{Answer, Request};
use ksg_cli_v2::base_anchor::{
    anchor_due, hand_over_owed, hand_to_for, read_key, word, Anchored, BaseCfg, BaseLink,
    OFFLINE_RECORDS,
};
use ksg_core_v2::crypto::hash::Hash;

use crate::flow::Layout;
use crate::session::Session;

/// Where a `light` capsule anchors: the arguments of `init --base`.
#[derive(Debug, Clone)]
pub struct BaseSpec {
    /// The node's JSON-RPC address.
    pub rpc: String,
    /// The `KsgAnchors` contract, `0x…`.
    pub contract: String,
    /// The file of the sender's secret key (a path, not the key).
    pub key: PathBuf,
}

/// The content of `base.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseFile {
    /// The anchoring state.
    pub cfg: BaseCfg,
    /// The contract refused an anchor as a stale predecessor: this file is a
    /// copy, or an older file, of the capsule.
    #[serde(default)]
    pub copy: bool,
}

impl Layout {
    /// Where the Base config is kept (`base.json`), mode `0600`: the path to
    /// the sender's key, never the key.
    #[must_use]
    pub fn base(&self) -> PathBuf {
        self.home.join("base.json")
    }

    /// The key file of a new owner's EVM key at a transfer, when it is not
    /// named: the issuer's desk keeps it at `stand/new_owner_evm.key`
    /// (64 hex characters, as the stand's `--evm-key`).
    #[must_use]
    pub fn new_owner_evm_key(&self) -> PathBuf {
        self.stand().join("new_owner_evm.key")
    }
}

impl BaseFile {
    /// Reads `base.json`; `None` when the capsule was printed without `--base`.
    ///
    /// # Errors
    ///
    /// The file is there but does not read.
    pub fn read(layout: &Layout) -> Result<Option<Self>, String> {
        let path = layout.base();
        match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("{}: {e}", path.display())),
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| format!("{}: {e}", path.display())),
        }
    }

    /// Writes `base.json` atomically, mode `0600`.
    ///
    /// # Errors
    ///
    /// The file system refused.
    pub fn write(&self, layout: &Layout) -> Result<(), String> {
        let path = layout.base();
        let bytes = serde_json::to_vec_pretty(self).map_err(|e| format!("{}: {e}", path.display()))?;
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

    /// Writes the first `base.json` of a capsule printed with `--base`: a
    /// fresh salt for the blind anchor key, nothing anchored yet.
    ///
    /// # Errors
    ///
    /// The key file is not a key, or the file system refused.
    pub fn create(layout: &Layout, spec: &BaseSpec) -> Result<(), String> {
        // The key is read once to know it is one; its value goes nowhere.
        read_key(&spec.key)?;
        let mut salt = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut salt);
        let file = Self {
            cfg: BaseCfg {
                rpc: spec.rpc.clone(),
                contract: spec.contract.clone(),
                key: spec.key.clone(),
                last: None,
                since: 0,
                pending: Vec::new(),
                last_tx: None,
                share: None,
                salt: Some(format!("0x{}", hex::encode(salt))),
                hand_to: None,
                sponsored: false,
                from_block: None,
            },
            copy: false,
        };
        file.write(layout)
    }
}

/// What the session says of the container, for the anchor.
struct Standing {
    template: Hash,
    next: [u8; 32],
}

/// The template and what is anchored — the top seal, else the status head
/// (`reader.rs`, `base_anchor`) — from a session's `Status`.
fn standing(session: &mut Session) -> Result<Standing, String> {
    let Answer::Done { bytes } = session.call(&Request::Status)? else {
        return Err("base: the module gives no status".into());
    };
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("base: the status: {e}"))?;
    let hash = |key: &str| -> Result<Option<Hash>, String> {
        v.get(key)
            .and_then(serde_json::Value::as_str)
            .map(|s| Hash::from_multihash(s).map_err(|e| format!("base: status.{key}: {e}")))
            .transpose()
    };
    let template = hash("template")?.ok_or("base: the status names no template")?;
    let next = match hash("top_seal")? {
        Some(seal) => seal,
        None => hash("status_head")?.ok_or("base: the status names no status_head")?,
    };
    Ok(Standing { template, next: word(&next) })
}

/// A capsule that anchors on Base, in the middle of a command.
pub(crate) struct Anchoring {
    file: BaseFile,
    link: Option<BaseLink>,
}

impl Anchoring {
    /// The capsule's Base state, or `None` for a capsule without `--base`
    /// (its behaviour is unchanged). Refuses a copy: nothing but the full
    /// export goes on from a file the contract has refused (Л10: before any
    /// write).
    ///
    /// # Errors
    ///
    /// `base.json` does not read, or it is marked a copy.
    pub(crate) fn begin(layout: &Layout) -> Result<Option<Self>, String> {
        let Some(file) = BaseFile::read(layout)? else {
            return Ok(None);
        };
        if file.copy {
            return Err(COPY.into());
        }
        Ok(Some(Self { file, link: None }))
    }

    /// Whether the ten offline records are used up: the next record waits
    /// for an anchor.
    pub(crate) const fn owes(&self) -> bool {
        self.file.cfg.since >= OFFLINE_RECORDS
    }

    /// Anchors the container's newest signed thing, as `session` holds it.
    /// A copy is marked in `base.json` and refused.
    ///
    /// # Errors
    ///
    /// The network does not answer, the contract refuses, the container was
    /// declared lost, or this file is a copy.
    pub(crate) fn anchor(&mut self, layout: &Layout, session: &mut Session) -> Result<Anchored, String> {
        let Standing { template, next } = standing(session)?;
        let Self { file, link } = self;
        let mut cfg = file.cfg.clone();
        let mut save = |c: &BaseCfg| -> Result<(), String> {
            BaseFile { cfg: c.clone(), copy: false }.write(layout)
        };
        let done = anchor_due(&mut cfg, link, &template, next, &mut save);
        file.cfg = cfg;
        match done {
            Ok(Anchored::Copy) => {
                file.copy = true;
                file.write(layout)?;
                Err(COPY.into())
            }
            Ok(a) => {
                file.write(layout)?;
                Ok(a)
            }
            Err(e) => {
                // What was saved on the way stays; so does what this run knew.
                file.write(layout)?;
                Err(e)
            }
        }
    }

    /// A record of work was written.
    pub(crate) fn recorded(&mut self, layout: &Layout) -> Result<(), String> {
        self.file.cfg.since += 1;
        self.file.write(layout)
    }

    /// The anchor right after initiation failed: the next record waits for
    /// the network (the stand's `since = OFFLINE_RECORDS`).
    pub(crate) fn owe(&mut self, layout: &Layout) -> Result<(), String> {
        self.file.cfg.since = OFFLINE_RECORDS;
        self.file.write(layout)
    }

    /// A transfer of rights was pressed: the writer's seat on the contract is
    /// owed to the new owner's key (`key`), handed over now if the network
    /// answers, else before the next anchor.
    ///
    /// # Errors
    ///
    /// `key` is not a key, or the file system refused. The network's refusal
    /// is not an error here: the hand-over waits in `base.json`.
    pub(crate) fn hand_to(&mut self, layout: &Layout, template: &Hash, key: &Path) -> Result<(), String> {
        self.file.cfg.hand_to = Some(hand_to_for(key)?);
        self.file.write(layout)?;
        let Self { file, link } = self;
        let mut cfg = file.cfg.clone();
        let mut save = |c: &BaseCfg| -> Result<(), String> {
            BaseFile { cfg: c.clone(), copy: false }.write(layout)
        };
        let _ = hand_over_owed(&mut cfg, link, template, &mut save);
        file.cfg = cfg;
        file.write(layout)
    }

    /// The template of the container in `session`.
    pub(crate) fn template(session: &mut Session) -> Result<Hash, String> {
        Ok(standing(session)?.template)
    }
}

/// Why a copy does the full export only.
const COPY: &str = "this file is a copy, or an older file, of the capsule: the chain continued \
                    after it (Base Sepolia). Only the full export is allowed";
