//! A party's one secret file (owner's decision 25.10 "one file"): its half of
//! the signing key, the seed of its map, its scan key (`Spec_kapsula` §4, §11,
//! §12 L-4). JSON, mode `0600`, ~1 KB.
//!
//! The map is kept as its 32-byte seed: both halves (X25519, ML-KEM-768) are
//! expanded from it (`ksg_container_v2::layers::OpenWith::from_bytes`), so
//! nothing longer has to be stored or wiped.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_container_v2::layers::OpenWith;
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

/// Which party the file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The agent-client.
    Client,
    /// The owner-holder.
    Owner,
}

/// The file as it lies on disk.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SideFile {
    /// Version of the file.
    pub v: u32,
    /// Whose file it is.
    pub role: Role,
    /// The container: its template before initiation, its identifier after.
    pub container: String,
    /// The party's half of signing: the client's mobile half (FROST state),
    /// or the owner's Ed25519 seed — base64url.
    pub half: String,
    /// The seed of the party's map, base64url (32 bytes).
    pub map: String,
    /// The scan key for blind anchors, base64url (32 bytes).
    pub scan: String,
}

impl Drop for SideFile {
    fn drop(&mut self) {
        self.half.zeroize();
        self.map.zeroize();
        self.scan.zeroize();
    }
}

impl SideFile {
    /// A new file for `role`; `map_seed` and `scan` come from the caller's CSPRNG.
    #[must_use]
    pub fn new(role: Role, container: &str, half: &[u8], map_seed: &[u8; 32], scan: &[u8; 32]) -> Self {
        Self {
            v: 1,
            role,
            container: container.into(),
            half: B64.encode(half),
            map: B64.encode(map_seed),
            scan: B64.encode(scan),
        }
    }

    /// The party's map, rebuilt from its seed.
    ///
    /// # Errors
    ///
    /// The seed is not 32 bytes of base64url.
    pub fn map(&self) -> Result<OpenWith, String> {
        let v = Zeroizing::new(B64.decode(&self.map).map_err(|_| "side file: map is not base64url")?);
        let seed: [u8; 32] = v.as_slice().try_into().map_err(|_| "side file: map is not 32 bytes")?;
        Ok(OpenWith::from_bytes(seed))
    }

    /// Writes the file atomically, mode `0600`.
    ///
    /// # Errors
    ///
    /// The file system refused.
    pub fn write(&self, path: &Path) -> Result<(), String> {
        let bytes = Zeroizing::new(serde_json::to_vec_pretty(self).map_err(|e| e.to_string())?);
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
        std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Reads a file written by [`SideFile::write`].
    ///
    /// # Errors
    ///
    /// Missing, unreadable, or not a side file of version 1.
    pub fn read(path: &Path) -> Result<Self, String> {
        let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?);
        Self::from_json(&bytes)
    }

    /// Reads a side file from the bytes the reader hands the module.
    ///
    /// # Errors
    ///
    /// Not JSON, or not a side file of version 1.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let f: Self = serde_json::from_slice(bytes).map_err(|e| format!("side file: {e}"))?;
        if f.v != 1 {
            return Err(format!("side file: version {} is not 1", f.v));
        }
        Ok(f)
    }
}
