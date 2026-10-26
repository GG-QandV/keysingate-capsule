//! `ksg-capsule-reader` — the reader outside the capsule (`Spec_kapsula` §5, §10 п. 3).
//!
//! It holds no secret of its own. A press: the party's secret file → its slot
//! → the code part → the module → a session → the new capsule, written
//! atomically → memory wiped. The network (anchors) and other parties'
//! signatures are the reader's work, asked for by the module.
//!
//! Skeleton of 26.10: the engine and the session land on 30.10 (plan v8, K5).

pub mod side;

use std::io::Write as _;
use std::path::Path;

/// The engine that runs the module: wasmtime, or wasmi if wasmtime is too
/// heavy to build (plan v8, risk 4).
pub trait Engine {
    /// Instantiates the module's bytes with the two host imports.
    ///
    /// # Errors
    ///
    /// The bytes are not a module of this boundary.
    fn instantiate(&mut self, module: &[u8]) -> Result<(), String>;
}

/// Writes the new capsule through a temporary file and a rename: a crash
/// leaves the old capsule or the new one, never half of one (Р-6).
///
/// # Errors
///
/// The file system refused.
pub fn write_capsule(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}
