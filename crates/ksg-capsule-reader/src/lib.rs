//! `ksg-capsule-reader` — the reader outside the capsule (`Spec_kapsula` §5,
//! §10 п. 3, §12 Л-1).
//!
//! It holds no secret of its own. A press: the party's secret file → its slot
//! → the code part → the module (wasmtime) → a session → the new capsule,
//! written atomically → memory wiped. The network (anchors) and other parties'
//! signatures are the reader's work, asked for by the module's answers.
//!
//! | Piece | Where |
//! |---|---|
//! | the engine: wasmtime, two imports, fuel and a memory limit | [`engine`] |
//! | the session: open → call ×N → close, the code part from the capsule | [`session`] |
//! | the offline commands of `ksg-capsule` (init, initiate, work, export, keys, status) | [`flow`] |
//! | the party's one secret file | [`side`] |
//!
//! The criteria it carries: K4 (a module with an import beyond
//! `ksg_host.random`/`now_ms` does not instantiate — WASI is not linked) and
//! the offline half of K5 (`tests/k5_offline.rs`).

pub mod engine;
pub mod flow;
pub mod session;
pub mod side;

pub use engine::Engine;
pub use session::Session;

use std::io::Write as _;
use std::path::Path;

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
