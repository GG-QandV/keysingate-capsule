//! A session of presses from **outside** the capsule (`Spec_kapsula` §5,
//! §10 item 3, §12 L-1).
//!
//! The reader opens the party's slot and the code part, instantiates the
//! module with [`crate::Engine`], then drives:
//!
//! ```text
//! Session::open(capsule, side_file, anchored)
//! Session::call(Request) × N
//! Session::close() → (new capsule, outputs)
//! ```
//!
//! The network and the signatures are the reader's work: [`Answer::NeedsAnchor`]
//! and [`Answer::NeedsSignature`] come out of [`Session::call`] for the caller
//! to answer — an anchor read from a node, a signature made by the party's key
//! — and [`Request::Reanchor`] / [`Request::Sign`] take the answer back in.

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;
use ksg_capsule_module::session::{Answer, Request};
use ksg_container_v2::capsule::{self, PartKind};

use crate::engine::Engine;
use crate::side::SideFile;

/// One opened capsule inside a module instance.
pub struct Session {
    engine: Engine,
}

impl Session {
    /// Opens a capsule: its code part (through the party's map), the module,
    /// then the container through `ksg_open`.
    ///
    /// `anchored` is what the reader read from the network (§5a) — each entry
    /// the JSON of a `ksg_core_v2::anchor::Attestation`, applied before the
    /// first command.
    ///
    /// # Errors
    ///
    /// The party's map opens no slot, the capsule carries no code, the module
    /// is not this boundary's, the side file is of another party.
    pub fn open(
        capsule_bytes: &[u8],
        side_json: &[u8],
        anchored: Vec<Vec<u8>>,
    ) -> Result<Self, String> {
        let code = code_part(capsule_bytes, side_json)?;
        let fuel = std::env::var("KSG_CAPSULE_FUEL")
            .ok()
            .and_then(|f| f.parse().ok())
            .unwrap_or(20_000_000_000);
        let mut engine = Engine::with_fuel(&code, fuel)?;
        let anchored_json = if anchored.is_empty() {
            Vec::new()
        } else {
            let encoded: Vec<String> = anchored.iter().map(|a| B64.encode(a)).collect();
            serde_json::to_vec(&encoded).map_err(|e| format!("anchored: {e}"))?
        };
        engine.open(capsule_bytes, side_json, &anchored_json)?;
        Ok(Self { engine })
    }

    /// One command. A `NeedsAnchor`/`NeedsSignature` is an answer, not a
    /// failure: nothing is written when the module answers so.
    ///
    /// # Errors
    ///
    /// The request does not encode, the module traps, the answer is not one.
    pub fn call(&mut self, request: &Request) -> Result<Answer, String> {
        let wire = serde_json::to_vec(request).map_err(|e| format!("the request: {e}"))?;
        let raw = self.engine.call(&wire)?;
        serde_json::from_slice(&raw).map_err(|e| format!("the answer does not read: {e}"))
    }

    /// Closes: the new capsule and the outputs the reader must keep outside
    /// it (the client's half after an initiation, the exported pages).
    ///
    /// # Errors
    ///
    /// The module traps or refuses to close (a birth pending, more than one
    /// map).
    pub fn close(mut self) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
        let raw = self.engine.close()?;
        let value: serde_json::Value =
            serde_json::from_slice(&raw).map_err(|e| format!("the close does not read: {e}"))?;
        let capsule = value
            .get("capsule")
            .and_then(serde_json::Value::as_str)
            .ok_or("the close names no capsule")?;
        let capsule = B64
            .decode(capsule)
            .map_err(|_| "the capsule is not base64url".to_string())?;
        let outputs = value
            .get("outputs")
            .and_then(serde_json::Value::as_array)
            .ok_or("the close names no outputs")?
            .iter()
            .map(|o| {
                o.as_str()
                    .ok_or("an output is not a string".to_string())
                    .and_then(|s| B64.decode(s).map_err(|_| "an output is not base64url".into()))
            })
            .collect::<Result<Vec<Vec<u8>>, String>>()?;
        Ok((capsule, outputs))
    }
}

/// The maximum a decompressed module may take: a module past it is not one
/// this reader puts in a capsule (a 6 MiB module fits with room).
pub const MAX_CODE: usize = 8 << 20;

/// The module's bytes as they lie in the capsule's code part: DEFLATE, so a
/// 2 MiB module takes ~0.5 MiB of the capsule's 6 (`Spec_kapsula` §11, K-2).
///
/// A part that already starts with the WebAssembly magic is taken as it is —
/// the stand's stand-in bytes and a module sealed before this rule.
///
/// # Errors
///
/// The module does not compress (it cannot fail in practice).
pub fn compress_code(wasm: &[u8]) -> Result<Vec<u8>, String> {
    use ksg_container_v2::pack::{Compressor as _, Deflate};
    Ok(Deflate { limit: MAX_CODE }.compress(wasm))
}

/// The module's bytes from the capsule's code part.
///
/// # Errors
///
/// A part that is neither a module nor DEFLATE this reader wrote.
pub fn decompress_code(code: &[u8]) -> Result<Vec<u8>, String> {
    use ksg_container_v2::pack::{Compressor as _, Deflate};
    if code.starts_with(b"\0asm") {
        return Ok(code.to_vec());
    }
    Deflate { limit: MAX_CODE }
        .decompress(code)
        .map_err(|_| "the capsule's code part does not open".to_string())
}

/// The module's bytes from the capsule's code part, opened through the party's
/// map — the reader parses nothing else.
///
/// # Errors
///
/// The side file is not one, its map opens no slot, or the capsule carries no
/// code part.
pub fn code_part(capsule_bytes: &[u8], side_json: &[u8]) -> Result<Vec<u8>, String> {
    let side = SideFile::from_json(side_json)?;
    let map = side.map()?;
    let (_role, parts) =
        capsule::open(capsule_bytes, &map).map_err(|e| format!("capsule: {e}"))?;
    let code = parts
        .into_iter()
        .find(|p| p.kind == PartKind::Code)
        .map(|p| p.bytes)
        .ok_or_else(|| "the capsule carries no code part".to_string())?;
    decompress_code(&code)
}
