//! The module's boundary: exports and the two host imports. The only place
//! `unsafe` is allowed in this crate (raw memory shared with the reader).
//!
//! # The wire (`Spec_kapsula` §10 item 3, §12 L-1)
//!
//! One module instance is one instance of a **session**:
//!
//! ```text
//! ksg_open(capsule, side_file, anchored) → answer
//! ksg_call(request) × N                  → answer
//! ksg_close()                            → answer
//! ```
//!
//! A call is one JSON object, UTF-8, in a buffer the reader got from
//! [`ksg_alloc`] and wrote into; the answer is a buffer this module allocates
//! and the reader must return with [`ksg_free`]. Buffers are
//! `[u32 little-endian length][bytes]`: the length is the answer's own, and
//! the whole buffer (`4 + length`) is what `ksg_free` takes. A zero-length
//! answer is a buffer of the four length bytes alone.
//!
//! | Export | Input | Answer |
//! |---|---|---|
//! | `ksg_open` | the capsule's bytes, the party's side file (JSON), the anchored commands (a JSON array of base64url strings, or empty) | `{"ok":true}` or `{"error":"…"}` |
//! | `ksg_call` | one request (see [`crate::session::Request`]) | one [`crate::session::Answer`], or `{"error":"…"}` |
//! | `ksg_close` | nothing | `{"capsule":"<base64url>","outputs":["<base64url>",…]}` or `{"error":"…"}` |
//!
//! An `error` is a failure of the boundary — bytes that are not a capsule, a
//! side file of another party, a request that does not parse. A command the
//! container refuses is not an error: it is `{"answer":"refused",…}` inside a
//! successful call, and nothing is written.
//!
//! Every byte string of the JSON is base64url without padding. One session per
//! module instance: a second `ksg_open` replaces the first, and closing the
//! instance (the reader's drop of the module) wipes what the session held.
#![allow(unsafe_code)]

use std::cell::RefCell;

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine as _;

use crate::session::{Answer, Request, Session};

/// Version of the boundary; the reader refuses a module of another one.
pub const ABI_VERSION: u32 = 1;

#[cfg(target_arch = "wasm32")]
#[link(wasm_import_module = "ksg_host")]
extern "C" {
    /// Fills `len` bytes at `ptr` from the reader's CSPRNG.
    #[link_name = "random"]
    fn host_random(ptr: *mut u8, len: u32);
    /// The reader's clock, milliseconds since the Unix epoch.
    #[link_name = "now_ms"]
    fn host_now_ms() -> u64;
}

/// The reader's randomness, for the container's `getrandom` and the capsule.
#[cfg(target_arch = "wasm32")]
pub fn random(out: &mut [u8]) {
    let len = u32::try_from(out.len()).expect("a request fits u32");
    // SAFETY: `out` is a live, exclusively borrowed buffer of `len` bytes.
    unsafe { host_random(out.as_mut_ptr(), len) }
}

/// The reader's clock.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn now_ms() -> u64 {
    // SAFETY: no arguments; the host returns a plain integer.
    unsafe { host_now_ms() }
}

/// The boundary's version, for the reader to check before anything else.
#[no_mangle]
pub extern "C" fn ksg_abi_version() -> u32 {
    ABI_VERSION
}

thread_local! {
    /// The instance's one session: opened, driven, closed.
    static SESSION: RefCell<Option<Session>> = const { RefCell::new(None) };
}

/// Allocates `len` zeroed bytes for the reader to write a request into.
///
/// The buffer must come back through [`ksg_free`] with the same `len`. A `len`
/// of zero returns an empty buffer that is still the reader's to free.
#[no_mangle]
pub extern "C" fn ksg_alloc(len: u32) -> *mut u8 {
    let boxed = vec![0u8; len as usize].into_boxed_slice();
    Box::into_raw(boxed).cast::<u8>()
}

/// Frees a buffer this module returned — an answer, or what [`ksg_alloc`]
/// handed out. `len` is the buffer's **whole** length, the four length bytes
/// included for an answer.
///
/// # Safety
///
/// `ptr` and `len` must be the pair [`ksg_alloc`] produced, or a buffer this
/// module returned as an answer, and the buffer must not be freed twice.
#[no_mangle]
pub unsafe extern "C" fn ksg_free(ptr: *mut u8, len: u32) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the pointer and the length are the pair `ksg_alloc` or an answer
    // produced: a boxed slice of exactly `len` bytes.
    unsafe {
        drop(Box::from_raw(std::ptr::slice_from_raw_parts_mut(
            ptr,
            len as usize,
        )));
    }
}

/// Opens a session: the capsule, the party's side file, the anchors the
/// network carried.
///
/// # Safety
///
/// The three pointers must be live buffers of their lengths — what
/// [`ksg_alloc`] handed out, filled by the reader.
#[no_mangle]
pub unsafe extern "C" fn ksg_open(
    capsule_ptr: *const u8,
    capsule_len: u32,
    side_ptr: *const u8,
    side_len: u32,
    anchored_ptr: *const u8,
    anchored_len: u32,
) -> *mut u8 {
    // SAFETY: the caller's contract above.
    let read = |ptr: *const u8, len: u32| unsafe { input(ptr, len) };
    let capsule = match read(capsule_ptr, capsule_len) {
        Ok(b) => b,
        Err(e) => return boundary_error(&e),
    };
    let side = match read(side_ptr, side_len) {
        Ok(b) => b,
        Err(e) => return boundary_error(&e),
    };
    let anchored = match read(anchored_ptr, anchored_len) {
        Ok(b) => b,
        Err(e) => return boundary_error(&e),
    };
    let anchored = match anchors(anchored) {
        Ok(a) => a,
        Err(e) => return boundary_error(&e),
    };
    match Session::open(capsule, side, anchored) {
        Ok(session) => {
            SESSION.with(|slot| *slot.borrow_mut() = Some(session));
            reply(r#"{"ok":true}"#.as_bytes())
        }
        Err(e) => boundary_error(&e),
    }
}

/// One request of the session.
///
/// # Safety
///
/// The pointer must be a live buffer of `request_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ksg_call(request_ptr: *const u8, request_len: u32) -> *mut u8 {
    // SAFETY: the caller's contract above.
    let request = match unsafe { input(request_ptr, request_len) } {
        Ok(b) => b,
        Err(e) => return boundary_error(&e),
    };
    let request: Request = match serde_json::from_slice(request) {
        Ok(r) => r,
        Err(e) => return boundary_error(&format!("the request does not read: {e}")),
    };
    SESSION.with(|slot| {
        let mut slot = slot.borrow_mut();
        let Some(session) = slot.as_mut() else {
            return boundary_error("no session: open the capsule first");
        };
        let answer: Answer = session.call(request);
        match serde_json::to_vec(&answer) {
            Ok(bytes) => reply(&bytes),
            Err(e) => boundary_error(&format!("the answer does not encode: {e}")),
        }
    })
}

/// Closes the session: the new capsule and the outputs the reader keeps.
///
/// The session is dropped here whether the close went through or not: a module
/// instance holds no secret past its close.
#[no_mangle]
pub extern "C" fn ksg_close() -> *mut u8 {
    SESSION.with(|slot| {
        let session = slot.borrow_mut().take();
        let Some(mut session) = session else {
            return boundary_error("no session: open the capsule first");
        };
        let closed = session.close();
        drop(session);
        match closed {
            Ok((capsule, outputs)) => {
                let outputs: Vec<String> = outputs.iter().map(|o| B64.encode(o)).collect();
                let answer = serde_json::json!({
                    "capsule": B64.encode(&capsule),
                    "outputs": outputs,
                });
                reply(answer.to_string().as_bytes())
            }
            Err(e) => boundary_error(&e),
        }
    })
}

/// A borrowed view of a buffer the reader allocated.
///
/// # Safety
///
/// `ptr` must be a live, aligned buffer of `len` bytes for the returned view's
/// lifetime; a null pointer is only allowed with a zero length.
unsafe fn input<'a>(ptr: *const u8, len: u32) -> Result<&'a [u8], String> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err("a null buffer where bytes were expected".into());
    }
    // SAFETY: the caller's contract above.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
}

/// The anchored commands: a JSON array of base64url strings.
fn anchors(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let encoded: Vec<String> =
        serde_json::from_slice(bytes).map_err(|e| format!("the anchored commands: {e}"))?;
    encoded
        .iter()
        .map(|e| {
            B64.decode(e)
                .map_err(|_| "the anchored commands: not base64url".to_string())
        })
        .collect()
}

/// An answer buffer: `[u32 little-endian length][bytes]`, boxed so the length
/// is exact and [`ksg_free`] can rebuild it.
fn reply(body: &[u8]) -> *mut u8 {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&u32::try_from(body.len()).unwrap_or(u32::MAX).to_le_bytes());
    out.extend_from_slice(body);
    Box::into_raw(out.into_boxed_slice()).cast::<u8>()
}

/// A failure of the boundary, as the reader reads it.
fn boundary_error(message: &str) -> *mut u8 {
    let body = serde_json::json!({ "error": message });
    reply(body.to_string().as_bytes())
}

#[cfg(target_arch = "wasm32")]
fn reader_random(out: &mut [u8]) -> Result<(), getrandom::Error> {
    random(out);
    Ok(())
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(reader_random);

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_carries_its_own_length() {
        let ptr = reply(b"hello");
        let len = u32::from_le_bytes(
            unsafe { std::slice::from_raw_parts(ptr, 4) }
                .try_into()
                .expect("four bytes"),
        );
        assert_eq!(len, 5);
        unsafe { ksg_free(ptr, 4 + len) };
    }

    #[test]
    fn the_request_and_the_answer_round_trip() {
        let request = Request::Work {
            text: "step one".into(),
        };
        let json = serde_json::to_vec(&request).expect("request");
        assert_eq!(
            serde_json::from_slice::<Request>(&json).expect("back"),
            request
        );
        let answer = Answer::Done {
            bytes: vec![1, 2, 3],
        };
        let json = serde_json::to_vec(&answer).expect("answer");
        assert_eq!(
            serde_json::from_slice::<Answer>(&json).expect("back"),
            answer
        );
        assert!(String::from_utf8(json)
            .expect("utf-8")
            .contains("\"answer\":\"done\""));
    }
}
