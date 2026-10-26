//! The module's boundary: exports and the two host imports. The only place
//! `unsafe` is allowed in this crate (raw memory shared with the reader).
#![allow(unsafe_code)]

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

#[cfg(target_arch = "wasm32")]
fn reader_random(out: &mut [u8]) -> Result<(), getrandom::Error> {
    random(out);
    Ok(())
}

#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(reader_random);
