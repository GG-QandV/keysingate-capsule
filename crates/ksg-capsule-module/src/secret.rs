//! The session's secret bytes: each secret lives in a type whose `Debug`
//! names it, never its bytes, and whose memory is wiped when it drops.
//!
//! The session holds three secrets while it runs: the key the container's
//! state is sealed under, the party's map opening (`OpenWith`, which wipes
//! itself), and the party's signing secret — the client's mobile half or
//! the owner's signing key. The map opening and the mobile half cross the
//! module's boundary through other crates' types, which already wipe
//! themselves on drop; this module owns the rest, and the rest is here:
//!
//! | Type | What it wraps | Why it exists |
//! |---|---|---|
//! | [`StateKey`] | the 32-byte state key | `Zeroizing` is erased by `Debug` |
//! | [`OwnerKey`] | an [`Ed25519Signer`] | the upsteam key prints nothing |
//!
//! `Zeroizing<[u8; 32]>` wipes, but its `Debug` prints the bytes: a
//! `format!("{state_key:?}")` in a log line is a key in a log line. These
//! wrappers print a name instead. `ZeroizeOnDrop` on the wrapper is the
//! belt to `Zeroizing`'s braces: dropping a `StateKey` zeroes the array
//! whether or not the inner `Zeroizing` is still armed.

use ksg_core_v2::crypto::sign::Ed25519Signer;
use zeroize::{Zeroize, Zeroizing};

/// The key the container's state is sealed under (`SharedSecrets`).
///
/// `Debug` names it, never its bytes.
pub struct StateKey(Zeroizing<[u8; 32]>);

impl StateKey {
    /// Takes the key over: from here on it is wiped when it drops.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(Zeroizing::new(key))
    }

    /// The key, for the seal and the open calls that take a slice.
    #[must_use]
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Debug for StateKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("StateKey(..)")
    }
}

impl Drop for StateKey {
    fn drop(&mut self) {
        // The halves wipe themselves; the state key goes here, in one
        // place a reader can point at. `Zeroizing` disarms — zeroes — on
        // drop already; the explicit wipe is the named guarantee a `Drop`
        // audit looks for.
        self.0.zeroize();
    }
}

/// The owner's signing key, from the side file's seed.
///
/// The upstream [`Ed25519Signer`] prints only the key identifier; this
/// wrapper adds the wipe: its `Drop` zeroes the seed the signer was built
/// from, so the seed has no lifetime past the key.
pub struct OwnerKey {
    /// What signs: kept whole, never borrowed out.
    signer: Ed25519Signer,
    /// The seed the signer was built from: what `Drop` wipes.
    seed: Zeroizing<[u8; 32]>,
}

impl OwnerKey {
    /// Builds the owner's key from the side file's seed: the seed that
    /// yields another key than the roster pinned is refused upstream.
    #[must_use]
    pub fn from_seed(signer: Ed25519Signer, seed: [u8; 32]) -> Self {
        Self {
            signer,
            seed: Zeroizing::new(seed),
        }
    }

    /// What signs.
    #[must_use]
    pub fn signer(&self) -> &Ed25519Signer {
        &self.signer
    }
}

impl core::fmt::Debug for OwnerKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // The signer prints `Ed25519Signer(kid=…)`; repeating even that
        // here would put a key identifier twice in a log line for no gain.
        f.write_str("OwnerKey(..)")
    }
}

impl Drop for OwnerKey {
    fn drop(&mut self) {
        self.seed.zeroize();
    }
}
