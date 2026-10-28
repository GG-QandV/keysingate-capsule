//! The phone↔reader channel: PAKE by a 6-digit code, then AEAD (И19).
//!
//! The birth of the client's key is split across two devices — the phone
//! holds one half, the capsule's reader the other. Before the halves may
//! travel, the two sides must agree they talk to each other and not to a
//! listener in the middle. The holder reads a 6-digit code off one screen
//! and types it into the other; that code is the whole shared secret. This
//! module turns the code into a channel key both sides compute — and a
//! listener that heard everything but the code cannot.
//!
//! # Protocol
//!
//! Both sides pick an ephemeral X25519 key, exchange the public halves in
//! the clear, and stretch the transcript into the channel key with HKDF:
//!
//! ```text
//! code  = the 6 digits the holder typed (21 bits of entropy)
//! salt  = SHA-256("ksg-pake-v1" || code || side_a_ephemeral || side_b_ephemeral)
//! ikm   = code || x25519(ephemeral_secret, peer_ephemeral)
//! key   = HKDF-SHA256(ikm, salt, "ksg-pake-channel-v1")
//! ```
//!
//! The code enters twice: it salts the transcript hash *and* prefixes the
//! key material. A listener that replays the ephemerals but guesses the
//! code wrong derives another key, and the AEAD check on the first wrapped
//! message refuses it. The 6-digit code has ~21 bits of entropy — enough
//! against one online guess per pairing ceremony, not against an offline
//! dictionary: the ephemerals MUST be fresh per ceremony, and a side MUST
//! stop after a handful of failed opens (the caller enforces both; this
//! module only derives and wraps).
//!
//! Messages after the handshake travel under XChaCha20-Poly1305 with the
//! channel key: each message carries its own 24-byte nonce (`nonce ||
//! ciphertext`), so a replayed message is a bit-exact duplicate the caller
//! can spot by the nonce it already saw.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// The domain tag hashed into the transcript salt.
const SALT_TAG: &[u8] = b"ksg-pake-v1";
/// The HKDF info string binding the key to this channel.
const CHANNEL_INFO: &[u8] = b"ksg-pake-channel-v1";
/// Length of an X25519 public key, bytes.
const EPHEMERAL_LEN: usize = 32;
/// Length of a 6-digit code, ASCII digits.
const CODE_LEN: usize = 6;
/// Length of the channel key, bytes.
pub const CHANNEL_KEY_LEN: usize = 32;
/// Length of the XChaCha20-Poly1305 nonce, bytes.
pub const NONCE_LEN: usize = 24;

/// What went wrong pairing or wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PakeError {
    /// The code is not 6 ASCII digits.
    BadCode,
    /// A peer ephemeral is not 32 bytes.
    BadEphemeral,
    /// The AEAD tag does not verify — wrong code, wrong key, or tampering.
    Refused,
}

impl core::fmt::Display for PakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadCode => f.write_str("the pairing code is not 6 digits"),
            Self::BadEphemeral => f.write_str("the peer ephemeral is not 32 bytes"),
            Self::Refused => f.write_str("the wrapped message does not open"),
        }
    }
}

impl std::error::Error for PakeError {}

/// The channel key both sides of a pairing derive: `Debug` names it, the
/// bytes wipe on drop (as [`crate::secret::StateKey`]).
pub struct ChannelKey(Zeroizing<[u8; CHANNEL_KEY_LEN]>);

impl ChannelKey {
    /// The key, for the wrap and unwrap calls that take a slice.
    #[must_use]
    pub fn bytes(&self) -> &[u8; CHANNEL_KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ChannelKey(..)")
    }
}

impl Drop for ChannelKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Checks the code is 6 ASCII digits.
fn check_code(code: &str) -> Result<(), PakeError> {
    if code.len() == CODE_LEN && code.bytes().all(|b| b.is_ascii_digit()) {
        Ok(())
    } else {
        Err(PakeError::BadCode)
    }
}

/// Derives the channel key from the pairing: the holder-typed 6-digit
/// `code`, our fresh ephemeral secret, and the peer's ephemeral public
/// half. Both sides call it with the same code and each other's public
/// halves, and both get the same key.
pub fn pair(
    code: &str,
    our_secret: &[u8; EPHEMERAL_LEN],
    peer_public: &[u8; EPHEMERAL_LEN],
) -> Result<ChannelKey, PakeError> {
    check_code(code)?;
    let secret = x25519_dalek::StaticSecret::from(*our_secret);
    let peer = x25519_dalek::PublicKey::from(*peer_public);
    let shared = secret.diffie_hellman(&peer);
    // `our_secret` is copied into the dalek secret above; wipe our array's
    // twin here — the caller's own array is theirs to wipe.
    let mut secret_copy = *our_secret;
    secret_copy.zeroize();

    let our_public = x25519_dalek::PublicKey::from(&secret);
    // Both sides hash the two ephemerals in the same (lexicographic)
    // order: `our || peer` on one side is `peer || our` on the other, and
    // the keys would never meet.
    let ours = *our_public.as_bytes();
    let (first, second) = if ours <= *peer_public {
        (ours, *peer_public)
    } else {
        (*peer_public, ours)
    };
    let mut salt_hash = Sha256::new();
    salt_hash.update(SALT_TAG);
    salt_hash.update(code.as_bytes());
    salt_hash.update(first);
    salt_hash.update(second);
    let salt = salt_hash.finalize();

    let mut ikm = Vec::with_capacity(CODE_LEN + EPHEMERAL_LEN);
    ikm.extend_from_slice(code.as_bytes());
    ikm.extend_from_slice(shared.as_bytes());
    let mut okm = [0u8; CHANNEL_KEY_LEN];
    Hkdf::<Sha256>::new(Some(&salt), &ikm)
        .expand(CHANNEL_INFO, &mut okm)
        .expect("HKDF-SHA256 expands 32 bytes");
    ikm.zeroize();
    Ok(ChannelKey(Zeroizing::new(okm)))
}

/// Wraps one message under the channel key: `nonce || ciphertext`. The
/// nonce comes from `rng` — fresh per message, never reused under one key.
pub fn wrap(
    key: &ChannelKey,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
    plaintext: &[u8],
) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.bytes()));
    let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(
        &cipher
            .encrypt(XNonce::from_slice(&nonce), plaintext)
            .expect("XChaCha20-Poly1305 seals"),
    );
    out
}

/// Opens a wrapped message: the AEAD check refuses a wrong code, a wrong
/// key, or any tampering.
pub fn unwrap(key: &ChannelKey, message: &[u8]) -> Result<Vec<u8>, PakeError> {
    if message.len() < NONCE_LEN {
        return Err(PakeError::Refused);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key.bytes()));
    cipher
        .decrypt(
            XNonce::from_slice(&message[..NONCE_LEN]),
            &message[NONCE_LEN..],
        )
        .map_err(|_| PakeError::Refused)
}
