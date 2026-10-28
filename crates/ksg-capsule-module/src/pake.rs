//! The phone↔reader channel: SPAKE2 PAKE by a 6-digit code, then AEAD (И19).
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
//! Both sides run SPAKE2 in symmetric mode ([`spake2`], RustCrypto, Ed25519
//! group) with the 6-digit code as the password and `ksg-pake-v1` as the
//! identity, exchange the 33-byte messages, and stretch the SPAKE2 output
//! into the channel key with HKDF:
//!
//! ```text
//! code  = the 6 digits the holder typed (21 bits of entropy)
//! raw   = SPAKE2-symmetric(code, identity "ksg-pake-v1", msg_a, msg_b)
//! key   = HKDF-SHA256(raw, info "ksg-pake-channel-v1")
//! proof(A→B) = HMAC-SHA256(key, "ksg-confirm-v1" || msg_a || msg_b)
//! proof(B→A) = HMAC-SHA256(key, "ksg-confirm-v1" || msg_b || msg_a)
//! ```
//!
//! The two confirmation proofs differ by direction on purpose: each side
//! sends its own and expects the mirror. If both proofs were the same
//! value, a middle could bounce a side's proof back at it — a reflection —
//! and be accepted without ever meeting anyone who typed the code. With
//! direction-bound proofs a reflected proof is refused ([`Opened::confirm`]
//! checks against the expected mirror, never against what was sent).
//!
//! SPAKE2 is a password-authenticated key exchange: a passive listener
//! learns nothing about the code or the key, and an active
//! person-in-the-middle gets exactly one guess at the code per ceremony —
//! a wrong guess derives an unrelated key, and, crucially, the transcript
//! alone never lets them check further guesses offline. The 10^6-code
//! dictionary cannot be replayed against a recording: each ceremony's
//! messages are fresh, and only the live peer's confirmation decides.
//!
//! Key confirmation comes before any channel data: each side sends its
//! own proof — an HMAC of its own message first, then the peer's, under
//! the channel key — and opens nothing until the peer's proof verifies
//! against the mirror ([`Opened::confirm`]). A side that typed another
//! code holds another key, its proof is refused, and the halves never
//! travel.
//!
//! The caller still stops after a handful of failed confirmations —
//! SPAKE2 grants the middle one guess per ceremony, so the count is the
//! rate limit (this module derives and confirms, it does not count).
//!
//! Messages after confirmation travel under XChaCha20-Poly1305 with the
//! channel key: each message carries its own 24-byte nonce (`nonce ||
//! ciphertext`), so a replayed message is a bit-exact duplicate the caller
//! can spot by the nonce it already saw.

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// The SPAKE2 identity string binding the exchange to this channel.
const IDENTITY: &[u8] = b"ksg-pake-v1";
/// The HKDF info string binding the key to this channel.
const CHANNEL_INFO: &[u8] = b"ksg-pake-channel-v1";
/// The confirmation label binding a proof to this channel.
const CONFIRM_LABEL: &[u8] = b"ksg-confirm-v1";
/// Length of a 6-digit code, ASCII digits.
const CODE_LEN: usize = 6;
/// Length of one SPAKE2 symmetric message (Ed25519 group), bytes.
pub const MESSAGE_LEN: usize = 33;
/// Length of a key-confirmation proof (HMAC-SHA256), bytes.
pub const PROOF_LEN: usize = 32;
/// Length of the channel key, bytes.
pub const CHANNEL_KEY_LEN: usize = 32;
/// Length of the XChaCha20-Poly1305 nonce, bytes.
pub const NONCE_LEN: usize = 24;

/// What went wrong pairing, confirming, or wrapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PakeError {
    /// The code is not 6 ASCII digits.
    BadCode,
    /// The peer pairing message is not a well-formed SPAKE2 message.
    BadMessage,
    /// The confirmation proof does not verify, or the AEAD tag does not —
    /// wrong code, wrong key, or tampering.
    Refused,
}

impl core::fmt::Display for PakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadCode => f.write_str("the pairing code is not 6 digits"),
            Self::BadMessage => f.write_str("the peer pairing message is malformed"),
            Self::Refused => f.write_str("the pairing is refused: wrong code or tampering"),
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

/// Our half of a pairing ceremony: the SPAKE2 state plus the message we
/// sent, kept for the transcript the confirmation HMAC covers. `Debug`
/// names it — the state holds the ephemeral scalar.
pub struct Pairing {
    /// The SPAKE2 state, consumed by [`open`].
    state: Spake2<Ed25519Group>,
    /// The message [`begin`] returned, in full.
    outbound: [u8; MESSAGE_LEN],
}

impl core::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Pairing(..)")
    }
}

/// A finished pairing: the channel key plus our confirmation proof to
/// send (ours first, then the peer's) and the proof we expect back (the
/// peer's first, then ours). Trust the key only after
/// [`Opened::confirm`] accepts the peer's proof — before that it may be
/// the key of a stranger's ceremony.
pub struct Opened {
    /// The channel key this side derived.
    key: ChannelKey,
    /// HMAC-SHA256(key, "ksg-confirm-v1" || our_msg || peer_msg): ours.
    proof: [u8; PROOF_LEN],
    /// HMAC-SHA256(key, "ksg-confirm-v1" || peer_msg || our_msg): theirs.
    expected: [u8; PROOF_LEN],
}

impl Opened {
    /// Our confirmation proof, to send to the peer before any data.
    #[must_use]
    pub fn proof(&self) -> &[u8; PROOF_LEN] {
        &self.proof
    }

    /// The derived channel key. Trust it only after `confirm` accepted
    /// the peer's proof.
    #[must_use]
    pub fn key(&self) -> &ChannelKey {
        &self.key
    }

    /// Checks the peer's confirmation proof in constant time: same key on
    /// both sides means the peer's proof equals our `expected`, and equal
    /// means the peer typed the same code. A stranger's proof — and our
    /// own proof bounced back at us (a reflection) — is refused, and no
    /// channel data may flow.
    pub fn confirm(&self, peer_proof: &[u8]) -> Result<&ChannelKey, PakeError> {
        if peer_proof.len() != PROOF_LEN {
            return Err(PakeError::Refused);
        }
        if self.expected.as_slice().ct_eq(peer_proof).into() {
            Ok(&self.key)
        } else {
            Err(PakeError::Refused)
        }
    }
}

impl core::fmt::Debug for Opened {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Opened(..)")
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

/// Starts our side of a pairing: validates the 6-digit `code` and returns
/// the ceremony state plus the message to send to the peer. Both sides
/// call it with the same code; the randomness comes from `rng` — fresh
/// per ceremony, so no two ceremonies share a transcript.
pub fn begin(
    code: &str,
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(Pairing, [u8; MESSAGE_LEN]), PakeError> {
    check_code(code)?;
    let (state, outbound) = Spake2::<Ed25519Group>::start_symmetric_with_rng(
        &Password::new(code.as_bytes()),
        &Identity::new(IDENTITY),
        &mut *rng,
    );
    let outbound: [u8; MESSAGE_LEN] =
        outbound.try_into().map_err(|_| PakeError::BadMessage)?;
    Ok((Pairing { state, outbound }, outbound))
}

/// Finishes the pairing with the peer's message: runs SPAKE2 to completion,
/// stretches the output into the channel key, and precomputes our
/// confirmation proof over the ordered transcript. A malformed message is
/// refused; a well-formed message under another code still finishes — the
/// stranger is caught later, by [`Opened::confirm`].
pub fn open(pairing: Pairing, peer_msg: &[u8]) -> Result<Opened, PakeError> {
    if peer_msg.len() != MESSAGE_LEN {
        return Err(PakeError::BadMessage);
    }
    let raw = pairing
        .state
        .finish(peer_msg)
        .map_err(|_| PakeError::BadMessage)?;
    let raw = Zeroizing::new(raw);
    let mut okm = [0u8; CHANNEL_KEY_LEN];
    Hkdf::<Sha256>::new(None, &raw)
        .expand(CHANNEL_INFO, &mut okm)
        .expect("HKDF-SHA256 expands 32 bytes");
    drop(raw);
    // The proofs are direction-bound: ours covers `ours || peer`, the
    // expected one covers `peer || ours`. Both sides compute the same
    // pair — what we send is what the peer expects — and a proof bounced
    // back at its sender (a reflection) matches nothing.
    let mut ours =
        <Hmac<Sha256> as Mac>::new_from_slice(&okm).expect("HMAC takes any key length");
    ours.update(CONFIRM_LABEL);
    ours.update(&pairing.outbound);
    ours.update(peer_msg);
    let ours: [u8; PROOF_LEN] = ours.finalize().into_bytes().into();
    let mut theirs =
        <Hmac<Sha256> as Mac>::new_from_slice(&okm).expect("HMAC takes any key length");
    theirs.update(CONFIRM_LABEL);
    theirs.update(peer_msg);
    theirs.update(&pairing.outbound);
    let theirs: [u8; PROOF_LEN] = theirs.finalize().into_bytes().into();
    Ok(Opened {
        key: ChannelKey(Zeroizing::new(okm)),
        proof: ours,
        expected: theirs,
    })
}

/// Wraps one message under the channel key: `nonce || ciphertext`. The
/// nonce comes from `rng` — fresh per message, never reused under one key.
/// Send only after [`Opened::confirm`] accepted the peer.
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

/// Opens a wrapped message: the AEAD check refuses a wrong key or any
/// tampering.
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
