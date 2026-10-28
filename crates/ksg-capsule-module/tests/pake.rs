//! The phone↔reader pairing channel (track И19): [`pair`] turns the
//! holder-typed 6-digit code and the two sides' ephemeral halves into one
//! channel key, and [`wrap`]/[`unwrap`] carry the halves under it.
//!
//! The properties the tests pin:
//!
//! | Property | Test |
//! |---|----|
//! | both sides with one code derive one key | `both_sides_derive_one_key` |
//! | a wrapped message opens under the peer's key | `a_wrapped_message_opens_under_the_peers_key` |
//! | a stranger's code derives another key and refuses the wrap | `a_strangers_code_refuses` |
//! | a tampered or truncated wrap refuses | `a_tampered_wrap_refuses`, `a_cut_wrap_refuses` |
//! | the key's `Debug` names it, never its bytes | `channel_key_debug_names_it` |
//! | a non-6-digit code is refused before any key | `a_non_code_refuses` |
//!
//! ```text
//! code  = the 6 digits the holder typed
//! ka    = pair(code, secret_a, public_b)
//! kb    = pair(code, secret_b, public_a)   // ka == kb
//! wrap  = nonce || XChaCha20-Poly1305(key, nonce, plaintext)
//! ```

use ksg_capsule_module::pake::{pair, unwrap, wrap};
use rand_core::RngCore;

/// A deterministic RNG for the tests: the nonces only need freshness, not
/// secrecy, so a counter stream is enough and keeps the tests reproducible.
struct Ctr(u64);

impl RngCore for Ctr {
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E3779B97F4A7C15);
        self.0
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for Ctr {}

/// Two fresh ephemeral halves and their publics, deterministically.
fn ephemerals(rng: &mut Ctr) -> ([u8; 32], [u8; 32], [u8; 32], [u8; 32]) {
    let mut secret_a = [0u8; 32];
    let mut secret_b = [0u8; 32];
    rng.fill_bytes(&mut secret_a);
    rng.fill_bytes(&mut secret_b);
    let public_a = {
        let secret = x25519_dalek::StaticSecret::from(secret_a);
        *x25519_dalek::PublicKey::from(&secret).as_bytes()
    };
    let public_b = {
        let secret = x25519_dalek::StaticSecret::from(secret_b);
        *x25519_dalek::PublicKey::from(&secret).as_bytes()
    };
    (secret_a, secret_b, public_a, public_b)
}

/// Both sides with one code derive one key.
#[test]
fn both_sides_derive_one_key() {
    let mut rng = Ctr(7);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key_a = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let key_b = pair("482916", &secret_b, &public_a).expect("the code pairs");
    assert_eq!(
        key_a.bytes(),
        key_b.bytes(),
        "one code, two sides, one channel key"
    );
}

/// A wrapped message opens under the peer's key.
#[test]
fn a_wrapped_message_opens_under_the_peers_key() {
    let mut rng = Ctr(11);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key_a = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let key_b = pair("482916", &secret_b, &public_a).expect("the code pairs");
    let message = wrap(&key_a, &mut rng, b"the client's half travels here");
    let opened = unwrap(&key_b, &message).expect("the peer's key opens the wrap");
    assert_eq!(
        opened,
        b"the client's half travels here",
        "the halves travel under the channel key"
    );
}

/// A stranger's code derives another key and refuses the wrap.
#[test]
fn a_strangers_code_refuses() {
    let mut rng = Ctr(13);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key_a = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let key_wrong = pair("482917", &secret_b, &public_a).expect("a code still derives");
    assert_ne!(
        key_a.bytes(),
        key_wrong.bytes(),
        "one digit off, another key"
    );
    let message = wrap(&key_a, &mut rng, b"the client's half travels here");
    assert!(
        unwrap(&key_wrong, &message).is_err(),
        "the stranger's code does not open the wrap"
    );
}

/// A tampered wrap refuses.
#[test]
fn a_tampered_wrap_refuses() {
    let mut rng = Ctr(17);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key_a = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let key_b = pair("482916", &secret_b, &public_a).expect("the code pairs");
    let mut message = wrap(&key_a, &mut rng, b"the client's half travels here");
    let last = message.len() - 1;
    message[last] ^= 1;
    assert!(
        unwrap(&key_b, &message).is_err(),
        "a flipped bit fails the AEAD check"
    );
}

/// A cut wrap refuses: too short for the nonce, or a cut ciphertext.
#[test]
fn a_cut_wrap_refuses() {
    let mut rng = Ctr(19);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key_a = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let key_b = pair("482916", &secret_b, &public_a).expect("the code pairs");
    let message = wrap(&key_a, &mut rng, b"the client's half travels here");
    assert!(
        unwrap(&key_b, &message[..10]).is_err(),
        "shorter than a nonce refuses"
    );
    assert!(
        unwrap(&key_b, &message[..message.len() - 2]).is_err(),
        "a cut ciphertext fails the AEAD check"
    );
}

/// The channel key's `Debug` names it, never its bytes.
#[test]
fn channel_key_debug_names_it() {
    let mut rng = Ctr(23);
    let (secret_a, secret_b, public_a, public_b) = ephemerals(&mut rng);
    let key = pair("482916", &secret_a, &public_b).expect("the code pairs");
    let shown = format!("{key:?}");
    assert_eq!(shown, "ChannelKey(..)", "a name, not bytes: {shown}");
    let other = pair("000000", &secret_b, &public_a).expect("another code pairs");
    assert_eq!(
        format!("{other:?}"),
        shown,
        "different bytes, the same name"
    );
}

/// A non-6-digit code is refused before any key: short, long, non-digit.
#[test]
fn a_non_code_refuses() {
    let mut rng = Ctr(29);
    let (secret_a, _secret_b, _public_a, public_b) = ephemerals(&mut rng);
    for bad in ["", "48291", "4829160", "48291a", "abcdef", "4829 6"] {
        assert!(
            pair(bad, &secret_a, &public_b).is_err(),
            "not 6 ASCII digits refuses: {bad:?}"
        );
    }
}
