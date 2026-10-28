//! The phone↔reader pairing (track И19): [`pair`] turns the 6 digits
//! the holder typed into a channel key both sides compute — and a side
//! with another code gets another key, so the first wrapped message
//! refuses to open.
//!
//! The ceremony the tests pin:
//!
//! ```text
//! same code on both sides → the same key → the message opens
//! another code on one side → another key → `Refused`
//! ```

use ksg_capsule_module::pake::{pair, unwrap, wrap, PakeError};

/// One fresh ephemeral pair: the secret this side keeps, the public half
/// it sends in the clear.
fn ephemeral(rng: &mut TestRng) -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rng.fill_bytes(&mut secret);
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    (secret, *public.as_bytes())
}

/// A deterministic generator for the tests only: splitmix64, the same
/// stream the session tests' stand uses. Its quality is irrelevant — what
/// the tests check is the pairing, not the keys.
struct TestRng(u64);

impl TestRng {
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(8) {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            let bytes = z.to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }
}

impl rand_core::RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        Self::fill_bytes(self, dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TestRng {}

/// The same code on both sides derives the same channel key, and a message
/// wrapped under it opens.
#[test]
fn the_same_code_meets_and_the_message_opens() {
    let mut rng = TestRng(41);
    let (sec_a, pub_a) = ephemeral(&mut rng);
    let (sec_b, pub_b) = ephemeral(&mut rng);
    let key_a = pair("482917", &sec_a, &pub_b).expect("the phone pairs");
    let key_b = pair("482917", &sec_b, &pub_a).expect("the reader pairs");
    assert_eq!(
        key_a.bytes(),
        key_b.bytes(),
        "one ceremony, one channel key"
    );
    let message = wrap(&key_a, &mut rng, b"the holder half travels");
    assert_eq!(
        unwrap(&key_b, &message).expect("the message opens"),
        b"the holder half travels",
        "the channel carries"
    );
}

/// A side with another code derives another key: the first wrapped message
/// refuses to open.
#[test]
fn a_stranger_code_is_refused() {
    let mut rng = TestRng(42);
    let (sec_a, pub_a) = ephemeral(&mut rng);
    let (sec_b, pub_b) = ephemeral(&mut rng);
    let key_a = pair("482917", &sec_a, &pub_b).expect("the phone pairs");
    let stranger = pair("000000", &sec_b, &pub_a).expect("the pairing derives, not checks");
    assert_ne!(
        key_a.bytes(),
        stranger.bytes(),
        "another code, another key"
    );
    let message = wrap(&key_a, &mut rng, b"the holder half travels");
    assert_eq!(
        unwrap(&stranger, &message).unwrap_err(),
        PakeError::Refused,
        "the stranger code does not open the channel"
    );
}

/// What is not 6 ASCII digits never starts a pairing.
#[test]
fn what_is_not_six_digits_never_pairs() {
    let secret = [0x11; 32];
    let peer = [0x22; 32];
    for bad in ["", "12345", "1234567", "abcdef", "12 345"] {
        assert_eq!(
            pair(bad, &secret, &peer).unwrap_err(),
            PakeError::BadCode,
            "no pairing under {bad:?}"
        );
    }
}

/// A tampered message and a stub too short for a nonce refuse to open.
#[test]
fn tampering_and_a_stub_are_refused() {
    let mut rng = TestRng(43);
    let (sec_a, pub_a) = ephemeral(&mut rng);
    let (sec_b, pub_b) = ephemeral(&mut rng);
    let key_a = pair("482917", &sec_a, &pub_b).expect("the phone pairs");
    let key_b = pair("482917", &sec_b, &pub_a).expect("the reader pairs");
    let mut message = wrap(&key_a, &mut rng, b"the holder half travels");
    let last = message.len() - 1;
    message[last] ^= 0x01;
    assert_eq!(
        unwrap(&key_b, &message).unwrap_err(),
        PakeError::Refused,
        "a flipped byte breaks the seal"
    );
    assert_eq!(
        unwrap(&key_b, &message[..7]).unwrap_err(),
        PakeError::Refused,
        "a stub holds no nonce"
    );
}
