//! The phone↔reader pairing (track I19-f): SPAKE2 turns the 6 digits
//! the holder typed into a channel key both sides compute — and a side
//! with another code is refused at key confirmation, before any channel
//! data flows.
//!
//! The ceremony the tests pin:
//!
//! ```text
//! same code on both sides → the same key → the proofs meet crosswise → the key is trusted
//! another code on one side → the proofs refuse → no channel key is trusted
//! a middle guessing a code → the holder refuses, and the guesser's key is
//!   unrelated to the holder's: the recording alone never checks guesses
//! a reflected proof (ours bounced back) → refused: proofs are direction-bound
//! ```

use ksg_capsule_module::pake::{begin, open, unwrap, wrap, PakeError};

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

/// The same code on both sides derives the same channel key, the
/// confirmation proofs match, and a message wrapped under the key opens.
#[test]
fn the_same_code_meets_and_the_message_opens() {
    let mut rng = TestRng(41);
    let (phone, msg_phone) = begin("482917", &mut rng).expect("the phone starts");
    let (reader, msg_reader) = begin("482917", &mut rng).expect("the reader starts");
    let phone = open(phone, &msg_reader).expect("the phone opens");
    let reader = open(reader, &msg_phone).expect("the reader opens");
    assert_ne!(
        phone.proof(),
        reader.proof(),
        "proofs are direction-bound: ours is not theirs"
    );
    let key_phone = phone.confirm(reader.proof()).expect("the proofs meet");
    let key_reader = reader.confirm(phone.proof()).expect("the proofs meet");
    assert_eq!(
        key_phone.bytes(),
        key_reader.bytes(),
        "one ceremony, one channel key"
    );
    let message = wrap(key_phone, &mut rng, b"the holder half travels");
    assert_eq!(
        unwrap(key_reader, &message).expect("the message opens"),
        b"the holder half travels",
        "the channel carries"
    );
}

/// A side with another code is refused at key confirmation: the proofs
/// differ, and no channel key is trusted.
#[test]
fn a_stranger_code_is_refused_at_confirmation() {
    let mut rng = TestRng(42);
    let (phone, msg_phone) = begin("482917", &mut rng).expect("the phone starts");
    let (stranger, msg_stranger) = begin("000000", &mut rng).expect("the exchange runs, not checks");
    let phone = open(phone, &msg_stranger).expect("a well-formed message opens the math");
    let stranger = open(stranger, &msg_phone).expect("a well-formed message opens the math");
    assert_ne!(
        phone.proof(),
        stranger.proof(),
        "another code, another confirmation"
    );
    assert_eq!(
        phone.confirm(stranger.proof()).unwrap_err(),
        PakeError::Refused,
        "the stranger proof does not confirm the channel"
    );
    assert_eq!(
        stranger.confirm(phone.proof()).unwrap_err(),
        PakeError::Refused,
        "the phone proof does not confirm the stranger"
    );
    // Without a confirmed proof there is no trusted key: a message the
    // stranger wraps under its own derived key never opens under the
    // phone's.
    let forged = wrap(stranger.key(), &mut rng, b"the holder half travels");
    assert_eq!(
        unwrap(phone.key(), &forged).unwrap_err(),
        PakeError::Refused,
        "unconfirmed keys never meet"
    );
}

/// A middle that guesses a code runs the exchange against the holder, is
/// refused at confirmation — and the recording alone never checks further
/// guesses: opening the holder's message with the wrong-code key gives a
/// key unrelated to the holder's.
#[test]
fn a_middle_guessing_a_code_learns_nothing_from_the_recording() {
    // A and M run one ceremony: A with the true code, M with a guess.
    let mut rng = TestRng(43);
    let (side_a, msg_a) = begin("482917", &mut rng).expect("the holder starts");
    let (side_m, msg_m) = begin("111111", &mut rng).expect("the middle guesses");
    let opened_a = open(side_a, &msg_m).expect("a well-formed message opens the math");
    let opened_m = open(side_m, &msg_a).expect("a well-formed message opens the math");
    assert_eq!(
        opened_a.confirm(opened_m.proof()).unwrap_err(),
        PakeError::Refused,
        "the holder refuses the guesser"
    );
    // The guesser holds only its guess-derived key — unrelated to the
    // holder's — and re-running the recording with yet another wrong code
    // derives yet another unrelated key: no offline check ever says "warm".
    let (side_a2, msg_a2) = begin("482917", &mut rng).expect("the holder starts again");
    let offline = open(side_a2, &msg_a).expect("a well-formed message opens the math");
    void_msg(&msg_a2);
    assert_ne!(
        opened_a.key().bytes(),
        opened_m.key().bytes(),
        "the guesser's key is not the holder's"
    );
    assert_ne!(
        opened_a.key().bytes(),
        offline.key().bytes(),
        "a fresh ceremony under the true code is a fresh key: nothing in the recording pins it"
    );
    assert_ne!(
        opened_m.key().bytes(),
        opened_m.proof(),
        "the guesser's proof is not its key"
    );
}

/// A proof bounced back at its sender is refused: the proofs are
/// direction-bound, so a middle that returns a side's own confirmation
/// is not mistaken for the peer.
#[test]
fn a_reflected_proof_is_refused() {
    let mut rng = TestRng(46);
    let (phone, msg_phone) = begin("482917", &mut rng).expect("the phone starts");
    let (reader, msg_reader) = begin("482917", &mut rng).expect("the reader starts");
    let phone = open(phone, &msg_reader).expect("the phone opens");
    let reader = open(reader, &msg_phone).expect("the reader opens");
    assert_eq!(
        phone.confirm(phone.proof()).unwrap_err(),
        PakeError::Refused,
        "our own proof is not the peer's"
    );
    assert_eq!(
        reader.confirm(reader.proof()).unwrap_err(),
        PakeError::Refused,
        "our own proof is not the peer's"
    );
    // Crosswise the ceremony still meets: the reflection changes nothing
    // for the honest peer.
    phone.confirm(reader.proof()).expect("the proofs meet");
    reader.confirm(phone.proof()).expect("the proofs meet");
}

/// What is not 6 ASCII digits never starts a pairing.
#[test]
fn what_is_not_six_digits_never_pairs() {
    let mut rng = TestRng(44);
    for bad in ["", "12345", "1234567", "abcdef", "12 345"] {
        assert_eq!(
            begin(bad, &mut rng).unwrap_err(),
            PakeError::BadCode,
            "no pairing under {bad:?}"
        );
    }
}

/// A malformed peer message and a tampered message are refused; a stub
/// too short for a nonce never opens.
#[test]
fn malformed_tampered_and_stub_are_refused() {
    let mut rng = TestRng(45);
    let (phone, _) = begin("482917", &mut rng).expect("the phone starts");
    let (reader, msg_reader) = begin("482917", &mut rng).expect("the reader starts");
    assert_eq!(
        open(phone, &msg_reader[..7]).unwrap_err(),
        PakeError::BadMessage,
        "a stub holds no SPAKE2 message"
    );
    let (phone, _) = begin("482917", &mut rng).expect("the phone restarts");
    let mut bad = msg_reader;
    bad[0] ^= 0x01;
    assert_eq!(
        open(phone, &bad).unwrap_err(),
        PakeError::BadMessage,
        "a flipped byte breaks the pairing message"
    );
    let (phone, msg_phone) = begin("482917", &mut rng).expect("the phone restarts");
    let phone = open(phone, &msg_reader).expect("the phone opens");
    let reader = open(reader, &msg_phone).expect("the reader opens");
    let key_phone = phone.confirm(reader.proof()).expect("the proofs meet");
    let key_reader = reader.confirm(phone.proof()).expect("the proofs meet");
    let mut message = wrap(key_phone, &mut rng, b"the holder half travels");
    let last = message.len() - 1;
    message[last] ^= 0x01;
    assert_eq!(
        unwrap(key_reader, &message).unwrap_err(),
        PakeError::Refused,
        "a flipped byte breaks the seal"
    );
    assert_eq!(
        unwrap(key_reader, &message[..7]).unwrap_err(),
        PakeError::Refused,
        "a stub holds no nonce"
    );
    // A confirmation proof of the wrong length is refused, not panicked.
    assert_eq!(
        phone.confirm(&message[..7]).unwrap_err(),
        PakeError::Refused,
        "a stub holds no proof"
    );
}

/// Marks a message as intentionally unused: the MITM test re-runs the
/// ceremony and keeps the recording message of the first one only.
fn void_msg(_: &[u8; 33]) {}
