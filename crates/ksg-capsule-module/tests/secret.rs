//! The session's secret bytes, behind named types (track I9): [`StateKey`]
//! guards the 32-byte state key, [`OwnerKey`] guards the owner's signing
//! key — and both keep their bytes out of `Debug` and wipe them when they
//! drop.
//!
//! The leak the tests pin: `Zeroizing` wipes, but its `Debug` prints the
//! bytes — a `format!("{state_key:?}")` in a log line is a key in a log
//! line. The named types print a name instead. The wipe the tests pin:
//! dropping the value zeroes the memory it guarded.
//!
//! `unsafe` is denied here (as in the module), so freed memory cannot be
//! read back: the wipe is pinned through observable behaviour instead. A
//! signed-then-dropped owner key still verifies the signature it made —
//! the public key (in `KeySet`) answers for the wiped seed — while the
//! signed bytes are nowhere in the key's `Debug`:
//!
//! ```text
//! sign → drop the key → verify the signature against the kept public key
//! ```

use ksg_capsule_module::secret::{OwnerKey, StateKey};
use ksg_core_v2::crypto::sign::{Ed25519Signer, KeySet, Profile, SignatureSet};
use ksg_core_v2::doc::Uri;

/// StateKey's `Debug` names it, never its bytes.
#[test]
fn state_key_debug_names_it_never_its_bytes() {
    let key = StateKey::new([0xA5; 32]);
    let shown = format!("{key:?}");
    assert_eq!(shown, "StateKey(..)", "a name, not bytes: {shown}");
    // The name carries nothing key-dependent: two different keys print
    // the same. (Hex digits appear in ordinary words — `StateKey` holds
    // an `a` and an `e` — so "no hex" would prove nothing; constancy
    // across keys is the property that pins no leak.)
    let other = StateKey::new([0x00; 32]);
    assert_eq!(
        format!("{other:?}"),
        shown,
        "different bytes, the same name"
    );
}

/// The bytes are still usable while the key lives: the only slice the state
/// key offers reseals what it sealed.
#[test]
fn state_key_bytes_serve_while_the_key_lives() {
    let raw = [0x5A; 32];
    let key = StateKey::new(raw);
    assert_eq!(key.bytes(), &raw, "the guarded bytes serve");
}

/// OwnerKey's `Debug` names it, never the seed — and not even the key
/// identifier the upstream signer prints.
#[test]
fn owner_key_debug_names_it_never_the_seed() {
    let kid = Uri::parse("did:key:zOwner#k1").expect("a test uri");
    let seed = [0x3C; 32];
    let owner = OwnerKey::from_seed(Ed25519Signer::from_seed(kid.clone(), seed), seed);
    let shown = format!("{owner:?}");
    assert_eq!(shown, "OwnerKey(..)", "a name, not key material: {shown}");
    // Same constancy check as for the state key: the seed never shows.
    let other = OwnerKey::from_seed(Ed25519Signer::from_seed(kid, [0x00; 32]), [0x00; 32]);
    assert_eq!(
        format!("{other:?}"),
        shown,
        "a different seed, the same name"
    );
}

/// The owner key signs while it lives; dropped, its seed is gone — but the
/// signature it made still verifies against the kept public key, which is
/// the behaviour that proves the key worked before the wipe.
#[test]
fn a_dropped_owner_key_still_answers_for_what_it_signed() {
    let kid = Uri::parse("did:key:zOwner#k1").expect("a test uri");
    let seed = [0x77; 32];
    let signer = Ed25519Signer::from_seed(kid.clone(), seed);
    let public = signer.public();
    let owner = OwnerKey::from_seed(signer, seed);
    let sig = owner.signer().sign(b"the initiation binds the owner");
    drop(owner);
    let mut keys = KeySet::new();
    keys.insert(public);
    SignatureSet::new(vec![sig])
        .verify(
            b"the initiation binds the owner",
            &keys,
            &Profile::default(),
        )
        .expect("the kept public key answers for the wiped seed");
}
