//! Audit Round 23 pins for finding DK-A47: the envelope header
//! types Header and Kdf derived PartialEq without Eq, against
//! the crate's own trait coverage everywhere else. Every field
//! of both types is Eq, Header's String, Route, String, and
//! Option<Kdf>, and Kdf's two u32 costs and its salt, and every
//! other public value type in the crate that carries PartialEq
//! carries Eq beside it, so the omission reads as an oversight
//! and costs a caller the generic contexts that require Eq.
//!
//! The first pin is the discriminating limb. It names the Eq
//! bound on both types in a generic assertion, and this file
//! does not compile against the code before the repair, which
//! is the failure the repair removes. The remaining pins are
//! preservation pins. They check that equal headers compare
//! equal and differing headers compare unequal, and they pass
//! against the old code by design, standing guard over the
//! value semantics the added bound must not disturb.
//!
//! Every fixture is synthetic and names itself as one. No test
//! here touches a real keychain, and no store is opened.

use deadbolt::envelope::{Header, Kdf};
use deadbolt::Route;

fn assert_eq_bound<T: Eq>() {}

fn keychain_header() -> Header {
    Header {
        payload: "deadbolt-state/1".to_string(),
        route: Route::Keychain,
        store: "a".repeat(64),
        kdf: None,
    }
}

fn passphrase_header() -> Header {
    Header {
        payload: "deadbolt-state/1".to_string(),
        route: Route::Passphrase,
        store: "b".repeat(64),
        kdf: Some(Kdf {
            memory: 65536,
            time: 3,
            salt: [7u8; 16],
        }),
    }
}

#[test]
fn header_and_kdf_carry_the_eq_bound() {
    assert_eq_bound::<Header>();
    assert_eq_bound::<Kdf>();
}

#[test]
fn equal_headers_compare_equal() {
    assert_eq!(keychain_header(), keychain_header());
    assert_eq!(passphrase_header(), passphrase_header());
}

#[test]
fn differing_headers_compare_unequal() {
    assert_ne!(keychain_header(), passphrase_header());
    let mut other_store = passphrase_header();
    other_store.store = "c".repeat(64);
    assert_ne!(passphrase_header(), other_store);
    let mut other_time = passphrase_header();
    if let Some(kdf) = &mut other_time.kdf {
        kdf.time = 4;
    }
    assert_ne!(passphrase_header(), other_time);
}
