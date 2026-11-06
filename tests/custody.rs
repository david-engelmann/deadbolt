//! Pins for the custody seam of DK-18 and DK-19, driven through the
//! fixture backend and the passphrase backend.
//!
//! The platform backend is constructed and driven once, in the last
//! test, against the machine the suite runs on. That machine runs no
//! keychain service, so the drive lands in the failure outcome, which
//! is the outcome DK-24 names as the residue this suite cannot retire.

#[cfg(target_os = "linux")]
use deadbolt::custody::platform_custody;
use deadbolt::custody::{
    derive_key, CustodyLoad, FixtureCustody, KeyCustody, PassphraseCustody, StoreKey,
};
use zeroize::Zeroizing;

const STORE_ID: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
const OTHER_STORE_ID: &str = "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e1fca7e58b3";

const PROBE_SALT: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
];
const PROBE_PASSPHRASE: &[u8] = b"SYNTHETIC-TEST-VALUE-probe-passphrase";
// The DK-19 derivation vector, recorded by the build probe of design
// section 12 at the pinned parameters over the probe values above.
const DERIVATION_VECTOR_HEX: &str =
    "75a1e75522a7e405e2a302d4454a4f5d2768cfa840f1cbbae5a1749eda513448";

fn sample_key() -> StoreKey {
    let mut bytes = [0u8; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(1);
    }
    StoreKey::new(bytes)
}

fn other_key() -> StoreKey {
    StoreKey::new([0xa5; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn fixture_round_trip_returns_the_stored_key() {
    let custody = FixtureCustody::new();
    let key = sample_key();
    custody.store_key(STORE_ID, &key).unwrap();
    match custody.load_key(STORE_ID) {
        CustodyLoad::Key(loaded) => assert_eq!(loaded, key),
        other => panic!("expected the stored key, got {other:?}"),
    }
}

#[test]
fn fixture_store_is_scoped_by_store_identifier() {
    let custody = FixtureCustody::new();
    custody.store_key(STORE_ID, &sample_key()).unwrap();
    assert_eq!(custody.load_key(OTHER_STORE_ID), CustodyLoad::Absent);
}

#[test]
fn fixture_absent_for_a_store_that_never_stored() {
    let custody = FixtureCustody::new();
    assert_eq!(custody.load_key(STORE_ID), CustodyLoad::Absent);
}

#[test]
fn fixture_delete_removes_the_key_and_deleting_again_still_answers_ok() {
    let custody = FixtureCustody::new();
    custody.store_key(STORE_ID, &sample_key()).unwrap();
    custody.delete_key(STORE_ID).unwrap();
    assert_eq!(custody.load_key(STORE_ID), CustodyLoad::Absent);
    custody.delete_key(STORE_ID).unwrap();
}

#[test]
fn fixture_service_failure_reaches_store_load_and_delete_until_cleared() {
    let custody = FixtureCustody::new();
    custody.store_key(STORE_ID, &sample_key()).unwrap();
    custody.fail_with("SYNTHETIC-TEST-VALUE-service-down");
    assert_eq!(
        custody.load_key(STORE_ID),
        CustodyLoad::ServiceFailure("SYNTHETIC-TEST-VALUE-service-down".to_string())
    );
    let err = custody.store_key(STORE_ID, &sample_key()).unwrap_err();
    assert!(err
        .to_string()
        .contains("SYNTHETIC-TEST-VALUE-service-down"));
    let err = custody.delete_key(STORE_ID).unwrap_err();
    assert!(err
        .to_string()
        .contains("SYNTHETIC-TEST-VALUE-service-down"));
    custody.clear_failure();
    match custody.load_key(STORE_ID) {
        CustodyLoad::Key(_) => {}
        other => panic!("expected the stored key after clearing, got {other:?}"),
    }
}

#[test]
fn custody_works_through_a_trait_object() {
    let custody: Box<dyn KeyCustody> = Box::new(FixtureCustody::new());
    custody.store_key(STORE_ID, &sample_key()).unwrap();
    match custody.load_key(STORE_ID) {
        CustodyLoad::Key(loaded) => assert_eq!(loaded, sample_key()),
        other => panic!("expected the stored key, got {other:?}"),
    }
    custody.delete_key(STORE_ID).unwrap();
    assert_eq!(custody.load_key(STORE_ID), CustodyLoad::Absent);
}

#[test]
fn store_key_debug_never_prints_key_material() {
    let rendered = format!("{:?}", sample_key());
    assert_eq!(rendered, "StoreKey(<redacted>)");
    assert!(!rendered.contains(&hex(sample_key().as_bytes())));
}

#[test]
fn passphrase_load_derives_the_same_key_on_every_load() {
    let custody = PassphraseCustody::new(
        Zeroizing::new("SYNTHETIC-TEST-VALUE-passphrase".to_string()),
        PROBE_SALT,
    );
    let first = match custody.load_key(STORE_ID) {
        CustodyLoad::Key(key) => key,
        other => panic!("expected a derived key, got {other:?}"),
    };
    let second = match custody.load_key(OTHER_STORE_ID) {
        CustodyLoad::Key(key) => key,
        other => panic!("expected a derived key, got {other:?}"),
    };
    assert_eq!(first, second);
    assert_eq!(
        first,
        derive_key(b"SYNTHETIC-TEST-VALUE-passphrase", &PROBE_SALT)
    );
}

#[test]
fn passphrase_derivation_matches_the_recorded_probe_vector() {
    let derived = derive_key(PROBE_PASSPHRASE, &PROBE_SALT);
    assert_eq!(hex(derived.as_bytes()), DERIVATION_VECTOR_HEX);
}

#[test]
fn passphrase_store_accepts_the_derived_key_and_refuses_any_other() {
    let custody = PassphraseCustody::new(
        Zeroizing::new("SYNTHETIC-TEST-VALUE-passphrase".to_string()),
        PROBE_SALT,
    );
    let derived = derive_key(b"SYNTHETIC-TEST-VALUE-passphrase", &PROBE_SALT);
    custody.store_key(STORE_ID, &derived).unwrap();
    let err = custody.store_key(STORE_ID, &other_key()).unwrap_err();
    assert!(
        err.to_string()
            .contains("not the key this passphrase derives"),
        "{err}"
    );
}

#[test]
fn passphrase_delete_answers_ok_because_nothing_was_stored() {
    let custody = PassphraseCustody::new(
        Zeroizing::new("SYNTHETIC-TEST-VALUE-passphrase".to_string()),
        PROBE_SALT,
    );
    custody.delete_key(STORE_ID).unwrap();
}

#[test]
#[cfg(target_os = "linux")]
fn platform_custody_without_a_service_answers_service_failure() {
    // This drive is the one DK-24 names, and its premise is a machine
    // with no keychain service behind it, stated here as an executable
    // condition and not only as this comment. Where a session bus
    // address stands in the environment a service may be live, and a
    // live service answers absence for a missing entry rather than the
    // failure outcome, or can block on an unlock prompt, so the drive
    // stands down there instead of failing on a host fact. Where the
    // premise holds, the platform backend must answer promptly with
    // the failure outcome, never with absence and never by panicking
    // or hanging.
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return;
    }
    let custody = platform_custody();
    match custody.load_key(STORE_ID) {
        CustodyLoad::ServiceFailure(_) => {}
        other => panic!("expected a service failure with no service running, got {other:?}"),
    }
}
