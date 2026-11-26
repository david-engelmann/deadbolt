//! Pins for the custody seam of DK-18 and DK-19, driven through the
//! fixture backend and the passphrase backend.
//!
//! The platform backend is constructed and driven in
//! platform_custody_without_a_service_answers_service_failure on
//! hosts where no keychain service answers, landing in the failure
//! outcome DK-24 names for the default gate, and in
//! platform_custody_round_trips_against_a_live_service_when_armed
//! when DEADBOLT_LIVE_KEYCHAIN_TEST arms the live round trip inside
//! an ephemeral keychain session.

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
use deadbolt::custody::platform_custody;
use deadbolt::custody::{
    derive_key, derive_key_with_params, store_key_from_secret, CustodyLoad, FixtureCustody,
    KeyCustody, PassphraseCustody, StoreKey,
};
use zeroize::Zeroizing;

// The shared test harness home of audit finding DK-A19. Items a
// suite does not use stand allowed dead in its crate.
#[allow(dead_code)]
mod common;

use common::hex;

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
        derive_key(b"SYNTHETIC-TEST-VALUE-passphrase", &PROBE_SALT).unwrap()
    );
}

#[test]
fn passphrase_derivation_matches_the_recorded_probe_vector() {
    let derived = derive_key(PROBE_PASSPHRASE, &PROBE_SALT).unwrap();
    assert_eq!(hex(derived.as_bytes()), DERIVATION_VECTOR_HEX);
}

#[test]
fn passphrase_store_accepts_the_derived_key_and_refuses_any_other() {
    let custody = PassphraseCustody::new(
        Zeroizing::new("SYNTHETIC-TEST-VALUE-passphrase".to_string()),
        PROBE_SALT,
    );
    let derived = derive_key(b"SYNTHETIC-TEST-VALUE-passphrase", &PROBE_SALT).unwrap();
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

#[test]
fn secret_conversion_zeroes_the_source_buffer() {
    let expected = sample_key();
    let mut secret = expected.as_bytes().to_vec();
    let key = store_key_from_secret(&mut secret).expect("a key length buffer converts");
    assert_eq!(key, expected);
    assert!(secret.iter().all(|byte| *byte == 0));
}

#[test]
fn secret_conversion_refuses_a_wrong_length_and_still_zeroes() {
    let mut secret = vec![0xa5u8; 16];
    assert!(store_key_from_secret(&mut secret).is_none());
    assert!(secret.iter().all(|byte| *byte == 0));
}

// Audit finding DK-A1: derivation answers an error, never a panic.
// Before the fix both calls below panicked inside the derivation,
// the first at the parameter construction and the second at the
// same place, so these pins could not pass against the old code.

#[test]
fn derive_key_with_params_refuses_zero_memory() {
    let err = derive_key_with_params(PROBE_PASSPHRASE, &PROBE_SALT, 0, 3).unwrap_err();
    assert!(err.to_string().contains("parameters"), "{err}");
}

#[test]
fn derive_key_with_params_refuses_zero_time() {
    let err = derive_key_with_params(PROBE_PASSPHRASE, &PROBE_SALT, 8_192, 0).unwrap_err();
    assert!(err.to_string().contains("parameters"), "{err}");
}

#[test]
fn derive_key_derives_at_the_pinned_parameters() {
    let derived = derive_key(PROBE_PASSPHRASE, &PROBE_SALT).unwrap();
    let at_pinned = derive_key_with_params(PROBE_PASSPHRASE, &PROBE_SALT, 65_536, 3).unwrap();
    assert_eq!(derived, at_pinned);
    assert_eq!(hex(derived.as_bytes()), DERIVATION_VECTOR_HEX);
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
#[test]
fn platform_custody_round_trips_against_a_live_service_when_armed() {
    if std::env::var_os("DEADBOLT_LIVE_KEYCHAIN_TEST").is_none() {
        return;
    }
    let custody = platform_custody();
    let live_id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let _ = custody.delete_key(live_id);
    assert_eq!(custody.load_key(live_id), CustodyLoad::Absent);
    let key = sample_key();
    custody.store_key(live_id, &key).unwrap();
    match custody.load_key(live_id) {
        CustodyLoad::Key(loaded) => assert_eq!(loaded, key),
        other => panic!("expected the stored key from the live service, got {other:?}"),
    }
    custody.delete_key(live_id).unwrap();
    assert_eq!(custody.load_key(live_id), CustodyLoad::Absent);
}

// Consolidated audit round submodules. Each former standalone tests/audit_*.rs
// file stands verbatim inside its own isolated module namespace so Cargo builds
// four integration test binaries instead of twenty while keeping every closed
// round's harness, assertions, and historical file-path comments intact.

mod audit_r12_dka38 {
    //! Audit Round 12 pins for finding DK-A38: a keychain entry that
    //! stands but holds bytes that are not a store key draws its own
    //! locked refusal, "the store is locked because its keychain entry
    //! does not hold a store key", and not the service failure wording
    //! of DK-22, because the service answered and the entry stands.
    //! Before the repair the custody seam folded the case into its
    //! service failure outcome, whose diagnostic the store layer
    //! discards unread, so the operator was told the keychain service
    //! is not available over a service that had answered.
    //!
    //! The pins drive the unlock through a custody double over the
    //! fixture backend, in the pattern of tests/audit_r2_dka2.rs,
    //! because the platform backend that produces the malformed entry
    //! outcome cannot be driven on a machine with no keychain service,
    //! the limit DK-24 names. What the pins judge is the seam: each
    //! load outcome the double returns draws the refusal DK-22 and
    //! its Round 12 amendment word for it. The pin file names the new
    //! outcome, so it fails to compile against the unrepaired seam.
    //!
    //! Every fixture is synthetic and names itself as one. No test
    //! here touches a real keychain.

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    use deadbolt::custody::{CustodyError, CustodyLoad, FixtureCustody, KeyCustody, StoreKey};
    use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

    const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
    const T0: i64 = 1_700_000_000;

    const LOCKED_NO_SERVICE: &str =
        "the store is locked because the keychain service is not available";
    const LOCKED_NO_ENTRY: &str = "the store is locked because its keychain entry is missing, and the broker holds no other copy and no fallback will be tried";
    const LOCKED_MALFORMED: &str =
        "the store is locked because its keychain entry does not hold a store key";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r12-dka38-{tag}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn read_scope() -> Scope {
        Scope {
            resource: "vault".to_string(),
            action: "read".to_string(),
        }
    }

    struct Supply;

    impl PassphraseSource for Supply {
        fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
            Some(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()))
        }
    }

    /// What the double answers when the store layer loads a key.
    #[derive(Clone, Copy)]
    enum Load {
        Fixture,
        Malformed,
        ServiceDown,
        Absent,
    }

    /// A custody double over the fixture backend whose load answer the
    /// test arms, in the pattern of the double in
    /// tests/audit_r2_dka2.rs. Stores and deletes pass through to the
    /// fixture, so a store enrolls for real and only the load outcome
    /// is staged.
    struct DoubleCustody {
        inner: FixtureCustody,
        load: Mutex<Load>,
    }

    impl DoubleCustody {
        fn new() -> DoubleCustody {
            DoubleCustody {
                inner: FixtureCustody::new(),
                load: Mutex::new(Load::Fixture),
            }
        }

        fn answer(&self, load: Load) {
            *self.load.lock().unwrap() = load;
        }
    }

    impl KeyCustody for DoubleCustody {
        fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
            self.inner.store_key(store_id, key)
        }

        fn load_key(&self, store_id: &str) -> CustodyLoad {
            match *self.load.lock().unwrap() {
                Load::Fixture => self.inner.load_key(store_id),
                Load::Malformed => CustodyLoad::MalformedEntry(
                    "the keychain entry for this store holds 9 bytes and a store key is 32 bytes"
                        .to_string(),
                ),
                Load::ServiceDown => {
                    CustodyLoad::ServiceFailure("SYNTHETIC-TEST-VALUE-service-down".to_string())
                }
                Load::Absent => CustodyLoad::Absent,
            }
        }

        fn delete_key(&self, store_id: &str) -> Result<(), CustodyError> {
            self.inner.delete_key(store_id)
        }
    }

    fn keychain_store(custody: &DoubleCustody, dir: &Path) -> PathBuf {
        let state = dir.join("state.json");
        let supply = Supply;
        let creating = Unlock {
            route: Some(Route::Keychain),
            custody,
            passphrase: &supply,
        };
        deadbolt::enroll(&state, &creating, "cache-key", VALUE, &[read_scope()], T0).unwrap();
        state
    }

    #[test]
    fn a_malformed_keychain_entry_draws_its_own_locked_refusal() {
        let dir = test_dir("malformed");
        let custody = DoubleCustody::new();
        let state = keychain_store(&custody, &dir);
        let before = std::fs::read_to_string(&state).unwrap();
        custody.answer(Load::Malformed);
        let supply = Supply;
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Refusal(_)), "{err}");
        assert_eq!(format!("{err}"), LOCKED_MALFORMED);
        assert_eq!(std::fs::read_to_string(&state).unwrap(), before);
    }

    #[test]
    fn the_neighbouring_outcomes_keep_their_dk22_wordings() {
        let dir = test_dir("neighbours");
        let custody = DoubleCustody::new();
        let state = keychain_store(&custody, &dir);
        let supply = Supply;
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        custody.answer(Load::ServiceDown);
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Refusal(_)), "{err}");
        assert_eq!(format!("{err}"), LOCKED_NO_SERVICE);
        custody.answer(Load::Absent);
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Refusal(_)), "{err}");
        assert_eq!(format!("{err}"), LOCKED_NO_ENTRY);
        custody.answer(Load::Fixture);
        assert_eq!(deadbolt::audit(&state, &open, T0).unwrap().len(), 1);
    }
}
