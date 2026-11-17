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

const LOCKED_NO_SERVICE: &str = "the store is locked because the keychain service is not available";
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
