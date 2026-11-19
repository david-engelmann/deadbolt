//! Audit Round 41 pins for finding DK-A49: a refusal recorded
//! against a standing state whose recording publish fails answers
//! the filesystem error in the refusal's place, never the refusal
//! itself. record_refusal appends the refusal entry to the loaded
//! document and publishes with the error propagated, which is
//! DK-9's discipline that the recording and the publication cannot
//! drift apart: a caller told of a refusal is told of one that
//! stands recorded, and where nothing could be published the
//! caller meets the failure that prevented the recording.
//!
//! These are preservation pins in the form DK-A44 and DK-A48 set.
//! Each passes against the standing code by design and fails on
//! the plausible wrong forms of the branch: record_refusal
//! swallowing its publish error, by a let underscore or an ok
//! conversion at that one call, which would let every act answer
//! its refusal as though recorded while nothing was published,
//! and an act returning its refusal ahead of the recording, which
//! would lie in the same direction. The control pin below stands
//! unarmed beside the two armed pins, so the contrast itself
//! proves the sabotage is what the armed pins judge.
//!
//! The failure is forced by a custody double over the fixture
//! backend, in the pattern of tests/audit_r2_dka2.rs, whose load
//! replaces the state file with a non-empty directory after the
//! key is loaded, so the open completes on the text already read
//! and the recording publish's rename cannot land. Every fixture
//! is synthetic and names itself as one. No test here touches a
//! real keychain.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use deadbolt::custody::{CustodyError, CustodyLoad, FixtureCustody, KeyCustody, StoreKey};
use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const T0: i64 = 1_700_000_000;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r41-dka49-test-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn read_scope() -> Scope {
    Scope {
        resource: "bucket".to_string(),
        action: "read".to_string(),
    }
}

/// A passphrase supply answering one fixed answer. The stores
/// below stand on the keychain route, so the supply is never
/// consulted; it stands because an unlock context names one.
struct Supply;

impl PassphraseSource for Supply {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()))
    }
}

/// A custody double over the fixture backend. Stores and deletes
/// pass through to the fixture, so a store enrolls for real. Once
/// armed, a load answers the fixture's key and then replaces the
/// state file with a non-empty directory, so the publish that
/// follows the open, the recording publish of a refusal among
/// them, meets a rename target it cannot land on.
struct SabotageOnLoadCustody {
    inner: FixtureCustody,
    dir: PathBuf,
    armed: Mutex<bool>,
}

impl SabotageOnLoadCustody {
    fn new(dir: PathBuf) -> Self {
        SabotageOnLoadCustody {
            inner: FixtureCustody::new(),
            dir,
            armed: Mutex::new(false),
        }
    }

    fn arm(&self) {
        *self.armed.lock().unwrap() = true;
    }
}

impl KeyCustody for SabotageOnLoadCustody {
    fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
        self.inner.store_key(store_id, key)
    }

    fn load_key(&self, store_id: &str) -> CustodyLoad {
        let loaded = self.inner.load_key(store_id);
        if *self.armed.lock().unwrap() {
            let state = self.dir.join("state.json");
            let _ = std::fs::remove_file(&state);
            let _ = std::fs::create_dir_all(state.join("blocker"));
        }
        loaded
    }

    fn delete_key(&self, store_id: &str) -> Result<(), CustodyError> {
        self.inner.delete_key(store_id)
    }
}

fn keychain_store(custody: &SabotageOnLoadCustody, dir: &Path) -> PathBuf {
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

fn open(custody: &SabotageOnLoadCustody) -> Unlock<'_> {
    Unlock {
        route: None,
        custody,
        passphrase: &Supply,
    }
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[test]
fn an_unarmed_refusal_answers_in_its_words_and_stands_recorded() {
    let dir = test_dir("control");
    let custody = SabotageOnLoadCustody::new(dir.clone());
    let state = keychain_store(&custody, &dir);
    let err = deadbolt::grant(
        &state,
        &open(&custody),
        "ghost",
        &read_scope(),
        60,
        None,
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        format!("{err}"),
        "grant refused, no credential named ghost stands"
    );
    let entries = deadbolt::audit(&state, &open(&custody), T0).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].kind, "grant");
    assert_eq!(entries[1].outcome, "refused, unknown credential");
}

#[test]
fn a_grant_refusal_whose_recording_publish_fails_answers_the_filesystem_error() {
    let dir = test_dir("grant-armed");
    let custody = SabotageOnLoadCustody::new(dir.clone());
    let state = keychain_store(&custody, &dir);
    custody.arm();
    let err = deadbolt::grant(
        &state,
        &open(&custody),
        "ghost",
        &read_scope(),
        60,
        None,
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err}");
    assert!(!matches!(err, Error::Refusal(_)), "{err}");
    // The failed publish left no sealed temporary copy standing,
    // the cleanup DK-A4 landed holding on this path as on its own.
    let entries = dir_entries(&dir);
    assert!(
        entries.iter().all(|name| !name.contains(".tmp-")),
        "a sealed temp copy stands in {entries:?}"
    );
    assert_eq!(entries, ["state.json", "state.json.lock"]);
}

#[test]
fn a_redeem_refusal_whose_recording_publish_fails_answers_the_filesystem_error() {
    let dir = test_dir("redeem-armed");
    let custody = SabotageOnLoadCustody::new(dir.clone());
    let state = keychain_store(&custody, &dir);
    custody.arm();
    let err =
        deadbolt::redeem(&state, &open(&custody), &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Io(_)), "{err}");
    assert!(!matches!(err, Error::Redeem(_)), "{err}");
    let entries = dir_entries(&dir);
    assert!(
        entries.iter().all(|name| !name.contains(".tmp-")),
        "a sealed temp copy stands in {entries:?}"
    );
    assert_eq!(entries, ["state.json", "state.json.lock"]);
}
