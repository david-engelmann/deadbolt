//! Audit Round 3 pin for finding DK-A8: the Debug rendering of a
//! grant receipt never prints the bearer token it carries, in the
//! same discipline the suite pins for the store key in
//! tests/custody.rs. The rendering still shows the receipt's
//! shape, its grant id and its expiry instant, with the token
//! standing as redacted.
//!
//! Every fixture is synthetic and names itself as one. Custody
//! runs against the fixture backend, and no test here touches a
//! real keychain.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::FixtureCustody;
use deadbolt::{PassphraseSource, Route, Scope, Unlock, Zeroizing};

const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const T0: i64 = 1_700_000_000;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r3-dka8-test-{}-{tag}-{n}",
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

/// A passphrase supply answering one fixed answer.
struct Supply;

impl PassphraseSource for Supply {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()))
    }
}

#[test]
fn grant_receipt_debug_never_prints_the_token() {
    let dir = test_dir("receipt-debug");
    let custody = FixtureCustody::new();
    let supply = Supply;
    let state = dir.join("state.json");
    let creating = Unlock {
        route: Some(Route::Keychain),
        custody: &custody,
        passphrase: &supply,
    };
    deadbolt::enroll(&state, &creating, "cache-key", VALUE, &[read_scope()], T0).unwrap();
    let opening = Unlock {
        route: None,
        custody: &custody,
        passphrase: &supply,
    };
    let receipt =
        deadbolt::grant(&state, &opening, "cache-key", &read_scope(), 600, None, T0).unwrap();
    let rendered = format!("{receipt:?}");
    assert!(
        !rendered.contains(&receipt.token),
        "the token stands in the Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains(&receipt.grant_id),
        "the grant id stands in the Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains(&receipt.expires_at.to_string()),
        "the expiry instant stands in the Debug rendering: {rendered}"
    );
    assert!(
        rendered.contains("redacted"),
        "the token stands as redacted in the Debug rendering: {rendered}"
    );
}
