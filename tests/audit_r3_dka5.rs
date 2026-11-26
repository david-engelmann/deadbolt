//! Audit Round 3 pins for finding DK-A5: the reader range for
//! envelope KDF parameters stands tightened to a memory cost of
//! 262,144 kibibytes and a time cost of 6, against the writer's
//! pinned 65,536 and 3. A header naming the old ceiling values,
//! memory 1,048,576 or time 10, now refuses as envelope
//! corruption in the standing range words, where before it named
//! a derivation of a gibibyte and roughly one hundred seconds
//! that an open paid before any authentication, under the
//! store's exclusive lock. A header naming the new ceiling
//! values passes the range check and reaches authentication,
//! where it draws the locked refusal of DK-22 like any edited
//! parameter, because the header stands as the cipher's
//! associated data and the derived key no longer matches.
//!
//! Every fixture is synthetic and names itself as one. Custody
//! runs against the fixture backend, and no test here touches a
//! real keychain.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::FixtureCustody;
use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const T0: i64 = 1_700_000_000;

const LOCKED_BAD_KEY: &str = "the store is locked because the key did not open it";
const KDF_RANGE: &str = "the envelope carries KDF parameters outside the range the reader accepts";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r3-dka5-test-{}-{tag}-{n}",
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

struct Ctx {
    custody: FixtureCustody,
    supply: Supply,
}

impl Ctx {
    fn new() -> Ctx {
        Ctx {
            custody: FixtureCustody::new(),
            supply: Supply,
        }
    }

    fn open(&self) -> Unlock<'_> {
        Unlock {
            route: None,
            custody: &self.custody,
            passphrase: &self.supply,
        }
    }

    fn creating(&self, route: Route) -> Unlock<'_> {
        Unlock {
            route: Some(route),
            custody: &self.custody,
            passphrase: &self.supply,
        }
    }
}

fn state_text(state: &PathBuf) -> String {
    std::fs::read_to_string(state).unwrap()
}

fn envelope_json(state: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&state_text(state)).unwrap()
}

fn write_store_file(dir: &Path, text: &str) -> PathBuf {
    let state = dir.join("state.json");
    std::fs::write(&state, text).unwrap();
    // Portability adaptation applies POSIX 0600 mode bits on Unix only.
    #[cfg(unix)]
    {
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    state
}

fn passphrase_store(ctx: &Ctx, dir: &Path) -> PathBuf {
    let state = dir.join("state.json");
    deadbolt::enroll(
        &state,
        &ctx.creating(Route::Passphrase),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap();
    state
}

/// A copy of the standing passphrase store with its header KDF
/// parameters edited to the stated memory and time costs.
fn edited_store(ctx: &Ctx, tag: &str, memory: u32, time: u32) -> (PathBuf, String) {
    let dir = test_dir(tag);
    let state = passphrase_store(ctx, &dir);
    let mut edited = envelope_json(&state);
    edited["header"]["kdf"]["memory"] = serde_json::json!(memory);
    edited["header"]["kdf"]["time"] = serde_json::json!(time);
    let text = edited.to_string();
    let copy = write_store_file(&test_dir(&format!("{tag}-copy")), &text);
    (copy, text)
}

#[test]
fn a_header_at_the_old_memory_ceiling_refuses_as_corruption() {
    let ctx = Ctx::new();
    let (state, text) = edited_store(&ctx, "old-memory-ceiling", 1_048_576, 3);
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert_eq!(format!("{err}"), KDF_RANGE);
    assert_eq!(state_text(&state), text, "the file must never be reset");
}

#[test]
fn a_header_at_the_old_time_ceiling_refuses_as_corruption() {
    let ctx = Ctx::new();
    let (state, text) = edited_store(&ctx, "old-time-ceiling", 65_536, 10);
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert_eq!(format!("{err}"), KDF_RANGE);
    assert_eq!(state_text(&state), text, "the file must never be reset");
}

#[test]
fn a_header_at_the_new_memory_ceiling_reaches_authentication() {
    let ctx = Ctx::new();
    // The memory ceiling value itself stands inside the tightened
    // range, paired with a time cost of 1 to keep the derivation
    // the edited key costs this test short. The refusal is the
    // authentication wording, not the range wording.
    let (state, text) = edited_store(&ctx, "new-memory-ceiling", 262_144, 1);
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&state), text, "the file must never be reset");
}

#[test]
fn a_header_at_the_new_time_ceiling_reaches_authentication() {
    let ctx = Ctx::new();
    // The time ceiling value itself stands inside the tightened
    // range, paired with the floor memory cost to keep the
    // derivation the edited key costs this test short.
    let (state, text) = edited_store(&ctx, "new-time-ceiling", 8_192, 6);
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&state), text, "the file must never be reset");
}
