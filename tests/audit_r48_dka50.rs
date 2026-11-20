//! Audit Round 48 finding DK-A50: redeem's incarnation fallback
//! stands pinned.
//!
//! Redeem judges a grant against the instant it is presented at,
//! while the reader judges a grant's liveness against the document
//! floor, the latest audit instant, and checks name and incarnation
//! only for grants live at the floor. A grant that stands dead at
//! the floor by expiry, unended, passes the reader whole even when
//! the credential it names has since stepped to a new incarnation
//! under a replace past its expiry, or been removed by a retire
//! past its expiry. A redeem of that grant's token at an instant
//! inside its own window passes the refusal order of DK-7 whole,
//! unended, unexpired at the presented instant, and at its granted
//! scope, and reaches the fallback, which looks the credential up
//! by name and incarnation together and answers Corrupt, a live
//! grant names a credential that does not stand, recording nothing
//! and publishing nothing, as DK-9 requires of an act refused by
//! corruption.
//!
//! The pins below stage that split with honest acts alone, and
//! each one fails on a plausible wrong form of what it pins. A
//! lookup by name alone answers the replacement's value to the old
//! token in the stepped arm. A fallback answering a DK-7 refusal
//! or the Refusal class in place of Corrupt fails the class and
//! wording assertions. A reader that refuses the document at open
//! answers in the reader's own words, a live grant in the state
//! file names a credential that does not stand, and the exact
//! wording assertion discriminates the two seats.
//!
//! Every fixture is synthetic and names itself as one. Credential
//! shaped strings carry the SYNTHETIC-TEST-VALUE marker so no
//! fixture can be mistaken for a real key.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::FixtureCustody;
use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
const VALUE_B: &str = "SYNTHETIC-TEST-VALUE-beta-0002";
const STORE_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-store-passphrase";
const T0: i64 = 1_700_000_000;

const FALLBACK_WORDING: &str = "a live grant names a credential that does not stand";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r48-{}-{tag}-{n}",
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

/// A passphrase supply that always answers the store passphrase.
struct Supply(Option<&'static [u8]>);

impl PassphraseSource for Supply {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.map(|bytes| Zeroizing::new(bytes.to_vec()))
    }
}

/// The per test custody context, one fixture backend standing
/// behind every call a test makes, as in tests/audit_r41_dka49.rs.
struct Ctx {
    custody: FixtureCustody,
    supply: Supply,
}

impl Ctx {
    fn new() -> Ctx {
        Ctx {
            custody: FixtureCustody::new(),
            supply: Supply(Some(STORE_PASSPHRASE.as_bytes())),
        }
    }

    fn open(&self) -> Unlock<'_> {
        Unlock {
            route: None,
            custody: &self.custody,
            passphrase: &self.supply,
        }
    }

    fn creating(&self) -> Unlock<'_> {
        Unlock {
            route: Some(Route::Keychain),
            custody: &self.custody,
            passphrase: &self.supply,
        }
    }
}

fn enroll_a(ctx: &Ctx, state: &PathBuf) {
    deadbolt::enroll(
        state,
        &ctx.creating(),
        "cache-key",
        VALUE_A,
        &[read_scope()],
        T0,
    )
    .unwrap();
}

fn audit_kinds(ctx: &Ctx, state: &PathBuf) -> Vec<String> {
    deadbolt::audit(state, &ctx.open(), T0)
        .unwrap()
        .iter()
        .map(|entry| entry.kind.clone())
        .collect()
}

/// The control. The same staging redeems the standing value inside
/// the window, and a token granted after the replace redeems the
/// new value at the stepped incarnation, so the Corrupt answers in
/// the arms below are the fallback and nothing else in the staging.
#[test]
fn redeem_answers_inside_the_window_and_the_new_value_after_a_replace() {
    let dir = test_dir("control");
    let ctx = Ctx::new();
    let state = dir.join("state.json");
    enroll_a(&ctx, &state);
    let receipt = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        100,
        None,
        T0,
    )
    .unwrap();
    assert_eq!(receipt.expires_at, T0 + 100);
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 50).unwrap(),
        VALUE_A
    );
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &ctx.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 120,
    )
    .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(stood_up, 2);
    let fresh = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 130,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &fresh.token, &read_scope(), T0 + 131).unwrap(),
        VALUE_B
    );
}

/// The stepped arm. The replace past the grant's expiry ends
/// nothing, because the grant already stands dead at that instant,
/// and steps the credential to incarnation 2. The old token,
/// redeemed at an instant inside its own window, answers Corrupt
/// in the fallback's exact words, and the failed redeem records
/// nothing and publishes nothing.
#[test]
fn a_stepped_incarnation_answers_corrupt_to_a_token_minted_under_the_earlier_one() {
    let dir = test_dir("stepped");
    let ctx = Ctx::new();
    let state = dir.join("state.json");
    enroll_a(&ctx, &state);
    let receipt = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        100,
        None,
        T0,
    )
    .unwrap();
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &ctx.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 120,
    )
    .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(stood_up, 2);
    let before = std::fs::read(&state).unwrap();
    let err =
        deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 50).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert_eq!(err.to_string(), FALLBACK_WORDING);
    assert_eq!(std::fs::read(&state).unwrap(), before);
    assert_eq!(audit_kinds(&ctx, &state), ["enroll", "grant", "replace"]);
}

/// The removed arm. The retire past the grant's expiry ends
/// nothing and removes the credential the grant names. The same
/// travelling redeem answers the same Corrupt in the same words,
/// with the file unchanged and the trail standing at the three
/// acts that staged it.
#[test]
fn a_removed_credential_answers_corrupt_to_a_token_minted_against_it() {
    let dir = test_dir("removed");
    let ctx = Ctx::new();
    let state = dir.join("state.json");
    enroll_a(&ctx, &state);
    let receipt = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        100,
        None,
        T0,
    )
    .unwrap();
    let ended = deadbolt::retire(&state, &ctx.open(), "cache-key", T0 + 120).unwrap();
    assert_eq!(ended, 0);
    let before = std::fs::read(&state).unwrap();
    let err =
        deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 50).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert_eq!(err.to_string(), FALLBACK_WORDING);
    assert_eq!(std::fs::read(&state).unwrap(), before);
    assert_eq!(audit_kinds(&ctx, &state), ["enroll", "grant", "retire"]);
}
