//! Protocol tests for the broker core, pinning DK-1 to DK-14 and
//! DK-25 to DK-27 over stores the envelope of DK-15 to DK-24 seals.
//! Every fixture is synthetic and names itself as one. Credential
//! shaped strings carry the SYNTHETIC-TEST-VALUE marker so no fixture
//! can be mistaken for a real key.
//!
//! The unlock rework of Round 2 is the named mechanical consequence
//! that runs through this file. Every act takes an unlock context,
//! one fixture custody backend stands behind every call a test
//! makes, and document assertions read the decrypted document
//! through the helpers below rather than the raw file, because the
//! file now holds the envelope and the document stands inside it.
//! The envelope's own pins stand in tests/envelope.rs.

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

// The shared test harness home of audit finding DK-A19. Items a
// suite does not use stand allowed dead in its crate.
#[allow(dead_code)]
mod common;

use common::{decrypt_document, hex_bytes, read_scope, set_mode, state_text};
use deadbolt::custody::{CustodyLoad, FixtureCustody, KeyCustody};
use deadbolt::{Error, PassphraseSource, RedeemRefusal, Route, Scope, Unlock, Zeroizing};

const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
const VALUE_B: &str = "SYNTHETIC-TEST-VALUE-beta-0002";
const VALUE_C: &str = "SYNTHETIC-TEST-VALUE-gamma-0003";
const VALUE_D: &str = "SYNTHETIC-TEST-VALUE-delta-0004";
const STORE_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-store-passphrase";
const CLI_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-cli-passphrase";
const T0: i64 = 1_700_000_000;

fn test_dir(tag: &str) -> PathBuf {
    common::test_dir("deadbolt-test", tag)
}

fn scope(resource: &str, action: &str) -> Scope {
    Scope {
        resource: resource.to_string(),
        action: action.to_string(),
    }
}

/// A passphrase supply that always answers the store passphrase.
struct FixedPassphrase;

impl PassphraseSource for FixedPassphrase {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(STORE_PASSPHRASE.as_bytes().to_vec()))
    }
}

/// The per test custody context.
///
/// One fixture backend stands behind every call a test makes,
/// because a store created through the fixture answers later loads
/// from the same backend, exactly as one keychain serves every
/// process on a machine.
struct Harness {
    custody: FixtureCustody,
    passphrase: FixedPassphrase,
}

impl Harness {
    fn new() -> Harness {
        Harness {
            custody: FixtureCustody::new(),
            passphrase: FixedPassphrase,
        }
    }

    /// The unlock context for an act against a standing store.
    fn open(&self) -> Unlock<'_> {
        Unlock {
            route: None,
            custody: &self.custody,
            passphrase: &self.passphrase,
        }
    }

    /// The unlock context for the act that creates the store.
    fn creating(&self) -> Unlock<'_> {
        Unlock {
            route: Some(Route::Keychain),
            custody: &self.custody,
            passphrase: &self.passphrase,
        }
    }
}

fn enroll_a(h: &Harness, state: &Path) {
    deadbolt::enroll(
        state,
        &h.creating(),
        "cache-key",
        VALUE_A,
        &[read_scope(), scope("bucket", "write")],
        T0,
    )
    .unwrap();
}

/// The decrypted document of a store the harness's fixture serves.
fn document_text(h: &Harness, state: &PathBuf) -> String {
    let raw = state_text(state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let store_id = envelope["header"]["store"].as_str().unwrap();
    let key = match h.custody.load_key(store_id) {
        CustodyLoad::Key(key) => key,
        _ => panic!("the fixture holds no key for this store"),
    };
    decrypt_document(&raw, &key)
}

fn document_json(h: &Harness, state: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&document_text(h, state)).unwrap()
}

/// The decrypted document of a store the command line made on the
/// passphrase route, derived from the CLI passphrase and the salt
/// the header records.
fn cli_document_json(state: &PathBuf) -> serde_json::Value {
    let raw = state_text(state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let salt = hex_bytes(envelope["header"]["kdf"]["salt"].as_str().unwrap());
    let salt: [u8; 16] = salt.try_into().unwrap();
    let key = deadbolt::custody::derive_key(CLI_PASSPHRASE.as_bytes(), &salt).unwrap();
    serde_json::from_str(&decrypt_document(&raw, &key)).unwrap()
}

#[cfg(unix)]
fn mode_of(state: &PathBuf) -> u32 {
    std::fs::metadata(state).unwrap().permissions().mode() & 0o777
}

#[test]
fn enroll_grant_redeem_round_trip_and_expiry_boundary() {
    let dir = test_dir("round-trip");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(receipt.expires_at, T0 + 60);
    let value =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 59).unwrap();
    assert_eq!(value, VALUE_A);
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 60).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn enroll_duplicate_name_is_refused_and_recorded() {
    let dir = test_dir("dup-enroll");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err = deadbolt::enroll(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].outcome, "refused, name already stands");
    let value = deadbolt::redeem(
        &state,
        &h.open(),
        &deadbolt::grant(
            &state,
            &h.open(),
            "cache-key",
            &read_scope(),
            60,
            None,
            T0 + 2,
        )
        .unwrap()
        .token,
        &read_scope(),
        T0 + 3,
    )
    .unwrap();
    assert_eq!(value, VALUE_A);
}

#[test]
fn enroll_shape_errors_are_caller_errors() {
    let dir = test_dir("enroll-shapes");
    let h = Harness::new();
    let state = dir.join("state.json");
    for (name, value, scopes) in [
        ("cache-key", VALUE_A, Vec::new()),
        ("cache-key", VALUE_A, vec![read_scope(), read_scope()]),
        ("cache-key", "", vec![read_scope()]),
        ("cache-key", "two\nlines", vec![read_scope()]),
        ("bad name", VALUE_A, vec![read_scope()]),
        ("-leading", VALUE_A, vec![read_scope()]),
        ("", VALUE_A, vec![read_scope()]),
    ] {
        let err = deadbolt::enroll(&state, &h.creating(), name, value, &scopes, T0).unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{name} {err}");
    }
    let long_name = "a".repeat(65);
    let err = deadbolt::enroll(
        &state,
        &h.creating(),
        &long_name,
        VALUE_A,
        &[read_scope()],
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert!(!state.exists());
}

#[test]
fn grant_refusals_for_unknown_credential_and_unenrolled_scopes() {
    let dir = test_dir("grant-refusals");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err =
        deadbolt::grant(&state, &h.open(), "missing", &read_scope(), 60, None, T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    for wanted in [
        scope("bucket", "read-all"),
        scope("bucket", "delete"),
        scope("other", "read"),
    ] {
        let err =
            deadbolt::grant(&state, &h.open(), "cache-key", &wanted, 60, None, T0).unwrap_err();
        assert!(matches!(err, Error::Refusal(_)), "{wanted:?} {err}");
    }
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let outcomes: Vec<&str> = entries.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        [
            "enrolled",
            "refused, unknown credential",
            "refused, scope not enrolled",
            "refused, scope not enrolled",
            "refused, scope not enrolled",
        ]
    );
}

#[test]
fn grant_ttl_bounds() {
    let dir = test_dir("ttl-bounds");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 0, None, T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let err = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        86_401,
        None,
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        86_400,
        None,
        T0,
    )
    .unwrap();
    assert_eq!(receipt.expires_at, T0 + 86_400);
}

#[test]
fn grant_expiry_past_the_largest_instant_is_a_caller_error() {
    let dir = test_dir("instant-bounds");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        None,
        deadbolt::INSTANT_MAX,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let err = deadbolt::redeem(&state, &h.open(), "whatever", &read_scope(), -1).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
}

#[test]
fn token_shape_and_storage() {
    let dir = test_dir("token-shape");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let one = deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let two = deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(one.token.len(), 64);
    assert!(one
        .token
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_ne!(one.token, two.token);
    assert_ne!(one.grant_id, two.grant_id);
    let text = state_text(&state);
    assert!(
        !text.contains(&one.token),
        "the token itself must not be stored"
    );
    let json = document_json(&h, &state);
    let hash = json["grants"][0]["token_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    // The hash stands in the document and nowhere else. On the
    // plaintext build this pin asserted the raw file carried the
    // hash, because the file was the document. The envelope of
    // DK-15 is the named mechanical consequence that inverts the
    // raw direction here, and the raw absence is pinned in full by
    // the containment pins of tests/envelope.rs.
    assert!(!text.contains(hash));
}

#[test]
fn redeem_refusal_reasons_are_distinct() {
    let dir = test_dir("redeem-reasons");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err = deadbolt::redeem(&state, &h.open(), &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::UnknownToken)),
        "{err}"
    );
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let err = deadbolt::redeem(
        &state,
        &h.open(),
        &receipt.token,
        &scope("bucket", "write"),
        T0 + 1,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::ScopeMismatch)),
        "{err}"
    );
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 60).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
    deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0 + 61).unwrap();
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 30).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
}

#[test]
fn redeem_of_an_ended_grant_after_its_expiry_answers_revoked() {
    // DK-7 names the revoked reason at every instant, including
    // instants after the grant expiry, and names expired only for
    // a grant that stands unended. This pin stages the after
    // expiry half of that sentence, which the rest of the suite
    // leaves unstaged: every other ended grant here is redeemed
    // inside its window, and the expired pins stage grants that
    // were never ended. A redeem path that checked expiry before
    // ended-ness would answer Expired for both halves below.
    let dir = test_dir("revoked-after-expiry");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0 + 10).unwrap();
    for at in [T0 + 60, T0 + 600] {
        let err =
            deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), at).unwrap_err();
        assert!(
            matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
            "{err}"
        );
    }
    let second =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    deadbolt::retire(&state, &h.open(), "cache-key", T0 + 20).unwrap();
    let err =
        deadbolt::redeem(&state, &h.open(), &second.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.kind, "redeem");
    assert_eq!(last.outcome, "refused, revoked");
}

#[test]
fn revoke_is_permanent_and_double_revoke_is_refused() {
    let dir = test_dir("revoke");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0 + 100).unwrap();
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 50).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
    let err = deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0 + 101).unwrap_err();
    assert!(
        format!("{err}").contains("already ended by revoked"),
        "{err}"
    );
    let err = deadbolt::revoke(&state, &h.open(), "no-such-grant", T0 + 102).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
}

#[test]
fn cutoff_ends_only_the_named_run() {
    let dir = test_dir("cutoff");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let run_one = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    let run_one_b = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &scope("bucket", "write"),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    let run_two = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-2"),
        T0,
    )
    .unwrap();
    let runless =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::cutoff(&state, &h.open(), "run-1", T0 + 10).unwrap();
    assert_eq!(ended, 2);
    for receipt in [&run_one, &run_one_b] {
        let wanted = if receipt.grant_id == run_one.grant_id {
            read_scope()
        } else {
            scope("bucket", "write")
        };
        let err =
            deadbolt::redeem(&state, &h.open(), &receipt.token, &wanted, T0 + 20).unwrap_err();
        assert!(
            matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
            "{err}"
        );
    }
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &run_two.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &runless.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    let ended = deadbolt::cutoff(&state, &h.open(), "run-1", T0 + 30).unwrap();
    assert_eq!(ended, 0);
    let err = deadbolt::cutoff(&state, &h.open(), "run-9", T0 + 40).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
}

#[test]
fn retire_ends_grants_inside_their_window() {
    let dir = test_dir("retire");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::retire(&state, &h.open(), "cache-key", T0 + 10).unwrap();
    assert_eq!(ended, 1);
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 20).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
    let err = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        None,
        T0 + 30,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    let err = deadbolt::retire(&state, &h.open(), "cache-key", T0 + 40).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    deadbolt::enroll(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 50,
    )
    .unwrap();
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        None,
        T0 + 51,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 52).unwrap(),
        VALUE_B
    );
}

#[test]
fn audit_records_every_act_in_order() {
    let dir = test_dir("audit-order");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 1).unwrap();
    let _ = deadbolt::redeem(
        &state,
        &h.open(),
        &receipt.token,
        &scope("bucket", "write"),
        T0 + 2,
    );
    deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0 + 3).unwrap();
    deadbolt::cutoff(&state, &h.open(), "run-1", T0 + 4).unwrap();
    deadbolt::retire(&state, &h.open(), "cache-key", T0 + 5).unwrap();
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["enroll", "grant", "redeem", "redeem", "revoke", "cutoff", "retire"]
    );
    let outcomes: Vec<&str> = entries.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        [
            "enrolled",
            "granted",
            "redeemed",
            "refused, scope mismatch",
            "revoked",
            "cut off, 0 ended",
            "retired",
        ]
    );
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
}

#[test]
fn audit_never_carries_value_token_or_hash() {
    let dir = test_dir("audit-secrets");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 1).unwrap();
    let hash = document_json(&h, &state)["grants"][0]["token_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let printed = entries
        .iter()
        .map(|entry| serde_json::to_string(entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!printed.contains(VALUE_A));
    assert!(!printed.contains(&receipt.token));
    assert!(!printed.contains(&hash));
}

#[test]
fn refusals_against_a_missing_state_create_no_file() {
    let dir = test_dir("missing-state");
    let h = Harness::new();
    let state = dir.join("state.json");
    let err = deadbolt::redeem(&state, &h.open(), &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::UnknownToken)),
        "{err}"
    );
    assert!(deadbolt::grant(&state, &h.open(), "ghost", &read_scope(), 60, None, T0).is_err());
    assert!(deadbolt::retire(&state, &h.open(), "ghost", T0).is_err());
    assert!(deadbolt::revoke(&state, &h.open(), "ghost-grant", T0).is_err());
    assert!(deadbolt::cutoff(&state, &h.open(), "run-1", T0).is_err());
    assert!(!state.exists());
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert!(entries.is_empty());
    assert!(!state.exists());
}

// Portability adaptation gates POSIX 0600 mode checks to Unix per the
// portability amendment in CONTRACT.md.
#[cfg(unix)]
#[test]
fn permission_gate_refuses_every_operation_and_recovers() {
    let dir = test_dir("permission-gate");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let before = state_text(&state);
    set_mode(&state, 0o644);
    let attempts: Vec<Result<(), Error>> = vec![
        deadbolt::enroll(&state, &h.open(), "other", VALUE_B, &[read_scope()], T0),
        deadbolt::retire(&state, &h.open(), "cache-key", T0).map(|_| ()),
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).map(|_| ()),
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0).map(|_| ()),
        deadbolt::revoke(&state, &h.open(), &receipt.grant_id, T0),
        deadbolt::cutoff(&state, &h.open(), "run-1", T0).map(|_| ()),
        deadbolt::audit(&state, &h.open(), T0).map(|_| ()),
    ];
    for attempt in attempts {
        let err = attempt.unwrap_err();
        assert!(matches!(err, Error::Permission(_)), "{err}");
    }
    assert_eq!(state_text(&state), before);
    set_mode(&state, 0o600);
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 1).unwrap(),
        VALUE_A
    );
}

// Portability adaptation gates POSIX 0600 mode creation pins to Unix.
#[cfg(unix)]
#[test]
fn state_file_is_created_owner_only_and_stays_so() {
    let dir = test_dir("mode-creation");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    assert_eq!(mode_of(&state), 0o600);
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(mode_of(&state), 0o600);
}

// Portability adaptation gates unlink-while-open inode race pin to Unix.
#[cfg(unix)]
#[test]
fn lock_acquisition_recovers_when_an_unlinked_lock_is_held() {
    use fs2::FileExt;
    let dir = test_dir("lock-inode-race");
    let state = dir.join("state.json");
    let lock_path = dir.join("state.json.lock");
    let old_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    old_lock.lock_exclusive().unwrap();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let state_clone = state.clone();
    let handle = std::thread::spawn(move || {
        let h = Harness::new();
        ready_tx.send(()).unwrap();
        enroll_a(&h, &state_clone);
        done_tx.send(()).unwrap();
    });
    ready_rx.recv().unwrap();
    std::thread::sleep(std::time::Duration::from_millis(30));
    std::fs::remove_file(&lock_path).unwrap();
    let replacement_lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&lock_path)
        .unwrap();
    replacement_lock.lock_exclusive().unwrap();
    drop(old_lock);
    assert!(
        done_rx
            .recv_timeout(std::time::Duration::from_millis(80))
            .is_err(),
        "enroll must not proceed under the unlinked lock while replacement_lock stands held"
    );
    assert!(!state.exists());
    drop(replacement_lock);
    done_rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .unwrap();
    handle.join().unwrap();
    assert!(lock_path.is_file());
    assert!(state.is_file());
}

fn corrupt_variants() -> Vec<(String, String)> {
    let dir = test_dir("corrupt-base");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    // The variants are built from the document the envelope holds
    // and written back as plaintext files, so each variant keeps its
    // DK-2 intent through the plaintext reading path. A corrupt
    // envelope is a different class and is pinned in
    // tests/envelope.rs.
    let good = document_text(&h, &state);
    let mut variants: Vec<(String, String)> = Vec::new();
    variants.push((
        "duplicated key at the top level".to_string(),
        good.replacen(
            "\"format\"",
            "\"format\": \"deadbolt-state/1\", \"format\"",
            1,
        ),
    ));
    variants.push((
        "duplicated key inside a credential".to_string(),
        good.replacen(
            "\"name\": \"cache-key\"",
            "\"name\": \"cache-key\", \"name\": \"cache-key\"",
            1,
        ),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["surprise"] = serde_json::json!(true);
    variants.push((
        "unknown field at the top level".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["surprise"] = serde_json::json!(true);
    variants.push(("unknown field inside a grant".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"] = serde_json::json!({"name": "cache-key"});
    variants.push(("credentials of the wrong type".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["format"] = serde_json::json!("deadbolt-state/2");
    variants.push((
        "a format this broker does not read".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    let twin = doc["credentials"][0].clone();
    doc["credentials"].as_array_mut().unwrap().push(twin);
    variants.push((
        "a credential name standing twice".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    let twin = doc["grants"][0].clone();
    doc["grants"].as_array_mut().unwrap().push(twin);
    variants.push(("a grant id standing twice".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["audit"][1]["seq"] = serde_json::json!(7);
    variants.push(("a gap in the audit sequence".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"].as_array_mut().unwrap().clear();
    variants.push((
        "a live grant naming no standing credential".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["expires_at"] = doc["grants"][0]["granted_at"].clone();
    variants.push((
        "a grant expiring at its own grant instant".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["ended_at"] = serde_json::json!(T0 + 1);
    variants.push((
        "an ending in only one of its two fields".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"][0]["enrolled_at"] = serde_json::json!(253_402_300_800i64);
    variants.push((
        "a stored instant outside its range".to_string(),
        doc.to_string(),
    ));
    variants.push((
        "a stored number with thousands of digits".to_string(),
        good.replacen(
            &format!("\"enrolled_at\": {T0}"),
            &format!("\"enrolled_at\": {}", "9".repeat(5000)),
            1,
        ),
    ));
    variants
}

#[test]
fn strict_reading_refuses_every_corrupt_variant() {
    let h = Harness::new();
    for (label, text) in corrupt_variants() {
        let dir = test_dir("corrupt");
        let state = dir.join("state.json");
        std::fs::write(&state, &text).unwrap();
        set_mode(&state, 0o600);
        let err = deadbolt::audit(&state, &h.open(), T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        let err = deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0)
            .unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(
            state_text(&state),
            text,
            "{label}: the file must never be reset"
        );
    }
}

#[test]
fn parallel_grants_under_the_lock_keep_the_document_whole() {
    let dir = test_dir("parallel");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let mut tokens = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..8 {
            handles.push(scope.spawn(|| {
                let mut tokens = Vec::new();
                for _ in 0..10 {
                    let receipt = deadbolt::grant(
                        &state,
                        &h.open(),
                        "cache-key",
                        &read_scope(),
                        600,
                        None,
                        T0,
                    )
                    .unwrap();
                    tokens.push(receipt.token);
                }
                tokens
            }));
        }
        let mut tokens = Vec::new();
        for handle in handles {
            tokens.extend(handle.join().unwrap());
        }
        tokens
    });
    assert_eq!(tokens.len(), 80);
    tokens.sort();
    tokens.dedup();
    assert_eq!(tokens.len(), 80);
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 81);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    for token in &tokens {
        assert_eq!(
            deadbolt::redeem(&state, &h.open(), token, &read_scope(), T0 + 1).unwrap(),
            VALUE_A
        );
    }
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .env_remove("DEADBOLT_PASSPHRASE")
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Drive the command line with the CLI passphrase standing in its
/// environment channel, as an operator on a machine with no
/// keychain service drives the passphrase route.
fn run_cli_pp(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .env("DEADBOLT_PASSPHRASE", CLI_PASSPHRASE)
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn write_value_file(dir: &Path, value: &str) -> String {
    let path = dir.join("value.txt");
    std::fs::write(&path, format!("{value}\n")).unwrap();
    path.to_string_lossy().into_owned()
}

fn cli_enroll_and_grant(dir: &Path) -> (String, String) {
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(dir, VALUE_A);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "--route",
        "passphrase",
        "enroll",
        "--name",
        "cache-key",
        "--value-file",
        &value_file,
        "--scope",
        "bucket:read",
        "--scope",
        "bucket:write",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "600",
        "--run",
        "run-1",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    (
        parsed["token"].as_str().unwrap().to_string(),
        parsed["grant_id"].as_str().unwrap().to_string(),
    )
}

#[test]
fn cli_round_trip_and_redeem_output_is_the_value_alone() {
    let dir = test_dir("cli-round-trip");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, _grant_id) = cli_enroll_and_grant(&dir);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, format!("{VALUE_A}\n"));
    assert_eq!(out.stderr, "");
}

#[test]
fn cli_refusals_exit_1_with_distinct_single_line_errors() {
    let dir = test_dir("cli-refusals");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, grant_id) = cli_enroll_and_grant(&dir);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &"0".repeat(64),
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("unknown token"), "{}", out.stderr);
    assert_eq!(out.stderr.lines().count(), 1);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &token,
        "--scope",
        "bucket:write",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("scope mismatch"), "{}", out.stderr);
    let out = run_cli_pp(&["--state", &state_arg, "revoke", "--grant", &grant_id]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("revoked"), "{}", out.stderr);
}

#[test]
fn cli_caller_errors_exit_2() {
    let dir = test_dir("cli-caller-errors");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE_A);
    let cases: Vec<Vec<&str>> = vec![
        vec!["enroll", "--name", "cache-key"],
        vec!["--state", &state_arg, "frobnicate"],
        vec![
            "--state",
            &state_arg,
            "enroll",
            "--name",
            "cache-key",
            "--value",
            VALUE_A,
            "--scope",
            "bucket:read",
        ],
        vec![
            "--state",
            &state_arg,
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            "/nonexistent/value.txt",
            "--scope",
            "bucket:read",
        ],
        vec![
            "--state",
            &state_arg,
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucketread",
        ],
        vec![
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "abc",
        ],
        vec![
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "86401",
        ],
        vec![
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "99999999999999999999999999",
        ],
    ];
    for args in cases {
        let out = run_cli(&args);
        assert_eq!(out.status, 2, "{args:?}: {} {}", out.stdout, out.stderr);
        assert!(out.stderr.starts_with("error: "), "{args:?}");
        assert_eq!(out.stderr.lines().count(), 1, "{args:?}");
    }
}

#[test]
fn cli_containment_battery() {
    let dir = test_dir("cli-containment");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE_A);
    let mut outputs: Vec<(String, CliOutput)> = Vec::new();
    let mut drive = |label: &str, args: &[&str]| -> CliOutput {
        let out = run_cli_pp(args);
        outputs.push((
            label.to_string(),
            CliOutput {
                status: out.status,
                stdout: out.stdout.clone(),
                stderr: out.stderr.clone(),
            },
        ));
        out
    };
    let enroll_out = drive(
        "enroll",
        &[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
            "--scope",
            "bucket:write",
        ],
    );
    assert_eq!(enroll_out.status, 0, "{}", enroll_out.stderr);
    let grant_out = drive(
        "grant",
        &[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "600",
            "--run",
            "run-1",
        ],
    );
    assert_eq!(grant_out.status, 0, "{}", grant_out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&grant_out.stdout).unwrap();
    let token = parsed["token"].as_str().unwrap().to_string();
    let grant_id = parsed["grant_id"].as_str().unwrap().to_string();
    let redeem_out = drive(
        "redeem",
        &[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            &token,
            "--scope",
            "bucket:read",
        ],
    );
    assert_eq!(redeem_out.status, 0);
    assert_eq!(redeem_out.stdout, format!("{VALUE_A}\n"));
    drive(
        "duplicate enroll",
        &[
            "--state",
            &state_arg,
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ],
    );
    drive(
        "grant unknown credential",
        &[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "ghost",
            "--scope",
            "bucket:read",
            "--ttl",
            "60",
        ],
    );
    drive(
        "grant unenrolled scope",
        &[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:delete",
            "--ttl",
            "60",
        ],
    );
    drive(
        "redeem unknown token",
        &[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            &"0".repeat(64),
            "--scope",
            "bucket:read",
        ],
    );
    drive(
        "redeem wrong scope",
        &[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            &token,
            "--scope",
            "bucket:write",
        ],
    );
    drive(
        "revoke unknown grant",
        &["--state", &state_arg, "revoke", "--grant", "no-such-grant"],
    );
    drive(
        "cutoff unknown run",
        &["--state", &state_arg, "cutoff", "--run", "run-9"],
    );
    drive(
        "cutoff",
        &["--state", &state_arg, "cutoff", "--run", "run-1"],
    );
    drive(
        "revoke",
        &["--state", &state_arg, "revoke", "--grant", &grant_id],
    );
    drive("audit", &["--state", &state_arg, "audit"]);
    drive(
        "retire",
        &["--state", &state_arg, "retire", "--name", "cache-key"],
    );
    let hash = cli_document_json(&state)["grants"][0]["token_hash"]
        .as_str()
        .unwrap()
        .to_string();
    for (label, out) in &outputs {
        let everything = format!("{}{}", out.stdout, out.stderr);
        if label.as_str() != "redeem" {
            assert!(
                !everything.contains(VALUE_A),
                "{label} leaked the value: {everything}"
            );
        }
        if label.as_str() != "grant" {
            assert!(
                !everything.contains(&token),
                "{label} leaked the token: {everything}"
            );
        }
        assert!(
            !everything.contains(&hash),
            "{label} leaked the token hash: {everything}"
        );
    }
    let grant_everything = format!("{}{}", grant_out.stdout, grant_out.stderr);
    assert!(
        grant_everything.contains(&token),
        "grant must show the token once"
    );
}

fn lock_path(state: &Path) -> PathBuf {
    PathBuf::from(format!("{}.lock", state.display()))
}

#[test]
fn cutoff_leaves_expired_grants_unended_and_answering_expired() {
    let dir = test_dir("cutoff-expired");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let short = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        Some("run-x"),
        T0,
    )
    .unwrap();
    let long = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-x"),
        T0,
    )
    .unwrap();
    let ended = deadbolt::cutoff(&state, &h.open(), "run-x", T0 + 120).unwrap();
    assert_eq!(ended, 1);
    let json = document_json(&h, &state);
    let expired = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["expires_at"] == T0 + 60)
        .unwrap();
    assert!(expired["ended_at"].is_null());
    assert!(expired["end_reason"].is_null());
    let err =
        deadbolt::redeem(&state, &h.open(), &short.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
    let err =
        deadbolt::redeem(&state, &h.open(), &long.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
}

#[test]
fn retire_leaves_expired_grants_unended_and_answering_expired() {
    let dir = test_dir("retire-expired");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let short =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let _long =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::retire(&state, &h.open(), "cache-key", T0 + 120).unwrap();
    assert_eq!(ended, 1);
    let json = document_json(&h, &state);
    let expired = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["expires_at"] == T0 + 60)
        .unwrap();
    assert!(expired["ended_at"].is_null());
    assert!(expired["end_reason"].is_null());
    let err =
        deadbolt::redeem(&state, &h.open(), &short.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn cutoff_over_a_run_of_expired_grants_reports_zero() {
    let dir = test_dir("cutoff-all-expired");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let _one = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        Some("run-y"),
        T0,
    )
    .unwrap();
    let _two = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        30,
        Some("run-y"),
        T0,
    )
    .unwrap();
    let ended = deadbolt::cutoff(&state, &h.open(), "run-y", T0 + 120).unwrap();
    assert_eq!(ended, 0);
    let json = document_json(&h, &state);
    for grant in json["grants"].as_array().unwrap() {
        assert!(grant["ended_at"].is_null());
        assert!(grant["end_reason"].is_null());
    }
}

#[test]
fn missing_state_acts_create_the_lock_file_but_no_state_file() {
    let dir = test_dir("missing-state-lock");
    let h = Harness::new();
    let state = dir.join("state.json");
    let err = deadbolt::redeem(&state, &h.open(), &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::UnknownToken)),
        "{err}"
    );
    assert!(!state.exists());
    assert!(lock_path(&state).exists());
}

// Portability adaptation gates POSIX 0600 lock mode checks to Unix per
// the portability amendment in CONTRACT.md.
#[cfg(unix)]
#[test]
fn lock_file_is_created_owner_only() {
    let dir = test_dir("lock-mode");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    assert_eq!(mode_of(&lock_path(&state)), 0o600);
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(mode_of(&lock_path(&state)), 0o600);
}

#[test]
fn redeem_of_an_expired_grant_at_the_wrong_scope_answers_expired() {
    let dir = test_dir("expired-beats-scope");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let err = deadbolt::redeem(
        &state,
        &h.open(),
        &receipt.token,
        &scope("bucket", "write"),
        T0 + 60,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn strict_reading_refuses_a_duplicated_token_hash_with_distinct_ids() {
    let dir = test_dir("dup-hash");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    // The edited document is written back as a plaintext file, so
    // the refusal arrives through the plaintext reading path exactly
    // as it did when the file was the document.
    let mut doc = document_json(&h, &state);
    let hash = doc["grants"][0]["token_hash"].as_str().unwrap().to_string();
    doc["grants"][1]["token_hash"] = serde_json::json!(hash);
    let first_id = doc["grants"][0]["id"].as_str().unwrap().to_string();
    let second_id = doc["grants"][1]["id"].as_str().unwrap().to_string();
    assert_ne!(first_id, second_id);
    std::fs::write(&state, doc.to_string()).unwrap();
    set_mode(&state, 0o600);
    let err = deadbolt::audit(&state, &h.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert!(format!("{err}").contains("token hash"), "{err}");
}

#[test]
fn a_caller_error_against_a_standing_state_records_nothing() {
    let dir = test_dir("caller-error-no-record");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let before = state_text(&state);
    let err =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 0, None, T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let err = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        86_401,
        None,
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert_eq!(state_text(&state), before);
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 1);
}

#[test]
fn a_grant_expiring_at_the_largest_instant_succeeds() {
    let dir = test_dir("instant-max-grant");
    let h = Harness::new();
    let state = dir.join("state.json");
    let start = deadbolt::INSTANT_MAX - 60;
    deadbolt::enroll(
        &state,
        &h.creating(),
        "cache-key",
        VALUE_A,
        &[read_scope()],
        start,
    )
    .unwrap();
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        60,
        None,
        start,
    )
    .unwrap();
    assert_eq!(receipt.expires_at, deadbolt::INSTANT_MAX);
    let value = deadbolt::redeem(
        &state,
        &h.open(),
        &receipt.token,
        &read_scope(),
        deadbolt::INSTANT_MAX - 1,
    )
    .unwrap();
    assert_eq!(value, VALUE_A);
    let err = deadbolt::redeem(
        &state,
        &h.open(),
        &receipt.token,
        &read_scope(),
        deadbolt::INSTANT_MAX,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn cli_filesystem_failure_names_the_path_and_exits_2() {
    let dir = test_dir("cli-io-path");
    let state = dir.join("missing").join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let out = run_cli(&["--state", &state_arg, "audit"]);
    assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
    assert_eq!(out.stderr.lines().count(), 1);
    assert!(out.stderr.contains(&state_arg), "{}", out.stderr);
    assert!(
        out.stderr.contains("the filesystem refused"),
        "{}",
        out.stderr
    );
}

#[test]
fn rotation_links_successor_to_predecessor_in_the_audit() {
    let dir = test_dir("rotate-link");
    let h = Harness::new();
    let state = dir.join("state.json");
    deadbolt::enroll(
        &state,
        &h.creating(),
        "alpha-key",
        VALUE_A,
        &[read_scope(), scope("bucket", "write")],
        T0,
    )
    .unwrap();
    deadbolt::enroll(&state, &h.open(), "beta-key", VALUE_B, &[read_scope()], T0).unwrap();
    deadbolt::enroll(
        &state,
        &h.open(),
        "cache-key",
        VALUE_C,
        &[scope("vault", "read")],
        T0,
    )
    .unwrap();
    deadbolt::grant(&state, &h.open(), "alpha-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &scope("vault", "read"),
        600,
        None,
        T0,
    )
    .unwrap();
    let ended = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "vault-key",
        VALUE_D,
        &[scope("vault", "read"), scope("vault", "write")],
        T0 + 10,
    )
    .unwrap();
    assert_eq!(ended, 1);
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["enroll", "enroll", "enroll", "grant", "grant", "enroll", "retire"]
    );
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    let link = &entries[5];
    assert_eq!(link.credential.as_deref(), Some("vault-key"));
    assert_eq!(link.outcome, "enrolled, rotation of cache-key");
    assert_eq!(link.at, T0 + 10);
    assert!(link.resource.is_none() && link.action.is_none() && link.run_id.is_none());
    let close = &entries[6];
    assert_eq!(close.credential.as_deref(), Some("cache-key"));
    assert_eq!(close.outcome, "retired, rotation to vault-key");
    assert_eq!(close.at, T0 + 10);
    let json = document_json(&h, &state);
    let names: Vec<&str> = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alpha-key", "beta-key", "vault-key"]);
    let successor = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|credential| credential["name"] == "vault-key")
        .unwrap();
    assert_eq!(successor["value"], VALUE_D);
    assert_eq!(successor["scopes"].as_array().unwrap().len(), 2);
    let ended_grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["credential"] == "cache-key")
        .unwrap();
    assert_eq!(ended_grant["ended_at"], T0 + 10);
    assert_eq!(ended_grant["end_reason"], "retired");
    let standing_grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["credential"] == "alpha-key")
        .unwrap();
    assert!(standing_grant["ended_at"].is_null());
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "vault-key",
        &scope("vault", "read"),
        600,
        None,
        T0 + 20,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(
            &state,
            &h.open(),
            &receipt.token,
            &scope("vault", "read"),
            T0 + 21
        )
        .unwrap(),
        VALUE_D
    );
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "alpha-key",
        &read_scope(),
        600,
        None,
        T0 + 20,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 21).unwrap(),
        VALUE_A
    );
}

#[test]
fn rotation_ends_live_grants_and_their_tokens_answer_revoked() {
    let dir = test_dir("rotate-revoked");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 10).unwrap(),
        VALUE_A
    );
    let ended = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "successor-key",
        VALUE_B,
        &[read_scope()],
        T0 + 20,
    )
    .unwrap();
    assert_eq!(ended, 1);
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 30).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
    let json = document_json(&h, &state);
    let grant = &json["grants"].as_array().unwrap()[0];
    assert_eq!(grant["ended_at"], T0 + 20);
    assert_eq!(grant["end_reason"], "retired");
}

#[test]
fn rotation_leaves_expired_grants_unended_and_answering_expired() {
    let dir = test_dir("rotate-expired");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let short =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let _long =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "successor-key",
        VALUE_B,
        &[read_scope()],
        T0 + 120,
    )
    .unwrap();
    assert_eq!(ended, 1);
    let json = document_json(&h, &state);
    let expired = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["expires_at"] == T0 + 60)
        .unwrap();
    assert!(expired["ended_at"].is_null());
    assert!(expired["end_reason"].is_null());
    let err =
        deadbolt::redeem(&state, &h.open(), &short.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn a_failed_rotation_leaves_the_predecessor_standing_and_redeeming() {
    let dir = test_dir("rotate-failed");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::enroll(&state, &h.open(), "other", VALUE_B, &[read_scope()], T0).unwrap();
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let err = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "other",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "rotate refused, a credential named other already stands"
    );
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    let json = document_json(&h, &state);
    let predecessor = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|credential| credential["name"] == "cache-key")
        .unwrap();
    assert_eq!(predecessor["value"], VALUE_A);
    assert_eq!(predecessor["scopes"].as_array().unwrap().len(), 2);
    let grant = &json["grants"].as_array().unwrap()[0];
    assert!(grant["ended_at"].is_null());
    assert!(grant["end_reason"].is_null());
}

#[test]
fn rotation_refusals_name_their_reasons_and_record_one_entry() {
    let dir = test_dir("rotate-refusals");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let err = deadbolt::rotate(
        &state,
        &h.open(),
        "ghost",
        "new-key",
        VALUE_B,
        &[read_scope()],
        T0 + 1,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "rotate refused, no credential named ghost stands"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 2);
    let refusal = &entries[1];
    assert_eq!(refusal.kind, "rotate");
    assert_eq!(refusal.credential.as_deref(), Some("ghost"));
    assert_eq!(refusal.outcome, "refused, unknown credential");
    deadbolt::enroll(&state, &h.open(), "taken", VALUE_B, &[read_scope()], T0 + 2).unwrap();
    let err = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "taken",
        VALUE_B,
        &[read_scope()],
        T0 + 3,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "rotate refused, a credential named taken already stands"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 4);
    let refusal = &entries[3];
    assert_eq!(refusal.kind, "rotate");
    assert_eq!(refusal.credential.as_deref(), Some("cache-key"));
    assert_eq!(refusal.outcome, "refused, name already stands");
    let json = document_json(&h, &state);
    let names: Vec<&str> = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["cache-key", "taken"]);
}

#[test]
fn rotation_to_the_same_name_refuses_and_leaves_the_predecessor_untouched() {
    let dir = test_dir("rotate-same-name");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let err = deadbolt::rotate(
        &state,
        &h.open(),
        "cache-key",
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "rotate refused, a credential named cache-key already stands"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 3);
    let refusal = &entries[2];
    assert_eq!(refusal.kind, "rotate");
    assert_eq!(refusal.credential.as_deref(), Some("cache-key"));
    assert_eq!(refusal.outcome, "refused, name already stands");
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    let json = document_json(&h, &state);
    let names: Vec<&str> = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|credential| credential["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["cache-key"]);
    let predecessor = &json["credentials"].as_array().unwrap()[0];
    assert_eq!(predecessor["value"], VALUE_A);
    let scopes = predecessor["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.contains(&serde_json::json!({"resource": "bucket", "action": "read"})));
    assert!(scopes.contains(&serde_json::json!({"resource": "bucket", "action": "write"})));
    let grant = &json["grants"].as_array().unwrap()[0];
    assert!(grant["ended_at"].is_null());
    assert!(grant["end_reason"].is_null());
}

#[test]
fn rotation_shape_errors_are_caller_errors_and_record_nothing() {
    let dir = test_dir("rotate-shapes");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let attempts: Vec<(&str, &str, Vec<Scope>)> = vec![
        ("bad name", VALUE_B, vec![read_scope()]),
        ("", VALUE_B, vec![read_scope()]),
        ("successor-key", VALUE_B, vec![]),
        ("successor-key", VALUE_B, vec![read_scope(), read_scope()]),
        ("successor-key", "", vec![read_scope()]),
        ("successor-key", "two\nlines", vec![read_scope()]),
    ];
    for (successor, value, scopes) in &attempts {
        let err = deadbolt::rotate(
            &state,
            &h.open(),
            "cache-key",
            successor,
            value,
            scopes,
            T0 + 1,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{err}");
    }
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 1);
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 2,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 3).unwrap(),
        VALUE_A
    );
}

#[test]
fn cli_rotation_round_trip_and_its_output() {
    let dir = test_dir("cli-rotate");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, _grant_id) = cli_enroll_and_grant(&dir);
    let successor_file = dir.join("value2.txt");
    std::fs::write(&successor_file, format!("{VALUE_B}\n")).unwrap();
    let successor_arg = successor_file.to_string_lossy().into_owned();
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "rotate",
        "--name",
        "cache-key",
        "--new-name",
        "successor-key",
        "--value-file",
        &successor_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(parsed["rotated"], "cache-key");
    assert_eq!(parsed["successor"], "successor-key");
    assert_eq!(parsed["grants_ended"], 1);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "successor-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "600",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let new_token = parsed["token"].as_str().unwrap().to_string();
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &new_token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, format!("{VALUE_B}\n"));
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(out.stderr.contains("revoked"), "{}", out.stderr);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "rotate",
        "--name",
        "cache-key",
        "--new-name",
        "third-key",
        "--value-file",
        &successor_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("rotate refused, no credential named cache-key stands"),
        "{}",
        out.stderr
    );
    let out = run_cli_pp(&["--state", &state_arg, "audit"]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let lines: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let pair = lines
        .windows(2)
        .find(|pair| pair[0]["outcome"] == "enrolled, rotation of cache-key")
        .expect("the audit shows the rotation pair");
    assert_eq!(pair[0]["kind"], "enroll");
    assert_eq!(pair[0]["credential"], "successor-key");
    assert_eq!(pair[1]["kind"], "retire");
    assert_eq!(pair[1]["credential"], "cache-key");
    assert_eq!(pair[1]["outcome"], "retired, rotation to successor-key");
}

fn assert_exact_keys(value: &serde_json::Value, expected: &[&str]) {
    let actual: std::collections::BTreeSet<&str> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    let expected: std::collections::BTreeSet<&str> = expected.iter().copied().collect();
    assert_eq!(actual, expected);
}

fn assert_text_key_order(text: &str, start: usize, expected: &[&str]) {
    let mut position = start;
    for key in expected {
        let needle = format!("\"{key}\"");
        let found = text[position..]
            .find(&needle)
            .map(|offset| position + offset)
            .unwrap_or_else(|| panic!("the key {key} does not stand after byte {position}"));
        position = found + needle.len();
    }
}

/// The field list one object's sentence of DK-26 states, read out
/// of the contract text itself.
///
/// The sentence stands located by its opening words, and the list
/// it names runs from the word fields to the next comma. Reading
/// the list from the contract, rather than restating it in this
/// file alone, is what lets a key respelled or dropped inside
/// DK-26 fail the pin that checks renderings against the same
/// expectation.
fn contract_field_list<'a>(dk26: &'a str, opening: &str) -> Vec<&'a str> {
    let at = dk26
        .find(opening)
        .unwrap_or_else(|| panic!("DK-26 carries no sentence opening {opening}"));
    let rest = &dk26[at + opening.len()..];
    let segment = rest.split(',').next().unwrap();
    let list = segment
        .strip_prefix("fields ")
        .unwrap_or_else(|| panic!("the sentence opening {opening} names no field list"));
    list.split(" and ").collect()
}

#[test]
fn contract_key_table_matches_the_rendered_document() {
    let dir = test_dir("contract-key-table");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let live = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    let ended =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::revoke(&state, &h.open(), &ended.grant_id, T0 + 1).unwrap();
    assert_ne!(live.grant_id, ended.grant_id);

    let text = document_text(&h, &state);
    let document: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_exact_keys(
        &document,
        &["format", "store_id", "credentials", "grants", "audit"],
    );
    let store_id = document["store_id"].as_str().unwrap();
    assert_eq!(store_id.len(), 64);
    assert!(store_id
        .chars()
        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    assert_text_key_order(
        &text,
        0,
        &["format", "store_id", "credentials", "grants", "audit"],
    );

    let credentials = document["credentials"].as_array().unwrap();
    assert_eq!(credentials.len(), 1);
    let credential = &credentials[0];
    assert_exact_keys(credential, &["name", "value", "scopes", "enrolled_at"]);
    let scopes = credential["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 2);
    for scope_object in scopes {
        assert_exact_keys(scope_object, &["resource", "action"]);
    }
    let credentials_at = text.find("\"credentials\"").unwrap();
    assert_text_key_order(
        &text,
        credentials_at,
        &[
            "name",
            "value",
            "scopes",
            "resource",
            "action",
            "enrolled_at",
        ],
    );

    let grants = document["grants"].as_array().unwrap();
    assert_eq!(grants.len(), 2);
    let grant_keys = [
        "id",
        "credential",
        "resource",
        "action",
        "run_id",
        "token_hash",
        "granted_at",
        "expires_at",
        "ended_at",
        "end_reason",
    ];
    for grant in grants {
        assert_exact_keys(grant, &grant_keys);
        let grant_id = grant["id"].as_str().unwrap();
        assert_eq!(grant_id.len(), 32);
        assert!(grant_id
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
        let token_hash = grant["token_hash"].as_str().unwrap();
        assert_eq!(token_hash.len(), 64);
        assert!(token_hash
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }
    let live_grant = grants
        .iter()
        .find(|grant| grant["id"] == live.grant_id)
        .unwrap();
    assert_eq!(live_grant["run_id"], "run-1");
    assert!(live_grant["ended_at"].is_null());
    assert!(live_grant["end_reason"].is_null());
    let ended_grant = grants
        .iter()
        .find(|grant| grant["id"] == ended.grant_id)
        .unwrap();
    assert!(ended_grant["run_id"].is_null());
    assert_eq!(ended_grant["ended_at"], T0 + 1);
    assert_eq!(ended_grant["end_reason"], "revoked");
    let grants_at = text.find("\"grants\"").unwrap();
    assert_text_key_order(&text, grants_at, &grant_keys);
    let first_grant_end = text[grants_at..]
        .find("\"end_reason\"")
        .map(|offset| grants_at + offset)
        .unwrap();
    assert_text_key_order(&text, first_grant_end, &grant_keys);

    let audit = document["audit"].as_array().unwrap();
    assert_eq!(audit.len(), 4);
    let audit_keys = [
        "seq",
        "at",
        "kind",
        "credential",
        "resource",
        "action",
        "run_id",
        "outcome",
    ];
    for entry in audit {
        assert_exact_keys(entry, &audit_keys);
    }
    assert_eq!(audit[0]["kind"], "enroll");
    assert!(audit[0]["resource"].is_null());
    assert!(audit[0]["action"].is_null());
    assert!(audit[0]["run_id"].is_null());
    assert_eq!(audit[1]["run_id"], "run-1");
    assert!(audit[2]["run_id"].is_null());
    assert_eq!(audit[3]["kind"], "revoke");
    assert_eq!(audit[3]["credential"], "cache-key");
    assert_eq!(audit[3]["resource"], "bucket");
    assert_eq!(audit[3]["action"], "read");
    assert!(audit[3]["run_id"].is_null());
    let audit_at = text.find("\"audit\"").unwrap();
    assert_text_key_order(&text, audit_at, &audit_keys);

    // The unstamped arm renders through the library on the
    // passphrase route, where the document stamp stands empty
    // under DK-20, so the writer itself renders the document
    // without the store_id field, and a later act reads that
    // rendering back through the library.
    let passphrase_state = dir.join("passphrase.json");
    let creating_passphrase = Unlock {
        route: Some(Route::Passphrase),
        custody: &h.custody,
        passphrase: &h.passphrase,
    };
    deadbolt::enroll(
        &passphrase_state,
        &creating_passphrase,
        "cache-key",
        VALUE_A,
        &[read_scope(), scope("bucket", "write")],
        T0,
    )
    .unwrap();
    deadbolt::grant(
        &passphrase_state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    let entries = deadbolt::audit(&passphrase_state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 2);
    let raw = state_text(&passphrase_state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let salt = hex_bytes(envelope["header"]["kdf"]["salt"].as_str().unwrap());
    let salt: [u8; 16] = salt.try_into().unwrap();
    let key = deadbolt::custody::derive_key(STORE_PASSPHRASE.as_bytes(), &salt).unwrap();
    let plain_text = decrypt_document(&raw, &key);
    let plain_document: serde_json::Value = serde_json::from_str(&plain_text).unwrap();
    assert!(plain_document.get("store_id").is_none());
    assert_exact_keys(
        &plain_document,
        &["format", "credentials", "grants", "audit"],
    );
    assert_text_key_order(
        &plain_text,
        0,
        &["format", "credentials", "grants", "audit"],
    );
    let plain_grants = plain_document["grants"].as_array().unwrap();
    assert_eq!(plain_grants.len(), 1);
    assert_exact_keys(&plain_grants[0], &grant_keys);
    assert!(plain_grants[0]["ended_at"].is_null());
    assert!(plain_grants[0]["end_reason"].is_null());

    // The replace arm of the table, DK-27. A credential replaced
    // once renders with the incarnation key standing last at 2,
    // and a grant minted against it renders with the key standing
    // last at 2, while the grants minted at incarnation 1 in the
    // same document keep rendering no key at all, so both arms of
    // the conditional rendering stand checked against renderings
    // here and against the contract text below.
    let (replace_ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope(), scope("bucket", "write")],
        T0 + 2,
    )
    .unwrap();
    assert_eq!(replace_ended, 1);
    assert_eq!(stood_up, 2);
    let replaced_receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 3,
    )
    .unwrap();
    let replaced_text = document_text(&h, &state);
    let replaced_document: serde_json::Value = serde_json::from_str(&replaced_text).unwrap();
    let credential_keys_with_mark = ["name", "value", "scopes", "enrolled_at", "incarnation"];
    let replaced_credentials = replaced_document["credentials"].as_array().unwrap();
    assert_eq!(replaced_credentials.len(), 1);
    assert_exact_keys(&replaced_credentials[0], &credential_keys_with_mark);
    assert_eq!(replaced_credentials[0]["incarnation"], 2);
    let replaced_credentials_at = replaced_text.find("\"credentials\"").unwrap();
    assert_text_key_order(
        &replaced_text,
        replaced_credentials_at,
        &credential_keys_with_mark,
    );
    let grant_keys_with_mark = [
        "id",
        "credential",
        "resource",
        "action",
        "run_id",
        "token_hash",
        "granted_at",
        "expires_at",
        "ended_at",
        "end_reason",
        "incarnation",
    ];
    let replaced_grants = replaced_document["grants"].as_array().unwrap();
    assert_eq!(replaced_grants.len(), 3);
    let replaced_grant = replaced_grants
        .iter()
        .find(|grant| grant["id"] == replaced_receipt.grant_id)
        .unwrap();
    assert_exact_keys(replaced_grant, &grant_keys_with_mark);
    assert_eq!(replaced_grant["incarnation"], 2);
    let replaced_grant_at = replaced_text
        .find(&format!("\"id\": \"{}\"", replaced_receipt.grant_id))
        .unwrap();
    assert_text_key_order(&replaced_text, replaced_grant_at, &grant_keys_with_mark);
    for grant in replaced_grants
        .iter()
        .filter(|grant| grant["id"] != replaced_receipt.grant_id)
    {
        assert_exact_keys(grant, &grant_keys);
        assert!(grant.get("incarnation").is_none());
    }

    // The contract half of the table. The lists and lengths the
    // renderings above were checked against are read out of
    // DK-26's own sentences here, so a key respelled inside the
    // contract, or a length the contract states falsely, fails
    // this pin instead of passing against a transcription.
    let contract_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("CONTRACT.md");
    let contract = std::fs::read_to_string(contract_path).unwrap();
    let dk26 = &contract[contract.find("### Obligation DK-26").unwrap()..];
    assert_eq!(
        contract_field_list(dk26, "one JSON object carrying the "),
        vec!["format", "credentials", "grants", "audit"]
    );
    assert!(dk26.contains(
        "one further field store_id standing exactly when the document has been stamped"
    ));
    assert!(dk26.contains(
        "in the construction order format and store_id and credentials and grants and audit"
    ));
    assert_eq!(
        contract_field_list(dk26, "Each credential object carries exactly the "),
        vec!["name", "value", "scopes", "enrolled_at", "incarnation"]
    );
    assert_eq!(
        contract_field_list(dk26, "each scope object carries exactly the "),
        vec!["resource", "action"]
    );
    assert_eq!(
        contract_field_list(dk26, "Each grant object carries exactly the "),
        grant_keys_with_mark.to_vec()
    );
    assert_eq!(
        contract_field_list(dk26, "Each audit entry carries exactly the "),
        audit_keys.to_vec()
    );
    assert!(dk26.contains(
        "The store_id field carries the store identifier as 64 lowercase hexadecimal characters"
    ));
    assert!(dk26.contains(
        "The id field carries the grant identifier as 32 lowercase hexadecimal characters"
    ));
    assert!(dk26.contains(
        "The token_hash field carries the SHA-256 hash of the grant token as 64 lowercase hexadecimal characters"
    ));
}

#[test]
fn audit_output_carries_exactly_the_contract_audit_fields() {
    let dir = test_dir("audit-output-fields");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (_token, _grant_id) = cli_enroll_and_grant(&dir);
    let successor_file = dir.join("value2.txt");
    std::fs::write(&successor_file, format!("{VALUE_B}\n")).unwrap();
    let successor_arg = successor_file.to_string_lossy().into_owned();
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "rotate",
        "--name",
        "cache-key",
        "--new-name",
        "successor-key",
        "--value-file",
        &successor_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);

    let out = run_cli_pp(&["--state", &state_arg, "audit"]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let lines: Vec<&str> = out.stdout.lines().collect();
    assert_eq!(lines.len(), 4);
    let audit_keys = [
        "seq",
        "at",
        "kind",
        "credential",
        "resource",
        "action",
        "run_id",
        "outcome",
    ];
    for line in lines {
        let entry: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_exact_keys(&entry, &audit_keys);
        assert_text_key_order(line, 0, &audit_keys);
    }
}

// DK-27, same name replacement and the incarnation mark. The pins
// below land with the build slice, over the standing harness, and
// every fixture value carries the SYNTHETIC-TEST-VALUE marker.

#[test]
fn replace_swaps_the_value_under_a_standing_name_and_counts_the_incarnation() {
    let dir = test_dir("replace-swaps");
    let h = Harness::new();
    let state = dir.join("state.json");
    deadbolt::enroll(
        &state,
        &h.creating(),
        "alpha-key",
        VALUE_A,
        &[read_scope()],
        T0,
    )
    .unwrap();
    deadbolt::enroll(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope(), scope("bucket", "write")],
        T0,
    )
    .unwrap();
    deadbolt::enroll(
        &state,
        &h.open(),
        "vault-key",
        VALUE_C,
        &[scope("vault", "read")],
        T0,
    )
    .unwrap();
    let alpha_receipt =
        deadbolt::grant(&state, &h.open(), "alpha-key", &read_scope(), 600, None, T0).unwrap();
    let vault_receipt = deadbolt::grant(
        &state,
        &h.open(),
        "vault-key",
        &scope("vault", "read"),
        600,
        None,
        T0,
    )
    .unwrap();
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_D,
        &[scope("bucket", "write")],
        T0 + 10,
    )
    .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(stood_up, 2);
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_A,
        &[read_scope()],
        T0 + 20,
    )
    .unwrap();
    assert_eq!(ended, 0);
    assert_eq!(stood_up, 3);
    let fresh = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 30,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &fresh.token, &read_scope(), T0 + 31).unwrap(),
        VALUE_A
    );
    assert_eq!(
        deadbolt::redeem(
            &state,
            &h.open(),
            &alpha_receipt.token,
            &read_scope(),
            T0 + 31
        )
        .unwrap(),
        VALUE_A
    );
    assert_eq!(
        deadbolt::redeem(
            &state,
            &h.open(),
            &vault_receipt.token,
            &scope("vault", "read"),
            T0 + 31
        )
        .unwrap(),
        VALUE_C
    );
    let text = document_text(&h, &state);
    let json = document_json(&h, &state);
    let credentials = json["credentials"].as_array().unwrap();
    let names: Vec<&str> = credentials
        .iter()
        .map(|credential| credential["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["alpha-key", "cache-key", "vault-key"]);
    let replaced = &credentials[1];
    assert_eq!(replaced["value"], VALUE_A);
    assert_eq!(replaced["incarnation"], 3);
    assert_eq!(replaced["enrolled_at"], T0 + 20);
    assert_eq!(replaced["scopes"].as_array().unwrap().len(), 1);
    assert!(credentials[0].get("incarnation").is_none());
    assert!(credentials[2].get("incarnation").is_none());
    let credentials_at = text.find("\"credentials\"").unwrap();
    assert_text_key_order(
        &text,
        credentials_at,
        &[
            "name",
            "value",
            "scopes",
            "enrolled_at",
            "name",
            "value",
            "scopes",
            "enrolled_at",
            "incarnation",
        ],
    );
}

#[test]
fn replace_ends_live_grants_and_their_tokens_answer_revoked() {
    let dir = test_dir("replace-revoked");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 10).unwrap(),
        VALUE_A
    );
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 20,
    )
    .unwrap();
    assert_eq!(ended, 1);
    assert_eq!(stood_up, 2);
    let err =
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 30).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
    let json = document_json(&h, &state);
    let grant = &json["grants"].as_array().unwrap()[0];
    assert_eq!(grant["ended_at"], T0 + 20);
    assert_eq!(grant["end_reason"], "retired");
    assert!(grant.get("incarnation").is_none());
}

#[test]
fn replace_leaves_expired_grants_unended_and_answering_expired() {
    let dir = test_dir("replace-expired");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let short =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 60, None, T0).unwrap();
    let _long =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 120,
    )
    .unwrap();
    assert_eq!(ended, 1);
    assert_eq!(stood_up, 2);
    let json = document_json(&h, &state);
    let expired = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["expires_at"] == T0 + 60)
        .unwrap();
    assert!(expired["ended_at"].is_null());
    assert!(expired["end_reason"].is_null());
    let err =
        deadbolt::redeem(&state, &h.open(), &short.token, &read_scope(), T0 + 120).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Expired)),
        "{err}"
    );
}

#[test]
fn replace_records_one_entry_naming_the_new_incarnation() {
    let dir = test_dir("replace-entry");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let before = deadbolt::audit(&state, &h.open(), T0).unwrap();
    deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap();
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), before.len() + 1);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    let entry = entries.last().unwrap();
    assert_eq!(entry.kind, "replace");
    assert_eq!(entry.credential.as_deref(), Some("cache-key"));
    assert_eq!(entry.outcome, "replaced, incarnation 2");
    assert_eq!(entry.at, T0 + 10);
    assert!(entry.resource.is_none() && entry.action.is_none() && entry.run_id.is_none());
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["enroll", "grant", "replace"]);
}

#[test]
fn a_failed_replace_leaves_the_credential_standing_and_redeeming() {
    let dir = test_dir("replace-failed");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let receipt =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let err = deadbolt::replace(
        &state,
        &h.open(),
        "ghost",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "replace refused, no credential named ghost stands"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 3);
    let refusal = &entries[2];
    assert_eq!(refusal.kind, "replace");
    assert_eq!(refusal.credential.as_deref(), Some("ghost"));
    assert_eq!(refusal.outcome, "refused, unknown credential");
    deadbolt::enroll(&state, &h.open(), "gone", VALUE_C, &[read_scope()], T0 + 11).unwrap();
    deadbolt::retire(&state, &h.open(), "gone", T0 + 12).unwrap();
    let err = deadbolt::replace(&state, &h.open(), "gone", VALUE_B, &[read_scope()], T0 + 13)
        .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(
        err.to_string(),
        "replace refused, no credential named gone stands"
    );
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    let last = entries.last().unwrap();
    assert_eq!(last.kind, "replace");
    assert_eq!(last.credential.as_deref(), Some("gone"));
    assert_eq!(last.outcome, "refused, unknown credential");
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    let json = document_json(&h, &state);
    let control = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|credential| credential["name"] == "cache-key")
        .unwrap();
    assert_eq!(control["value"], VALUE_A);
    assert!(control.get("incarnation").is_none());
}

#[test]
fn replace_shape_errors_are_caller_errors_and_record_nothing() {
    let dir = test_dir("replace-shapes");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let attempts: Vec<(&str, &str, Vec<Scope>)> = vec![
        ("bad name", VALUE_B, vec![read_scope()]),
        ("", VALUE_B, vec![read_scope()]),
        ("cache-key", VALUE_B, vec![]),
        ("cache-key", VALUE_B, vec![read_scope(), read_scope()]),
        ("cache-key", "", vec![read_scope()]),
        ("cache-key", "two\nlines", vec![read_scope()]),
        ("cache-key", VALUE_B, vec![scope("bad name", "read")]),
        ("cache-key", VALUE_B, vec![scope("bucket", "bad action")]),
    ];
    for (name, value, scopes) in &attempts {
        let err = deadbolt::replace(&state, &h.open(), name, value, scopes, T0 + 1).unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{err}");
    }
    let entries = deadbolt::audit(&state, &h.open(), T0).unwrap();
    assert_eq!(entries.len(), 1);
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 2,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &receipt.token, &read_scope(), T0 + 3).unwrap(),
        VALUE_A
    );
}

#[test]
fn grants_carry_the_incarnation_they_were_minted_under() {
    let dir = test_dir("replace-grant-marks");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    let first =
        deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let json = document_json(&h, &state);
    let grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["id"] == first.grant_id)
        .unwrap();
    assert!(grant.get("incarnation").is_none());
    deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap();
    let second = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 20,
    )
    .unwrap();
    let text = document_text(&h, &state);
    let json = document_json(&h, &state);
    let grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["id"] == second.grant_id)
        .unwrap();
    assert_eq!(grant["incarnation"], 2);
    let grant_at = text
        .find(&format!("\"id\": \"{}\"", second.grant_id))
        .unwrap();
    assert_text_key_order(
        &text,
        grant_at,
        &[
            "id",
            "credential",
            "resource",
            "action",
            "run_id",
            "token_hash",
            "granted_at",
            "expires_at",
            "ended_at",
            "end_reason",
            "incarnation",
        ],
    );
    deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_C,
        &[read_scope()],
        T0 + 30,
    )
    .unwrap();
    let json = document_json(&h, &state);
    let credential = &json["credentials"].as_array().unwrap()[0];
    assert_eq!(credential["incarnation"], 3);
    let grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["id"] == second.grant_id)
        .unwrap();
    assert_eq!(grant["incarnation"], 2);
    assert_eq!(grant["ended_at"], T0 + 30);
    assert_eq!(grant["end_reason"], "retired");
    let err =
        deadbolt::redeem(&state, &h.open(), &second.token, &read_scope(), T0 + 40).unwrap_err();
    assert!(
        matches!(err, Error::Redeem(RedeemRefusal::Revoked)),
        "{err}"
    );
}

#[test]
fn strict_reading_refuses_incarnation_variants() {
    let dir = test_dir("incarnation-corrupt-base");
    let h = Harness::new();
    let base = dir.join("base.json");
    enroll_a(&h, &base);
    deadbolt::grant(
        &base,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        Some("run-1"),
        T0,
    )
    .unwrap();
    let plain_text = document_text(&h, &base);
    let plain = dir.join("plain.json");
    std::fs::write(&plain, &plain_text).unwrap();
    set_mode(&plain, 0o600);
    // The control reads clean through the plaintext path, so each
    // refusal below is the staged mark and nothing else.
    let control = deadbolt::audit(&plain, &h.creating(), T0 + 1).unwrap();
    assert_eq!(control.len(), 3);

    let mut variants: Vec<(String, String)> = Vec::new();
    let mut doc = serde_json::from_str::<serde_json::Value>(&plain_text).unwrap();
    doc["credentials"][0]["incarnation"] = serde_json::json!(0);
    variants.push((
        "a credential carrying an incarnation of 0".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&plain_text).unwrap();
    doc["grants"][0]["incarnation"] = serde_json::json!(0);
    variants.push((
        "a grant carrying an incarnation of 0".to_string(),
        doc.to_string(),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&plain_text).unwrap();
    doc["grants"][0]["incarnation"] = serde_json::json!(2);
    variants.push((
        "a live grant carrying an incarnation above its credential".to_string(),
        doc.to_string(),
    ));

    let rdir = test_dir("incarnation-corrupt-replaced");
    let rstate = rdir.join("state.json");
    enroll_a(&h, &rstate);
    deadbolt::replace(
        &rstate,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope(), scope("bucket", "write")],
        T0 + 10,
    )
    .unwrap();
    let live = deadbolt::grant(
        &rstate,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 20,
    )
    .unwrap();
    let replaced_text = document_text(&h, &rstate);
    let mut doc = serde_json::from_str::<serde_json::Value>(&replaced_text).unwrap();
    let grant_index = doc["grants"]
        .as_array()
        .unwrap()
        .iter()
        .position(|grant| grant["id"] == live.grant_id)
        .unwrap();
    doc["grants"][grant_index]["incarnation"] = serde_json::json!(1);
    variants.push((
        "a live grant carrying an incarnation below its credential".to_string(),
        doc.to_string(),
    ));
    // The discrimination the round exists for. The same grant with
    // the incarnation key deleted reads at 1 beside the credential
    // as it stood before the replacement, and reads clean.
    let pre_dir = test_dir("incarnation-pre-replacement");
    let pre_state = pre_dir.join("state.json");
    std::fs::write(&pre_state, &plain_text).unwrap();
    set_mode(&pre_state, 0o600);
    assert!(deadbolt::audit(&pre_state, &h.creating(), T0 + 1).is_ok());

    let mut doc = serde_json::from_str::<serde_json::Value>(&plain_text).unwrap();
    doc["credentials"][0]["incarnation"] = serde_json::json!(u64::MAX);
    doc["grants"][0]["incarnation"] = serde_json::json!(u64::MAX);
    variants.push((
        "a credential standing at the largest incarnation value".to_string(),
        doc.to_string(),
    ));

    for (label, text) in &variants {
        let vdir = test_dir("incarnation-corrupt");
        let vstate = vdir.join("state.json");
        std::fs::write(&vstate, text).unwrap();
        set_mode(&vstate, 0o600);
        if label == "a credential standing at the largest incarnation value" {
            // An honest document at the reader, which then refuses
            // its replacement in the words of DK-27.
            let entries = deadbolt::audit(&vstate, &h.creating(), T0 + 1).unwrap();
            assert_eq!(entries.len(), 3, "{label}");
            let err = deadbolt::replace(
                &vstate,
                &h.open(),
                "cache-key",
                VALUE_B,
                &[read_scope()],
                T0 + 2,
            )
            .unwrap_err();
            assert!(matches!(err, Error::Refusal(_)), "{label}: {err}");
            assert_eq!(
                err.to_string(),
                "replace refused, the credential named cache-key stands at the last incarnation",
                "{label}"
            );
            let entries = deadbolt::audit(&vstate, &h.open(), T0 + 3).unwrap();
            let last = entries.last().unwrap();
            assert_eq!(last.kind, "replace");
            assert_eq!(last.outcome, "refused, incarnation exhausted");
            continue;
        }
        let err = deadbolt::audit(&vstate, &h.open(), T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        let err = deadbolt::grant(&vstate, &h.open(), "cache-key", &read_scope(), 60, None, T0)
            .unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(state_text(&vstate), *text, "{label}");
    }
}

#[test]
fn pre_mark_documents_read_at_incarnation_one_and_render_without_the_key() {
    let dir = test_dir("pre-mark");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::grant(&state, &h.open(), "cache-key", &read_scope(), 600, None, T0).unwrap();
    let text = document_text(&h, &state);
    assert!(!text.contains("incarnation"), "{text}");
    let (ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 10,
    )
    .unwrap();
    assert_eq!(ended, 1);
    assert_eq!(stood_up, 2);
    let json = document_json(&h, &state);
    assert_eq!(json["credentials"].as_array().unwrap()[0]["incarnation"], 2);

    // A plaintext document written in the pre mark shape adopts
    // with every incarnation standing at 1 and no entry owed to
    // the mark.
    let plain_dir = test_dir("pre-mark-plain");
    let source = plain_dir.join("source.json");
    enroll_a(&h, &source);
    let token_receipt = deadbolt::grant(
        &source,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0,
    )
    .unwrap();
    let plain_text = document_text(&h, &source);
    assert!(!plain_text.contains("incarnation"));
    let plain = plain_dir.join("plain.json");
    std::fs::write(&plain, &plain_text).unwrap();
    set_mode(&plain, 0o600);
    let entries = deadbolt::audit(&plain, &h.creating(), T0 + 10).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["enroll", "grant", "adopt"]);
    let adopted_text = document_text(&h, &plain);
    assert!(!adopted_text.contains("incarnation"), "{adopted_text}");
    assert_eq!(
        deadbolt::redeem(
            &plain,
            &h.open(),
            &token_receipt.token,
            &read_scope(),
            T0 + 20
        )
        .unwrap(),
        VALUE_A
    );
    let (_ended, stood_up) = deadbolt::replace(
        &plain,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope()],
        T0 + 30,
    )
    .unwrap();
    assert_eq!(stood_up, 2);
}

#[test]
fn cli_replace_round_trip_and_its_output() {
    let dir = test_dir("cli-replace");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, _grant_id) = cli_enroll_and_grant(&dir);
    let value_file = dir.join("value2.txt");
    std::fs::write(&value_file, format!("{VALUE_B}\n")).unwrap();
    let value_arg = value_file.to_string_lossy().into_owned();
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "replace",
        "--name",
        "cache-key",
        "--value-file",
        &value_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(parsed["replaced"], "cache-key");
    assert_eq!(parsed["incarnation"], 2);
    assert_eq!(parsed["grants_ended"], 1);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "600",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    let new_token = parsed["token"].as_str().unwrap().to_string();
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &new_token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, format!("{VALUE_B}\n"));
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        &token,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(out.stderr.contains("revoked"), "{}", out.stderr);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "replace",
        "--name",
        "ghost",
        "--value-file",
        &value_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 1, "{}", out.stderr);
    assert!(
        out.stderr
            .contains("replace refused, no credential named ghost stands"),
        "{}",
        out.stderr
    );
    let out = run_cli_pp(&["--state", &state_arg, "audit"]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let lines: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let replace_entries: Vec<&serde_json::Value> = lines
        .iter()
        .filter(|line| line["kind"] == "replace")
        .collect();
    assert_eq!(replace_entries.len(), 2);
    assert_eq!(replace_entries[0]["credential"], "cache-key");
    assert_eq!(replace_entries[0]["outcome"], "replaced, incarnation 2");
    let audit_keys = [
        "seq",
        "at",
        "kind",
        "credential",
        "resource",
        "action",
        "run_id",
        "outcome",
    ];
    for line in &lines {
        assert_exact_keys(line, &audit_keys);
    }
}

#[test]
fn replace_retire_and_enroll_again_leaves_the_store_readable() {
    let dir = test_dir("replace-era-boundary");
    let h = Harness::new();
    let state = dir.join("state.json");
    enroll_a(&h, &state);
    deadbolt::enroll(&state, &h.open(), "other-key", VALUE_C, &[read_scope()], T0).unwrap();
    let other_receipt =
        deadbolt::grant(&state, &h.open(), "other-key", &read_scope(), 600, None, T0).unwrap();
    let (_ended, stood_up) = deadbolt::replace(
        &state,
        &h.open(),
        "cache-key",
        VALUE_B,
        &[read_scope(), scope("bucket", "write")],
        T0 + 10,
    )
    .unwrap();
    assert_eq!(stood_up, 2);
    let receipt = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 20,
    )
    .unwrap();
    let ended = deadbolt::retire(&state, &h.open(), "cache-key", T0 + 30).unwrap();
    assert_eq!(ended, 1);
    deadbolt::enroll(
        &state,
        &h.open(),
        "cache-key",
        VALUE_D,
        &[read_scope()],
        T0 + 40,
    )
    .unwrap();
    // The store opens on a fresh read beside the ended grant
    // carrying incarnation 2 and the standing credential at 1.
    // This pin fails against any reader that caps a non live
    // grant at the standing incarnation of its credential.
    let entries = deadbolt::audit(&state, &h.open(), T0 + 50).unwrap();
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        ["enroll", "enroll", "grant", "replace", "grant", "retire", "enroll"]
    );
    let json = document_json(&h, &state);
    let standing = json["credentials"]
        .as_array()
        .unwrap()
        .iter()
        .find(|credential| credential["name"] == "cache-key")
        .unwrap();
    assert_eq!(standing["value"], VALUE_D);
    assert!(standing.get("incarnation").is_none());
    let ended_grant = json["grants"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["id"] == receipt.grant_id)
        .unwrap();
    assert_eq!(ended_grant["incarnation"], 2);
    assert_eq!(ended_grant["ended_at"], T0 + 30);
    assert_eq!(ended_grant["end_reason"], "retired");
    assert_eq!(
        deadbolt::redeem(
            &state,
            &h.open(),
            &other_receipt.token,
            &read_scope(),
            T0 + 60
        )
        .unwrap(),
        VALUE_C
    );
    let fresh = deadbolt::grant(
        &state,
        &h.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 70,
    )
    .unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &h.open(), &fresh.token, &read_scope(), T0 + 71).unwrap(),
        VALUE_D
    );
}

// Consolidated audit round submodules. Each former standalone tests/audit_*.rs
// file stands verbatim inside its own isolated module namespace so Cargo builds
// four integration test binaries instead of twenty while keeping every closed
// round's harness, assertions, and historical file-path comments intact.

mod audit_r3_dka8 {
    //! Audit Round 3 pin for finding DK-A8: the Debug rendering of a
    //! grant receipt never prints the token it carries, in the same
    //! discipline the suite pins for the store key in
    //! tests/custody.rs. The rendering still shows the receipt's
    //! shape, its grant id and its expiry instant, with the token
    //! standing as the word redacted.
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
}

mod audit_r3_dka9 {
    //! Audit Round 3 pins for finding DK-A9: neither binary panics
    //! on an argument that is not valid Unicode text. Each answers
    //! through its standing one line error surface at the caller
    //! error exit, the deadbolt command line with its error line at
    //! exit 2 under DK-13 and the codepoint scanner with its scan
    //! error line at exit 2, where the argument collection of the
    //! standard library panicked and exited 101 before.
    //!
    //! Every fixture is synthetic. The staged argument is two bytes
    //! that decode as no text at all, passed to each binary as an
    //! operating system argument exactly as a shell would pass it.

    use std::ffi::OsString;
    use std::process::Command;

    // Portability adaptation builds invalid UTF-8 bytes on Unix and an
    // unpaired UTF-16 surrogate on Windows so both OS string forms are pinned.
    #[cfg(unix)]
    fn non_unicode_argument() -> OsString {
        use std::os::unix::ffi::OsStringExt;
        OsString::from_vec(b"\xff\xfe".to_vec())
    }

    #[cfg(windows)]
    fn non_unicode_argument() -> OsString {
        use std::os::windows::ffi::OsStringExt;
        OsString::from_wide(&[0xD800])
    }

    #[test]
    fn the_command_line_answers_a_non_unicode_argument_as_a_caller_error() {
        let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
            .arg("--state")
            .arg(non_unicode_argument())
            .arg("audit")
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(stderr.starts_with("error: "), "{stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(output.stdout.is_empty());
    }

    #[test]
    fn the_scanner_answers_a_non_unicode_argument_as_a_scan_error() {
        let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
            .arg(non_unicode_argument())
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(stderr.starts_with("scan error, "), "{stderr}");
        assert_eq!(stderr.lines().count(), 1, "{stderr}");
        assert!(output.stdout.is_empty());
    }
}

mod audit_r5_dka23 {
    //! Audit Round 5 pins for finding DK-A23: neither binary panics
    //! when a write to its standing output fails. Each answers
    //! through its standing one line error surface at the filesystem
    //! exit, the deadbolt command line with its error line at exit 2
    //! under DK-13 and the codepoint scanner with its scan error line
    //! at exit 2, where print! and println! panicked and exited 101
    //! before. A caller error whose own error line cannot be written
    //! still exits 2, because the exit code is the last surface of
    //! the taxonomy standing.
    //!
    //! Every fixture is synthetic and names itself as one. The full
    //! stream prefers /dev/full where the host provides it and falls
    //! back to a pipe whose reader is closed on hosts without /dev/full,
    //! proving a failing write before handing the stream to the child
    //! so these pins run across Linux, macOS, and Windows. Custody runs
    //! on the passphrase route, and no test here touches a real keychain.

    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
    const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r5-dka23-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A writable handle whose writes always fail, using /dev/full when
    /// present and falling back to a pipe with its reader closed.
    fn full_stream() -> Stdio {
        use std::io::Write;
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/full")
        {
            if file.write_all(b"probe").is_err() {
                return Stdio::from(file);
            }
        }
        // Portability adaptation retries pipe creation when a concurrent child
        // spawn on macOS inherits reader before FIOCLEX closes the race window.
        for _ in 0..64 {
            let (reader, mut writer) = std::io::pipe().unwrap();
            drop(reader);
            if writer.write_all(b"probe").is_err() {
                return Stdio::from(writer);
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        panic!("writes to a closed pipe must fail")
    }

    struct CliOutput {
        status: i32,
        stdout: String,
        stderr: String,
    }

    fn run_deadbolt(args: &[&str], stdout: Stdio, stderr: Stdio) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
            .args(args)
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .stdout(stdout)
            .stderr(stderr)
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn run_scanner(root: &Path) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
            .arg(root)
            .stdout(full_stream())
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn run_scanner_with_surplus_on_full_stderr(root: &Path) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
            .arg(root)
            .arg("second-root")
            .stdout(Stdio::piped())
            .stderr(full_stream())
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    #[test]
    fn a_successful_act_whose_report_cannot_be_written_exits_2() {
        let dir = test_dir("full-stdout");
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_path = dir.join("value.txt");
        std::fs::write(&value_path, format!("{VALUE}\n")).unwrap();
        let value_arg = value_path.to_string_lossy().into_owned();
        let out = run_deadbolt(
            &[
                "--state",
                &state_arg,
                "--route",
                "passphrase",
                "enroll",
                "--name",
                "cache-key",
                "--value-file",
                &value_arg,
                "--scope",
                "bucket:read",
            ],
            full_stream(),
            Stdio::piped(),
        );
        assert_eq!(out.status, 2, "{}", out.stderr);
        assert!(
            out.stderr
                .starts_with("error: the output could not be written because "),
            "{}",
            out.stderr
        );
        assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
        assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
        // The act itself succeeded and the store stands; only its
        // report failed, and the audit read shows the enroll alone.
        assert!(state.exists());
        let audit = run_deadbolt(
            &["--state", &state_arg, "audit"],
            Stdio::piped(),
            Stdio::piped(),
        );
        assert_eq!(audit.status, 0, "{}", audit.stderr);
        assert_eq!(audit.stdout.lines().count(), 1, "{}", audit.stdout);
        assert!(
            audit.stdout.contains("\"kind\":\"enroll\""),
            "{}",
            audit.stdout
        );
    }

    #[test]
    fn a_caller_error_keeps_its_exit_when_standard_error_refuses() {
        let dir = test_dir("full-stderr");
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        // The grant names no --ttl, a caller error at exit 2. With
        // standard error standing on /dev/full the error line cannot
        // be written, and the exit code still stands at 2, where the
        // panic on the error write exited 101 before the fix.
        let out = run_deadbolt(
            &[
                "--state",
                &state_arg,
                "grant",
                "--credential",
                "cache-key",
                "--scope",
                "bucket:read",
            ],
            Stdio::piped(),
            full_stream(),
        );
        assert_eq!(out.status, 2);
        assert!(out.stdout.is_empty());
    }

    #[test]
    fn the_scanner_answers_a_full_stdout_as_a_scan_error() {
        let dir = test_dir("scanner-clean");
        std::fs::write(dir.join("clean.md"), "clean").unwrap();
        let out = run_scanner(&dir);
        assert_eq!(out.status, 2, "{}", out.stderr);
        assert!(
            out.stderr
                .starts_with("scan error, the report could not be written because "),
            "{}",
            out.stderr
        );
        assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
        assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
    }

    #[test]
    fn the_scanner_answers_a_full_stdout_on_a_dash_hit_as_a_scan_error() {
        let dir = test_dir("scanner-dash");
        std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
        let out = run_scanner(&dir);
        assert_eq!(out.status, 2, "{}", out.stderr);
        assert!(
            out.stderr
                .starts_with("scan error, the report could not be written because "),
            "{}",
            out.stderr
        );
        assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
        assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
    }

    #[test]
    fn the_scanners_surplus_refusal_keeps_its_exit_when_standard_error_refuses() {
        let dir = test_dir("scanner-surplus-full-stderr");
        std::fs::write(dir.join("clean.md"), "clean").unwrap();
        // The surplus argument refusal at exit 2. With standard error
        // standing on /dev/full the refusal line cannot be written,
        // and the exit code still stands at 2, where the bare print
        // panicked on the failed write and exited 101 before the fix.
        let out = run_scanner_with_surplus_on_full_stderr(&dir);
        assert_eq!(out.status, 2);
        assert!(out.stdout.is_empty());
    }
}

mod audit_r5_dka25 {
    //! Audit Round 5 pins for finding DK-A25: a time to live text
    //! of digits alone whose value overflows the type draws the
    //! range wording the library speaks for a value outside the
    //! accepted range, not the not a whole number wording, which is
    //! false for it. A lettered text keeps the standing wording, so
    //! the split stands pinned at both sides.
    //!
    //! Every fixture is synthetic and names itself as one. Custody
    //! runs on the passphrase route, and no test here touches a real
    //! keychain.

    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
    const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
    const RANGE_WORDING: &str = "error: the time to live must stand from 1 to 86400 seconds\n";
    const WHOLE_WORDING: &str = "error: the time to live is not a whole number of seconds\n";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r5-dka25-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct CliOutput {
        status: i32,
        stdout: String,
        stderr: String,
    }

    fn run_cli(args: &[&str]) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
            .args(args)
            .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    /// A standing passphrase store holding one enrolled credential,
    /// answering its state path as a string beside the path itself.
    fn standing_store(tag: &str) -> (PathBuf, String) {
        let dir = test_dir(tag);
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_path = dir.join("value.txt");
        std::fs::write(&value_path, format!("{VALUE}\n")).unwrap();
        let value_arg = value_path.to_string_lossy().into_owned();
        let out = run_cli(&[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_arg,
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        (state, state_arg)
    }

    #[test]
    fn an_overflowing_time_to_live_draws_the_range_wording() {
        let (_state, state_arg) = standing_store("overflow");
        let out = run_cli(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "99999999999999999999999999",
        ]);
        assert_eq!(out.status, 2, "{}", out.stderr);
        assert_eq!(out.stderr, RANGE_WORDING);
        // The refusal stands at the parse, before the act, so nothing
        // is recorded: the audit read still shows the enroll alone.
        let audit = run_cli(&["--state", &state_arg, "audit"]);
        assert_eq!(audit.status, 0, "{}", audit.stderr);
        assert_eq!(audit.stdout.lines().count(), 1, "{}", audit.stdout);
    }

    #[test]
    fn a_lettered_time_to_live_keeps_the_whole_number_wording() {
        let (_state, state_arg) = standing_store("lettered");
        let out = run_cli(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "12x",
        ]);
        assert_eq!(out.status, 2, "{}", out.stderr);
        assert_eq!(out.stderr, WHOLE_WORDING);
    }
}

mod audit_r9_dka10 {
    //! Audit Round 9 pins for finding DK-A10: a valued option whose
    //! value slot is taken by the name of an option the same command
    //! offers refuses at parse time as a caller error, with the
    //! standing wording for an option that stands with no value after
    //! it, at exit 2, before the store opens. Before the repair the
    //! swallowed name was taken as the value: in the redeem and
    //! revoke shapes below it was looked up against the store and
    //! drew a recorded refusal at exit 1, and in the grant shape it
    //! failed the time to live parse under the wrong fault's wording.
    //!
    //! The fourth pin is a preservation pin. A value that merely
    //! begins with hyphens and names no offered option still parses
    //! as a value and meets its downstream check, exactly as before
    //! the repair; it passes against the old code by design and
    //! fails on the blanket form of the fix, which would refuse
    //! every hyphen led value with the valueless wording.
    //!
    //! Every fixture is synthetic and names itself as one. Custody
    //! runs on the passphrase route through the environment channel,
    //! and no test here touches a real keychain.

    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
    const CLI_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-cli-passphrase";
    const VALUELESS: &str = "error: an option that takes a value stands with no value after it\n";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r9-dka10-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct CliOutput {
        status: i32,
        stdout: String,
        stderr: String,
    }

    fn run_cli_pp(args: &[&str]) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
            .args(args)
            .env("DEADBOLT_PASSPHRASE", CLI_PASSPHRASE)
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn write_value_file(dir: &Path, value: &str) -> String {
        let path = dir.join("value.txt");
        std::fs::write(&path, format!("{value}\n")).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Enroll one credential and grant once against it, and answer
    /// the state path in its argument form.
    fn enroll_and_grant(dir: &Path) -> String {
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_file = write_value_file(dir, VALUE_A);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "600",
        ]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        state_arg
    }

    fn audit_line_count(state_arg: &str) -> usize {
        let out = run_cli_pp(&["--state", state_arg, "audit"]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        out.stdout.lines().count()
    }

    #[test]
    fn a_redeem_whose_token_option_swallows_the_scope_name_refuses_as_a_caller_error_and_records_nothing(
    ) {
        let dir = test_dir("redeem-swallowed");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "redeem",
            "--scope",
            "bucket:read",
            "--token",
            "--scope",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_revoke_whose_grant_option_swallows_its_own_name_refuses_as_a_caller_error_and_records_nothing(
    ) {
        let dir = test_dir("revoke-swallowed");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&["--state", &state_arg, "revoke", "--grant", "--grant"]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_grant_whose_ttl_option_swallows_the_run_name_names_the_missing_value() {
        let dir = test_dir("grant-swallowed");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "--run",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_value_that_begins_with_hyphens_and_names_no_offered_option_still_parses_as_a_value() {
        let dir = test_dir("hyphen-value");
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_file = write_value_file(&dir, VALUE_A);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "--not-an-option",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert!(out.stderr.starts_with("error: "), "{}", out.stderr);
        assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
        assert!(
            !out.stderr.contains("stands with no value after it"),
            "{}",
            out.stderr
        );
        assert!(!state.exists());
    }
}

mod audit_r9_dka35 {
    //! Audit Round 9 pin for finding DK-A35: the library's Error
    //! answers its carried filesystem error through the standard
    //! error chain. Before the repair the Error implementation
    //! carried no source override, so a caller walking source()
    //! from an Io error arrived at None and the filesystem failure
    //! that explained the refusal stayed sealed inside the variant.
    //! The second half of the pin fences the repair's shape: the
    //! variants whose payloads are text, and the redemption refusal
    //! variant, answer no source, because nothing stands beneath
    //! them to source.

    use std::error::Error as _;

    use deadbolt::{Error, RedeemRefusal};

    #[test]
    fn the_io_variant_answers_its_carried_error_as_its_source() {
        let err: Error = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "SYNTHETIC-TEST-VALUE-io-probe",
        )
        .into();
        let source = err
            .source()
            .expect("the carried filesystem error stands in the chain");
        let io = source
            .downcast_ref::<std::io::Error>()
            .expect("the source is the carried io error");
        assert_eq!(io.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            io.to_string()
                .contains("the filesystem refused an operation"),
            "{io}"
        );
    }

    #[test]
    fn the_text_and_refusal_variants_answer_no_source() {
        for err in [
            Error::Caller("probe".to_string()),
            Error::Refusal("probe".to_string()),
            Error::Corrupt("probe".to_string()),
            Error::Permission("probe".to_string()),
            Error::Redeem(RedeemRefusal::Expired),
        ] {
            assert!(err.source().is_none(), "{err}");
        }
    }
}

mod audit_r13_dka39 {
    //! Audit Round 13 pins for finding DK-A39: the swallow check
    //! DK-A10 landed consults the options the command itself offers,
    //! and the two global options, --state and --route, stand in
    //! every call but in no command's list, so a value slot taken by
    //! one of them was still swallowed as a value. In the redeem and
    //! revoke shapes below the swallowed name was looked up against
    //! the store and drew a recorded refusal at exit 1, where DK-9
    //! names a request shape that fails before the store opens as a
    //! caller error that is never recorded. In the grant shape it
    //! failed the time to live parse under the wrong fault's
    //! wording, the number wording for an option that stands with
    //! no value after it.
    //!
    //! The fourth pin is a preservation pin. A value that merely
    //! begins with hyphens and names no offered option, global or
    //! the command's own, still parses as a value and meets its
    //! downstream check, exactly as before the repair; it passes
    //! against the old code by design and fails on the blanket form
    //! of the fix, which would refuse every hyphen led value with
    //! the valueless wording.
    //!
    //! Every fixture is synthetic and names itself as one. Custody
    //! runs on the passphrase route through the environment channel,
    //! and no test here touches a real keychain.

    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
    const CLI_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-cli-passphrase";
    const VALUELESS: &str = "error: an option that takes a value stands with no value after it\n";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r13-dka39-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    struct CliOutput {
        status: i32,
        stdout: String,
        stderr: String,
    }

    fn run_cli_pp(args: &[&str]) -> CliOutput {
        let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
            .args(args)
            .env("DEADBOLT_PASSPHRASE", CLI_PASSPHRASE)
            .output()
            .unwrap();
        CliOutput {
            status: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn write_value_file(dir: &Path, value: &str) -> String {
        let path = dir.join("value.txt");
        std::fs::write(&path, format!("{value}\n")).unwrap();
        path.to_string_lossy().into_owned()
    }

    /// Enroll one credential and grant once against it, and answer
    /// the state path in its argument form.
    fn enroll_and_grant(dir: &Path) -> String {
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_file = write_value_file(dir, VALUE_A);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "600",
        ]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        state_arg
    }

    fn audit_line_count(state_arg: &str) -> usize {
        let out = run_cli_pp(&["--state", state_arg, "audit"]);
        assert_eq!(out.status, 0, "{}", out.stderr);
        out.stdout.lines().count()
    }

    #[test]
    fn a_redeem_whose_token_option_swallows_the_state_name_refuses_as_a_caller_error_and_records_nothing(
    ) {
        let dir = test_dir("redeem-swallowed-state");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            "--state",
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_revoke_whose_grant_option_swallows_the_route_name_refuses_as_a_caller_error_and_records_nothing(
    ) {
        let dir = test_dir("revoke-swallowed-route");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&["--state", &state_arg, "revoke", "--grant", "--route"]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_grant_whose_ttl_option_swallows_the_state_name_names_the_missing_value() {
        let dir = test_dir("grant-swallowed-state");
        let state_arg = enroll_and_grant(&dir);
        let before = audit_line_count(&state_arg);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "--state",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert_eq!(out.stderr, VALUELESS);
        assert_eq!(audit_line_count(&state_arg), before);
    }

    #[test]
    fn a_value_that_begins_with_hyphens_and_names_no_offered_option_still_parses_as_a_value() {
        let dir = test_dir("hyphen-value");
        let state = dir.join("state.json");
        let state_arg = state.to_string_lossy().into_owned();
        let value_file = write_value_file(&dir, VALUE_A);
        let out = run_cli_pp(&[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "enroll",
            "--name",
            "--not-an-option",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ]);
        assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
        assert!(out.stderr.starts_with("error: "), "{}", out.stderr);
        assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
        assert!(
            !out.stderr.contains("stands with no value after it"),
            "{}",
            out.stderr
        );
        assert!(!state.exists());
    }
}

mod audit_r41_dka49 {
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
        let err = deadbolt::redeem(&state, &open(&custody), &"0".repeat(64), &read_scope(), T0)
            .unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        assert!(!matches!(err, Error::Redeem(_)), "{err}");
        let entries = dir_entries(&dir);
        assert!(
            entries.iter().all(|name| !name.contains(".tmp-")),
            "a sealed temp copy stands in {entries:?}"
        );
        assert_eq!(entries, ["state.json", "state.json.lock"]);
    }
}

mod audit_r48_dka50 {
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

    use std::path::{Path, PathBuf};
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

    fn enroll_a(ctx: &Ctx, state: &Path) {
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

    fn audit_kinds(ctx: &Ctx, state: &Path) -> Vec<String> {
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
        let err = deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 50)
            .unwrap_err();
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
        let err = deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 50)
            .unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err}");
        assert_eq!(err.to_string(), FALLBACK_WORDING);
        assert_eq!(std::fs::read(&state).unwrap(), before);
        assert_eq!(audit_kinds(&ctx, &state), ["enroll", "grant", "retire"]);
    }
}
