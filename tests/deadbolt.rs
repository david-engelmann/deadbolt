//! Protocol tests for the broker core, pinning DK-1 to DK-14 over
//! stores the envelope of DK-15 to DK-24 seals.
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

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::{CustodyLoad, FixtureCustody, KeyCustody};
use deadbolt::{Error, PassphraseSource, RedeemRefusal, Route, Scope, Unlock, Zeroizing};

const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
const VALUE_B: &str = "SYNTHETIC-TEST-VALUE-beta-0002";
const VALUE_C: &str = "SYNTHETIC-TEST-VALUE-gamma-0003";
const VALUE_D: &str = "SYNTHETIC-TEST-VALUE-delta-0004";
const STORE_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-store-passphrase";
const CLI_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-cli-passphrase";
const T0: i64 = 1_700_000_000;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("deadbolt-test-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn scope(resource: &str, action: &str) -> Scope {
    Scope {
        resource: resource.to_string(),
        action: action.to_string(),
    }
}

fn read_scope() -> Scope {
    scope("bucket", "read")
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

fn state_text(state: &PathBuf) -> String {
    std::fs::read_to_string(state).unwrap()
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = (bytes[index] as char).to_digit(16).unwrap();
        let low = (bytes[index + 1] as char).to_digit(16).unwrap();
        out.push((high * 16 + low) as u8);
        index += 2;
    }
    out
}

/// Decrypt the document inside an envelope under a known key.
///
/// The header bytes the tag authenticates are the header exactly as
/// the envelope carries it, and the rendering of the parsed header
/// stands identical to those bytes because the writer renders the
/// header in the canonical sorted form.
fn decrypt_document(raw: &str, key: &deadbolt::custody::StoreKey) -> String {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    let envelope: serde_json::Value = serde_json::from_str(raw).unwrap();
    let header = envelope["header"].to_string();
    let nonce = hex_bytes(envelope["nonce"].as_str().unwrap());
    let ciphertext = hex_bytes(envelope["ciphertext"].as_str().unwrap());
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let plain = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: header.as_bytes(),
            },
        )
        .unwrap();
    String::from_utf8(plain).unwrap()
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
    let key = deadbolt::custody::derive_key(CLI_PASSPHRASE.as_bytes(), &salt);
    serde_json::from_str(&decrypt_document(&raw, &key)).unwrap()
}

fn set_mode(state: &PathBuf, mode: u32) {
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
}

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
    assert_eq!(predecessor["scopes"].as_array().unwrap().len(), 2);
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
