//! Envelope tests for the broker core, pinning DK-15 to DK-24.
//! Every fixture is synthetic and names itself as one. Credential
//! shaped strings and passphrases carry the SYNTHETIC-TEST-VALUE
//! marker so no fixture can be mistaken for a real key.
//!
//! No test here touches a real keychain, a real D-Bus session, or a
//! real desktop service. Custody dependent behavior runs against
//! the fixture backend behind the same seam the platform backends
//! stand behind, and the passphrase route runs directly, which is
//! the standing limit DK-24 names.

use std::path::{Path, PathBuf};
use std::process::Command;

// The shared test harness home of audit finding DK-A19. Items a
// suite does not use stand allowed dead in its crate.
#[allow(dead_code)]
mod common;

use common::{decrypt_document, hex, hex_bytes, read_scope, set_mode, state_text};
use deadbolt::custody::{CustodyLoad, FixtureCustody, KeyCustody, StoreKey};
use deadbolt::{Error, PassphraseSource, Route, Unlock, Zeroizing};

const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const WRONG_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-wrong-lantern-9911";
const T0: i64 = 1_700_000_000;

const LOCKED_NO_SERVICE: &str = "the store is locked because the keychain service is not available";
const LOCKED_NO_ENTRY: &str = "the store is locked because its keychain entry is missing, and the broker holds no other copy and no fallback will be tried";
const LOCKED_BAD_KEY: &str = "the store is locked because the key did not open it";
const LOCKED_TRANSPLANT: &str =
    "the store is locked because the envelope does not belong to this store";

fn test_dir(tag: &str) -> PathBuf {
    common::test_dir("deadbolt-envelope-test", tag)
}

/// A passphrase supply answering one fixed answer, or none.
struct Supply(Option<&'static [u8]>);

impl PassphraseSource for Supply {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        self.0.map(|bytes| Zeroizing::new(bytes.to_vec()))
    }
}

/// The per test custody context, one fixture backend and one
/// passphrase supply standing behind every call the test makes.
struct Ctx {
    custody: FixtureCustody,
    supply: Supply,
}

impl Ctx {
    fn with_passphrase(passphrase: &'static str) -> Ctx {
        Ctx {
            custody: FixtureCustody::new(),
            supply: Supply(Some(passphrase.as_bytes())),
        }
    }

    fn no_passphrase() -> Ctx {
        Ctx {
            custody: FixtureCustody::new(),
            supply: Supply(None),
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

fn envelope_json(state: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&state_text(state)).unwrap()
}

fn write_store_file(dir: &Path, text: &str) -> PathBuf {
    let state = dir.join("state.json");
    std::fs::write(&state, text).unwrap();
    set_mode(&state, 0o600);
    state
}

/// The decrypted document of a keychain store the context's fixture
/// serves.
fn document_text(ctx: &Ctx, state: &PathBuf) -> String {
    let raw = state_text(state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let store_id = envelope["header"]["store"].as_str().unwrap();
    let key = match ctx.custody.load_key(store_id) {
        CustodyLoad::Key(key) => key,
        _ => panic!("the fixture holds no key for this store"),
    };
    decrypt_document(&raw, &key)
}

/// The decrypted document of a passphrase store under the context's
/// passphrase.
fn passphrase_document_text(ctx: &Ctx, state: &PathBuf) -> String {
    let raw = state_text(state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let salt = hex_bytes(envelope["header"]["kdf"]["salt"].as_str().unwrap());
    let salt: [u8; 16] = salt.try_into().unwrap();
    let passphrase = ctx.supply.passphrase().unwrap();
    let key = deadbolt::custody::derive_key(&passphrase, &salt).unwrap();
    decrypt_document(&raw, &key)
}

/// Seal a document under a stated header and key, test side.
///
/// The transplant and inner corruption pins build envelopes the
/// broker would never write, an honest envelope carrying a document
/// that belongs to another store or no store, and this helper is
/// the whole of that construction.
fn seal_text(header: &serde_json::Value, key: &StoreKey, plaintext: &str) -> String {
    use chacha20poly1305::aead::{Aead, Payload};
    use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
    let header_raw = header.to_string();
    let nonce = [7u8; 24];
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: header_raw.as_bytes(),
            },
        )
        .unwrap();
    format!(
        "{{\"ciphertext\":\"{}\",\"format\":\"deadbolt-envelope/1\",\"header\":{header_raw},\"nonce\":\"{}\"}}",
        hex(&ciphertext),
        hex(&nonce)
    )
}

/// Create a keychain store holding the value and one live grant,
/// and answer its grant token.
fn keychain_store(ctx: &Ctx, dir: &Path) -> (PathBuf, String) {
    let state = dir.join("state.json");
    deadbolt::enroll(
        &state,
        &ctx.creating(Route::Keychain),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap();
    let receipt = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0,
    )
    .unwrap();
    (state, receipt.token)
}

/// Create a passphrase store holding the value and one live grant,
/// and answer its grant token.
fn passphrase_store(ctx: &Ctx, dir: &Path) -> (PathBuf, String) {
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
    let receipt = deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0,
    )
    .unwrap();
    (state, receipt.token)
}

/// Whether any fragment of eight or more characters of the needle
/// stands in the haystack, the absence DK-15's containment pin and
/// section 9 of the design require.
fn contains_fragment(haystack: &[u8], needle: &str) -> bool {
    let text = String::from_utf8_lossy(haystack);
    needle
        .as_bytes()
        .windows(8)
        .any(|window| text.contains(std::str::from_utf8(window).unwrap()))
}

fn sorted_keys(value: &serde_json::Value) -> Vec<String> {
    let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    keys
}

// DK-15, the envelope and its field sets.

#[test]
fn envelope_field_sets_on_each_route() {
    let keychain_ctx = Ctx::with_passphrase(PASSPHRASE);
    let keychain_dir = test_dir("fields-keychain");
    let (keychain_state, _) = keychain_store(&keychain_ctx, &keychain_dir);
    let envelope = envelope_json(&keychain_state);
    assert_eq!(
        sorted_keys(&envelope),
        ["ciphertext", "format", "header", "nonce"]
    );
    assert_eq!(envelope["format"], "deadbolt-envelope/1");
    let header = &envelope["header"];
    assert_eq!(sorted_keys(header), ["payload", "route", "store"]);
    assert_eq!(header["payload"], "deadbolt-state/1");
    assert_eq!(header["route"], "keychain");
    let store_id = header["store"].as_str().unwrap();
    assert_eq!(store_id.len(), 64);
    assert!(store_id
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_eq!(hex_bytes(envelope["nonce"].as_str().unwrap()).len(), 24);

    let passphrase_ctx = Ctx::with_passphrase(PASSPHRASE);
    let passphrase_dir = test_dir("fields-passphrase");
    let (passphrase_state, _) = passphrase_store(&passphrase_ctx, &passphrase_dir);
    let envelope = envelope_json(&passphrase_state);
    assert_eq!(
        sorted_keys(&envelope),
        ["ciphertext", "format", "header", "nonce"]
    );
    let header = &envelope["header"];
    assert_eq!(sorted_keys(header), ["kdf", "payload", "route", "store"]);
    assert_eq!(header["route"], "passphrase");
    let kdf = &header["kdf"];
    assert_eq!(sorted_keys(kdf), ["algorithm", "memory", "salt", "time"]);
    assert_eq!(kdf["algorithm"], "argon2id");
    // The header of a passphrase store stands against the parameters
    // DK-19 pins for the writer.
    assert_eq!(kdf["memory"], 65_536);
    assert_eq!(kdf["time"], 3);
    assert_eq!(hex_bytes(kdf["salt"].as_str().unwrap()).len(), 16);
}

#[test]
fn a_further_field_at_any_level_refuses_as_corrupt() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("extra-field");
    let (state, _) = keychain_store(&ctx, &dir);
    let base = envelope_json(&state);
    let mut variants: Vec<(String, serde_json::Value)> = Vec::new();
    let mut envelope_level = base.clone();
    envelope_level["surprise"] = serde_json::json!(true);
    variants.push(("at the envelope level".to_string(), envelope_level));
    let mut header_level = base.clone();
    header_level["header"]["surprise"] = serde_json::json!(true);
    variants.push(("at the header level".to_string(), header_level));
    for (label, variant) in variants {
        let variant_dir = test_dir("extra-field-variant");
        let variant_state = write_store_file(&variant_dir, &variant.to_string());
        let err = deadbolt::audit(&variant_state, &ctx.open(), T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(state_text(&variant_state), variant.to_string(), "{label}");
    }

    let pp_dir = test_dir("extra-field-kdf");
    let (pp_state, _) = passphrase_store(&ctx, &pp_dir);
    let mut kdf_level = envelope_json(&pp_state);
    kdf_level["header"]["kdf"]["surprise"] = serde_json::json!(true);
    let variant_state =
        write_store_file(&test_dir("extra-field-kdf-variant"), &kdf_level.to_string());
    let err = deadbolt::audit(&variant_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "at the kdf level: {err}");

    // A duplicated key at the envelope level refuses the same way.
    let raw = state_text(&state);
    let duplicated = raw.replacen(
        "\"format\":\"deadbolt-envelope/1\"",
        "\"format\":\"deadbolt-envelope/1\",\"format\":\"deadbolt-envelope/1\"",
        1,
    );
    assert_ne!(duplicated, raw);
    let dup_state = write_store_file(&test_dir("extra-field-dup"), &duplicated);
    let err = deadbolt::audit(&dup_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "duplicated key: {err}");
}

// DK-16, the cipher, its nonce discipline, and its associated data.

#[test]
fn two_publishes_from_one_loaded_state_draw_fresh_nonces() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("fresh-nonces");
    let state = dir.join("state.json");
    deadbolt::enroll(
        &state,
        &ctx.creating(Route::Keychain),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap();
    let first = envelope_json(&state);
    deadbolt::grant(
        &state,
        &ctx.open(),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0,
    )
    .unwrap();
    let second = envelope_json(&state);
    assert_ne!(first["nonce"], second["nonce"]);
    assert_ne!(first["ciphertext"], second["ciphertext"]);
    assert_eq!(first["header"], second["header"]);
}

#[test]
fn a_reordered_header_fails_authentication() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("header-reorder");
    let (state, _) = keychain_store(&ctx, &dir);
    let raw = state_text(&state);
    let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let header = &envelope["header"];
    let reordered = format!(
        "{{\"route\":\"keychain\",\"store\":\"{}\",\"payload\":\"deadbolt-state/1\"}}",
        header["store"].as_str().unwrap()
    );
    let edited = raw.replacen(&header.to_string(), &reordered, 1);
    assert_ne!(edited, raw);
    let edited_state = write_store_file(&test_dir("header-reorder-copy"), &edited);
    // Every value in the edited header stands identical to the
    // original, so only the authenticated bytes changed.
    let err = deadbolt::audit(&edited_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&edited_state), edited);
}

#[test]
fn a_ciphertext_moved_between_envelopes_fails_authentication() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let (state_a, _) = keychain_store(&ctx, &test_dir("moved-a"));
    let (state_b, _) = keychain_store(&ctx, &test_dir("moved-b"));
    let mut moved = envelope_json(&state_a);
    moved["ciphertext"] = envelope_json(&state_b)["ciphertext"].clone();
    let moved_state = write_store_file(&test_dir("moved-copy"), &moved.to_string());
    let err = deadbolt::audit(&moved_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
}

#[test]
fn a_corrupted_ciphertext_byte_fails_authentication() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("ciphertext-byte");
    let (state, _) = keychain_store(&ctx, &dir);
    let mut edited = envelope_json(&state);
    let ciphertext = edited["ciphertext"].as_str().unwrap().to_string();
    let flipped = format!(
        "{}{}",
        &ciphertext[..ciphertext.len() - 1],
        if ciphertext.ends_with('0') { "1" } else { "0" }
    );
    edited["ciphertext"] = serde_json::json!(flipped);
    let edited_state = write_store_file(&test_dir("ciphertext-byte-copy"), &edited.to_string());
    let err = deadbolt::audit(&edited_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&edited_state), edited.to_string());
}

// DK-17, strict reading of the envelope.

#[test]
fn envelope_shape_variants_refuse_as_corruption() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let pp_dir = test_dir("shapes-passphrase");
    let (pp_state, _) = passphrase_store(&ctx, &pp_dir);
    let pp = envelope_json(&pp_state);
    let kc_dir = test_dir("shapes-keychain");
    let (kc_state, _) = keychain_store(&ctx, &kc_dir);
    let kc = envelope_json(&kc_state);

    let mut variants: Vec<(String, serde_json::Value)> = Vec::new();
    let mut v = pp.clone();
    v["format"] = serde_json::json!("deadbolt-envelope/2");
    variants.push(("a successor format this build does not read".to_string(), v));
    let mut v = pp.clone();
    v.as_object_mut().unwrap().remove("format");
    variants.push(("the format field missing".to_string(), v));
    let mut v = pp.clone();
    v["header"] = serde_json::json!("a string, not an object");
    variants.push(("the header of the wrong type".to_string(), v));
    let mut v = pp.clone();
    v["nonce"] = serde_json::json!("00".repeat(23));
    variants.push(("a nonce of 23 bytes".to_string(), v));
    let mut v = pp.clone();
    v["nonce"] = serde_json::json!("0".repeat(47));
    variants.push(("a nonce of odd length".to_string(), v));
    let mut v = pp.clone();
    v["nonce"] = serde_json::json!("zz".repeat(24));
    variants.push(("a nonce that is not hexadecimal".to_string(), v));
    let mut v = pp.clone();
    let store = v["header"]["store"].as_str().unwrap().to_string();
    v["header"]["store"] = serde_json::json!(format!("A{}", &store[1..]));
    variants.push(("a store identifier with an uppercase letter".to_string(), v));
    let mut v = pp.clone();
    v["header"]["store"] = serde_json::json!("a".repeat(63));
    variants.push(("a store identifier of 63 characters".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["salt"] = serde_json::json!("00".repeat(15));
    variants.push(("a salt of 15 bytes".to_string(), v));
    let mut v = pp.clone();
    v["ciphertext"] = serde_json::json!("00".repeat(15));
    variants.push(("a ciphertext shorter than its tag".to_string(), v));
    let mut v = pp.clone();
    v["ciphertext"] = serde_json::json!("zz".repeat(64));
    variants.push(("a ciphertext that is not hexadecimal".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["memory"] = serde_json::json!(8_191);
    variants.push(("a memory cost below the reader floor".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["memory"] = serde_json::json!(1_048_577);
    variants.push(("a memory cost above the reader ceiling".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["time"] = serde_json::json!(0);
    variants.push(("a time cost of zero".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["time"] = serde_json::json!(11);
    variants.push(("a time cost above the reader ceiling".to_string(), v));
    let mut v = pp.clone();
    v["header"]["route"] = serde_json::json!("vault");
    variants.push(("a route the format does not name".to_string(), v));
    let mut v = pp.clone();
    v["header"]["payload"] = serde_json::json!("deadbolt-state/2");
    variants.push(("a payload format this broker does not read".to_string(), v));
    let mut v = pp.clone();
    v["header"]["kdf"]["algorithm"] = serde_json::json!("argon2i");
    variants.push(("a KDF algorithm this broker does not carry".to_string(), v));
    let mut v = pp.clone();
    v["header"].as_object_mut().unwrap().remove("kdf");
    variants.push(("a passphrase header with no kdf field".to_string(), v));
    let mut v = kc.clone();
    v["header"]["kdf"] = serde_json::json!({
        "algorithm": "argon2id",
        "memory": 65_536,
        "time": 3,
        "salt": "00".repeat(16),
    });
    variants.push(("a keychain header carrying a kdf field".to_string(), v));

    for (label, variant) in variants {
        let variant_state = write_store_file(&test_dir("shape-variant"), &variant.to_string());
        let err = deadbolt::audit(&variant_state, &ctx.open(), T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(
            state_text(&variant_state),
            variant.to_string(),
            "{label}: the file must never be reset"
        );
    }
}

#[test]
fn envelope_corruption_answers_ahead_of_any_custody_outcome() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("corruption-order");
    let (state, _) = keychain_store(&ctx, &dir);
    ctx.custody.fail_with("the fixture service is down");
    // The standing store under an armed failure draws the custody
    // refusal, which proves the arm is live.
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_NO_SERVICE);
    // The same store with a broken envelope shape answers
    // corruption instead, because envelope reading stands ahead of
    // custody in the order DK-22 names.
    let mut broken = envelope_json(&state);
    broken["nonce"] = serde_json::json!("00".repeat(23));
    let broken_state = write_store_file(&test_dir("corruption-order-copy"), &broken.to_string());
    let err = deadbolt::audit(&broken_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    ctx.custody.clear_failure();
}

// DK-19, the passphrase route.

#[test]
fn derive_key_with_params_honors_the_recorded_parameters() {
    let salt = [4u8; 16];
    let pinned = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt).unwrap();
    let at_pinned = deadbolt::custody::derive_key_with_params(
        PASSPHRASE.as_bytes(),
        &salt,
        deadbolt::custody::ARGON2_MEMORY_KIB,
        deadbolt::custody::ARGON2_TIME,
    )
    .unwrap();
    assert_eq!(pinned, at_pinned);
    let lighter =
        deadbolt::custody::derive_key_with_params(PASSPHRASE.as_bytes(), &salt, 8_192, 1).unwrap();
    assert_ne!(pinned, lighter);
    let lighter_again =
        deadbolt::custody::derive_key_with_params(PASSPHRASE.as_bytes(), &salt, 8_192, 1).unwrap();
    assert_eq!(lighter, lighter_again);
}

#[test]
fn a_wrong_passphrase_draws_the_locked_refusal_and_records_nothing() {
    let right = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("wrong-passphrase");
    let (state, token) = passphrase_store(&right, &dir);
    let before = state_text(&state);
    let wrong = Ctx::with_passphrase(WRONG_PASSPHRASE);
    let err = deadbolt::redeem(&state, &wrong.open(), &token, &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&state), before);
    let entries = deadbolt::audit(&state, &right.open(), T0).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(
        deadbolt::redeem(&state, &right.open(), &token, &read_scope(), T0).unwrap(),
        VALUE
    );
}

#[test]
fn an_empty_or_missing_passphrase_is_a_caller_error() {
    let dir = test_dir("empty-passphrase");
    let state = dir.join("state.json");
    let empty = Ctx::with_passphrase("");
    let err = deadbolt::enroll(
        &state,
        &empty.creating(Route::Passphrase),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert!(!state.exists());
    let none = Ctx::no_passphrase();
    let err = deadbolt::enroll(
        &state,
        &none.creating(Route::Passphrase),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert_eq!(
        format!("{err}"),
        "the passphrase route needs a passphrase and none was supplied"
    );
    assert!(!state.exists());
    static OVERSIZED: [u8; 1025] = [b'x'; 1025];
    let big_ctx = Ctx {
        custody: FixtureCustody::new(),
        supply: Supply(Some(&OVERSIZED)),
    };
    let err = deadbolt::enroll(
        &state,
        &big_ctx.creating(Route::Passphrase),
        "cache-key",
        VALUE,
        &[read_scope()],
        T0,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert!(!state.exists());

    // An empty passphrase against a standing passphrase store is a
    // caller error too, and writes nothing.
    let right = Ctx::with_passphrase(PASSPHRASE);
    let pp_dir = test_dir("empty-passphrase-standing");
    let (pp_state, _) = passphrase_store(&right, &pp_dir);
    let before = state_text(&pp_state);
    let err = deadbolt::audit(&pp_state, &empty.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert_eq!(state_text(&pp_state), before);
}

// DK-20, route binding and creation.

#[test]
fn creation_without_a_route_is_a_caller_error_and_creates_no_state_file() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("creation-no-route");
    let state = dir.join("state.json");
    let err =
        deadbolt::enroll(&state, &ctx.open(), "cache-key", VALUE, &[read_scope()], T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert_eq!(
        format!("{err}"),
        "a store creating act must name its custody route, keychain or passphrase"
    );
    assert!(!state.exists());
}

#[test]
fn the_route_option_beside_a_standing_store_is_a_caller_error() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("route-beside-store");
    let (state, token) = keychain_store(&ctx, &dir);
    let before = state_text(&state);
    for route in [Route::Keychain, Route::Passphrase] {
        let err = deadbolt::audit(&state, &ctx.creating(route), T0).unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{err}");
        assert_eq!(
            format!("{err}"),
            "the custody route stands beside a store that already stands"
        );
        let err =
            deadbolt::redeem(&state, &ctx.creating(route), &token, &read_scope(), T0).unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{err}");
    }
    assert_eq!(state_text(&state), before);
    // The store itself stands untouched and still opens.
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0).unwrap(),
        VALUE
    );
}

#[test]
fn a_transplanted_document_refuses_as_locked() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let (state_a, _) = keychain_store(&ctx, &test_dir("transplant-a"));
    let (state_b, _) = keychain_store(&ctx, &test_dir("transplant-b"));
    // Store A's document, sealed under store B's key and header and
    // standing at a fresh path, authenticates and then refuses,
    // because the document names A and the header names B.
    let document_a = document_text(&ctx, &state_a);
    let envelope_b = envelope_json(&state_b);
    let store_b = envelope_b["header"]["store"].as_str().unwrap();
    let key_b = match ctx.custody.load_key(store_b) {
        CustodyLoad::Key(key) => key,
        _ => panic!("the fixture holds no key for store B"),
    };
    let sealed = seal_text(&envelope_b["header"], &key_b, &document_a);
    let standing = write_store_file(&test_dir("transplant-standing"), &sealed);
    let err = deadbolt::audit(&standing, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_TRANSPLANT);

    // A document naming an identifier inside a passphrase envelope
    // refuses the same way.
    let (pp_state, _) = passphrase_store(&ctx, &test_dir("transplant-passphrase"));
    let pp_envelope = envelope_json(&pp_state);
    let salt = hex_bytes(pp_envelope["header"]["kdf"]["salt"].as_str().unwrap());
    let salt: [u8; 16] = salt.try_into().unwrap();
    let pp_key = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt).unwrap();
    let sealed = seal_text(&pp_envelope["header"], &pp_key, &document_a);
    let standing = write_store_file(&test_dir("transplant-standing-pp"), &sealed);
    let err = deadbolt::audit(&standing, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_TRANSPLANT);
}

#[test]
fn a_passphrase_store_never_consults_the_keychain() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("passphrase-no-keychain");
    let (state, token) = passphrase_store(&ctx, &dir);
    ctx.custody.fail_with("the fixture service is down");
    // The armed fixture would fail any keychain consultation, and
    // the passphrase store opens without one.
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0).unwrap(),
        VALUE
    );
    ctx.custody.clear_failure();
}

// DK-22, the unlock refusal classes.

#[test]
fn a_missing_keychain_entry_refuses_locked_with_no_fallback() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("missing-entry");
    let (state, _) = keychain_store(&ctx, &dir);
    let store_id = envelope_json(&state)["header"]["store"]
        .as_str()
        .unwrap()
        .to_string();
    let before = state_text(&state);
    ctx.custody.delete_key(&store_id).unwrap();
    // The context supplies a passphrase, and the store still refuses
    // with the absence wording, because no fallback is ever tried
    // for a keychain store.
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_NO_ENTRY);
    assert_eq!(state_text(&state), before);
}

#[test]
fn a_keychain_service_failure_refuses_locked() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("service-failure");
    let (state, token) = keychain_store(&ctx, &dir);
    let before = state_text(&state);
    ctx.custody.fail_with("the fixture service is down");
    let err = deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_NO_SERVICE);
    assert_eq!(state_text(&state), before);
    ctx.custody.clear_failure();
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0).unwrap(),
        VALUE
    );
}

#[test]
fn a_wrong_keychain_key_draws_the_same_locked_refusal() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("wrong-key");
    let (state, _) = keychain_store(&ctx, &dir);
    let store_id = envelope_json(&state)["header"]["store"]
        .as_str()
        .unwrap()
        .to_string();
    ctx.custody
        .store_key(&store_id, &StoreKey::new([9u8; 32]))
        .unwrap();
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
}

#[test]
fn edited_kdf_parameters_draw_the_locked_refusal() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("edited-parameters");
    let (state, _) = passphrase_store(&ctx, &dir);
    let mut edited = envelope_json(&state);
    edited["header"]["kdf"]["memory"] = serde_json::json!(65_537);
    let edited_state = write_store_file(&test_dir("edited-parameters-copy"), &edited.to_string());
    // The edited parameters stand inside the reader range, so the
    // envelope reads, and the refusal is the authentication wording
    // of DK-22, the same words a wrong passphrase draws.
    let err = deadbolt::audit(&edited_state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    assert_eq!(format!("{err}"), LOCKED_BAD_KEY);
    assert_eq!(state_text(&edited_state), edited.to_string());
}

#[test]
fn an_envelope_over_a_corrupt_document_names_the_document() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let store_id = "ab".repeat(32);
    let key = StoreKey::new([3u8; 32]);
    ctx.custody.store_key(&store_id, &key).unwrap();
    let header = serde_json::json!({
        "payload": "deadbolt-state/1",
        "route": "keychain",
        "store": store_id,
    });
    let sealed = seal_text(&header, &key, "this is not a state document");
    let standing = write_store_file(&test_dir("corrupt-inner"), &sealed);
    let err = deadbolt::audit(&standing, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    assert_eq!(
        format!("{err}"),
        "the state file does not parse as the deadbolt-state/1 format"
    );
}

// DK-21, the unlock discipline.

#[test]
fn a_failed_unlock_writes_nothing_and_records_nothing() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("failed-unlock");
    let (state, token) = keychain_store(&ctx, &dir);
    let before = state_text(&state);
    let listing_before: Vec<String> = dir_entries(&dir);
    ctx.custody.fail_with("the fixture service is down");
    let err = deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    ctx.custody.clear_failure();
    let store_id = envelope_json(&state)["header"]["store"]
        .as_str()
        .unwrap()
        .to_string();
    let saved = match ctx.custody.load_key(&store_id) {
        CustodyLoad::Key(key) => key,
        _ => panic!("the fixture holds no key for this store"),
    };
    ctx.custody.delete_key(&store_id).unwrap();
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    ctx.custody.store_key(&store_id, &saved).unwrap();
    assert_eq!(state_text(&state), before);
    assert_eq!(dir_entries(&dir), listing_before);
    // The audit sequence stands as the last successful acts left
    // it, enroll and grant and nothing for the failed unlocks.
    let entries = deadbolt::audit(&state, &ctx.open(), T0).unwrap();
    assert_eq!(entries.len(), 2);
}

fn dir_entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// Portability adaptation gates POSIX 0600 mode checks to Unix per the
// portability amendment in CONTRACT.md.
#[cfg(unix)]
#[test]
fn the_permission_gate_stands_before_any_custody() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("gate-before-custody");
    let (state, _) = keychain_store(&ctx, &dir);
    set_mode(&state, 0o644);
    ctx.custody.fail_with("the fixture service is down");
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Permission(_)), "{err}");
    ctx.custody.clear_failure();
    set_mode(&state, 0o600);

    let pp_dir = test_dir("gate-before-derivation");
    let (pp_state, _) = passphrase_store(&ctx, &pp_dir);
    set_mode(&pp_state, 0o644);
    let wrong = Ctx::with_passphrase(WRONG_PASSPHRASE);
    let err = deadbolt::audit(&pp_state, &wrong.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Permission(_)), "{err}");
    set_mode(&pp_state, 0o600);
}

// DK-15 and section 9 of the design, the headline containment pin.

#[test]
fn no_plaintext_stands_in_a_watched_directory_on_either_route() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    for route in [Route::Keychain, Route::Passphrase] {
        let dir = test_dir("watched");
        let state = dir.join("state.json");
        deadbolt::enroll(
            &state,
            &ctx.creating(route),
            "cache-key",
            VALUE,
            &[read_scope()],
            T0,
        )
        .unwrap();
        let receipt = deadbolt::grant(
            &state,
            &ctx.open(),
            "cache-key",
            &read_scope(),
            600,
            None,
            T0,
        )
        .unwrap();
        assert_eq!(
            deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0).unwrap(),
            VALUE
        );
        // After every act the directory holds the state file and
        // its lock file and nothing else, and no file in it carries
        // the value whole or in any fragment of eight or more
        // characters, nor the token, nor the token's hash.
        assert_eq!(dir_entries(&dir), ["state.json", "state.json.lock"]);
        let document = match route {
            Route::Keychain => document_text(&ctx, &state),
            Route::Passphrase => passphrase_document_text(&ctx, &state),
        };
        let document_json: serde_json::Value = serde_json::from_str(&document).unwrap();
        let hash = document_json["grants"][0]["token_hash"].as_str().unwrap();
        for name in dir_entries(&dir) {
            let bytes = std::fs::read(dir.join(&name)).unwrap();
            assert!(
                !contains_fragment(&bytes, VALUE),
                "{route:?}: the value stands in {name}"
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains(&receipt.token),
                "{route:?}: the token stands in {name}"
            );
            assert!(
                !String::from_utf8_lossy(&bytes).contains(hash),
                "{route:?}: the token hash stands in {name}"
            );
            if route == Route::Passphrase {
                assert!(
                    !contains_fragment(&bytes, PASSPHRASE),
                    "the passphrase stands in {name}"
                );
            }
        }
    }
}

// DK-23, adoption of a plaintext store.

/// A standing plaintext store, written from the decrypted document
/// of a passphrase store so its stamp stands empty exactly as a
/// store written before the envelope existed stands.
fn plaintext_store(ctx: &Ctx, dir: &Path) -> (PathBuf, String) {
    let source_dir = test_dir("adoption-source");
    let (source, token) = passphrase_store(ctx, &source_dir);
    let document = passphrase_document_text(ctx, &source);
    let state = write_store_file(dir, &document);
    (state, token)
}

#[test]
fn adoption_on_the_keychain_route() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("adopt-keychain");
    let (state, token) = plaintext_store(&ctx, &dir);
    let receipt = deadbolt::grant(
        &state,
        &ctx.creating(Route::Keychain),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 10,
    )
    .unwrap();
    // The file is an envelope afterward, on the keychain route.
    let envelope = envelope_json(&state);
    assert_eq!(envelope["format"], "deadbolt-envelope/1");
    assert_eq!(envelope["header"]["route"], "keychain");
    // The stamp inside the document names the header's identifier.
    let document = document_text(&ctx, &state);
    let document_json: serde_json::Value = serde_json::from_str(&document).unwrap();
    assert_eq!(
        document_json["store_id"].as_str().unwrap(),
        envelope["header"]["store"].as_str().unwrap()
    );
    // The audit sequence stays gapless across the adoption entry,
    // which names the route and stands ahead of the adopting act.
    let entries = deadbolt::audit(&state, &ctx.open(), T0 + 11).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["enroll", "grant", "adopt", "grant"]);
    assert_eq!(entries[2].outcome, "adopted, keychain route");
    assert_eq!(entries[2].at, T0 + 10);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    // Every prior act still redeems.
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &token, &read_scope(), T0 + 12).unwrap(),
        VALUE
    );
    assert_eq!(
        deadbolt::redeem(&state, &ctx.open(), &receipt.token, &read_scope(), T0 + 12).unwrap(),
        VALUE
    );
}

#[test]
fn adoption_on_the_passphrase_route() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("adopt-passphrase");
    let (state, token) = plaintext_store(&ctx, &dir);
    let value = deadbolt::redeem(
        &state,
        &ctx.creating(Route::Passphrase),
        &token,
        &read_scope(),
        T0 + 10,
    )
    .unwrap();
    assert_eq!(value, VALUE);
    let envelope = envelope_json(&state);
    assert_eq!(envelope["format"], "deadbolt-envelope/1");
    assert_eq!(envelope["header"]["route"], "passphrase");
    // The document inside a passphrase envelope names no identifier.
    let document = passphrase_document_text(&ctx, &state);
    let document_json: serde_json::Value = serde_json::from_str(&document).unwrap();
    assert!(document_json.get("store_id").is_none());
    let entries = deadbolt::audit(&state, &ctx.open(), T0 + 11).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["enroll", "grant", "adopt", "redeem"]);
    assert_eq!(entries[2].outcome, "adopted, passphrase route");
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
}

#[test]
fn adoption_without_a_route_is_a_caller_error_and_writes_nothing() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("adopt-no-route");
    let (state, _) = plaintext_store(&ctx, &dir);
    let before = state_text(&state);
    let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert_eq!(
        format!("{err}"),
        "the store stands in plaintext and its adoption must name a custody route"
    );
    assert_eq!(state_text(&state), before);
}

#[test]
fn a_corrupt_plaintext_store_is_never_adopted() {
    let ctx = Ctx::with_passphrase(PASSPHRASE);
    let dir = test_dir("adopt-corrupt");
    let (state, _) = plaintext_store(&ctx, &dir);
    let mut document: serde_json::Value = serde_json::from_str(&state_text(&state)).unwrap();
    document["audit"][1]["seq"] = serde_json::json!(7);
    let corrupted = write_store_file(&test_dir("adopt-corrupt-copy"), &document.to_string());
    let err = deadbolt::grant(
        &corrupted,
        &ctx.creating(Route::Keychain),
        "cache-key",
        &read_scope(),
        600,
        None,
        T0 + 10,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Corrupt(_)), "{err}");
    // The file still stands as the corrupt plaintext, and no
    // envelope was written over it.
    assert_eq!(state_text(&corrupted), document.to_string());
}

// DK-19 and DK-20 on the command line.

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli_env(args: &[&str], passphrase: Option<&str>) -> CliOutput {
    let mut command = Command::new(env!("CARGO_BIN_EXE_deadbolt"));
    command.args(args);
    match passphrase {
        Some(value) => {
            command.env("DEADBOLT_PASSPHRASE", value);
        }
        None => {
            command.env_remove("DEADBOLT_PASSPHRASE");
        }
    }
    let output = command.output().unwrap();
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

#[test]
fn cli_route_option_standing() {
    let dir = test_dir("cli-route");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE);
    // Creation without the route option is a caller error and
    // creates no state file, even with a passphrase standing by.
    let out = run_cli_env(
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
        Some(PASSPHRASE),
    );
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(!state.exists());
    // A route value outside the two the option names is a caller
    // error.
    let out = run_cli_env(
        &[
            "--state",
            &state_arg,
            "--route",
            "vault",
            "enroll",
            "--name",
            "cache-key",
            "--value-file",
            &value_file,
            "--scope",
            "bucket:read",
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(!state.exists());
    // Audit against a store that does not stand needs no route.
    let out = run_cli_env(&["--state", &state_arg, "audit"], None);
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, "");
    // Creation with the route stands, and the route beside the
    // standing store is a caller error from then on.
    let out = run_cli_env(
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
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli_env(
        &[
            "--state",
            &state_arg,
            "--route",
            "passphrase",
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
            "--ttl",
            "60",
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(out.stderr.contains("already stands"), "{}", out.stderr);
}

#[test]
fn cli_passphrase_appears_in_no_output_or_error() {
    let dir = test_dir("cli-passphrase-grep");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE);
    let mut outputs: Vec<CliOutput> = Vec::new();
    let enroll = run_cli_env(
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
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(enroll.status, 0, "{}", enroll.stderr);
    outputs.push(enroll);
    let grant = run_cli_env(
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
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(grant.status, 0, "{}", grant.stderr);
    let token = serde_json::from_str::<serde_json::Value>(&grant.stdout).unwrap()["token"]
        .as_str()
        .unwrap()
        .to_string();
    outputs.push(grant);
    let redeem = run_cli_env(
        &[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            &token,
            "--scope",
            "bucket:read",
        ],
        Some(PASSPHRASE),
    );
    assert_eq!(redeem.status, 0, "{}", redeem.stderr);
    outputs.push(redeem);
    // A wrong passphrase draws the one locked line at the command
    // line, exit 1, and the line carries neither passphrase.
    let wrong = run_cli_env(
        &[
            "--state",
            &state_arg,
            "redeem",
            "--token",
            &token,
            "--scope",
            "bucket:read",
        ],
        Some(WRONG_PASSPHRASE),
    );
    assert_eq!(wrong.status, 1);
    assert_eq!(wrong.stderr, format!("error: {LOCKED_BAD_KEY}\n"));
    outputs.push(wrong);
    let audit = run_cli_env(&["--state", &state_arg, "audit"], Some(PASSPHRASE));
    assert_eq!(audit.status, 0, "{}", audit.stderr);
    outputs.push(audit);
    for out in &outputs {
        let everything = format!("{}{}", out.stdout, out.stderr);
        assert!(
            !everything.contains(PASSPHRASE),
            "the passphrase stands in an output: {everything}"
        );
        assert!(
            !everything.contains(WRONG_PASSPHRASE),
            "the wrong passphrase stands in an output: {everything}"
        );
    }
}

// Consolidated audit round submodules. Each former standalone tests/audit_*.rs
// file stands verbatim inside its own isolated module namespace so Cargo builds
// four integration test binaries instead of twenty while keeping every closed
// round's harness, assertions, and historical file-path comments intact.

mod audit_r2_dka2 {
    //! Audit Round 2 pins for finding DK-A2: a creation or adoption
    //! that fails with a returned error after its key was stored
    //! removes the stored key again, so a handled failure never
    //! orphans a live unlock key under an identifier nothing
    //! references. DK-23's crash residue stands untouched: every
    //! failure here is a handled one, with the process alive and the
    //! error in hand.
    //!
    //! Every fixture is synthetic and names itself as one. No test
    //! here touches a real keychain: custody runs against a test
    //! double over the fixture backend, and the failures are forced
    //! by sabotaging the filesystem inside the double's store_key,
    //! so the publish that follows the store fails deterministically.

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
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
            "deadbolt-audit-r2-dka2-test-{}-{tag}-{n}",
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

    /// A passphrase supply answering one fixed answer, or none.
    struct Supply(Option<&'static [u8]>);

    impl PassphraseSource for Supply {
        fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.0.map(|bytes| Zeroizing::new(bytes.to_vec()))
        }
    }

    /// What the double does to the filesystem inside store_key, after
    /// the fixture backend has taken the key, so the publish that
    /// follows the store meets a failure it must return.
    #[derive(Clone, Copy)]
    enum Sabotage {
        /// Nothing: the act that follows runs clean.
        None,
        /// Remove the whole store directory, so the temporary write
        /// of the first publish has nowhere to stand.
        RemoveDirectory,
        /// Replace the state file with a non-empty directory, so the
        /// rename of the adoption publish cannot land.
        BlockStatePath,
    }

    /// A custody double over the fixture backend. It records the
    /// store identifiers it is asked to store and to delete, and it
    /// sabotages the filesystem inside store_key as its Sabotage
    /// states, so the failure lands after the store and before the
    /// publish completes, the exact window DK-A2 names.
    struct SabotageCustody {
        inner: FixtureCustody,
        stored: Mutex<Vec<String>>,
        deleted: Mutex<Vec<String>>,
        dir: PathBuf,
        sabotage: Sabotage,
    }

    impl SabotageCustody {
        fn new(dir: PathBuf, sabotage: Sabotage) -> Self {
            SabotageCustody {
                inner: FixtureCustody::new(),
                stored: Mutex::new(Vec::new()),
                deleted: Mutex::new(Vec::new()),
                dir,
                sabotage,
            }
        }

        fn stored_ids(&self) -> Vec<String> {
            self.stored.lock().unwrap().clone()
        }

        fn deleted_ids(&self) -> Vec<String> {
            self.deleted.lock().unwrap().clone()
        }
    }

    impl KeyCustody for SabotageCustody {
        fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
            self.inner.store_key(store_id, key)?;
            self.stored.lock().unwrap().push(store_id.to_string());
            match self.sabotage {
                Sabotage::None => {}
                Sabotage::RemoveDirectory => {
                    let _ = std::fs::remove_dir_all(&self.dir);
                    // Portability adaptation because Windows keeps self.dir
                    // alive while state.json.lock stands open, so block the
                    // rename target on Windows to force the first publish to fail.
                    #[cfg(windows)]
                    {
                        let _ =
                            std::fs::create_dir_all(self.dir.join("state.json").join("blocker"));
                    }
                }
                Sabotage::BlockStatePath => {
                    let state = self.dir.join("state.json");
                    let _ = std::fs::remove_file(&state);
                    let _ = std::fs::create_dir_all(state.join("blocker"));
                }
            }
            Ok(())
        }

        fn load_key(&self, store_id: &str) -> CustodyLoad {
            self.inner.load_key(store_id)
        }

        fn delete_key(&self, store_id: &str) -> Result<(), CustodyError> {
            self.deleted.lock().unwrap().push(store_id.to_string());
            self.inner.delete_key(store_id)
        }
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

    /// Decrypt the document inside an envelope under a known key,
    /// the same helper shape tests/envelope.rs carries.
    fn decrypt_document(raw: &str, key: &StoreKey) -> String {
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

    /// A standing plaintext store, written from the decrypted
    /// document of a passphrase store so its shape is one the broker
    /// itself wrote, exactly as a store written before the envelope
    /// existed stands.
    fn plaintext_store(dir: &Path) -> PathBuf {
        let custody = FixtureCustody::new();
        let supply = Supply(Some(PASSPHRASE.as_bytes()));
        let creating = Unlock {
            route: Some(Route::Passphrase),
            custody: &custody,
            passphrase: &supply,
        };
        let source_dir = test_dir("adoption-source");
        let source = source_dir.join("state.json");
        deadbolt::enroll(&source, &creating, "cache-key", VALUE, &[read_scope()], T0).unwrap();
        let raw = std::fs::read_to_string(&source).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let salt = hex_bytes(envelope["header"]["kdf"]["salt"].as_str().unwrap());
        let salt: [u8; 16] = salt.try_into().unwrap();
        let key = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt)
            .expect("the pinned parameters derive a key");
        let document = decrypt_document(&raw, &key);
        let state = dir.join("state.json");
        std::fs::write(&state, document).unwrap();
        // Portability adaptation applies POSIX 0600 mode bits on Unix only.
        #[cfg(unix)]
        {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        state
    }

    #[test]
    fn a_creation_that_fails_after_the_store_removes_the_key() {
        let dir = test_dir("creation-failure");
        let state = dir.join("state.json");
        let custody = SabotageCustody::new(dir.clone(), Sabotage::RemoveDirectory);
        let supply = Supply(None);
        let unlock = Unlock {
            route: Some(Route::Keychain),
            custody: &custody,
            passphrase: &supply,
        };
        let err =
            deadbolt::enroll(&state, &unlock, "cache-key", VALUE, &[read_scope()], T0).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        let stored = custody.stored_ids();
        assert_eq!(stored.len(), 1);
        assert_eq!(custody.deleted_ids(), stored);
        assert!(matches!(custody.load_key(&stored[0]), CustodyLoad::Absent));
    }

    #[test]
    fn an_adoption_that_fails_after_the_store_removes_the_key() {
        let dir = test_dir("adoption-failure");
        let state = plaintext_store(&dir);
        let custody = SabotageCustody::new(dir.clone(), Sabotage::BlockStatePath);
        let supply = Supply(None);
        let unlock = Unlock {
            route: Some(Route::Keychain),
            custody: &custody,
            passphrase: &supply,
        };
        let err = deadbolt::audit(&state, &unlock, T0).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        let stored = custody.stored_ids();
        assert_eq!(stored.len(), 1);
        assert_eq!(custody.deleted_ids(), stored);
        assert!(matches!(custody.load_key(&stored[0]), CustodyLoad::Absent));
    }

    #[test]
    fn a_creation_that_succeeds_keeps_its_key() {
        let dir = test_dir("creation-success");
        let state = dir.join("state.json");
        let custody = SabotageCustody::new(dir.clone(), Sabotage::None);
        let supply = Supply(None);
        let unlock = Unlock {
            route: Some(Route::Keychain),
            custody: &custody,
            passphrase: &supply,
        };
        deadbolt::enroll(&state, &unlock, "cache-key", VALUE, &[read_scope()], T0).unwrap();
        let stored = custody.stored_ids();
        assert_eq!(stored.len(), 1);
        assert!(custody.deleted_ids().is_empty());
        assert!(matches!(custody.load_key(&stored[0]), CustodyLoad::Key(_)));
        // The store the key belongs to opens with it.
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        let receipt =
            deadbolt::grant(&state, &open, "cache-key", &read_scope(), 600, None, T0).unwrap();
        assert_eq!(
            deadbolt::redeem(&state, &open, &receipt.token, &read_scope(), T0).unwrap(),
            VALUE
        );
    }
}

mod audit_r2_dka4 {
    //! Audit Round 2 pins for finding DK-A4: when the rename of a
    //! publish fails, the sealed temporary copy is removed before
    //! the error returns, as the write-error path already removes
    //! it, so a failed publish leaves the store directory exactly
    //! as it stood.
    //!
    //! Every fixture is synthetic and names itself as one. The
    //! failure is forced by a passphrase source that sabotages the
    //! state path inside its passphrase call: custody establishment
    //! consults the source, and by the time the publish runs, the
    //! state file has been replaced by a non-empty directory the
    //! rename cannot land on. No test here touches a real keychain.

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deadbolt::custody::FixtureCustody;
    use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

    const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
    const T0: i64 = 1_700_000_000;

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r2-dka4-test-{}-{tag}-{n}",
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

    /// A passphrase supply answering one fixed answer, or none.
    struct Supply(Option<&'static [u8]>);

    impl PassphraseSource for Supply {
        fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
            self.0.map(|bytes| Zeroizing::new(bytes.to_vec()))
        }
    }

    /// A passphrase source that replaces the state file with a
    /// non-empty directory before it answers, so the publish that
    /// follows custody establishment cannot rename over it.
    struct SabotageSource {
        dir: PathBuf,
    }

    impl PassphraseSource for SabotageSource {
        fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
            let state = self.dir.join("state.json");
            let _ = std::fs::remove_file(&state);
            let _ = std::fs::create_dir_all(state.join("blocker"));
            Some(Zeroizing::new(PASSPHRASE.as_bytes().to_vec()))
        }
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

    /// Decrypt the document inside an envelope under a known key,
    /// the same helper shape tests/envelope.rs carries.
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

    /// A standing plaintext store, written from the decrypted
    /// document of a passphrase store so its shape is one the broker
    /// itself wrote, exactly as a store written before the envelope
    /// existed stands.
    fn plaintext_store(dir: &Path) -> PathBuf {
        let custody = FixtureCustody::new();
        let supply = Supply(Some(PASSPHRASE.as_bytes()));
        let creating = Unlock {
            route: Some(Route::Passphrase),
            custody: &custody,
            passphrase: &supply,
        };
        let source_dir = test_dir("adoption-source");
        let source = source_dir.join("state.json");
        deadbolt::enroll(&source, &creating, "cache-key", VALUE, &[read_scope()], T0).unwrap();
        let raw = std::fs::read_to_string(&source).unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let salt = hex_bytes(envelope["header"]["kdf"]["salt"].as_str().unwrap());
        let salt: [u8; 16] = salt.try_into().unwrap();
        let key = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt)
            .expect("the pinned parameters derive a key");
        let document = decrypt_document(&raw, &key);
        let state = dir.join("state.json");
        std::fs::write(&state, document).unwrap();
        // Portability adaptation applies POSIX 0600 mode bits on Unix only.
        #[cfg(unix)]
        {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        state
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
    fn a_rename_failure_removes_the_sealed_temp_copy() {
        let dir = test_dir("rename-failure");
        let state = plaintext_store(&dir);
        let custody = FixtureCustody::new();
        let source = SabotageSource { dir: dir.clone() };
        let unlock = Unlock {
            route: Some(Route::Passphrase),
            custody: &custody,
            passphrase: &source,
        };
        let err = deadbolt::audit(&state, &unlock, T0).unwrap_err();
        assert!(matches!(err, Error::Io(_)), "{err}");
        // The directory holds the lock file and the directory the
        // sabotage put in the state file's place, and no temporary
        // copy of the sealed document under its dot-prefixed name.
        let entries = dir_entries(&dir);
        assert!(
            entries.iter().all(|name| !name.contains(".tmp-")),
            "a sealed temp copy stands in {entries:?}"
        );
        assert_eq!(entries, ["state.json", "state.json.lock"]);
    }

    #[test]
    fn a_successful_adoption_leaves_no_temp_copy() {
        let dir = test_dir("adoption-success");
        let state = plaintext_store(&dir);
        let custody = FixtureCustody::new();
        let supply = Supply(Some(PASSPHRASE.as_bytes()));
        let unlock = Unlock {
            route: Some(Route::Passphrase),
            custody: &custody,
            passphrase: &supply,
        };
        let entries = deadbolt::audit(&state, &unlock, T0).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[1].kind, "adopt");
        assert_eq!(dir_entries(&dir), ["state.json", "state.json.lock"]);
    }
}

mod audit_r3_dka5 {
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
    const KDF_RANGE: &str =
        "the envelope carries KDF parameters outside the range the reader accepts";

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
}

mod audit_r6_dka27 {
    //! Pins for audit finding DK-A27, the discriminating pins DK-A14's
    //! reopening condition names for the envelope classification read.
    //!
    //! names_envelope reads the whole state text into a serde_json
    //! Value and answers on the format field of the collapsed map,
    //! which keeps the last value of a duplicated key and answers None
    //! for a value that is not a string. parse_envelope and the state
    //! reader both read through typed structures that refuse a
    //! duplicated key outright. Until this round the suite pinned the
    //! duplicated format key only where both values agree, so the two
    //! readers' disagreement stood unpinned. The three pins below
    //! stage the disagreement over a real envelope harvested from a
    //! standing store and record today's outcomes exactly, so a future
    //! classification probe of either shape can be proven equivalent
    //! against them, and so the wording move a strict probe would
    //! make cannot land silently inside a performance fix.
    //!
    //! Every fixture is synthetic and names itself as one. No test
    //! here touches a real keychain: the store stands on the fixture
    //! backend behind the custody seam.

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deadbolt::custody::FixtureCustody;
    use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

    const VALUE: &str = "SYNTHETIC-TEST-VALUE-audit-r6-dka27";
    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-audit-r6-dka27-passphrase";
    const T0: i64 = 1_700_000_000;

    const STATE_WORDING: &str = "the state file does not parse as the deadbolt-state/1 format";
    const ENVELOPE_WORDING: &str = "the envelope does not parse as the deadbolt-envelope/1 format";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r6-dka27-test-{}-{tag}-{n}",
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

    fn set_mode(state: &PathBuf, mode: u32) {
        // Portability adaptation applies POSIX mode bits on Unix only.
        #[cfg(unix)]
        {
            std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        #[cfg(not(unix))]
        {
            let _ = (state, mode);
        }
    }

    fn write_store_file(dir: &Path, text: &str) -> PathBuf {
        let state = dir.join("state.json");
        std::fs::write(&state, text).unwrap();
        set_mode(&state, 0o600);
        state
    }

    /// The fields of a standing envelope the staged texts rebuild
    /// around a format field of the pin's own choosing.
    struct Parts {
        ciphertext: String,
        header: String,
        nonce: String,
    }

    fn envelope_parts(ctx: &Ctx) -> Parts {
        let dir = test_dir("harvest");
        let state = dir.join("state.json");
        deadbolt::enroll(
            &state,
            &ctx.creating(Route::Keychain),
            "cache-key",
            VALUE,
            &[read_scope()],
            T0,
        )
        .unwrap();
        let envelope: serde_json::Value = serde_json::from_str(&state_text(&state)).unwrap();
        Parts {
            ciphertext: envelope["ciphertext"].as_str().unwrap().to_string(),
            header: envelope["header"].to_string(),
            nonce: envelope["nonce"].as_str().unwrap().to_string(),
        }
    }

    fn staged(parts: &Parts, format_fields: &str) -> String {
        format!(
            "{{{format_fields},\"ciphertext\":\"{}\",\"header\":{},\"nonce\":\"{}\"}}",
            parts.ciphertext, parts.header, parts.nonce
        )
    }

    fn assert_refuses_as(ctx: &Ctx, label: &str, text: &str, wording: &str) {
        let state = write_store_file(&test_dir(label), text);
        let err = deadbolt::audit(&state, &ctx.open(), T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(format!("{err}"), wording, "{label}");
        let err = deadbolt::grant(
            &state,
            &ctx.open(),
            "cache-key",
            &read_scope(),
            60,
            None,
            T0,
        )
        .unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(format!("{err}"), wording, "{label}");
        assert_eq!(
            state_text(&state),
            text,
            "{label}: the file must never be reset"
        );
    }

    #[test]
    fn a_duplicated_format_key_with_the_envelope_value_last_draws_the_envelope_wording() {
        // The classification read keeps the last value, so this text
        // names the envelope family and stands on the envelope path,
        // where the typed reader refuses the duplicated key in the
        // envelope's own corruption wording. A classifier keeping the
        // first value would send the text to the plaintext path and
        // draw the state wording instead, and fail this pin.
        let ctx = Ctx::new();
        let parts = envelope_parts(&ctx);
        let text = staged(
            &parts,
            "\"format\":\"some-other-format\",\"format\":\"deadbolt-envelope/1\"",
        );
        assert_refuses_as(&ctx, "dup-envelope-last", &text, ENVELOPE_WORDING);
    }

    #[test]
    fn a_duplicated_format_key_with_the_envelope_value_first_draws_the_state_wording() {
        // The classification read keeps the last value, a foreign one,
        // so this text falls to the plaintext path, where the state
        // reader refuses the duplicated key in the state corruption
        // wording. A strict typed classifier would refuse the text on
        // the envelope path and draw the envelope wording; that is the
        // wording move DK-A14 contemplates, and it must change this
        // pin deliberately rather than land silently.
        let ctx = Ctx::new();
        let parts = envelope_parts(&ctx);
        let text = staged(
            &parts,
            "\"format\":\"deadbolt-envelope/1\",\"format\":\"some-other-format\"",
        );
        assert_refuses_as(&ctx, "dup-envelope-first", &text, STATE_WORDING);
    }

    #[test]
    fn a_format_value_that_is_not_a_string_draws_the_state_wording() {
        // The classification read answers None for a format value that
        // is not a string, so the text falls to the plaintext path and
        // the state reader refuses it there. A classifier coercing the
        // value into its comparison, or classifying on the key's
        // presence alone, would take the envelope path and fail this
        // pin.
        let ctx = Ctx::new();
        let parts = envelope_parts(&ctx);
        let text = staged(&parts, "\"format\":7");
        assert_refuses_as(&ctx, "format-not-a-string", &text, STATE_WORDING);
    }
}

mod audit_r23_dka47 {
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
}

mod audit_r27_dka48 {
    //! Audit Round 27 pins for finding DK-A48: the two corruption
    //! branches of the open path that answer for bytes that are not
    //! valid UTF-8 text carry no pin anywhere else in the suite. A
    //! state file whose bytes are not valid UTF-8 text fails the
    //! read in Session::open before classification or parsing can
    //! run, and answers Corrupt with the wording "the state file is
    //! not valid UTF-8 text". An envelope that authenticates and
    //! decrypts to bytes that are not valid UTF-8 text reaches the
    //! conversion in open_document, one step before the strict
    //! read, and answers Corrupt with the wording "the state
    //! document inside the envelope is not valid UTF-8 text". The
    //! standing inner corruption pin of tests/envelope.rs seals
    //! text that is valid UTF-8 and not a document, and draws the
    //! parse wording; the third pin below restates that case as
    //! the control, so the discrimination between the two wordings
    //! stands inside this file.
    //!
    //! These are preservation pins in the form DK-A44 set. Each
    //! passes against the standing code by design and fails on
    //! the plausible wrong form of its branch: the first if the
    //! state file case folded into the filesystem refusal class
    //! or into the parse wording, and the second if the
    //! conversion error folded into the parse wording its
    //! control asserts.
    //!
    //! Every fixture is synthetic and names itself as one. Custody
    //! runs against the fixture backend, and no test here touches
    //! a real keychain.

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use deadbolt::custody::{FixtureCustody, KeyCustody, StoreKey};
    use deadbolt::{Error, PassphraseSource, Unlock, Zeroizing};

    const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
    const T0: i64 = 1_700_000_000;

    const FILE_NOT_UTF8: &str = "the state file is not valid UTF-8 text";
    const DOCUMENT_NOT_UTF8: &str =
        "the state document inside the envelope is not valid UTF-8 text";
    const DOCUMENT_UNPARSEABLE: &str =
        "the state file does not parse as the deadbolt-state/1 format";

    static COUNTER: AtomicUsize = AtomicUsize::new(0);

    fn test_dir(tag: &str) -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!(
            "deadbolt-audit-r27-dka48-test-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
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

    fn write_store_bytes(dir: &Path, bytes: &[u8]) -> PathBuf {
        let state = dir.join("state.json");
        std::fs::write(&state, bytes).unwrap();
        // Portability adaptation applies POSIX 0600 mode bits on Unix only.
        #[cfg(unix)]
        {
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        state
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// Seal bytes under a stated header and key, test side, in the
    /// pattern of the seal_text helper of tests/envelope.rs, over
    /// a byte slice so a payload that is not UTF-8 text can stand
    /// inside an honest envelope.
    fn seal_bytes(header: &serde_json::Value, key: &StoreKey, plaintext: &[u8]) -> String {
        use chacha20poly1305::aead::{Aead, Payload};
        use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
        let header_raw = header.to_string();
        let nonce = [7u8; 24];
        let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: header_raw.as_bytes(),
                },
            )
            .unwrap();
        format!(
            "{{\"ciphertext\":\"{}\",\"format\":\"deadbolt-envelope/1\",\"header\":{header_raw},\"nonce\":\"{}\"}}",
            hex(&ciphertext),
            hex(&nonce)
        )
    }

    /// A keychain envelope over the stated payload bytes, sealed
    /// under a key the fixture holds, standing at a fresh path.
    fn envelope_over(custody: &FixtureCustody, dir: &Path, payload: &[u8]) -> (PathBuf, String) {
        let store_id = "ab".repeat(32);
        let key = StoreKey::new([3u8; 32]);
        custody.store_key(&store_id, &key).unwrap();
        let header = serde_json::json!({
            "payload": "deadbolt-state/1",
            "route": "keychain",
            "store": store_id,
        });
        let sealed = seal_bytes(&header, &key, payload);
        let state = write_store_bytes(dir, sealed.as_bytes());
        (state, sealed)
    }

    #[test]
    fn a_state_file_that_is_not_utf8_text_refuses_as_corrupt_in_its_own_wording() {
        let dir = test_dir("file-not-utf8");
        let custody = FixtureCustody::new();
        let supply = Supply;
        let bytes: &[u8] = b"\xff\xfe not utf-8 text";
        let state = write_store_bytes(&dir, bytes);
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err}");
        assert_eq!(format!("{err}"), FILE_NOT_UTF8);
        assert_eq!(std::fs::read(&state).unwrap(), bytes);
    }

    #[test]
    fn an_envelope_over_non_utf8_bytes_refuses_as_corrupt_in_its_own_wording() {
        let dir = test_dir("payload-not-utf8");
        let custody = FixtureCustody::new();
        let supply = Supply;
        let (state, sealed) = envelope_over(&custody, &dir, b"\xff\xfe\x00 not utf-8");
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err}");
        assert_eq!(format!("{err}"), DOCUMENT_NOT_UTF8);
        assert_eq!(std::fs::read_to_string(&state).unwrap(), sealed);
    }

    #[test]
    fn an_envelope_over_text_that_is_not_a_document_keeps_the_parse_wording() {
        let dir = test_dir("payload-not-a-document");
        let custody = FixtureCustody::new();
        let supply = Supply;
        let (state, sealed) = envelope_over(&custody, &dir, b"this is not a state document");
        let open = Unlock {
            route: None,
            custody: &custody,
            passphrase: &supply,
        };
        let err = deadbolt::audit(&state, &open, T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{err}");
        assert_eq!(format!("{err}"), DOCUMENT_UNPARSEABLE);
        assert_eq!(std::fs::read_to_string(&state).unwrap(), sealed);
    }
}
