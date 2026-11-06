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

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::{CustodyLoad, FixtureCustody, KeyCustody, StoreKey};
use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const WRONG_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-wrong-lantern-9911";
const T0: i64 = 1_700_000_000;

const LOCKED_NO_SERVICE: &str = "the store is locked because the keychain service is not available";
const LOCKED_NO_ENTRY: &str = "the store is locked because its keychain entry is missing, and the broker holds no other copy and no fallback will be tried";
const LOCKED_BAD_KEY: &str = "the store is locked because the key did not open it";
const LOCKED_TRANSPLANT: &str =
    "the store is locked because the envelope does not belong to this store";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-envelope-test-{}-{tag}-{n}",
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

fn state_text(state: &PathBuf) -> String {
    std::fs::read_to_string(state).unwrap()
}

fn envelope_json(state: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&state_text(state)).unwrap()
}

fn set_mode(state: &PathBuf, mode: u32) {
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn write_store_file(dir: &Path, text: &str) -> PathBuf {
    let state = dir.join("state.json");
    std::fs::write(&state, text).unwrap();
    set_mode(&state, 0o600);
    state
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
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

/// Decrypt the document inside an envelope under a known key, the
/// same helper shape tests/deadbolt.rs carries.
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
    let key = deadbolt::custody::derive_key(&passphrase, &salt);
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
    let pinned = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt);
    let at_pinned = deadbolt::custody::derive_key_with_params(
        PASSPHRASE.as_bytes(),
        &salt,
        deadbolt::custody::ARGON2_MEMORY_KIB,
        deadbolt::custody::ARGON2_TIME,
    );
    assert_eq!(pinned, at_pinned);
    let lighter = deadbolt::custody::derive_key_with_params(PASSPHRASE.as_bytes(), &salt, 8_192, 1);
    assert_ne!(pinned, lighter);
    let lighter_again =
        deadbolt::custody::derive_key_with_params(PASSPHRASE.as_bytes(), &salt, 8_192, 1);
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
    let pp_key = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt);
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
