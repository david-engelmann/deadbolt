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
const DOCUMENT_NOT_UTF8: &str = "the state document inside the envelope is not valid UTF-8 text";
const DOCUMENT_UNPARSEABLE: &str = "the state file does not parse as the deadbolt-state/1 format";

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
