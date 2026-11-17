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
    let key = deadbolt::custody::derive_key(PASSPHRASE.as_bytes(), &salt);
    let document = decrypt_document(&raw, &key);
    let state = dir.join("state.json");
    std::fs::write(&state, document).unwrap();
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
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
