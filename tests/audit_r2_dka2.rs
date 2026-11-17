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
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o600)).unwrap();
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
