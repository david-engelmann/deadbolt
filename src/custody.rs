//! The custody seam for the store unlock key, written to obligations
//! DK-15 to DK-20 in CONTRACT.md.
//!
//! The seam separates holding the 32 byte unlock key from using it. A
//! backend either holds the key in the operating system keychain or
//! derives it from a passphrase on every load. Nothing in this module
//! reads or writes the store file itself. The envelope that consumes a
//! loaded key is a later slice. Custody dependent behavior in this
//! slice is driven through the fixture backend in the test suite, and
//! the keychain backend is driven once against a machine with no
//! keychain service running, which DK-24 names as the standing limit
//! of this layer.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

/// The length in bytes of a store unlock key.
pub const KEY_LEN: usize = 32;

/// The length in bytes of the salt the passphrase route derives under.
pub const SALT_LEN: usize = 16;

/// The Argon2id memory cost in kibibytes pinned by DK-19.
pub const ARGON2_MEMORY_KIB: u32 = 65_536;

/// The Argon2id time cost pinned by DK-19.
pub const ARGON2_TIME: u32 = 3;

/// The Argon2id lane count pinned by DK-19.
pub const ARGON2_LANES: u32 = 1;

/// The service name every keychain entry for this crate is stored under.
pub const KEYCHAIN_SERVICE: &str = "deadbolt";

/// A store unlock key, held in memory that zeroes when it drops.
///
/// The bytes are reachable only through [`StoreKey::as_bytes`], and the
/// debug form prints a placeholder so a key never lands in a log line
/// or a test failure message.
pub struct StoreKey(Zeroizing<[u8; KEY_LEN]>);

impl StoreKey {
    /// Wrap raw key bytes, taking ownership of the zeroizing buffer.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        StoreKey(Zeroizing::new(bytes))
    }

    /// Wrap an already zeroizing buffer without copying the bytes.
    pub fn from_zeroizing(bytes: Zeroizing<[u8; KEY_LEN]>) -> Self {
        StoreKey(bytes)
    }

    /// Borrow the key bytes for the one act that consumes them.
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl fmt::Debug for StoreKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoreKey(<redacted>)")
    }
}

impl PartialEq for StoreKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_bytes()[..] == other.as_bytes()[..]
    }
}

impl Eq for StoreKey {}

/// What a custody backend answers when it is asked for a store key.
///
/// A backend that cannot reach its service answers
/// [`CustodyLoad::ServiceFailure`] and never answers
/// [`CustodyLoad::Absent`] for that failure, because absence and
/// unreachability carry opposite meanings for the caller under DK-22.
#[derive(Debug, PartialEq, Eq)]
pub enum CustodyLoad {
    /// The store key was found or derived.
    Key(StoreKey),
    /// The store holds no key under this store identifier.
    Absent,
    /// The custody service could not be reached or answered wrongly.
    /// The string is the diagnostic the store layer surfaces.
    ServiceFailure(String),
}

/// A custody operation that failed outside the load outcome taxonomy.
///
/// Store and delete have no absence outcome of their own, so their
/// failures travel as this error, and the refusal wording built on it
/// lives in the store layer where refusals are worded.
#[derive(Debug)]
pub struct CustodyError(String);

impl CustodyError {
    /// Build the error from the diagnostic the backend reported.
    pub fn new(message: impl Into<String>) -> Self {
        CustodyError(message.into())
    }
}

impl fmt::Display for CustodyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for CustodyError {}

/// The seam every custody backend stands behind.
///
/// `store_id` is the store identifier the envelope header carries, and
/// it is the only name a backend ever sees for a store. Implementations
/// must be safe to share between threads, because the store layer
/// decides where a backend value lives.
pub trait KeyCustody: Send + Sync {
    /// Place the key for a store with the backend.
    fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError>;

    /// Answer what the backend holds for a store.
    fn load_key(&self, store_id: &str) -> CustodyLoad;

    /// Remove whatever the backend holds for a store. Removing a key
    /// the backend does not hold is not an error, because the state
    /// the caller wants is already the state that stands.
    fn delete_key(&self, store_id: &str) -> Result<(), CustodyError>;
}

/// Derive the unlock key for the passphrase route at the parameters
/// DK-19 pins.
///
/// The derivation is the whole of the passphrase route's custody. It
/// runs on every load, its output is never stored anywhere, and the
/// salt travels with the envelope header rather than with the service.
pub fn derive_key(passphrase: &[u8], salt: &[u8; SALT_LEN]) -> StoreKey {
    let params = Params::new(ARGON2_MEMORY_KIB, ARGON2_TIME, ARGON2_LANES, Some(KEY_LEN))
        .expect("the pinned Argon2id parameters are valid");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, &mut *out)
        .expect("the pinned Argon2id parameters are valid");
    StoreKey::from_zeroizing(out)
}

/// The passphrase route's backend, binding one passphrase to one salt.
///
/// Loading derives the key again, storing checks an offered key
/// against the derivation and refuses a key this passphrase does not
/// derive, and deleting holds nothing to remove because nothing was
/// ever stored.
pub struct PassphraseCustody {
    passphrase: Zeroizing<String>,
    salt: [u8; SALT_LEN],
}

impl PassphraseCustody {
    /// Bind a passphrase and the salt its store's header carries.
    pub fn new(passphrase: Zeroizing<String>, salt: [u8; SALT_LEN]) -> Self {
        PassphraseCustody { passphrase, salt }
    }
}

impl KeyCustody for PassphraseCustody {
    fn store_key(&self, _store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
        if derive_key(self.passphrase.as_bytes(), &self.salt) == *key {
            Ok(())
        } else {
            Err(CustodyError::new(
                "the offered key is not the key this passphrase derives",
            ))
        }
    }

    fn load_key(&self, _store_id: &str) -> CustodyLoad {
        CustodyLoad::Key(derive_key(self.passphrase.as_bytes(), &self.salt))
    }

    fn delete_key(&self, _store_id: &str) -> Result<(), CustodyError> {
        Ok(())
    }
}

/// The keychain route's backend module, compiled only on the three
/// platforms DK-18 names.
///
/// On any other target the keyring dependency itself is absent from
/// the manifest, so no platform backend can be selected silently. The
/// keyring crate falls back to its in-memory mock store when no
/// platform feature is enabled, and a key stored into that mock is
/// lost the moment the entry value drops, so this seam names no
/// backend at all where none of the three platforms stands.
#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
mod platform {
    use super::{CustodyError, CustodyLoad, KeyCustody, StoreKey, KEYCHAIN_SERVICE, KEY_LEN};

    /// The keychain route's backend, standing behind the keyring crate.
    ///
    /// The platform store is the one the keyring crate selects for the
    /// operating system, the macOS Keychain on macOS, the credential store
    /// over DPAPI on Windows, and the Secret Service over the D-Bus
    /// session bus on Linux. Entries are named by the store identifier
    /// under one service name, and keys travel as raw secret bytes.
    pub struct KeychainCustody;

    impl KeychainCustody {
        /// Build the backend. Reaching the service happens per operation,
        /// so building the backend cannot fail on a missing service.
        pub fn new() -> Self {
            KeychainCustody
        }

        fn entry(store_id: &str) -> Result<keyring::Entry, CustodyError> {
            keyring::Entry::new(KEYCHAIN_SERVICE, store_id)
                .map_err(|err| CustodyError::new(err.to_string()))
        }
    }

    impl Default for KeychainCustody {
        fn default() -> Self {
            Self::new()
        }
    }

    impl KeyCustody for KeychainCustody {
        fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
            Self::entry(store_id)?
                .set_secret(key.as_bytes())
                .map_err(|err| CustodyError::new(err.to_string()))
        }

        fn load_key(&self, store_id: &str) -> CustodyLoad {
            let entry = match Self::entry(store_id) {
                Ok(entry) => entry,
                Err(err) => return CustodyLoad::ServiceFailure(err.to_string()),
            };
            match entry.get_secret() {
                Ok(bytes) => {
                    let array: Result<[u8; KEY_LEN], _> = bytes.as_slice().try_into();
                    match array {
                    Ok(array) => CustodyLoad::Key(StoreKey::new(array)),
                    Err(_) => CustodyLoad::ServiceFailure(format!(
                        "the keychain entry for this store holds {} bytes and a store key is {KEY_LEN} bytes",
                        bytes.len()
                    )),
                }
                }
                Err(keyring::Error::NoEntry) => CustodyLoad::Absent,
                Err(err) => CustodyLoad::ServiceFailure(err.to_string()),
            }
        }

        fn delete_key(&self, store_id: &str) -> Result<(), CustodyError> {
            match Self::entry(store_id)?.delete_credential() {
                Ok(()) => Ok(()),
                Err(keyring::Error::NoEntry) => Ok(()),
                Err(err) => Err(CustodyError::new(err.to_string())),
            }
        }
    }

    /// Select the platform custody backend for the keychain route.
    ///
    /// The choice happens where the backend is built, never where it is
    /// used, so the store layer above the seam reads the same on every
    /// platform.
    pub fn platform_custody() -> Box<dyn KeyCustody> {
        Box::new(KeychainCustody::new())
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub use platform::{platform_custody, KeychainCustody};

#[cfg(feature = "custody-fixture")]
mod fixture {
    use std::collections::BTreeMap;
    use std::sync::Mutex;

    use super::{CustodyError, CustodyLoad, KeyCustody, StoreKey, KEY_LEN};

    /// The tests-only custody backend, holding keys in memory.
    ///
    /// The fixture answers each of the three load outcomes the seam
    /// defines, a stored key, an absent key, and a service failure the
    /// test arms and clears. It is compiled only into the test suite
    /// behind the custody-fixture feature and is never linked into the
    /// binary or the library a caller depends on.
    #[derive(Default)]
    pub struct FixtureCustody {
        entries: Mutex<BTreeMap<String, [u8; KEY_LEN]>>,
        failure: Mutex<Option<String>>,
    }

    impl FixtureCustody {
        /// Build an empty fixture with no failure armed.
        pub fn new() -> Self {
            FixtureCustody::default()
        }

        /// Arm the service failure outcome with the given diagnostic.
        /// Every operation answers with the failure until it clears.
        pub fn fail_with(&self, message: impl Into<String>) {
            *self.failure.lock().expect("fixture failure lock") = Some(message.into());
        }

        /// Clear an armed service failure.
        pub fn clear_failure(&self) {
            *self.failure.lock().expect("fixture failure lock") = None;
        }

        fn armed_failure(&self) -> Option<String> {
            self.failure.lock().expect("fixture failure lock").clone()
        }
    }

    impl KeyCustody for FixtureCustody {
        fn store_key(&self, store_id: &str, key: &StoreKey) -> Result<(), CustodyError> {
            if let Some(message) = self.armed_failure() {
                return Err(CustodyError::new(message));
            }
            self.entries
                .lock()
                .expect("fixture entry lock")
                .insert(store_id.to_string(), *key.as_bytes());
            Ok(())
        }

        fn load_key(&self, store_id: &str) -> CustodyLoad {
            if let Some(message) = self.armed_failure() {
                return CustodyLoad::ServiceFailure(message);
            }
            match self
                .entries
                .lock()
                .expect("fixture entry lock")
                .get(store_id)
            {
                Some(bytes) => CustodyLoad::Key(StoreKey::new(*bytes)),
                None => CustodyLoad::Absent,
            }
        }

        fn delete_key(&self, store_id: &str) -> Result<(), CustodyError> {
            if let Some(message) = self.armed_failure() {
                return Err(CustodyError::new(message));
            }
            self.entries
                .lock()
                .expect("fixture entry lock")
                .remove(store_id);
            Ok(())
        }
    }
}

#[cfg(feature = "custody-fixture")]
pub use fixture::FixtureCustody;
