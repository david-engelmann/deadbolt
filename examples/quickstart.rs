//! Self-contained Rust quickstart for deadbolt.
//!
//! Exercises credential enrollment on the Argon2id passphrase route,
//! non-secret store status inspection, scoped capability grant minting,
//! token redemption without printing secret material, scope-mismatch
//! refusal, run-scoped cutoff, atomic passphrase rekey, and audit trail
//! verification inside a temporary directory cleaned up on exit.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use deadbolt::custody::{CustodyError, CustodyLoad, KeyCustody, StoreKey};
use deadbolt::{
    audit, cutoff, enroll, grant, redeem, rekey, status, Error, GrantStatus, PassphraseSource,
    RedeemRefusal, Route, Scope, Unlock, Zeroizing,
};

struct TempDir(PathBuf);

impl TempDir {
    fn create(prefix: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let pid = std::process::id();
        let dir = std::env::temp_dir().join(format!("{prefix}-{pid}-{nanos}"));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct UnusedKeychain;

impl KeyCustody for UnusedKeychain {
    fn store_key(&self, _store_id: &str, _key: &StoreKey) -> Result<(), CustodyError> {
        Err(CustodyError::new("keychain unused on passphrase route"))
    }

    fn load_key(&self, _store_id: &str) -> CustodyLoad {
        CustodyLoad::ServiceFailure("keychain unused on passphrase route".to_string())
    }

    fn delete_key(&self, _store_id: &str) -> Result<(), CustodyError> {
        Ok(())
    }
}

struct StaticPassphrase(&'static [u8]);

impl PassphraseSource for StaticPassphrase {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        Some(Zeroizing::new(self.0.to_vec()))
    }
}

pub fn run_quickstart() -> Result<(), Box<dyn std::error::Error>> {
    let temp = TempDir::create("deadbolt-quickstart")?;
    let state_path = temp.0.join("vault.json");
    let keychain = UnusedKeychain;
    let pass_v1 = StaticPassphrase(b"SYNTHETIC-TEST-VALUE-passphrase-v1");
    let pass_v2 = StaticPassphrase(b"SYNTHETIC-TEST-VALUE-passphrase-v2");

    let read_scope = Scope {
        resource: "artifacts".to_string(),
        action: "read".to_string(),
    };
    let write_scope = Scope {
        resource: "artifacts".to_string(),
        action: "write".to_string(),
    };

    // 1. Create sealed store on the passphrase route and enroll one credential.
    let create_unlock = Unlock {
        route: Some(Route::Passphrase),
        custody: &keychain,
        passphrase: &pass_v1,
    };
    enroll(
        &state_path,
        &create_unlock,
        "storage-api",
        "SYNTHETIC-TEST-VALUE-storage-key",
        &[read_scope.clone(), write_scope.clone()],
        1_794_115_900,
    )?;
    println!("1. enrolled storage-api on passphrase route");

    // 2. Subsequent operations read the route from the authenticated header.
    let open_unlock = Unlock {
        route: None,
        custody: &keychain,
        passphrase: &pass_v1,
    };
    let summary = status(&state_path, &open_unlock, 1_794_115_901)?;
    assert_eq!(summary.route, Route::Passphrase);
    assert_eq!(summary.credentials.len(), 1);
    println!(
        "2. status verified route={} credentials={}",
        summary.route.name(),
        summary.credentials.len()
    );

    // 3. Mint a run-tagged capability grant for artifacts/read and redeem it.
    let receipt = grant(
        &state_path,
        &open_unlock,
        "storage-api",
        &read_scope,
        300,
        Some("demo-run"),
        1_794_115_902,
    )?;
    let secret = Zeroizing::new(redeem(
        &state_path,
        &open_unlock,
        &receipt.token,
        &read_scope,
        1_794_115_903,
    )?);
    assert_eq!(secret.as_str(), "SYNTHETIC-TEST-VALUE-storage-key");
    println!(
        "3. redeemed grant id={} without printing secret",
        receipt.grant_id
    );

    // 4. Attempting to redeem the read token against write is refused.
    let mismatch = redeem(
        &state_path,
        &open_unlock,
        &receipt.token,
        &write_scope,
        1_794_115_904,
    );
    assert!(matches!(
        mismatch,
        Err(Error::Redeem(RedeemRefusal::ScopeMismatch))
    ));
    println!("4. scope mismatch refused cleanly");

    // 5. Cut off demo-run and confirm subsequent redemption is refused as revoked.
    let ended = cutoff(&state_path, &open_unlock, "demo-run", 1_794_115_905)?;
    assert_eq!(ended, 1);
    let post_cutoff = redeem(
        &state_path,
        &open_unlock,
        &receipt.token,
        &read_scope,
        1_794_115_906,
    );
    assert!(matches!(
        post_cutoff,
        Err(Error::Redeem(RedeemRefusal::Revoked))
    ));
    println!("5. demo-run cut off (grants_ended={ended})");

    // 6. Atomically rekey the sealed store onto a rotated passphrase and verify audit.
    let prev_route = rekey(
        &state_path,
        &open_unlock,
        Route::Passphrase,
        &pass_v2,
        1_794_115_907,
    )?;
    assert_eq!(prev_route, Route::Passphrase);

    let rekeyed_unlock = Unlock {
        route: None,
        custody: &keychain,
        passphrase: &pass_v2,
    };
    let post_status = status(&state_path, &rekeyed_unlock, 1_794_115_908)?;
    assert_eq!(post_status.grants[0].status, GrantStatus::Revoked);
    let entries = audit(&state_path, &rekeyed_unlock, 1_794_115_908)?;
    assert_eq!(entries.len(), 7);
    assert_eq!(entries.last().map(|e| e.kind.as_str()), Some("rekey"));
    println!(
        "6. store rekeyed and {} audit entries verified",
        entries.len()
    );

    Ok(())
}

#[allow(dead_code)]
fn main() -> ExitCode {
    match run_quickstart() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(1)
        }
    }
}
