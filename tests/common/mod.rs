//! The shared test harness home of audit finding DK-A19.
//!
//! The helpers the integration suites once copied stand here
//! once: the temporary directory builder behind a prefix
//! parameter, the state file reader, the mode setter, the read
//! scope, the two hexadecimal helpers, and the envelope
//! decryptor the document assertions read through. Each suite
//! declares this module with dead code allowed, since no suite
//! uses every helper it carries. The audit pin files do not
//! join: each stands alone as its round's closed evidence and
//! keeps its own small harness, by the rule the finding records.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::custody::StoreKey;
use deadbolt::Scope;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A fresh temporary directory for one test, named by the
/// calling suite's prefix so a failing test's directory still
/// names the suite that made it.
pub fn test_dir(prefix: &str, tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("{prefix}-{}-{tag}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The scope the suites grant and redeem most, bucket read.
pub fn read_scope() -> Scope {
    Scope {
        resource: "bucket".to_string(),
        action: "read".to_string(),
    }
}

/// The standing bytes of a state file as text.
pub fn state_text(state: &PathBuf) -> String {
    std::fs::read_to_string(state).unwrap()
}

/// Set a state file's mode bits, for the permission gate pins.
pub fn set_mode(state: &PathBuf, mode: u32) {
    // Portability adaptation applies POSIX mode bits on Unix only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(not(unix))]
    {
        let _ = (state, mode);
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Render bytes as lowercase hexadecimal, in the nibble table
/// form production takes under DK-A13.
pub fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        out.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Decode hexadecimal text into bytes.
pub fn hex_bytes(text: &str) -> Vec<u8> {
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
/// The header bytes the tag authenticates are the header exactly
/// as the envelope carries it, and the rendering of the parsed
/// header stands identical to those bytes because the writer
/// renders the header in the canonical sorted form.
pub fn decrypt_document(raw: &str, key: &StoreKey) -> String {
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
