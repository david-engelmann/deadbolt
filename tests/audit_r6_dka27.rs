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
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
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
