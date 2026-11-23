//! Audit Round 5 pins for finding DK-A25: a time to live text
//! of digits alone whose value overflows the type draws the
//! range wording the library speaks for a value outside the
//! accepted range, not the not a whole number wording, which is
//! false for it. A lettered text keeps the standing wording, so
//! the split stands pinned at both sides.
//!
//! Every fixture is synthetic and names itself as one. Custody
//! runs on the passphrase route, and no test here touches a real
//! keychain.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";
const RANGE_WORDING: &str = "error: the time to live must stand from 1 to 86400 seconds\n";
const WHOLE_WORDING: &str = "error: the time to live is not a whole number of seconds\n";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r5-dka25-test-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// A standing passphrase store holding one enrolled credential,
/// answering its state path as a string beside the path itself.
fn standing_store(tag: &str) -> (PathBuf, String) {
    let dir = test_dir(tag);
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_path = dir.join("value.txt");
    std::fs::write(&value_path, format!("{VALUE}\n")).unwrap();
    let value_arg = value_path.to_string_lossy().into_owned();
    let out = run_cli(&[
        "--state",
        &state_arg,
        "--route",
        "passphrase",
        "enroll",
        "--name",
        "cache-key",
        "--value-file",
        &value_arg,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    (state, state_arg)
}

#[test]
fn an_overflowing_time_to_live_draws_the_range_wording() {
    let (_state, state_arg) = standing_store("overflow");
    let out = run_cli(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "99999999999999999999999999",
    ]);
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert_eq!(out.stderr, RANGE_WORDING);
    // The refusal stands at the parse, before the act, so nothing
    // is recorded: the audit read still shows the enroll alone.
    let audit = run_cli(&["--state", &state_arg, "audit"]);
    assert_eq!(audit.status, 0, "{}", audit.stderr);
    assert_eq!(audit.stdout.lines().count(), 1, "{}", audit.stdout);
}

#[test]
fn a_lettered_time_to_live_keeps_the_whole_number_wording() {
    let (_state, state_arg) = standing_store("lettered");
    let out = run_cli(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "12x",
    ]);
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert_eq!(out.stderr, WHOLE_WORDING);
}
