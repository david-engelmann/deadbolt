//! Audit Round 13 pins for finding DK-A39: the swallow check
//! DK-A10 landed consults the options the command itself offers,
//! and the two global options, --state and --route, stand in
//! every call but in no command's list, so a value slot taken by
//! one of them was still swallowed as a value. In the redeem and
//! revoke shapes below the swallowed name was looked up against
//! the store and drew a recorded refusal at exit 1, where DK-9
//! names a request shape that fails before the store opens as a
//! caller error that is never recorded. In the grant shape it
//! failed the time to live parse under the wrong fault's
//! wording, the number wording for an option that stands with
//! no value after it.
//!
//! The fourth pin is a preservation pin. A value that merely
//! begins with hyphens and names no offered option, global or
//! the command's own, still parses as a value and meets its
//! downstream check, exactly as before the repair; it passes
//! against the old code by design and fails on the blanket form
//! of the fix, which would refuse every hyphen led value with
//! the valueless wording.
//!
//! Every fixture is synthetic and names itself as one. Custody
//! runs on the passphrase route through the environment channel,
//! and no test here touches a real keychain.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
const CLI_PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-cli-passphrase";
const VALUELESS: &str = "error: an option that takes a value stands with no value after it\n";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r13-dka39-test-{}-{tag}-{n}",
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

fn run_cli_pp(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .env("DEADBOLT_PASSPHRASE", CLI_PASSPHRASE)
        .output()
        .unwrap();
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

/// Enroll one credential and grant once against it, and answer
/// the state path in its argument form.
fn enroll_and_grant(dir: &Path) -> String {
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(dir, VALUE_A);
    let out = run_cli_pp(&[
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
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "600",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    state_arg
}

fn audit_line_count(state_arg: &str) -> usize {
    let out = run_cli_pp(&["--state", state_arg, "audit"]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    out.stdout.lines().count()
}

#[test]
fn a_redeem_whose_token_option_swallows_the_state_name_refuses_as_a_caller_error_and_records_nothing(
) {
    let dir = test_dir("redeem-swallowed-state");
    let state_arg = enroll_and_grant(&dir);
    let before = audit_line_count(&state_arg);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "redeem",
        "--token",
        "--state",
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
    assert_eq!(out.stderr, VALUELESS);
    assert_eq!(audit_line_count(&state_arg), before);
}

#[test]
fn a_revoke_whose_grant_option_swallows_the_route_name_refuses_as_a_caller_error_and_records_nothing(
) {
    let dir = test_dir("revoke-swallowed-route");
    let state_arg = enroll_and_grant(&dir);
    let before = audit_line_count(&state_arg);
    let out = run_cli_pp(&["--state", &state_arg, "revoke", "--grant", "--route"]);
    assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
    assert_eq!(out.stderr, VALUELESS);
    assert_eq!(audit_line_count(&state_arg), before);
}

#[test]
fn a_grant_whose_ttl_option_swallows_the_state_name_names_the_missing_value() {
    let dir = test_dir("grant-swallowed-state");
    let state_arg = enroll_and_grant(&dir);
    let before = audit_line_count(&state_arg);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "grant",
        "--credential",
        "cache-key",
        "--scope",
        "bucket:read",
        "--ttl",
        "--state",
    ]);
    assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
    assert_eq!(out.stderr, VALUELESS);
    assert_eq!(audit_line_count(&state_arg), before);
}

#[test]
fn a_value_that_begins_with_hyphens_and_names_no_offered_option_still_parses_as_a_value() {
    let dir = test_dir("hyphen-value");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE_A);
    let out = run_cli_pp(&[
        "--state",
        &state_arg,
        "--route",
        "passphrase",
        "enroll",
        "--name",
        "--not-an-option",
        "--value-file",
        &value_file,
        "--scope",
        "bucket:read",
    ]);
    assert_eq!(out.status, 2, "{} {}", out.stdout, out.stderr);
    assert!(out.stderr.starts_with("error: "), "{}", out.stderr);
    assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
    assert!(
        !out.stderr.contains("stands with no value after it"),
        "{}",
        out.stderr
    );
    assert!(!state.exists());
}
