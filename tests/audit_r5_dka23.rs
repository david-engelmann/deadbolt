//! Audit Round 5 pins for finding DK-A23: neither binary panics
//! when a write to its standing output fails. Each answers
//! through its standing one line error surface at the filesystem
//! exit, the deadbolt command line with its error line at exit 2
//! under DK-13 and the codepoint scanner with its scan error line
//! at exit 2, where print! and println! panicked and exited 101
//! before. A caller error whose own error line cannot be written
//! still exits 2, because the exit code is the last surface of
//! the taxonomy standing.
//!
//! Every fixture is synthetic and names itself as one. The full
//! stream is /dev/full, the device whose writes always fail with
//! no space, driven here exactly as an operator's full disk or
//! closed pipe presents it. Custody runs on the passphrase route,
//! and no test here touches a real keychain. The pins stand on
//! /dev/full, a Linux device, so the file stands gated to Linux;
//! the behavior they pin is the binaries' own and stands on
//! every platform, and the fixture is the platform bound part.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};

const PASSPHRASE: &str = "SYNTHETIC-TEST-VALUE-copper-lantern-9911";
const VALUE: &str = "SYNTHETIC-TEST-VALUE-quiet-foxglove-7341";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-audit-r5-dka23-test-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A writable handle on /dev/full, the device that refuses every
/// write with no space left.
fn full_stream() -> Stdio {
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    Stdio::from(file)
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_deadbolt(args: &[&str], stdout: Stdio, stderr: Stdio) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .env("DEADBOLT_PASSPHRASE", PASSPHRASE)
        .stdout(stdout)
        .stderr(stderr)
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_scanner(root: &Path) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .stdout(full_stream())
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn run_scanner_with_surplus_on_full_stderr(root: &Path) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .arg("second-root")
        .stdout(Stdio::piped())
        .stderr(full_stream())
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn a_successful_act_whose_report_cannot_be_written_exits_2() {
    let dir = test_dir("full-stdout");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_path = dir.join("value.txt");
    std::fs::write(&value_path, format!("{VALUE}\n")).unwrap();
    let value_arg = value_path.to_string_lossy().into_owned();
    let out = run_deadbolt(
        &[
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
        ],
        full_stream(),
        Stdio::piped(),
    );
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(
        out.stderr
            .starts_with("error: the output could not be written because "),
        "{}",
        out.stderr
    );
    assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
    assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
    // The act itself succeeded and the store stands; only its
    // report failed, and the audit read shows the enroll alone.
    assert!(state.exists());
    let audit = run_deadbolt(
        &["--state", &state_arg, "audit"],
        Stdio::piped(),
        Stdio::piped(),
    );
    assert_eq!(audit.status, 0, "{}", audit.stderr);
    assert_eq!(audit.stdout.lines().count(), 1, "{}", audit.stdout);
    assert!(
        audit.stdout.contains("\"kind\":\"enroll\""),
        "{}",
        audit.stdout
    );
}

#[test]
fn a_caller_error_keeps_its_exit_when_standard_error_refuses() {
    let dir = test_dir("full-stderr");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    // The grant names no --ttl, a caller error at exit 2. With
    // standard error standing on /dev/full the error line cannot
    // be written, and the exit code still stands at 2, where the
    // panic on the error write exited 101 before the fix.
    let out = run_deadbolt(
        &[
            "--state",
            &state_arg,
            "grant",
            "--credential",
            "cache-key",
            "--scope",
            "bucket:read",
        ],
        Stdio::piped(),
        full_stream(),
    );
    assert_eq!(out.status, 2);
    assert!(out.stdout.is_empty());
}

#[test]
fn the_scanner_answers_a_full_stdout_as_a_scan_error() {
    let dir = test_dir("scanner-clean");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let out = run_scanner(&dir);
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(
        out.stderr
            .starts_with("scan error, the report could not be written because "),
        "{}",
        out.stderr
    );
    assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
    assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
}

#[test]
fn the_scanner_answers_a_full_stdout_on_a_dash_hit_as_a_scan_error() {
    let dir = test_dir("scanner-dash");
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let out = run_scanner(&dir);
    assert_eq!(out.status, 2, "{}", out.stderr);
    assert!(
        out.stderr
            .starts_with("scan error, the report could not be written because "),
        "{}",
        out.stderr
    );
    assert_eq!(out.stderr.lines().count(), 1, "{}", out.stderr);
    assert!(!out.stderr.contains("panicked"), "{}", out.stderr);
}

#[test]
fn the_scanners_surplus_refusal_keeps_its_exit_when_standard_error_refuses() {
    let dir = test_dir("scanner-surplus-full-stderr");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    // The surplus argument refusal at exit 2. With standard error
    // standing on /dev/full the refusal line cannot be written,
    // and the exit code still stands at 2, where the bare print
    // panicked on the failed write and exited 101 before the fix.
    let out = run_scanner_with_surplus_on_full_stderr(&dir);
    assert_eq!(out.status, 2);
    assert!(out.stdout.is_empty());
}
