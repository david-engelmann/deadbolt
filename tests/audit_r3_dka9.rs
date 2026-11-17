//! Audit Round 3 pins for finding DK-A9: neither binary panics
//! on an argument that is not valid Unicode text. Each answers
//! through its standing one line error surface at the caller
//! error exit, the deadbolt command line with its error line at
//! exit 2 under DK-13 and the codepoint scanner with its scan
//! error line at exit 2, where the argument collection of the
//! standard library panicked and exited 101 before.
//!
//! Every fixture is synthetic. The staged argument is two bytes
//! that decode as no text at all, passed to each binary as an
//! operating system argument exactly as a shell would pass it.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

fn non_unicode_argument() -> &'static OsStr {
    OsStr::from_bytes(b"\xff\xfe")
}

#[test]
fn the_command_line_answers_a_non_unicode_argument_as_a_caller_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .arg("--state")
        .arg(non_unicode_argument())
        .arg("audit")
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.starts_with("error: "), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(output.stdout.is_empty());
}

#[test]
fn the_scanner_answers_a_non_unicode_argument_as_a_scan_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(non_unicode_argument())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(2),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.starts_with("scan error, "), "{stderr}");
    assert_eq!(stderr.lines().count(), 1, "{stderr}");
    assert!(output.stdout.is_empty());
}
