//! The setup pins, translated from the Python setup suite the repo
//! was seeded with. Each test names the same fact its Python original
//! named. Two facts changed with the Rust conversion and the change
//! is stated where it lands. The CI gate commands are the Rust gate
//! commands of amended obligation S2, and the contract substance pin
//! asserts the amended S2 phrases.

use std::path::{Path, PathBuf};
use std::process::Command;

use sha2::{Digest, Sha256};

const MARKER: &str = "<!-- repo annex below this line -->";
const GATE_COMMAND: &str = "cargo test";
const SCAN_COMMAND: &str = "cargo run --bin codepoint_scan";
const FMT_COMMAND: &str = "cargo fmt --check";
const CLIPPY_COMMAND: &str = "cargo clippy --all-targets -- -D warnings";

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(name: &str) -> String {
    std::fs::read_to_string(root().join(name)).unwrap()
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("deadbolt-setup-test-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn seed_files_exist() {
    for name in ["README.md", "LICENSE", ".gitignore"] {
        assert!(root().join(name).is_file(), "{name}");
    }
}

#[test]
fn license_starts_with_mit_heading() {
    assert!(read("LICENSE").starts_with("MIT License\n"));
}

#[test]
fn agents_has_marker_and_deadbolt_annex_below_it() {
    let text = read("AGENTS.md");
    assert!(text.contains(MARKER));
    let annex = text.split(MARKER).nth(1).unwrap();
    assert!(annex.contains("deadbolt"));
    assert!(annex.contains("CONTRACT.md"));
    assert!(annex.contains("guards the credentials"));
}

#[test]
fn agents_canonical_part_carries_program_headings() {
    let text = read("AGENTS.md");
    let canonical = text.split(MARKER).next().unwrap();
    assert!(canonical.starts_with("# AGENTS.md\n"));
    assert!(canonical.contains("## The round discipline"));
    assert!(canonical.contains("## Contract first"));
    assert!(canonical.contains("39 repo storefront perfection program"));
}

#[test]
fn contract_names_five_setup_obligations() {
    let text = read("CONTRACT.md");
    for name in ["S1", "S2", "S3", "S4", "S5"] {
        assert!(
            text.contains(&format!("Obligation {name} covers")),
            "{name}"
        );
    }
    assert!(!text.contains("Obligation S6"));
}

fn status_section(text: &str) -> &str {
    let start = text.find("\n## Status\n").unwrap() + "\n## Status\n".len();
    let rest = &text[start..];
    match rest.find("\n## ") {
        Some(end) => &rest[..end],
        None => rest,
    }
}

#[test]
fn readme_status_states_one_hundred_of_one_hundred() {
    let text = read("README.md");
    assert!(text.contains("## Status"));
    let status = status_section(&text);
    assert!(status.contains("Closed perfection rounds are 100 of 100."));
    assert!(status.contains("08a05b881350c6ca5eb8a42af28d25f194c6d039"));
}

fn flush_step(step_lines: &mut Vec<String>, commands: &mut Vec<String>) {
    if step_lines.is_empty() {
        return;
    }
    let mut disabled = false;
    let mut runs = Vec::new();
    for stripped in step_lines.iter() {
        if let Some(value) = stripped.strip_prefix("if:") {
            let value = value
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .to_lowercase();
            if value == "false" {
                disabled = true;
            }
        }
        if let Some(pos) = stripped.find("run:") {
            runs.push(stripped[pos + "run:".len()..].trim().to_string());
        }
    }
    if !disabled {
        commands.extend(runs);
    }
    step_lines.clear();
}

fn run_commands(ci_text: &str) -> Vec<String> {
    let mut commands = Vec::new();
    let mut step_lines: Vec<String> = Vec::new();
    let mut in_steps = false;
    let mut in_test_job = false;
    let mut job_disabled = false;
    for line in ci_text.lines() {
        let stripped = line.trim();
        if stripped.starts_with('#') {
            continue;
        }
        if stripped == "test:" {
            in_test_job = true;
            continue;
        }
        if in_test_job && !in_steps && stripped.starts_with("if:") {
            let value = stripped
                .split_once(':')
                .map(|(_, rest)| rest)
                .unwrap_or_default()
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .to_lowercase();
            if value == "false" {
                job_disabled = true;
            }
            continue;
        }
        if stripped == "steps:" {
            in_steps = true;
            continue;
        }
        if in_steps && stripped.starts_with("- ") {
            flush_step(&mut step_lines, &mut commands);
            step_lines.push(stripped[2..].trim().to_string());
            continue;
        }
        if in_steps {
            step_lines.push(stripped.to_string());
        }
    }
    flush_step(&mut step_lines, &mut commands);
    if job_disabled {
        return Vec::new();
    }
    commands
}

#[test]
fn ci_runs_the_local_gate_commands() {
    let commands = run_commands(&read(".github/workflows/ci.yml"));
    assert!(commands.iter().any(|c| c == GATE_COMMAND));
    assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    assert!(commands.iter().any(|c| c == FMT_COMMAND));
    assert!(commands.iter().any(|c| c == CLIPPY_COMMAND));
}

#[test]
fn ci_carries_the_fleet_credential_hygiene() {
    let text = read(".github/workflows/ci.yml");
    // The workflow asks for no more than it uses. Its token
    // is limited to reading the repository, the checkout
    // leaves no credential behind for later steps, and the
    // toolchain action is pinned to a full commit SHA rather
    // than a moving branch name.
    assert!(text.contains("permissions:"));
    assert!(text.contains("contents: read"));
    assert!(text.contains("persist-credentials: false"));
    // No job level override may widen the read only limit.
    assert!(!text.contains("write-all"));
    assert!(!text.contains("contents: write"));
    assert!(!text.contains("rust-toolchain@master"));
    // Every toolchain step stands judged, not only the first
    // one the file finds: a second job whose toolchain step
    // named a tag, a branch, or a shortened pin would pass a
    // first line pin unseen (DK-A31).
    let toolchain_lines: Vec<&str> = text
        .lines()
        .filter(|line| line.contains("dtolnay/rust-toolchain@"))
        .collect();
    assert!(
        !toolchain_lines.is_empty(),
        "the workflow carries no toolchain step"
    );
    for toolchain_line in toolchain_lines {
        let pin = toolchain_line
            .split("dtolnay/rust-toolchain@")
            .nth(1)
            .unwrap()
            .trim();
        assert_eq!(pin.len(), 40, "{}", toolchain_line);
        assert!(pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}

#[test]
fn ci_gate_parser_skips_a_step_disabled_with_if_false() {
    let ci_text = read(".github/workflows/ci.yml");
    let gate_step = "      - name: Run the local gate\n        run: cargo test";
    assert!(ci_text.contains(gate_step));
    for flag in ["false", "\"false\""] {
        let disabled = ci_text.replace(
            gate_step,
            &format!(
                "      - name: Run the local gate\n        if: {flag}\n        run: cargo test"
            ),
        );
        let commands = run_commands(&disabled);
        assert!(!commands.iter().any(|c| c == GATE_COMMAND));
        assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    }
}

#[test]
fn ci_gate_parser_rejects_a_job_disabled_with_if_false() {
    let ci_text = read(".github/workflows/ci.yml");
    let job_head = "  test:\n    runs-on: ubuntu-latest";
    assert!(ci_text.contains(job_head));
    for flag in ["false", "\"false\""] {
        let disabled = ci_text.replace(
            job_head,
            &format!("  test:\n    if: {flag}\n    runs-on: ubuntu-latest"),
        );
        let commands = run_commands(&disabled);
        assert!(!commands.iter().any(|c| c == GATE_COMMAND));
        assert!(!commands.iter().any(|c| c == SCAN_COMMAND));
        assert!(!commands.iter().any(|c| c == FMT_COMMAND));
        assert!(!commands.iter().any(|c| c == CLIPPY_COMMAND));
    }
    let commands = run_commands(&ci_text);
    assert!(commands.iter().any(|c| c == GATE_COMMAND));
    assert!(commands.iter().any(|c| c == SCAN_COMMAND));
    assert!(commands.iter().any(|c| c == FMT_COMMAND));
    assert!(commands.iter().any(|c| c == CLIPPY_COMMAND));
}

struct ScanOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn scan_tree(root: &Path) -> ScanOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .output()
        .unwrap();
    ScanOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn scan_tree_with_extra(root: &Path, extra: &str) -> ScanOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .arg(extra)
        .output()
        .unwrap();
    ScanOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

#[test]
fn codepoint_scan_reports_zero_for_the_repo() {
    let result = scan_tree(&root());
    assert_eq!(result.status, 0, "{}", result.stdout);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

const CANONICAL_ABOVE_MARKER_SHA256: &str =
    "bb3e2fc1790b13729da3495c3f0902b968577f4e45ceb27e48e90b489f36e1a7";

#[test]
fn agents_canonical_part_matches_pinned_digest() {
    let agents = std::fs::read(root().join("AGENTS.md")).unwrap();
    let marker: &[u8] = b"<!-- repo annex below this line -->";
    let position = agents
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    let mut hasher = Sha256::new();
    hasher.update(&agents[..position]);
    let digest: String = hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(digest, CANONICAL_ABOVE_MARKER_SHA256);
}

#[test]
fn readme_has_exactly_one_status_section() {
    let text = read("README.md");
    assert_eq!(text.matches("\n## Status\n").count(), 1);
}

#[test]
fn readme_carries_no_wrong_arc_label() {
    assert!(!read("README.md").contains("Fleet Operations"));
}

#[test]
fn codepoint_scan_counts_an_em_dash() {
    let dir = temp_dir("em-dash");
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
    assert!(result.stdout.contains("note.md"));
}

#[test]
fn codepoint_scan_counts_an_en_dash() {
    let dir = temp_dir("en-dash");
    std::fs::write(dir.join("note.md"), "a\u{2013}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("en dash U+2013 count 1"));
}

#[test]
fn codepoint_scan_scans_a_root_under_an_excluded_ancestor() {
    let dir = temp_dir("excluded-ancestor").join("venv").join("tree");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_skips_excluded_dirs_below_the_root() {
    let dir = temp_dir("excluded-dirs");
    let cache = dir.join("build");
    std::fs::create_dir_all(&cache).unwrap();
    std::fs::write(cache.join("note.md"), "a\u{2014}b").unwrap();
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
}

#[test]
fn contract_obligations_carry_their_substance() {
    let text = read("CONTRACT.md");
    for phrase in [
        "present from the first commit",
        "every later change lands through a pull request",
        "no paid service",
        "cargo test plus the codepoint scan run through cargo",
        "0 of 100 until a full cycle",
        "no file carries a real trace or a real transcript or a real name",
        "SHA-256 digest of the part above the marked line",
    ] {
        assert!(text.contains(phrase), "{phrase}");
    }
}

#[test]
fn codepoint_scan_fails_loudly_on_undecodable_input() {
    let dir = temp_dir("undecodable");
    std::fs::write(dir.join("note.md"), b"\xff\xfe not utf-8").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 2);
    assert!(result.stderr.contains("note.md"));
}

#[test]
fn codepoint_scan_counts_a_dash_in_a_file_with_no_suffix() {
    let dir = temp_dir("no-suffix");
    std::fs::write(dir.join("LICENSE"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_counts_a_dash_in_an_uppercase_suffix_file() {
    let dir = temp_dir("upper-suffix");
    std::fs::write(dir.join("UPPER.MD"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_skips_a_file_with_an_uppercase_binary_suffix() {
    let dir = temp_dir("upper-binary");
    std::fs::write(dir.join("FAKE.PNG"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

// Audit finding DK-A3: the scanner collects regular files only.
// Before the fix a FIFO was collected as a file and its read
// blocked forever, so the FIFO pin drives the scanner under a
// deadline: against the old code the deadline expires and the
// pin fails on the missing answer, where against the fix the
// scan answers at once.

// Portability adaptation gates mkfifo and Unix symlink staging to Unix.
#[cfg(unix)]
fn scan_tree_with_deadline(root: &Path) -> Option<ScanOutput> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(root)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        match child.try_wait().unwrap() {
            Some(_) => {
                let output = child.wait_with_output().unwrap();
                return Some(ScanOutput {
                    status: output.status.code().unwrap_or(-1),
                    stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
                });
            }
            None => {
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return None;
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
    }
}

#[cfg(unix)]
#[test]
fn codepoint_scan_skips_a_fifo_and_terminates() {
    let dir = temp_dir("fifo");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let made = Command::new("mkfifo")
        .arg(dir.join("pipe"))
        .output()
        .unwrap();
    assert!(made.status.success());
    let result = scan_tree_with_deadline(&dir).expect("the scan terminated");
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

#[cfg(unix)]
#[test]
fn codepoint_scan_counts_a_dash_through_a_symlink_to_a_file() {
    let dir = temp_dir("symlink-file");
    std::fs::write(dir.join("real.md"), "a\u{2014}b").unwrap();
    std::os::unix::fs::symlink(dir.join("real.md"), dir.join("link.md")).unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 2"));
}

#[cfg(unix)]
#[test]
fn codepoint_scan_skips_a_dangling_symlink() {
    let dir = temp_dir("symlink-dangling");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    std::os::unix::fs::symlink(dir.join("missing.md"), dir.join("link.md")).unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
}

#[test]
fn portability_workflow_carries_the_fleet_credential_hygiene() {
    let port_text = read(".github/workflows/portability.yml");
    assert!(port_text.contains("permissions:\n  contents: read"));
    assert!(!port_text.contains("write-all"));
    assert!(!port_text.contains("contents: write"));
    let checkouts = port_text.matches("actions/checkout@").count();
    assert_eq!(checkouts, 3);
    assert_eq!(
        port_text.matches("persist-credentials: false").count(),
        checkouts
    );
    assert!(!port_text.contains("rust-toolchain@master"));
    let toolchain_lines: Vec<&str> = port_text
        .lines()
        .filter(|line| line.contains("dtolnay/rust-toolchain@"))
        .collect();
    assert_eq!(toolchain_lines.len(), 3);
    for toolchain_line in toolchain_lines {
        let pin = toolchain_line
            .split("dtolnay/rust-toolchain@")
            .nth(1)
            .unwrap()
            .trim();
        assert_eq!(pin.len(), 40, "{}", toolchain_line);
        assert!(pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }
}

#[test]
fn codepoint_scan_extra_argument_on_dead_stderr_exits_two() {
    use std::io::Write;
    let dir = temp_dir("extra-argument-dead-stderr");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    // Portability adaptation retries pipe creation when a concurrent child
    // spawn on macOS inherits reader before FIOCLEX closes the race window.
    let writer = (0..64)
        .find_map(|_| {
            let (reader, mut writer) = std::io::pipe().unwrap();
            drop(reader);
            if writer.write_all(b"probe").is_err() {
                Some(writer)
            } else {
                std::thread::sleep(std::time::Duration::from_millis(5));
                None
            }
        })
        .expect("writes to a closed pipe must fail");
    let status = Command::new(env!("CARGO_BIN_EXE_codepoint_scan"))
        .arg(&dir)
        .arg("second-root")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::from(writer))
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));
}

// Audit finding DK-A42: the scanner refuses an argument standing
// after the scan root. Before the fix the extra argument was
// dropped silently and the scan answered for the root alone, so
// the first pin below failed on the missing refusal and the
// second on the count report the old code printed instead.

#[test]
fn codepoint_scan_refuses_an_argument_after_the_root() {
    let dir = temp_dir("extra-argument");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let result = scan_tree_with_extra(&dir, "second-root");
    assert_eq!(result.status, 2, "{}", result.stdout);
    assert!(
        result.stderr.contains("at most one argument"),
        "{}",
        result.stderr
    );
    assert_eq!(result.stderr.lines().count(), 1, "{}", result.stderr);
    assert!(result.stdout.is_empty(), "{}", result.stdout);
}

#[test]
fn codepoint_scan_refuses_an_extra_argument_before_scanning() {
    let dir = temp_dir("extra-argument-dirty");
    std::fs::write(dir.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree_with_extra(&dir, "second-root");
    assert_eq!(result.status, 2, "{}", result.stdout);
    assert!(result.stdout.is_empty(), "{}", result.stdout);
}

// Audit finding DK-A44: the scanner answers a scan error at exit 2
// when the scan root does not stand, a deliberate difference from
// the setup scanner the module record names, which exited 0 with
// zero counts. This pin is a preservation pin: it passes against
// the standing code by design and fails on the plausible wrong
// form, a scanner that reads a missing root as an empty tree and
// answers the zero counts at exit 0.

#[test]
fn codepoint_scan_refuses_a_root_that_does_not_stand() {
    let dir = temp_dir("missing-root");
    let missing = dir.join("no-such-tree");
    let result = scan_tree(&missing);
    assert_eq!(result.status, 2, "{}", result.stdout);
    assert!(result.stderr.contains("cannot read"), "{}", result.stderr);
    assert!(
        result.stderr.contains(&missing.display().to_string()),
        "{}",
        result.stderr
    );
    assert_eq!(result.stderr.lines().count(), 1, "{}", result.stderr);
    assert!(result.stdout.is_empty(), "{}", result.stdout);
}

#[test]
fn codepoint_scan_counts_both_dashes_in_one_tree() {
    let dir = temp_dir("both-dashes");
    std::fs::write(dir.join("alpha.md"), "a\u{2014}b\u{2014}c\u{2013}d").unwrap();
    std::fs::write(dir.join("beta.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 1, "{}", result.stderr);
    let expected = format!(
        "{}: em dash 2, en dash 1\n{}: em dash 1, en dash 0\nem dash U+2014 count 3\nen dash U+2013 count 1\n",
        dir.join("alpha.md").display(),
        dir.join("beta.md").display()
    );
    assert_eq!(result.stdout, expected);
}

#[test]
fn codepoint_scan_skips_every_excluded_dir_below_the_root() {
    let dir = temp_dir("excluded-dirs-all");
    for name in [
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".venv",
        "venv",
        "node_modules",
        "build",
        "dist",
        "target",
    ] {
        let excluded = dir.join(name);
        std::fs::create_dir_all(&excluded).unwrap();
        std::fs::write(excluded.join("note.md"), "a\u{2014}b").unwrap();
    }
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
    let control = temp_dir("excluded-dirs-all-control");
    let inside = control.join("real-dir");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(inside.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&control);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

#[test]
fn codepoint_scan_skips_every_binary_suffix() {
    let dir = temp_dir("binary-suffixes-all");
    for suffix in [
        "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "gz", "tar", "whl", "so", "dylib",
    ] {
        std::fs::write(dir.join(format!("sample.{suffix}")), "a\u{2014}b").unwrap();
    }
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
    let control = temp_dir("binary-suffixes-all-control");
    std::fs::write(control.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&control);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

// Portability adaptation gates Unix directory symlink staging to Unix.
#[cfg(unix)]
#[test]
fn codepoint_scan_does_not_follow_a_symlink_to_a_directory() {
    let outside = temp_dir("symlink-dir-outside");
    std::fs::write(outside.join("note.md"), "a\u{2014}b").unwrap();
    let dir = temp_dir("symlink-dir");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("linked-dir")).unwrap();
    let result = scan_tree(&dir);
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
    let control = temp_dir("symlink-dir-control");
    let inside = control.join("real-dir");
    std::fs::create_dir_all(&inside).unwrap();
    std::fs::write(inside.join("note.md"), "a\u{2014}b").unwrap();
    let result = scan_tree(&control);
    assert_eq!(result.status, 1);
    assert!(result.stdout.contains("em dash U+2014 count 1"));
}

// Portability adaptation gates mkfifo and symlink-to-FIFO staging to Unix.
#[cfg(unix)]
#[test]
fn codepoint_scan_skips_a_symlink_to_a_fifo_and_terminates() {
    let dir = temp_dir("symlink-fifo");
    std::fs::write(dir.join("clean.md"), "clean").unwrap();
    let pipe_path = dir.join("pipe");
    let made = Command::new("mkfifo").arg(&pipe_path).output().unwrap();
    assert!(made.status.success());
    std::os::unix::fs::symlink(&pipe_path, dir.join("linked-pipe")).unwrap();
    let result = scan_tree_with_deadline(&dir).expect("the scan terminated");
    assert_eq!(result.status, 0, "{}", result.stderr);
    assert!(result.stdout.contains("em dash U+2014 count 0"));
    assert!(result.stdout.contains("en dash U+2013 count 0"));
}

fn job_sections(workflow_text: &str) -> Vec<(String, String)> {
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    let mut current_name: Option<String> = None;
    let mut current_body = String::new();
    for line in workflow_text.lines() {
        if line == "jobs:" {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let is_job_header = line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim().contains(' ');
        if is_job_header {
            if let Some(prev) = current_name.take() {
                jobs.push((prev, std::mem::take(&mut current_body)));
            }
            current_name = Some(line.trim().trim_end_matches(':').to_string());
        } else if current_name.is_some() {
            current_body.push_str(line);
            current_body.push('\n');
        }
    }
    if let Some(prev) = current_name {
        jobs.push((prev, current_body));
    }
    jobs
}

#[test]
fn dk29_release_packaging_metadata_and_version_parity() {
    assert_eq!(env!("CARGO_PKG_VERSION"), "0.2.0");
    let cargo_toml = read("Cargo.toml");
    for required in [
        "version = \"0.2.0\"",
        "rust-version = \"1.91\"",
        "default-run = \"deadbolt\"",
        "readme = \"README.md\"",
        "repository = \"https://github.com/david-engelmann/deadbolt\"",
        "homepage = \"https://github.com/david-engelmann/deadbolt\"",
        "documentation = \"https://docs.rs/deadbolt\"",
        "keywords = [",
        "categories = [",
        "exclude = [\".github/**\"]",
    ] {
        assert!(cargo_toml.contains(required), "missing {required}");
    }
    assert!(!root().join("bindings").exists());

    let ver_out = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .arg("--version")
        .output()
        .unwrap();
    assert_eq!(ver_out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&ver_out.stdout), "deadbolt 0.2.0\n");

    let changelog = read("CHANGELOG.md");
    assert!(changelog.contains("## 0.2.0"));
    assert!(changelog.contains("## 0.1.0"));
    let security = read("SECURITY.md");
    assert!(security.contains("0.2.x"));
    assert!(security.contains("GitHub Security Advisories"));
}

fn checkout_steps_all_disable_credentials(workflow_text: &str) -> usize {
    let mut count = 0usize;
    for (_, body) in job_sections(workflow_text) {
        let mut in_checkout = false;
        let mut saw_false = false;
        for line in body.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("- ") {
                if in_checkout {
                    assert!(
                        saw_false,
                        "checkout step missing persist-credentials: false in:\n{body}"
                    );
                }
                in_checkout = trimmed.contains("actions/checkout@");
                saw_false = false;
                if in_checkout {
                    count += 1;
                }
            } else if in_checkout && trimmed == "persist-credentials: false" {
                saw_false = true;
            }
        }
        if in_checkout {
            assert!(
                saw_false,
                "checkout step missing persist-credentials: false in:\n{body}"
            );
        }
    }
    count
}

#[test]
fn dk29_release_workflow_carries_the_fleet_credential_hygiene() {
    let rel_text = read(".github/workflows/release.yml");
    assert!(rel_text.contains("permissions:\n  contents: read"));
    assert!(rel_text.contains("- \"v*\""));
    assert!(rel_text.contains("workflow_dispatch:"));
    assert!(!rel_text.contains("write-all"));
    assert!(!rel_text.contains("id-token: write"));
    assert!(!rel_text.contains("rust-toolchain@master"));
    assert!(!rel_text.contains("python3 -"));
    let checkouts = checkout_steps_all_disable_credentials(&rel_text);
    assert_eq!(checkouts, 3);
    let toolchain_lines: Vec<&str> = rel_text
        .lines()
        .filter(|line| line.contains("dtolnay/rust-toolchain@"))
        .collect();
    assert!(!toolchain_lines.is_empty());
    for line in toolchain_lines {
        let pin = line.split("dtolnay/rust-toolchain@").nth(1).unwrap().trim();
        assert_eq!(pin.len(), 40, "{line}");
        assert!(pin
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    }

    let write_lines: Vec<&str> = rel_text
        .lines()
        .filter(|line| line.contains(": write"))
        .collect();
    assert_eq!(write_lines, vec!["      contents: write"]);

    let jobs = job_sections(&rel_text);
    let names: Vec<&str> = jobs.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(
        names,
        vec!["verify", "binaries", "publish-crates", "github-release"]
    );
    for (name, body) in &jobs {
        match name.as_str() {
            "verify" => {
                assert!(body.contains("REF_TYPE:"));
                assert!(body.contains("REF_NAME:"));
                assert!(body.contains("expected = f\"v{ver}\""));
            }
            "binaries" => {
                assert!(body.contains("    needs: verify\n"));
                for triple in [
                    "x86_64-unknown-linux-gnu",
                    "aarch64-unknown-linux-gnu",
                    "aarch64-apple-darwin",
                    "x86_64-pc-windows-msvc",
                ] {
                    assert!(body.contains(triple), "missing {triple}");
                }
            }
            "publish-crates" | "github-release" => {
                let (header, _) = body.split_once("\n    steps:\n").expect("steps header");
                assert!(header.lines().any(|l| l == "    needs: [verify, binaries]"));
                assert!(header
                    .lines()
                    .any(|l| l == "    if: github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')"));
                if name == "github-release" {
                    assert!(header.lines().any(|l| l == "      contents: write"));
                } else {
                    assert!(!body.contains("contents: write"));
                }
            }
            other => panic!("unexpected job {other}"),
        }
    }
}
