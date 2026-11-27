//! Integration pins for obligation DK-30 covering src/lib.rs obligation
//! range documentation, docs/GUIDE.md, verified README.md installation
//! commands, examples/quickstart.rs, and examples/broker_walkthrough.py.

#[path = "../examples/quickstart.rs"]
mod quickstart;

use std::path::Path;
use std::process::Command;

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn find_python() -> &'static str {
    for candidate in ["python3", "python"] {
        if Command::new(candidate)
            .args(["-c", "import sys"])
            .status()
            .is_ok_and(|status| status.success())
        {
            return candidate;
        }
    }
    panic!("neither python3 nor python is runnable on PATH");
}

fn strip_markdown_link_targets(line: &str) -> String {
    let mut current = line.to_string();
    loop {
        let mut out = String::with_capacity(current.len());
        let bytes = current.as_bytes();
        let mut i = 0;
        let mut changed = false;
        while i < bytes.len() {
            let bang = bytes[i] == b'!' && i + 1 < bytes.len() && bytes[i + 1] == b'[';
            let open = if bang { i + 1 } else { i };
            if bytes[open] == b'[' {
                if let Some(rel_close) = current[open + 1..].find(']') {
                    let close = open + 1 + rel_close;
                    let label = &current[open + 1..close];
                    if !label.contains('[')
                        && !label.contains(']')
                        && close + 1 < bytes.len()
                        && bytes[close + 1] == b'('
                    {
                        if let Some(rel_end) = current[close + 2..].find(')') {
                            out.push_str(label);
                            i = close + 2 + rel_end + 1;
                            changed = true;
                            continue;
                        }
                    }
                }
            }
            let ch = current[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
        if !changed {
            return out;
        }
        current = out;
    }
}

fn strip_inline_code_spans(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut in_code = false;
    for ch in line.chars() {
        if ch == '`' {
            in_code = !in_code;
        } else if !in_code {
            out.push(ch);
        }
    }
    out
}

fn is_table_delimiter_row(trimmed: &str) -> bool {
    let inner = trimmed.trim_matches('|').trim();
    !inner.is_empty()
        && inner.split('|').all(|cell| {
            let c = cell.trim();
            c.contains('-') && c.chars().all(|ch| matches!(ch, '-' | ':' | ' ' | '\t'))
        })
}

fn check_prose_violations(text: &str) -> Vec<String> {
    let mut violations = Vec::new();
    if text.contains('\u{2014}') {
        violations.push("em dash U+2014".to_string());
    }
    if text.contains('\u{2013}') {
        violations.push("en dash U+2013".to_string());
    }
    let mut in_fence = false;
    let mut fence_marker = String::new();
    for (idx, raw) in text.lines().enumerate() {
        let trimmed = raw.trim_start();
        if trimmed.starts_with("```") || trimmed.starts_with("~~~") {
            let ch = trimmed.chars().next().unwrap();
            let count = trimmed.chars().take_while(|c| *c == ch).count();
            let marker: String = std::iter::repeat_n(ch, count).collect();
            if !in_fence {
                in_fence = true;
                fence_marker = marker;
            } else if trimmed.starts_with(&fence_marker) {
                in_fence = false;
            }
            continue;
        }
        if in_fence || trimmed.starts_with("<!--") {
            continue;
        }
        let cleaned = if trimmed.starts_with('|') {
            if is_table_delimiter_row(trimmed) {
                continue;
            }
            strip_markdown_link_targets(&strip_inline_code_spans(raw))
        } else {
            strip_markdown_link_targets(raw)
        };
        if cleaned.contains(':') {
            violations.push(format!("line {}: colon in prose: {raw}", idx + 1));
        }
        if cleaned.contains(';') {
            violations.push(format!("line {}: semicolon in prose: {raw}", idx + 1));
        }
    }
    violations
}

fn assert_clean_prose(path: &Path, text: &str) {
    let violations = check_prose_violations(text);
    assert!(
        violations.is_empty(),
        "{} failed prose check: {violations:?}",
        path.display()
    );
}

fn assert_sanitized(path: &Path, text: &str) {
    for forbidden in ["/Users/", "/home/david", "@gmail.com"] {
        assert!(
            !text.contains(forbidden),
            "{} contains unsanitized marker {forbidden:?}",
            path.display()
        );
    }
}

#[test]
fn prose_scanner_rejects_colons_semicolons_and_table_prose_punctuation() {
    assert!(!check_prose_violations("a\u{2014}b").is_empty());
    assert!(!check_prose_violations("a\u{2013}b").is_empty());
    assert!(!check_prose_violations("Plain sentence: bad.").is_empty());
    assert!(!check_prose_violations("Plain sentence; bad.").is_empty());
    assert!(!check_prose_violations("| col | cell: bad |\n").is_empty());
    assert!(!check_prose_violations("| col | cell; bad |\n").is_empty());
    assert!(
        check_prose_violations(
            "Clean [guide](https://example.test/a:b).\n| col | desc |\n| --- | :---: |\n| `a:b` | clean cell |\n"
        )
        .is_empty()
    );
}

#[test]
fn lib_doc_contract_and_guide_satisfy_dk30() {
    let lib_rs = std::fs::read_to_string(repo_root().join("src/lib.rs")).expect("src/lib.rs");
    assert!(
        lib_rs.contains("DK-1 to DK-30 in CONTRACT.md"),
        "src/lib.rs must name the full obligation range DK-1 to DK-30"
    );
    assert!(!lib_rs.contains("DK-1 to DK-28"));

    let contract_path = repo_root().join("CONTRACT.md");
    let contract = std::fs::read_to_string(&contract_path).expect("CONTRACT.md exists");
    let (_, dk30_section) = contract
        .split_once(
            "## Operator guide, runnable quickstarters, and verified install paths amendment",
        )
        .expect("DK-30 amendment section present");
    assert_clean_prose(&contract_path, dk30_section);
    assert_sanitized(&contract_path, dk30_section);

    let guide_path = repo_root().join("docs/GUIDE.md");
    let guide = std::fs::read_to_string(&guide_path).expect("docs/GUIDE.md exists");
    assert_clean_prose(&guide_path, &guide);
    assert_sanitized(&guide_path, &guide);
    assert!(!guide.contains("cargo install deadbolt"));

    for needle in [
        "deadbolt-envelope/1",
        "XChaCha20-Poly1305",
        "0600",
        "Argon2id",
        "keychain",
        "passphrase",
        "GRANT_TOKEN=",
        "examples/redeem_wrapper.py",
        "status",
        "revoke",
        "cutoff",
        "rotate",
        "replace",
        "retire",
        "rekey",
        "examples/quickstart.rs",
        "examples/broker_walkthrough.py",
        "portcullis",
        "arvin",
        "mayfly",
    ] {
        assert!(guide.contains(needle), "docs/GUIDE.md missing {needle:?}");
    }
}

#[test]
fn readme_install_avoids_third_party_bare_crate_and_links_guides() {
    let readme_path = repo_root().join("README.md");
    let readme = std::fs::read_to_string(&readme_path).expect("README.md exists");
    assert_clean_prose(&readme_path, &readme);
    assert_sanitized(&readme_path, &readme);

    for required in [
        "cargo install --git https://github.com/david-engelmann/deadbolt.git --tag v0.2.0 --bin deadbolt",
        "https://github.com/david-engelmann/deadbolt/releases/tag/v0.2.0",
        "cargo install --path . --bin deadbolt",
        "[docs/GUIDE.md](docs/GUIDE.md)",
        "[examples/quickstart.rs](examples/quickstart.rs)",
        "[examples/broker_walkthrough.py](examples/broker_walkthrough.py)",
    ] {
        assert!(readme.contains(required), "README.md missing {required:?}");
    }
    assert!(
        !readme.contains("cargo install deadbolt"),
        "README.md must not instruct bare cargo install deadbolt"
    );
}

#[test]
fn rust_quickstart_example_runs_end_to_end() {
    assert_sanitized(
        &repo_root().join("examples/quickstart.rs"),
        &std::fs::read_to_string(repo_root().join("examples/quickstart.rs")).unwrap(),
    );
    quickstart::run_quickstart().expect("examples/quickstart.rs runs end to end");
}

#[test]
fn python_broker_walkthrough_runs_without_printing_secrets() {
    let script = repo_root().join("examples/broker_walkthrough.py");
    assert_sanitized(&script, &std::fs::read_to_string(&script).unwrap());

    let output = Command::new(find_python())
        .arg(&script)
        .arg("--deadbolt-bin")
        .arg(env!("CARGO_BIN_EXE_deadbolt"))
        .output()
        .expect("spawn examples/broker_walkthrough.py");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "broker_walkthrough.py failed ({:?}): stdout={stdout} stderr={stderr}",
        output.status.code()
    );
    for needle in [
        "1. enrolled storage-api",
        "2. status route= passphrase credentials= 1",
        "4. redeem_wrapper verified child secret injection and env scrubbing",
        "5. scope mismatch refused cleanly",
        "6. cutoff ended 1 grant and revoked subsequent redemption",
        "7. rekeyed store and verified 7 non-secret audit records",
    ] {
        assert!(
            stdout.contains(needle),
            "broker_walkthrough.py stdout missing {needle:?}: {stdout}"
        );
    }
    for secret in [
        "SYNTHETIC-TEST-VALUE-storage-key",
        "SYNTHETIC-TEST-VALUE-passphrase",
        "SYNTHETIC-TEST-VALUE-passphrase-v2",
    ] {
        assert!(!stdout.contains(secret), "secret leaked to stdout");
        assert!(!stderr.contains(secret), "secret leaked to stderr");
    }
}
