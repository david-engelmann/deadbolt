//! Scan text files for em dash and en dash codepoints.
//!
//! A std only Rust port of the setup scanner. It counts U+2014 and
//! U+2013 in every file under the scan root and exits 1 when either
//! count is nonzero. What it counts, the counts it prints, the
//! directory names it excludes below the scan root, and the binary
//! suffixes it skips match the setup scanner, and four differences
//! from that scanner stand named here as deliberate behaviour of
//! the port. The excluded directory names add target, the cargo
//! output directory, because in a Rust repo that is the generated
//! directory the gitignore names, and the scanner must be able to
//! run over a tree the local gate has already built in. The scan
//! root defaults to the current directory, where the setup scanner
//! defaulted to the root of the repo it shipped in. The gate runs
//! the scan from the root it means to scan and names no root, so
//! the default names that root. A scan root that does not stand
//! is a scan error at exit 2, where the setup scanner exited
//! 0 with zero counts. A file that cannot be read is a clean scan
//! error at exit 2, where the setup scanner let the failure escape
//! as a traceback at exit 1. The walk excludes directories by name
//! below the scan root, so the name of an ancestor of the root can
//! never exclude the root itself, and every file in the tree is
//! scanned, whatever its name or suffix, apart from the known
//! binary suffixes, and a file that does not decode as UTF-8 fails
//! the scan loudly instead of passing unseen.
//!
//! Only regular files are collected for reading, where a symlink
//! counts exactly when its target is a regular file, audit
//! finding DK-A3. A FIFO, a socket, or a device file is skipped,
//! because a read on one can block forever, and a gate step must
//! always terminate with a verdict.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const EM_DASH: char = '\u{2014}';
const EN_DASH: char = '\u{2013}';
const BINARY_SUFFIXES: [&str; 13] = [
    "png", "jpg", "jpeg", "gif", "ico", "webp", "pdf", "zip", "gz", "tar", "whl", "so", "dylib",
];
const EXCLUDED_DIRS: [&str; 9] = [
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".venv",
    "venv",
    "node_modules",
    "build",
    "dist",
    "target",
];

struct ScanError(String);

fn has_binary_suffix(path: &Path) -> bool {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) => BINARY_SUFFIXES.contains(&ext.to_lowercase().as_str()),
        None => false,
    }
}

fn collect(root: &Path, out: &mut Vec<PathBuf>) -> Result<(), ScanError> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    let mut files: Vec<PathBuf> = Vec::new();
    let entries = std::fs::read_dir(root)
        .map_err(|err| ScanError(format!("cannot read {}, {err}", root.display())))?;
    for entry in entries {
        let entry =
            entry.map_err(|err| ScanError(format!("cannot read {}, {err}", root.display())))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| ScanError(format!("cannot read {}, {err}", path.display())))?;
        if file_type.is_dir() {
            dirs.push(path);
        } else if file_type.is_file() || (file_type.is_symlink() && path.is_file()) {
            files.push(path);
        }
    }
    dirs.sort();
    files.sort();
    for file in files {
        if !has_binary_suffix(&file) {
            out.push(file);
        }
    }
    for dir in dirs {
        let name = dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !EXCLUDED_DIRS.contains(&name.as_str()) {
            collect(&dir, out)?;
        }
    }
    Ok(())
}

fn scan(root: &Path) -> Result<(usize, usize, Vec<String>), ScanError> {
    let mut files = Vec::new();
    collect(root, &mut files)?;
    let mut em_count = 0;
    let mut en_count = 0;
    let mut hits = Vec::new();
    for path in &files {
        let bytes = std::fs::read(path)
            .map_err(|err| ScanError(format!("cannot read {}, {err}", path.display())))?;
        let text = std::str::from_utf8(&bytes).map_err(|err| {
            ScanError(format!("cannot decode {} as UTF-8, {err}", path.display()))
        })?;
        let mut file_em = 0;
        let mut file_en = 0;
        for ch in text.chars() {
            if ch == EM_DASH {
                file_em += 1;
            } else if ch == EN_DASH {
                file_en += 1;
            }
        }
        if file_em > 0 || file_en > 0 {
            hits.push(format!(
                "{}: em dash {file_em}, en dash {file_en}",
                path.display()
            ));
        }
        em_count += file_em;
        en_count += file_en;
    }
    Ok((em_count, en_count, hits))
}

/// The scan root is the call's one optional argument, converted
/// strictly from its operating system form, audit finding DK-A9.
/// An argument that is not valid Unicode text is a scan error at
/// exit 2, where std::env::args() panicked and exited 101 before.
/// An argument standing after the root is a scan error at exit 2
/// as well, audit finding DK-A42: the scan serves the one root
/// its call names, and no part of a call is dropped silently.
fn main() -> ExitCode {
    let root = match std::env::args_os().nth(1) {
        Some(arg) => match arg.into_string() {
            Ok(text) => PathBuf::from(text),
            Err(_) => {
                scan_error_line("an argument is not valid Unicode text");
                return ExitCode::from(2);
            }
        },
        None => PathBuf::from("."),
    };
    if std::env::args_os().nth(2).is_some() {
        scan_error_line("the scan takes at most one argument, the scan root");
        return ExitCode::from(2);
    }
    match scan(&root) {
        Ok((em_count, en_count, hits)) => {
            let mut report = String::new();
            for hit in &hits {
                report.push_str(hit);
                report.push('\n');
            }
            report.push_str(&format!("em dash U+2014 count {em_count}\n"));
            report.push_str(&format!("en dash U+2013 count {en_count}\n"));
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            let written = lock.write_all(report.as_bytes()).and_then(|_| lock.flush());
            match written {
                Ok(()) => {
                    if em_count > 0 || en_count > 0 {
                        ExitCode::from(1)
                    } else {
                        ExitCode::from(0)
                    }
                }
                Err(err) => {
                    scan_error_line(&format!("the report could not be written because {err}"));
                    ExitCode::from(2)
                }
            }
        }
        Err(ScanError(message)) => {
            scan_error_line(&message);
            ExitCode::from(2)
        }
    }
}

/// Write the one scan error line to standard error through a
/// fallible write that never panics, audit finding DK-A23. The
/// print macros panic when a write fails, and a failed write on
/// the error line itself would replace the exit code with the
/// panic's 101, outside the exits this scanner states. A failure
/// here has no channel left to report through and is let go, so
/// the exit code always stands.
fn scan_error_line(message: &str) {
    let stderr = std::io::stderr();
    let mut lock = stderr.lock();
    let _ = lock.write_all(format!("scan error, {message}\n").as_bytes());
    let _ = lock.flush();
}
