//! The deadbolt command line, a thin front end over the library.
//!
//! The value an enrollment registers arrives from a named value file
//! only, never from an argument. The wall clock UTC instant is passed
//! to every operation and no option overrides it. The custody route
//! is a global option standing after the state path, required exactly
//! when an act creates a store or adopts a plaintext one. The
//! passphrase enters through the DEADBOLT_PASSPHRASE environment
//! variable, read once at startup, or through a terminal prompt with
//! echo disabled when the variable stands unset, and never through
//! an argument or a file. Exits follow DK-13, success 0, refusals
//! and corrupt and permission gated states 1, and caller errors 2,
//! with every error as one line on standard error.

use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use deadbolt::custody::KeyCustody;
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
use deadbolt::custody::{CustodyError, CustodyLoad, StoreKey};
use deadbolt::{Error, PassphraseSource, Route, Scope, Unlock, Zeroizing};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(output) => {
            print!("{output}");
            ExitCode::from(0)
        }
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::from(exit_code(&err))
        }
    }
}

fn exit_code(err: &Error) -> u8 {
    match err {
        Error::Caller(_) | Error::Io(_) => 2,
        Error::Refusal(_) | Error::Redeem(_) | Error::Corrupt(_) | Error::Permission(_) => 1,
    }
}

fn caller(message: &str) -> Error {
    Error::Caller(message.to_string())
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

/// The command line's passphrase supply, DK-19.
///
/// The environment variable is read once at startup. A variable
/// standing present, even holding an empty value, is the supply, and
/// the library judges what it holds. Only when the variable stands
/// unset and the standard input is a terminal is a prompt offered,
/// with echo disabled, and the prompted value is asked at most once
/// per invocation and kept in zeroizing memory.
struct CliPassphrase {
    from_env: Option<Zeroizing<String>>,
    prompted: Mutex<Option<Zeroizing<String>>>,
}

impl CliPassphrase {
    fn from_environment() -> CliPassphrase {
        CliPassphrase {
            from_env: std::env::var("DEADBOLT_PASSPHRASE")
                .ok()
                .map(Zeroizing::new),
            prompted: Mutex::new(None),
        }
    }
}

impl PassphraseSource for CliPassphrase {
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>> {
        if let Some(value) = &self.from_env {
            return Some(Zeroizing::new(value.as_bytes().to_vec()));
        }
        if !std::io::stdin().is_terminal() {
            return None;
        }
        let mut slot = self.prompted.lock().ok()?;
        if slot.is_none() {
            *slot = rpassword::prompt_password("passphrase: ")
                .ok()
                .map(Zeroizing::new);
        }
        slot.as_ref()
            .map(|value| Zeroizing::new(value.as_bytes().to_vec()))
    }
}

/// The custody backend for a target with no platform backend.
///
/// The keyring dependency stands only on the three platforms DK-18
/// names, so on any other target this backend stands in its place
/// and every operation reports the custody service as unreachable,
/// which the store layer words as the keychain service not being
/// available. No key is ever held here and no mock store is ever
/// selected in its place.
#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
struct NoCustodyService;

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
impl KeyCustody for NoCustodyService {
    fn store_key(&self, _store_id: &str, _key: &StoreKey) -> Result<(), CustodyError> {
        Err(CustodyError::new(
            "no keychain backend stands on this platform",
        ))
    }

    fn load_key(&self, _store_id: &str) -> CustodyLoad {
        CustodyLoad::ServiceFailure("no keychain backend stands on this platform".to_string())
    }

    fn delete_key(&self, _store_id: &str) -> Result<(), CustodyError> {
        Err(CustodyError::new(
            "no keychain backend stands on this platform",
        ))
    }
}

/// Select the keychain backend for this platform.
///
/// The selection happens here, once, and never enables the fixture
/// backend the crate's own tests use.
fn platform_backend() -> Box<dyn KeyCustody> {
    #[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
    {
        deadbolt::custody::platform_custody()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        Box::new(NoCustodyService)
    }
}

/// A minimal option reader over the arguments of one command.
struct Options {
    pairs: Vec<(String, String)>,
    flags: Vec<String>,
}

impl Options {
    fn parse(args: &[String], valued: &[&str], flags: &[&str]) -> Result<Options, Error> {
        let mut options = Options {
            pairs: Vec::new(),
            flags: Vec::new(),
        };
        let mut index = 0;
        while index < args.len() {
            let arg = &args[index];
            if valued.contains(&arg.as_str()) {
                let value = args.get(index + 1).ok_or_else(|| {
                    caller("an option that takes a value stands with no value after it")
                })?;
                options.pairs.push((arg.clone(), value.clone()));
                index += 2;
            } else if flags.contains(&arg.as_str()) {
                options.flags.push(arg.clone());
                index += 1;
            } else {
                return Err(caller(
                    "an argument the command does not offer stands in the call",
                ));
            }
        }
        Ok(options)
    }

    fn one(&self, name: &str) -> Result<Option<String>, Error> {
        let found: Vec<&String> = self
            .pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value)
            .collect();
        match found.len() {
            0 => Ok(None),
            1 => Ok(Some(found[0].clone())),
            _ => Err(caller(
                "an option that takes one value was given more than once",
            )),
        }
    }

    fn required(&self, name: &str) -> Result<String, Error> {
        self.one(name)?
            .ok_or_else(|| caller("a required option is missing from the call"))
    }

    fn many(&self, name: &str) -> Vec<String> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
            .collect()
    }
}

fn parse_scope(text: &str) -> Result<Scope, Error> {
    let mut parts = text.split(':');
    let resource = parts.next().unwrap_or_default();
    let action = parts.next().unwrap_or_default();
    if resource.is_empty() || action.is_empty() || parts.next().is_some() {
        return Err(caller(
            "a scope is stated as one resource and one action joined by a colon",
        ));
    }
    Ok(Scope {
        resource: resource.to_string(),
        action: action.to_string(),
    })
}

fn read_value_file(path: &str) -> Result<String, Error> {
    let text = std::fs::read_to_string(path)
        .map_err(|_| caller("the value file cannot be read as text"))?;
    let stripped = text
        .strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or(&text);
    Ok(stripped.to_string())
}

fn run(args: &[String]) -> Result<String, Error> {
    if args.len() < 3 || args[0] != "--state" {
        return Err(caller(
            "usage, deadbolt --state PATH with an optional --route keychain or passphrase and then one of enroll, retire, grant, redeem, revoke, cutoff, audit",
        ));
    }
    let state = PathBuf::from(&args[1]);
    let mut index = 2;
    let mut route = None;
    if args.get(index).map(String::as_str) == Some("--route") {
        let value = args
            .get(index + 1)
            .ok_or_else(|| caller("an option that takes a value stands with no value after it"))?;
        route = Some(match value.as_str() {
            "keychain" => Route::Keychain,
            "passphrase" => Route::Passphrase,
            _ => return Err(caller("the custody route is keychain or passphrase")),
        });
        index += 2;
    }
    let command = args.get(index).map(String::as_str).ok_or_else(|| {
        caller("the command is not one of enroll, retire, grant, redeem, revoke, cutoff, audit")
    })?;
    let rest = &args[index + 1..];
    let now = now_seconds();
    let backend = platform_backend();
    let passphrase = CliPassphrase::from_environment();
    let unlock = Unlock {
        route,
        custody: &*backend,
        passphrase: &passphrase,
    };
    match command {
        "enroll" => {
            let options = Options::parse(rest, &["--name", "--value-file", "--scope"], &[])?;
            let name = options.required("--name")?;
            let value_file = options.required("--value-file")?;
            let scope_texts = options.many("--scope");
            if scope_texts.is_empty() {
                return Err(caller("enroll names at least one scope"));
            }
            let mut scopes = Vec::new();
            for text in &scope_texts {
                scopes.push(parse_scope(text)?);
            }
            let value = read_value_file(&value_file)?;
            deadbolt::enroll(&state, &unlock, &name, &value, &scopes, now)?;
            Ok(format!("{}\n", serde_json::json!({"enrolled": name})))
        }
        "retire" => {
            let options = Options::parse(rest, &["--name"], &[])?;
            let name = options.required("--name")?;
            let ended = deadbolt::retire(&state, &unlock, &name, now)?;
            Ok(format!(
                "{}\n",
                serde_json::json!({"retired": name, "grants_ended": ended})
            ))
        }
        "grant" => {
            let options =
                Options::parse(rest, &["--credential", "--scope", "--ttl", "--run"], &[])?;
            let credential = options.required("--credential")?;
            let scope = parse_scope(&options.required("--scope")?)?;
            let ttl_text = options.required("--ttl")?;
            let ttl: u64 = ttl_text
                .parse()
                .map_err(|_| caller("the time to live is not a whole number of seconds"))?;
            let run = options.one("--run")?;
            let receipt = deadbolt::grant(
                &state,
                &unlock,
                &credential,
                &scope,
                ttl,
                run.as_deref(),
                now,
            )?;
            Ok(format!(
                "{}\n",
                serde_json::json!({
                    "grant_id": receipt.grant_id,
                    "token": receipt.token,
                    "expires_at": receipt.expires_at,
                })
            ))
        }
        "redeem" => {
            let options = Options::parse(rest, &["--token", "--scope"], &[])?;
            let token = options.required("--token")?;
            let scope = parse_scope(&options.required("--scope")?)?;
            let value = deadbolt::redeem(&state, &unlock, &token, &scope, now)?;
            Ok(format!("{value}\n"))
        }
        "revoke" => {
            let options = Options::parse(rest, &["--grant"], &[])?;
            let grant_id = options.required("--grant")?;
            deadbolt::revoke(&state, &unlock, &grant_id, now)?;
            Ok(format!("{}\n", serde_json::json!({"revoked": grant_id})))
        }
        "cutoff" => {
            let options = Options::parse(rest, &["--run"], &[])?;
            let run = options.required("--run")?;
            let ended = deadbolt::cutoff(&state, &unlock, &run, now)?;
            Ok(format!(
                "{}\n",
                serde_json::json!({"run_id": run, "grants_ended": ended})
            ))
        }
        "audit" => {
            let _options = Options::parse(rest, &[], &[])?;
            let entries = deadbolt::audit(&state, &unlock, now)?;
            let mut out = String::new();
            for entry in &entries {
                out.push_str(&serde_json::to_string(entry).unwrap_or_default());
                out.push('\n');
            }
            Ok(out)
        }
        _ => Err(caller(
            "the command is not one of enroll, retire, grant, redeem, revoke, cutoff, audit",
        )),
    }
}
