//! Protocol tests for the broker core, pinning DK-1 to DK-14.
//! Every fixture is synthetic and names itself as one. Credential
//! shaped strings carry the SYNTHETIC-TEST-VALUE marker so no fixture
//! can be mistaken for a real key.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use deadbolt::{Error, RedeemRefusal, Scope};

const VALUE_A: &str = "SYNTHETIC-TEST-VALUE-alpha-0001";
const VALUE_B: &str = "SYNTHETIC-TEST-VALUE-beta-0002";
const T0: i64 = 1_700_000_000;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_dir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "deadbolt-test-{}-{tag}-{n}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn scope(resource: &str, action: &str) -> Scope {
    Scope {
        resource: resource.to_string(),
        action: action.to_string(),
    }
}

fn read_scope() -> Scope {
    scope("bucket", "read")
}

fn enroll_a(state: &PathBuf) {
    deadbolt::enroll(
        state,
        "cache-key",
        VALUE_A,
        &[read_scope(), scope("bucket", "write")],
        T0,
    )
    .unwrap();
}

fn state_text(state: &PathBuf) -> String {
    std::fs::read_to_string(state).unwrap()
}

fn state_json(state: &PathBuf) -> serde_json::Value {
    serde_json::from_str(&state_text(state)).unwrap()
}

fn set_mode(state: &PathBuf, mode: u32) {
    std::fs::set_permissions(state, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn mode_of(state: &PathBuf) -> u32 {
    std::fs::metadata(state).unwrap().permissions().mode() & 0o777
}

#[test]
fn enroll_grant_redeem_round_trip_and_expiry_boundary() {
    let dir = test_dir("round-trip");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(receipt.expires_at, T0 + 60);
    let value = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 59).unwrap();
    assert_eq!(value, VALUE_A);
    let err = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 60).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::Expired)), "{err}");
}

#[test]
fn enroll_duplicate_name_is_refused_and_recorded() {
    let dir = test_dir("dup-enroll");
    let state = dir.join("state.json");
    enroll_a(&state);
    let err = deadbolt::enroll(&state, "cache-key", VALUE_B, &[read_scope()], T0 + 1)
        .unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    let entries = deadbolt::audit(&state).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[1].outcome, "refused, name already stands");
    let value = deadbolt::redeem(
        &state,
        &deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0 + 2)
            .unwrap()
            .token,
        &read_scope(),
        T0 + 3,
    )
    .unwrap();
    assert_eq!(value, VALUE_A);
}

#[test]
fn enroll_shape_errors_are_caller_errors() {
    let dir = test_dir("enroll-shapes");
    let state = dir.join("state.json");
    for (name, value, scopes) in [
        ("cache-key", VALUE_A, Vec::new()),
        ("cache-key", VALUE_A, vec![read_scope(), read_scope()]),
        ("cache-key", "", vec![read_scope()]),
        ("cache-key", "two\nlines", vec![read_scope()]),
        ("bad name", VALUE_A, vec![read_scope()]),
        ("-leading", VALUE_A, vec![read_scope()]),
        ("", VALUE_A, vec![read_scope()]),
    ] {
        let err = deadbolt::enroll(&state, name, value, &scopes, T0).unwrap_err();
        assert!(matches!(err, Error::Caller(_)), "{name} {err}");
    }
    let long_name = "a".repeat(65);
    let err = deadbolt::enroll(&state, &long_name, VALUE_A, &[read_scope()], T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    assert!(!state.exists());
}

#[test]
fn grant_refusals_for_unknown_credential_and_unenrolled_scopes() {
    let dir = test_dir("grant-refusals");
    let state = dir.join("state.json");
    enroll_a(&state);
    let err = deadbolt::grant(&state, "missing", &read_scope(), 60, None, T0).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    for wanted in [
        scope("bucket", "read-all"),
        scope("bucket", "delete"),
        scope("other", "read"),
    ] {
        let err = deadbolt::grant(&state, "cache-key", &wanted, 60, None, T0).unwrap_err();
        assert!(matches!(err, Error::Refusal(_)), "{wanted:?} {err}");
    }
    let entries = deadbolt::audit(&state).unwrap();
    let outcomes: Vec<&str> = entries.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        [
            "enrolled",
            "refused, unknown credential",
            "refused, scope not enrolled",
            "refused, scope not enrolled",
            "refused, scope not enrolled",
        ]
    );
}

#[test]
fn grant_ttl_bounds() {
    let dir = test_dir("ttl-bounds");
    let state = dir.join("state.json");
    enroll_a(&state);
    let err = deadbolt::grant(&state, "cache-key", &read_scope(), 0, None, T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let err = deadbolt::grant(&state, "cache-key", &read_scope(), 86_401, None, T0).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 86_400, None, T0).unwrap();
    assert_eq!(receipt.expires_at, T0 + 86_400);
}

#[test]
fn grant_expiry_past_the_largest_instant_is_a_caller_error() {
    let dir = test_dir("instant-bounds");
    let state = dir.join("state.json");
    enroll_a(&state);
    let err = deadbolt::grant(
        &state,
        "cache-key",
        &read_scope(),
        60,
        None,
        deadbolt::INSTANT_MAX,
    )
    .unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
    let err = deadbolt::redeem(&state, "whatever", &read_scope(), -1).unwrap_err();
    assert!(matches!(err, Error::Caller(_)), "{err}");
}

#[test]
fn token_shape_and_storage() {
    let dir = test_dir("token-shape");
    let state = dir.join("state.json");
    enroll_a(&state);
    let one = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap();
    let two = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(one.token.len(), 64);
    assert!(one
        .token
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    assert_ne!(one.token, two.token);
    assert_ne!(one.grant_id, two.grant_id);
    let text = state_text(&state);
    assert!(!text.contains(&one.token), "the token itself must not be stored");
    let json = state_json(&state);
    let hash = json["grants"][0]["token_hash"].as_str().unwrap();
    assert_eq!(hash.len(), 64);
    assert!(text.contains(hash));
}

#[test]
fn redeem_refusal_reasons_are_distinct() {
    let dir = test_dir("redeem-reasons");
    let state = dir.join("state.json");
    enroll_a(&state);
    let err = deadbolt::redeem(&state, &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::UnknownToken)), "{err}");
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap();
    let err = deadbolt::redeem(&state, &receipt.token, &scope("bucket", "write"), T0 + 1)
        .unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::ScopeMismatch)), "{err}");
    let err = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 60).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::Expired)), "{err}");
    deadbolt::revoke(&state, &receipt.grant_id, T0 + 61).unwrap();
    let err = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 30).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::Revoked)), "{err}");
}

#[test]
fn revoke_is_permanent_and_double_revoke_is_refused() {
    let dir = test_dir("revoke");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::revoke(&state, &receipt.grant_id, T0 + 100).unwrap();
    let err = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 50).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::Revoked)), "{err}");
    let err = deadbolt::revoke(&state, &receipt.grant_id, T0 + 101).unwrap_err();
    assert!(format!("{err}").contains("already ended by revoked"), "{err}");
    let err = deadbolt::revoke(&state, "no-such-grant", T0 + 102).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
}

#[test]
fn cutoff_ends_only_the_named_run() {
    let dir = test_dir("cutoff");
    let state = dir.join("state.json");
    enroll_a(&state);
    let run_one = deadbolt::grant(&state, "cache-key", &read_scope(), 600, Some("run-1"), T0).unwrap();
    let run_one_b = deadbolt::grant(&state, "cache-key", &scope("bucket", "write"), 600, Some("run-1"), T0).unwrap();
    let run_two = deadbolt::grant(&state, "cache-key", &read_scope(), 600, Some("run-2"), T0).unwrap();
    let runless = deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::cutoff(&state, "run-1", T0 + 10).unwrap();
    assert_eq!(ended, 2);
    for receipt in [&run_one, &run_one_b] {
        let wanted = if receipt.grant_id == run_one.grant_id {
            read_scope()
        } else {
            scope("bucket", "write")
        };
        let err = deadbolt::redeem(&state, &receipt.token, &wanted, T0 + 20).unwrap_err();
        assert!(matches!(err, Error::Redeem(RedeemRefusal::Revoked)), "{err}");
    }
    assert_eq!(
        deadbolt::redeem(&state, &run_two.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    assert_eq!(
        deadbolt::redeem(&state, &runless.token, &read_scope(), T0 + 20).unwrap(),
        VALUE_A
    );
    let ended = deadbolt::cutoff(&state, "run-1", T0 + 30).unwrap();
    assert_eq!(ended, 0);
    let err = deadbolt::cutoff(&state, "run-9", T0 + 40).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
}

#[test]
fn retire_ends_grants_inside_their_window() {
    let dir = test_dir("retire");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
    let ended = deadbolt::retire(&state, "cache-key", T0 + 10).unwrap();
    assert_eq!(ended, 1);
    let err = deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 20).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::Revoked)), "{err}");
    let err = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0 + 30).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    let err = deadbolt::retire(&state, "cache-key", T0 + 40).unwrap_err();
    assert!(matches!(err, Error::Refusal(_)), "{err}");
    deadbolt::enroll(&state, "cache-key", VALUE_B, &[read_scope()], T0 + 50).unwrap();
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0 + 51).unwrap();
    assert_eq!(
        deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 52).unwrap(),
        VALUE_B
    );
}

#[test]
fn audit_records_every_act_in_order() {
    let dir = test_dir("audit-order");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 600, Some("run-1"), T0).unwrap();
    deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 1).unwrap();
    let _ = deadbolt::redeem(&state, &receipt.token, &scope("bucket", "write"), T0 + 2);
    deadbolt::revoke(&state, &receipt.grant_id, T0 + 3).unwrap();
    deadbolt::cutoff(&state, "run-1", T0 + 4).unwrap();
    deadbolt::retire(&state, "cache-key", T0 + 5).unwrap();
    let entries = deadbolt::audit(&state).unwrap();
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(kinds, ["enroll", "grant", "redeem", "redeem", "revoke", "cutoff", "retire"]);
    let outcomes: Vec<&str> = entries.iter().map(|e| e.outcome.as_str()).collect();
    assert_eq!(
        outcomes,
        [
            "enrolled",
            "granted",
            "redeemed",
            "refused, scope mismatch",
            "revoked",
            "cut off, 0 ended",
            "retired",
        ]
    );
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
}

#[test]
fn audit_never_carries_value_token_or_hash() {
    let dir = test_dir("audit-secrets");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
    deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 1).unwrap();
    let hash = state_json(&state)["grants"][0]["token_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let entries = deadbolt::audit(&state).unwrap();
    let printed = entries
        .iter()
        .map(|entry| serde_json::to_string(entry).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(!printed.contains(VALUE_A));
    assert!(!printed.contains(&receipt.token));
    assert!(!printed.contains(&hash));
}

#[test]
fn refusals_against_a_missing_state_create_no_file() {
    let dir = test_dir("missing-state");
    let state = dir.join("state.json");
    let err = deadbolt::redeem(&state, &"0".repeat(64), &read_scope(), T0).unwrap_err();
    assert!(matches!(err, Error::Redeem(RedeemRefusal::UnknownToken)), "{err}");
    assert!(deadbolt::grant(&state, "ghost", &read_scope(), 60, None, T0).is_err());
    assert!(deadbolt::retire(&state, "ghost", T0).is_err());
    assert!(deadbolt::revoke(&state, "ghost-grant", T0).is_err());
    assert!(deadbolt::cutoff(&state, "run-1", T0).is_err());
    assert!(!state.exists());
    let entries = deadbolt::audit(&state).unwrap();
    assert!(entries.is_empty());
    assert!(!state.exists());
}

#[test]
fn permission_gate_refuses_every_operation_and_recovers() {
    let dir = test_dir("permission-gate");
    let state = dir.join("state.json");
    enroll_a(&state);
    let receipt = deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
    let before = state_text(&state);
    set_mode(&state, 0o644);
    let attempts: Vec<Result<(), Error>> = vec![
        deadbolt::enroll(&state, "other", VALUE_B, &[read_scope()], T0),
        deadbolt::retire(&state, "cache-key", T0).map(|_| ()),
        deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).map(|_| ()),
        deadbolt::redeem(&state, &receipt.token, &read_scope(), T0).map(|_| ()),
        deadbolt::revoke(&state, &receipt.grant_id, T0),
        deadbolt::cutoff(&state, "run-1", T0).map(|_| ()),
        deadbolt::audit(&state).map(|_| ()),
    ];
    for attempt in attempts {
        let err = attempt.unwrap_err();
        assert!(matches!(err, Error::Permission(_)), "{err}");
    }
    assert_eq!(state_text(&state), before);
    set_mode(&state, 0o600);
    assert_eq!(
        deadbolt::redeem(&state, &receipt.token, &read_scope(), T0 + 1).unwrap(),
        VALUE_A
    );
}

#[test]
fn state_file_is_created_owner_only_and_stays_so() {
    let dir = test_dir("mode-creation");
    let state = dir.join("state.json");
    enroll_a(&state);
    assert_eq!(mode_of(&state), 0o600);
    deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap();
    assert_eq!(mode_of(&state), 0o600);
}

fn corrupt_variants() -> Vec<(String, String)> {
    let dir = test_dir("corrupt-base");
    let state = dir.join("state.json");
    enroll_a(&state);
    deadbolt::grant(&state, "cache-key", &read_scope(), 600, Some("run-1"), T0).unwrap();
    let good = state_text(&state);
    let mut variants: Vec<(String, String)> = Vec::new();
    variants.push((
        "duplicated key at the top level".to_string(),
        good.replacen("\"format\"", "\"format\": \"deadbolt-state/1\", \"format\"", 1),
    ));
    variants.push((
        "duplicated key inside a credential".to_string(),
        good.replacen("\"name\": \"cache-key\"", "\"name\": \"cache-key\", \"name\": \"cache-key\"", 1),
    ));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["surprise"] = serde_json::json!(true);
    variants.push(("unknown field at the top level".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["surprise"] = serde_json::json!(true);
    variants.push(("unknown field inside a grant".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"] = serde_json::json!({"name": "cache-key"});
    variants.push(("credentials of the wrong type".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["format"] = serde_json::json!("deadbolt-state/2");
    variants.push(("a format this broker does not read".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    let twin = doc["credentials"][0].clone();
    doc["credentials"].as_array_mut().unwrap().push(twin);
    variants.push(("a credential name standing twice".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    let twin = doc["grants"][0].clone();
    doc["grants"].as_array_mut().unwrap().push(twin);
    variants.push(("a grant id standing twice".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["audit"][1]["seq"] = serde_json::json!(7);
    variants.push(("a gap in the audit sequence".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"].as_array_mut().unwrap().clear();
    variants.push(("a live grant naming no standing credential".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["expires_at"] = doc["grants"][0]["granted_at"].clone();
    variants.push(("a grant expiring at its own grant instant".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["grants"][0]["ended_at"] = serde_json::json!(T0 + 1);
    variants.push(("an ending in only one of its two fields".to_string(), doc.to_string()));
    let mut doc = serde_json::from_str::<serde_json::Value>(&good).unwrap();
    doc["credentials"][0]["enrolled_at"] = serde_json::json!(253_402_300_800i64);
    variants.push(("a stored instant outside its range".to_string(), doc.to_string()));
    variants.push((
        "a stored number with thousands of digits".to_string(),
        good.replacen(
            &format!("\"enrolled_at\": {T0}"),
            &format!("\"enrolled_at\": {}", "9".repeat(5000)),
            1,
        ),
    ));
    variants
}

#[test]
fn strict_reading_refuses_every_corrupt_variant() {
    for (label, text) in corrupt_variants() {
        let dir = test_dir("corrupt");
        let state = dir.join("state.json");
        std::fs::write(&state, &text).unwrap();
        set_mode(&state, 0o600);
        let err = deadbolt::audit(&state).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        let err = deadbolt::grant(&state, "cache-key", &read_scope(), 60, None, T0).unwrap_err();
        assert!(matches!(err, Error::Corrupt(_)), "{label}: {err}");
        assert_eq!(state_text(&state), text, "{label}: the file must never be reset");
    }
}

#[test]
fn parallel_grants_under_the_lock_keep_the_document_whole() {
    let dir = test_dir("parallel");
    let state = dir.join("state.json");
    enroll_a(&state);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let state = state.clone();
        handles.push(std::thread::spawn(move || {
            let mut tokens = Vec::new();
            for _ in 0..10 {
                let receipt =
                    deadbolt::grant(&state, "cache-key", &read_scope(), 600, None, T0).unwrap();
                tokens.push(receipt.token);
            }
            tokens
        }));
    }
    let mut tokens = Vec::new();
    for handle in handles {
        tokens.extend(handle.join().unwrap());
    }
    assert_eq!(tokens.len(), 80);
    tokens.sort();
    tokens.dedup();
    assert_eq!(tokens.len(), 80);
    let entries = deadbolt::audit(&state).unwrap();
    assert_eq!(entries.len(), 81);
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.seq, index as u64 + 1);
    }
    for token in &tokens {
        assert_eq!(
            deadbolt::redeem(&state, token, &read_scope(), T0 + 1).unwrap(),
            VALUE_A
        );
    }
}

struct CliOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn run_cli(args: &[&str]) -> CliOutput {
    let output = Command::new(env!("CARGO_BIN_EXE_deadbolt"))
        .args(args)
        .output()
        .unwrap();
    CliOutput {
        status: output.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

fn write_value_file(dir: &PathBuf, value: &str) -> String {
    let path = dir.join("value.txt");
    std::fs::write(&path, format!("{value}\n")).unwrap();
    path.to_string_lossy().into_owned()
}

fn cli_enroll_and_grant(dir: &PathBuf) -> (String, String) {
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(dir, VALUE_A);
    let out = run_cli(&[
        "--state", &state_arg, "enroll", "--name", "cache-key", "--value-file", &value_file,
        "--scope", "bucket:read", "--scope", "bucket:write",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli(&[
        "--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:read",
        "--ttl", "600", "--run", "run-1",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&out.stdout).unwrap();
    (
        parsed["token"].as_str().unwrap().to_string(),
        parsed["grant_id"].as_str().unwrap().to_string(),
    )
}

#[test]
fn cli_round_trip_and_redeem_output_is_the_value_alone() {
    let dir = test_dir("cli-round-trip");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, _grant_id) = cli_enroll_and_grant(&dir);
    let out = run_cli(&[
        "--state", &state_arg, "redeem", "--token", &token, "--scope", "bucket:read",
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    assert_eq!(out.stdout, format!("{VALUE_A}\n"));
    assert_eq!(out.stderr, "");
}

#[test]
fn cli_refusals_exit_1_with_distinct_single_line_errors() {
    let dir = test_dir("cli-refusals");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let (token, grant_id) = cli_enroll_and_grant(&dir);
    let out = run_cli(&[
        "--state", &state_arg, "redeem", "--token", &"0".repeat(64), "--scope", "bucket:read",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("unknown token"), "{}", out.stderr);
    assert_eq!(out.stderr.lines().count(), 1);
    let out = run_cli(&[
        "--state", &state_arg, "redeem", "--token", &token, "--scope", "bucket:write",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("scope mismatch"), "{}", out.stderr);
    let out = run_cli(&[
        "--state", &state_arg, "revoke", "--grant", &grant_id,
    ]);
    assert_eq!(out.status, 0, "{}", out.stderr);
    let out = run_cli(&[
        "--state", &state_arg, "redeem", "--token", &token, "--scope", "bucket:read",
    ]);
    assert_eq!(out.status, 1);
    assert!(out.stderr.contains("revoked"), "{}", out.stderr);
}

#[test]
fn cli_caller_errors_exit_2() {
    let dir = test_dir("cli-caller-errors");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE_A);
    let cases: Vec<Vec<&str>> = vec![
        vec!["enroll", "--name", "cache-key"],
        vec!["--state", &state_arg, "frobnicate"],
        vec!["--state", &state_arg, "enroll", "--name", "cache-key", "--value", VALUE_A, "--scope", "bucket:read"],
        vec!["--state", &state_arg, "enroll", "--name", "cache-key", "--value-file", "/nonexistent/value.txt", "--scope", "bucket:read"],
        vec!["--state", &state_arg, "enroll", "--name", "cache-key", "--value-file", &value_file, "--scope", "bucketread"],
        vec!["--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:read", "--ttl", "abc"],
        vec!["--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:read", "--ttl", "86401"],
        vec!["--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:read", "--ttl", "99999999999999999999999999"],
    ];
    for args in cases {
        let out = run_cli(&args);
        assert_eq!(out.status, 2, "{args:?}: {} {}", out.stdout, out.stderr);
        assert!(out.stderr.starts_with("error: "), "{args:?}");
        assert_eq!(out.stderr.lines().count(), 1, "{args:?}");
    }
}

#[test]
fn cli_containment_battery() {
    let dir = test_dir("cli-containment");
    let state = dir.join("state.json");
    let state_arg = state.to_string_lossy().into_owned();
    let value_file = write_value_file(&dir, VALUE_A);
    let mut outputs: Vec<(String, CliOutput)> = Vec::new();
    let mut drive = |label: &str, args: &[&str]| -> CliOutput {
        let out = run_cli(args);
        outputs.push((
            label.to_string(),
            CliOutput {
                status: out.status,
                stdout: out.stdout.clone(),
                stderr: out.stderr.clone(),
            },
        ));
        out
    };
    let enroll_out = drive("enroll", &[
        "--state", &state_arg, "enroll", "--name", "cache-key", "--value-file", &value_file,
        "--scope", "bucket:read", "--scope", "bucket:write",
    ]);
    assert_eq!(enroll_out.status, 0, "{}", enroll_out.stderr);
    let grant_out = drive("grant", &[
        "--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:read",
        "--ttl", "600", "--run", "run-1",
    ]);
    assert_eq!(grant_out.status, 0, "{}", grant_out.stderr);
    let parsed: serde_json::Value = serde_json::from_str(&grant_out.stdout).unwrap();
    let token = parsed["token"].as_str().unwrap().to_string();
    let grant_id = parsed["grant_id"].as_str().unwrap().to_string();
    let redeem_out = drive("redeem", &[
        "--state", &state_arg, "redeem", "--token", &token, "--scope", "bucket:read",
    ]);
    assert_eq!(redeem_out.status, 0);
    assert_eq!(redeem_out.stdout, format!("{VALUE_A}\n"));
    drive("duplicate enroll", &[
        "--state", &state_arg, "enroll", "--name", "cache-key", "--value-file", &value_file,
        "--scope", "bucket:read",
    ]);
    drive("grant unknown credential", &[
        "--state", &state_arg, "grant", "--credential", "ghost", "--scope", "bucket:read", "--ttl", "60",
    ]);
    drive("grant unenrolled scope", &[
        "--state", &state_arg, "grant", "--credential", "cache-key", "--scope", "bucket:delete", "--ttl", "60",
    ]);
    drive("redeem unknown token", &[
        "--state", &state_arg, "redeem", "--token", &"0".repeat(64), "--scope", "bucket:read",
    ]);
    drive("redeem wrong scope", &[
        "--state", &state_arg, "redeem", "--token", &token, "--scope", "bucket:write",
    ]);
    drive("revoke unknown grant", &[
        "--state", &state_arg, "revoke", "--grant", "no-such-grant",
    ]);
    drive("cutoff unknown run", &[
        "--state", &state_arg, "cutoff", "--run", "run-9",
    ]);
    drive("cutoff", &["--state", &state_arg, "cutoff", "--run", "run-1"]);
    drive("revoke", &["--state", &state_arg, "revoke", "--grant", &grant_id]);
    drive("audit", &["--state", &state_arg, "audit"]);
    drive("retire", &["--state", &state_arg, "retire", "--name", "cache-key"]);
    let hash = state_json(&state)["grants"][0]["token_hash"]
        .as_str()
        .unwrap()
        .to_string();
    for (label, out) in &outputs {
        let everything = format!("{}{}", out.stdout, out.stderr);
        if label.as_str() != "redeem" {
            assert!(!everything.contains(VALUE_A), "{label} leaked the value: {everything}");
        }
        if label.as_str() != "grant" {
            assert!(!everything.contains(&token), "{label} leaked the token: {everything}");
        }
        assert!(!everything.contains(&hash), "{label} leaked the token hash: {everything}");
    }
    let grant_everything = format!("{}{}", grant_out.stdout, grant_out.stderr);
    assert!(grant_everything.contains(&token), "grant must show the token once");
}
