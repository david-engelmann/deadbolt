//! The deadbolt broker core.
//!
//! One state file holds credentials, grants, and the audit trail as a
//! single JSON document in the deadbolt-state/1 format, sealed inside
//! the deadbolt-envelope/1 envelope of the envelope module under a
//! key the custody module holds. Every change is published by atomic
//! rename under one exclusive advisory lock, and the state file mode
//! is gated on every open. The obligations this code answers to are
//! DK-1 to DK-24 in CONTRACT.md.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use custody::{
    derive_key, derive_key_with_params, CustodyLoad, KeyCustody, StoreKey, ARGON2_MEMORY_KIB,
    ARGON2_TIME, KEY_LEN, SALT_LEN,
};
use envelope::{Header, Kdf, Sealed};

pub mod custody;
pub mod envelope;

pub use zeroize::Zeroizing;

pub const FORMAT: &str = "deadbolt-state/1";
pub const TTL_MIN: u64 = 1;
pub const TTL_MAX: u64 = 86_400;
pub const INSTANT_MIN: i64 = 0;
pub const INSTANT_MAX: i64 = 253_402_300_799;
pub const NAME_MAX: usize = 64;

/// A typed broker error. The command line maps the variants to exit
/// codes, caller errors to 2 and every refusal, corruption, and
/// permission failure to 1.
#[derive(Debug)]
pub enum Error {
    /// The request itself is malformed, bad names, bad shapes, an
    /// unreadable value file. Raised before the state is opened.
    Caller(String),
    /// The broker understood the request and refused it against the
    /// loaded state.
    Refusal(String),
    /// A redemption refusal, distinct per reason as DK-7 requires.
    Redeem(RedeemRefusal),
    /// The state document failed strict reading.
    Corrupt(String),
    /// The state file mode grants group or other access.
    Permission(String),
    /// The filesystem refused an operation the broker needed.
    Io(std::io::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Caller(message) => write!(f, "{message}"),
            Error::Refusal(message) => write!(f, "{message}"),
            Error::Redeem(reason) => write!(f, "redeem refused, {}", reason.word()),
            Error::Corrupt(message) => write!(f, "{message}"),
            Error::Permission(message) => write!(f, "{message}"),
            Error::Io(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(std::io::Error::new(
            err.kind(),
            format!("the filesystem refused an operation, {err}"),
        ))
    }
}

/// The environment failure for a filesystem refusal on an operator
/// supplied path. The line names the path and names the failure as
/// the filesystem refusing it, as DK-13 states.
fn io_refusal(path: &Path, err: std::io::Error) -> Error {
    Error::Io(std::io::Error::new(
        err.kind(),
        format!("the filesystem refused the path {}, {err}", path.display()),
    ))
}

/// The four distinct redemption refusal reasons of DK-7.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedeemRefusal {
    UnknownToken,
    Revoked,
    Expired,
    ScopeMismatch,
}

impl RedeemRefusal {
    /// The word the refusal and its audit outcome carry.
    pub fn word(&self) -> &'static str {
        match self {
            RedeemRefusal::UnknownToken => "unknown token",
            RedeemRefusal::Revoked => "revoked",
            RedeemRefusal::Expired => "expired",
            RedeemRefusal::ScopeMismatch => "scope mismatch",
        }
    }
}

/// The custody route a store is bound to at creation, DK-20.
///
/// The route is a creation fact the envelope header records, and no
/// later act re-decides it. An open follows the recorded route only,
/// so a keychain store never opens by derivation and a passphrase
/// store never opens by a keychain lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// The unlock key stands in the operating system keychain.
    Keychain,
    /// The unlock key is derived from a passphrase on every open.
    Passphrase,
}

impl Route {
    /// The word the envelope header and the adoption audit entry
    /// name for this route.
    pub fn name(&self) -> &'static str {
        match self {
            Route::Keychain => "keychain",
            Route::Passphrase => "passphrase",
        }
    }
}

/// The caller's supply of the passphrase for the passphrase route.
///
/// The library takes the passphrase as data from its caller, as it
/// takes a credential value as data under DK-3, and the caller owns
/// the channel the passphrase arrived by. The source is consulted
/// only when an act meets the passphrase route, and a caller that
/// cannot supply a passphrase for such an act answers none.
pub trait PassphraseSource {
    /// Answer the passphrase for this act, if the caller can.
    fn passphrase(&self) -> Option<Zeroizing<Vec<u8>>>;
}

/// Everything an act needs to open its store besides the path.
///
/// The route stands only at a store creating act or at the adoption
/// of a plaintext store, and beside a store that already stands in
/// an envelope its presence is a caller error, DK-20. The custody
/// backend serves the keychain route and the passphrase source
/// serves the passphrase route, and each is consulted only on its
/// own route.
pub struct Unlock<'a> {
    /// The custody route the caller names for this act, if any.
    pub route: Option<Route>,
    /// The backend the keychain route stores and loads keys through.
    pub custody: &'a dyn KeyCustody,
    /// The supply the passphrase route derives from.
    pub passphrase: &'a dyn PassphraseSource,
}

/// One scope, a resource and an action stated as a pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    pub resource: String,
    pub action: String,
}

/// What a successful grant hands back, exactly once.
#[derive(Debug)]
pub struct GrantReceipt {
    pub grant_id: String,
    pub token: String,
    pub expires_at: i64,
}

/// One audit entry. Entries never carry a value, a token, or a token
/// hash, so the whole record is safe to print.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditEntry {
    pub seq: u64,
    pub at: i64,
    pub kind: String,
    pub credential: Option<String>,
    pub resource: Option<String>,
    pub action: Option<String>,
    pub run_id: Option<String>,
    pub outcome: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Credential {
    name: String,
    value: String,
    scopes: Vec<Scope>,
    enrolled_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Grant {
    id: String,
    credential: String,
    resource: String,
    action: String,
    run_id: Option<String>,
    token_hash: String,
    granted_at: i64,
    expires_at: i64,
    ended_at: Option<i64>,
    end_reason: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    format: String,
    /// The store identifier this document is stamped with, DK-20.
    ///
    /// The stamp stands only inside a keychain envelope, set at
    /// creation or adoption, and stands empty everywhere else. While
    /// it stands empty the field is not rendered, so an unstamped
    /// document renders byte for byte as the broker has always
    /// rendered it, and a document written before the stamp existed
    /// reads with the field standing empty.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    store_id: String,
    credentials: Vec<Credential>,
    grants: Vec<Grant>,
    audit: Vec<AuditEntry>,
}

impl State {
    fn empty() -> State {
        State {
            format: FORMAT.to_string(),
            store_id: String::new(),
            credentials: Vec::new(),
            grants: Vec::new(),
            audit: Vec::new(),
        }
    }

    fn record(
        &mut self,
        at: i64,
        kind: &str,
        credential: Option<&str>,
        scope: Option<&Scope>,
        run_id: Option<&str>,
        outcome: String,
    ) {
        let seq = self.audit.len() as u64 + 1;
        self.audit.push(AuditEntry {
            seq,
            at,
            kind: kind.to_string(),
            credential: credential.map(str::to_string),
            resource: scope.map(|s| s.resource.clone()),
            action: scope.map(|s| s.action.clone()),
            run_id: run_id.map(str::to_string),
            outcome,
        });
    }
}

/// Strict reading of a state document, DK-2. Parsing goes into the
/// typed structures only, which refuse duplicated keys, unknown
/// fields, wrong types, and out of range numbers, and the cross
/// field invariants are checked here on every read.
fn parse_state(text: &str) -> Result<State, Error> {
    let state: State = serde_json::from_str(text).map_err(|_| {
        Error::Corrupt("the state file does not parse as the deadbolt-state/1 format".to_string())
    })?;
    if state.format != FORMAT {
        return Err(Error::Corrupt(
            "the state file names a format this broker does not read".to_string(),
        ));
    }
    let mut names: Vec<&str> = Vec::new();
    for credential in &state.credentials {
        if names.contains(&credential.name.as_str()) {
            return Err(Error::Corrupt(format!(
                "the state file carries the credential name {} more than once",
                credential.name
            )));
        }
        names.push(credential.name.as_str());
        check_stored_instant(credential.enrolled_at)?;
        if credential.scopes.is_empty() {
            return Err(Error::Corrupt(format!(
                "the credential {} stands with no scopes in the state file",
                credential.name
            )));
        }
        for scope in &credential.scopes {
            if credential
                .scopes
                .iter()
                .filter(|other| *other == scope)
                .count()
                > 1
            {
                return Err(Error::Corrupt(format!(
                    "the credential {} carries one scope twice in the state file",
                    credential.name
                )));
            }
        }
    }
    let mut ids: Vec<&str> = Vec::new();
    let mut hashes: Vec<&str> = Vec::new();
    // Live in DK-2 carries the meaning DK-7 gives it, judged against
    // the latest instant the document itself records in its audit
    // trail. A grant already dead by expiry at that instant is not
    // live, so it may name a credential that retirement removed,
    // exactly as DK-4 leaves it standing unended.
    let document_floor = state
        .audit
        .iter()
        .map(|entry| entry.at)
        .max()
        .unwrap_or(INSTANT_MIN);
    for grant in &state.grants {
        if ids.contains(&grant.id.as_str()) {
            return Err(Error::Corrupt(
                "the state file carries one grant id more than once".to_string(),
            ));
        }
        ids.push(grant.id.as_str());
        if hashes.contains(&grant.token_hash.as_str()) {
            return Err(Error::Corrupt(
                "the state file carries one token hash more than once".to_string(),
            ));
        }
        hashes.push(grant.token_hash.as_str());
        check_stored_instant(grant.granted_at)?;
        check_stored_instant(grant.expires_at)?;
        if grant.expires_at <= grant.granted_at {
            return Err(Error::Corrupt(
                "a grant in the state file expires no later than it was granted".to_string(),
            ));
        }
        match (&grant.ended_at, &grant.end_reason) {
            (None, None) => {
                if grant.expires_at > document_floor && !names.contains(&grant.credential.as_str())
                {
                    return Err(Error::Corrupt(
                        "a live grant in the state file names a credential that does not stand"
                            .to_string(),
                    ));
                }
            }
            (Some(ended_at), Some(reason)) => {
                check_stored_instant(*ended_at)?;
                if !matches!(reason.as_str(), "revoked" | "cutoff" | "retired") {
                    return Err(Error::Corrupt(
                        "a grant in the state file carries an end reason the format does not name"
                            .to_string(),
                    ));
                }
            }
            _ => {
                return Err(Error::Corrupt(
                    "a grant in the state file carries an ending in only one of its two fields"
                        .to_string(),
                ));
            }
        }
    }
    for (index, entry) in state.audit.iter().enumerate() {
        if entry.seq != index as u64 + 1 {
            return Err(Error::Corrupt(
                "the audit sequence in the state file does not stand gapless from one".to_string(),
            ));
        }
        check_stored_instant(entry.at)?;
    }
    Ok(state)
}

fn check_stored_instant(instant: i64) -> Result<(), Error> {
    if !(INSTANT_MIN..=INSTANT_MAX).contains(&instant) {
        return Err(Error::Corrupt(
            "the state file carries an instant outside the range the format allows".to_string(),
        ));
    }
    Ok(())
}

/// Whether two loaded documents stand equal field by field.
///
/// The adoption proof of DK-23 compares the document it loaded
/// against the document its rendered envelope decrypts to, and the
/// comparison runs over the document fields rather than rendered
/// bytes, because the proof vouches for the document and the
/// envelope is only its carrier.
fn state_documents_equal(a: &State, b: &State) -> bool {
    if a.format != b.format || a.store_id != b.store_id {
        return false;
    }
    if a.credentials.len() != b.credentials.len()
        || a.grants.len() != b.grants.len()
        || a.audit.len() != b.audit.len()
    {
        return false;
    }
    for (mine, theirs) in a.credentials.iter().zip(b.credentials.iter()) {
        if mine.name != theirs.name
            || mine.value != theirs.value
            || mine.scopes != theirs.scopes
            || mine.enrolled_at != theirs.enrolled_at
        {
            return false;
        }
    }
    for (mine, theirs) in a.grants.iter().zip(b.grants.iter()) {
        if mine.id != theirs.id
            || mine.credential != theirs.credential
            || mine.resource != theirs.resource
            || mine.action != theirs.action
            || mine.run_id != theirs.run_id
            || mine.token_hash != theirs.token_hash
            || mine.granted_at != theirs.granted_at
            || mine.expires_at != theirs.expires_at
            || mine.ended_at != theirs.ended_at
            || mine.end_reason != theirs.end_reason
        {
            return false;
        }
    }
    for (mine, theirs) in a.audit.iter().zip(b.audit.iter()) {
        if mine.seq != theirs.seq
            || mine.at != theirs.at
            || mine.kind != theirs.kind
            || mine.credential != theirs.credential
            || mine.resource != theirs.resource
            || mine.action != theirs.action
            || mine.run_id != theirs.run_id
            || mine.outcome != theirs.outcome
        {
            return false;
        }
    }
    true
}

/// Request shape validation. Failures here are caller errors, raised
/// before the state is opened and never recorded, as DK-9 states.
fn check_name(what: &str, name: &str) -> Result<(), Error> {
    let valid = !name.is_empty()
        && name.len() <= NAME_MAX
        && name
            .chars()
            .next()
            .map(|c| c.is_ascii_alphanumeric())
            .unwrap_or(false)
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'));
    if !valid {
        return Err(Error::Caller(format!(
            "the {what} is not a safe name of one to {NAME_MAX} characters"
        )));
    }
    Ok(())
}

fn check_scope(scope: &Scope) -> Result<(), Error> {
    check_name("resource", &scope.resource)?;
    check_name("action", &scope.action)?;
    Ok(())
}

fn check_instant(now: i64) -> Result<(), Error> {
    if !(INSTANT_MIN..=INSTANT_MAX).contains(&now) {
        return Err(Error::Caller(
            "the supplied instant stands outside the range the broker keeps".to_string(),
        ));
    }
    Ok(())
}

fn check_value(value: &str) -> Result<(), Error> {
    if value.is_empty() || value.contains('\n') || value.contains('\r') {
        return Err(Error::Caller(
            "the credential value must be one nonempty line of text".to_string(),
        ));
    }
    Ok(())
}

/// The refusal for an envelope standing in the wrong place, DK-22.
fn transplant_refusal() -> Error {
    Error::Refusal(
        "the store is locked because the envelope does not belong to this store".to_string(),
    )
}

/// Take and validate the passphrase for one act, DK-19.
///
/// The passphrase is a byte string of 1 to 1024 bytes. A caller that
/// cannot supply one, or supplies one outside that standing, is a
/// caller error, and no error here echoes the passphrase or reports
/// its length. Validation runs when the source is consulted, which
/// precedes any derivation, custody write, or publish in every path
/// that consults it.
fn take_passphrase(unlock: &Unlock) -> Result<Zeroizing<Vec<u8>>, Error> {
    let passphrase = unlock.passphrase.passphrase().ok_or_else(|| {
        Error::Caller("the passphrase route needs a passphrase and none was supplied".to_string())
    })?;
    if passphrase.is_empty() || passphrase.len() > 1024 {
        return Err(Error::Caller(
            "the passphrase must stand from 1 to 1024 bytes".to_string(),
        ));
    }
    Ok(passphrase)
}

/// Obtain the key a standing envelope opens under, DK-20 and DK-22.
///
/// The open follows the recorded route only. Custody failures word
/// themselves here, because the refusal wording lives in the store
/// layer where refusals are worded, and the backend diagnostic text,
/// whose vocabulary the broker does not control, is never printed.
fn unlock_key(sealed: &Sealed, unlock: &Unlock) -> Result<StoreKey, Error> {
    match sealed.header.route {
        Route::Keychain => match unlock.custody.load_key(&sealed.header.store) {
            CustodyLoad::Key(key) => Ok(key),
            CustodyLoad::Absent => Err(Error::Refusal(
                "the store is locked because its keychain entry is missing, and the broker holds no other copy and no fallback will be tried".to_string(),
            )),
            CustodyLoad::ServiceFailure(_) => Err(Error::Refusal(
                "the store is locked because the keychain service is not available".to_string(),
            )),
        },
        Route::Passphrase => {
            let passphrase = take_passphrase(unlock)?;
            let kdf = sealed.header.kdf.as_ref().ok_or_else(|| {
                Error::Corrupt(
                    "the envelope header field set does not match its route".to_string(),
                )
            })?;
            Ok(derive_key_with_params(
                &passphrase,
                &kdf.salt,
                kdf.memory,
                kdf.time,
            ))
        }
    }
}

/// Establish custody for a store that has none yet, DK-20 and DK-23.
///
/// Creation and adoption share this act. On the keychain route the
/// key and a fresh store identifier are drawn from the random
/// source and the key is stored under the identifier before
/// anything is published, and the document is stamped with the
/// identifier. On the passphrase route the salt is drawn and the key
/// derived at the pinned parameters of DK-19, and the document
/// stamp stands empty. Either way the returned header is the header
/// every envelope this store writes will carry.
fn establish_custody(
    route: Route,
    unlock: &Unlock,
    state: &mut State,
) -> Result<(Header, StoreKey), Error> {
    match route {
        Route::Keychain => {
            let mut key_bytes = Zeroizing::new([0u8; KEY_LEN]);
            getrandom::fill(&mut *key_bytes)
                .map_err(|_| Error::Io(std::io::Error::other("the random source refused")))?;
            let key = StoreKey::from_zeroizing(key_bytes);
            let store_id = random_hex(32)?;
            unlock.custody.store_key(&store_id, &key).map_err(|_| {
                Error::Refusal(
                    "the store is locked because the keychain service is not available".to_string(),
                )
            })?;
            state.store_id = store_id.clone();
            Ok((
                Header {
                    payload: FORMAT.to_string(),
                    route,
                    store: store_id,
                    kdf: None,
                },
                key,
            ))
        }
        Route::Passphrase => {
            let passphrase = take_passphrase(unlock)?;
            let mut salt = [0u8; SALT_LEN];
            getrandom::fill(&mut salt)
                .map_err(|_| Error::Io(std::io::Error::other("the random source refused")))?;
            let key = derive_key(&passphrase, &salt);
            let store_id = random_hex(32)?;
            state.store_id = String::new();
            Ok((
                Header {
                    payload: FORMAT.to_string(),
                    route,
                    store: store_id,
                    kdf: Some(Kdf {
                        memory: ARGON2_MEMORY_KIB,
                        time: ARGON2_TIME,
                        salt,
                    }),
                },
                key,
            ))
        }
    }
}

/// Prove a freshly sealed adoption envelope in memory, DK-23.
///
/// The proof seals the loaded document, decrypts the rendering,
/// strictly reads the result, and compares it against the loaded
/// document field by field. Only a passing proof lets the caller
/// publish, so a failed proof leaves the plaintext standing exactly
/// as it stood.
fn prove_adoption(state: &State, header: &Header, key: &StoreKey) -> Result<(), Error> {
    let text = serde_json::to_string_pretty(state).map_err(|_| {
        Error::Corrupt("the state could not be written in its own format".to_string())
    })?;
    let rendered = envelope::seal(header, key, format!("{text}\n").as_bytes())?;
    let sealed = envelope::parse_envelope(&rendered)?;
    let plain = envelope::open_sealed(&sealed, key)?;
    let plain_text = String::from_utf8(plain).map_err(|_| {
        Error::Corrupt("the state document inside the envelope is not valid UTF-8 text".to_string())
    })?;
    let proven = parse_state(&plain_text)?;
    if !state_documents_equal(state, &proven) {
        return Err(Error::Corrupt(
            "the adopted envelope does not decrypt to the document it was sealed from".to_string(),
        ));
    }
    Ok(())
}

/// How the standing store is sealed, or that no store stands yet.
///
/// A session that finds no state file carries the offered route and
/// establishes custody only if a publish creates the store, so an
/// act that refuses against an empty state creates nothing and
/// needs no route. A session over an envelope carries the header
/// and the key it opened under, so every publish re-seals under the
/// recorded route and no act re-decides it, DK-20 and DK-21.
enum Sealing {
    Uncreated { route: Option<Route> },
    Sealed { header: Header, key: StoreKey },
}

/// One open state under its lock. Opening performs the permission
/// gate of DK-11 and the unlock path of DK-21, being envelope
/// reading and custody and authentication and the strict reading of
/// DK-2, in the order DK-22 names.
struct Session<'a> {
    state_path: PathBuf,
    state: State,
    exists: bool,
    sealing: Sealing,
    unlock: &'a Unlock<'a>,
    _lock: File,
}

impl<'a> Session<'a> {
    fn open(state_path: &Path, unlock: &'a Unlock<'a>, now: i64) -> Result<Session<'a>, Error> {
        let lock_path = PathBuf::from(format!("{}.lock", state_path.display()));
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .mode(0o600)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|err| io_refusal(state_path, err))?;
        lock.lock_exclusive()
            .map_err(|err| io_refusal(state_path, err))?;
        match std::fs::metadata(state_path) {
            Ok(metadata) => {
                let mode = metadata.mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(Error::Permission(format!(
                        "the state file mode {mode:o} grants group or other access, and the broker refuses to operate on it"
                    )));
                }
                let text = std::fs::read_to_string(state_path).map_err(|err| {
                    if err.kind() == std::io::ErrorKind::InvalidData {
                        Error::Corrupt("the state file is not valid UTF-8 text".to_string())
                    } else {
                        io_refusal(state_path, err)
                    }
                })?;
                if envelope::names_envelope(&text) {
                    let sealed = envelope::parse_envelope(&text)?;
                    if unlock.route.is_some() {
                        return Err(Error::Caller(
                            "the custody route stands beside a store that already stands"
                                .to_string(),
                        ));
                    }
                    let key = unlock_key(&sealed, unlock)?;
                    let plain = envelope::open_sealed(&sealed, &key)?;
                    let plain_text = String::from_utf8(plain).map_err(|_| {
                        Error::Corrupt(
                            "the state document inside the envelope is not valid UTF-8 text"
                                .to_string(),
                        )
                    })?;
                    let state = parse_state(&plain_text)?;
                    match sealed.header.route {
                        Route::Keychain => {
                            if state.store_id != sealed.header.store {
                                return Err(transplant_refusal());
                            }
                        }
                        Route::Passphrase => {
                            if !state.store_id.is_empty() {
                                return Err(transplant_refusal());
                            }
                        }
                    }
                    Ok(Session {
                        state_path: state_path.to_path_buf(),
                        state,
                        exists: true,
                        sealing: Sealing::Sealed {
                            header: sealed.header,
                            key,
                        },
                        unlock,
                        _lock: lock,
                    })
                } else {
                    let mut state = parse_state(&text)?;
                    let route = unlock.route.ok_or_else(|| {
                        Error::Caller(
                            "the store stands in plaintext and its adoption must name a custody route"
                                .to_string(),
                        )
                    })?;
                    let (header, key) = establish_custody(route, unlock, &mut state)?;
                    state.record(
                        now,
                        "adopt",
                        None,
                        None,
                        None,
                        format!("adopted, {} route", route.name()),
                    );
                    prove_adoption(&state, &header, &key)?;
                    let mut session = Session {
                        state_path: state_path.to_path_buf(),
                        state,
                        exists: true,
                        sealing: Sealing::Sealed { header, key },
                        unlock,
                        _lock: lock,
                    };
                    session.publish()?;
                    Ok(session)
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Session {
                state_path: state_path.to_path_buf(),
                state: State::empty(),
                exists: false,
                sealing: Sealing::Uncreated {
                    route: unlock.route,
                },
                unlock,
                _lock: lock,
            }),
            Err(err) => Err(io_refusal(state_path, err)),
        }
    }

    /// Publish the whole document by atomic rename, DK-1 and DK-21.
    ///
    /// The document is sealed into its envelope under a fresh nonce
    /// on every publish. A session whose store does not stand yet
    /// establishes custody here, at the first publish that creates
    /// the store, because custody is established before the temp
    /// file is written and an act that never publishes creates
    /// nothing.
    fn publish(&mut self) -> Result<(), Error> {
        if let Sealing::Uncreated { route } = &self.sealing {
            let route = route.ok_or_else(|| {
                Error::Caller(
                    "a store creating act must name its custody route, keychain or passphrase"
                        .to_string(),
                )
            })?;
            let unlock = self.unlock;
            let (header, key) = establish_custody(route, unlock, &mut self.state)?;
            self.sealing = Sealing::Sealed { header, key };
        }
        let (header, key) = match &self.sealing {
            Sealing::Sealed { header, key } => (header, key),
            Sealing::Uncreated { .. } => {
                return Err(Error::Corrupt(
                    "the store stands unsealed at publish".to_string(),
                ))
            }
        };
        let text = serde_json::to_string_pretty(&self.state).map_err(|_| {
            Error::Corrupt("the state could not be written in its own format".to_string())
        })?;
        let sealed_text = envelope::seal(header, key, format!("{text}\n").as_bytes())?;
        let directory = self
            .state_path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let file_name = self
            .state_path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        let mut random = [0u8; 8];
        getrandom::fill(&mut random)
            .map_err(|_| Error::Io(std::io::Error::other("the random source refused")))?;
        let temp_path = directory.join(format!(".{file_name}.tmp-{}", hex(&random)));
        let write = (|| -> Result<(), Error> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&temp_path)
                .map_err(|err| io_refusal(&temp_path, err))?;
            file.write_all(sealed_text.as_bytes())
                .map_err(|err| io_refusal(&temp_path, err))?;
            file.write_all(b"\n")
                .map_err(|err| io_refusal(&temp_path, err))?;
            file.sync_all().map_err(|err| io_refusal(&temp_path, err))?;
            Ok(())
        })();
        if let Err(err) = write {
            let _ = std::fs::remove_file(&temp_path);
            return Err(err);
        }
        std::fs::rename(&temp_path, &self.state_path)
            .map_err(|err| io_refusal(&self.state_path, err))?;
        if let Ok(dir_file) = File::open(&directory) {
            let _ = dir_file.sync_all();
        }
        Ok(())
    }

    /// Record a refusal in the audit trail and publish it, DK-9.
    /// Every refusal against a loaded state goes through here, so
    /// the recording and the publication cannot drift apart between
    /// operations. An act against a state that does not stand
    /// records nothing, because there is no state to record it in.
    fn record_refusal(
        &mut self,
        at: i64,
        kind: &str,
        credential: Option<&str>,
        scope: Option<&Scope>,
        run_id: Option<&str>,
        outcome: String,
    ) -> Result<(), Error> {
        if self.exists {
            self.state
                .record(at, kind, credential, scope, run_id, outcome);
            self.publish()?;
        }
        Ok(())
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn token_hash(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex(&hasher.finalize())
}

fn random_hex(bytes: usize) -> Result<String, Error> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|_| Error::Io(std::io::Error::other("the random source refused")))?;
    Ok(hex(&buffer))
}

/// Enroll a credential with its value and allowed scopes, DK-3.
pub fn enroll(
    state_path: &Path,
    unlock: &Unlock,
    name: &str,
    value: &str,
    scopes: &[Scope],
    now: i64,
) -> Result<(), Error> {
    check_name("credential name", name)?;
    check_value(value)?;
    if scopes.is_empty() {
        return Err(Error::Caller(
            "an enrollment must name at least one scope".to_string(),
        ));
    }
    for scope in scopes {
        check_scope(scope)?;
        if scopes.iter().filter(|other| *other == scope).count() > 1 {
            return Err(Error::Caller(
                "an enrollment must not repeat a scope".to_string(),
            ));
        }
    }
    check_instant(now)?;
    let mut session = Session::open(state_path, unlock, now)?;
    if session
        .state
        .credentials
        .iter()
        .any(|credential| credential.name == name)
    {
        session.record_refusal(
            now,
            "enroll",
            Some(name),
            None,
            None,
            "refused, name already stands".to_string(),
        )?;
        return Err(Error::Refusal(format!(
            "enroll refused, a credential named {name} already stands"
        )));
    }
    session.state.credentials.push(Credential {
        name: name.to_string(),
        value: value.to_string(),
        scopes: scopes.to_vec(),
        enrolled_at: now,
    });
    session.state.record(
        now,
        "enroll",
        Some(name),
        None,
        None,
        "enrolled".to_string(),
    );
    session.publish()?;
    Ok(())
}

/// Retire a credential and end every live grant it carries, DK-4.
/// Returns how many grants the act ended.
pub fn retire(state_path: &Path, unlock: &Unlock, name: &str, now: i64) -> Result<usize, Error> {
    check_name("credential name", name)?;
    check_instant(now)?;
    let mut session = Session::open(state_path, unlock, now)?;
    if !session
        .state
        .credentials
        .iter()
        .any(|credential| credential.name == name)
    {
        session.record_refusal(
            now,
            "retire",
            Some(name),
            None,
            None,
            "refused, unknown credential".to_string(),
        )?;
        return Err(Error::Refusal(format!(
            "retire refused, no credential named {name} stands"
        )));
    }
    let mut ended = 0;
    for grant in session.state.grants.iter_mut() {
        if grant.credential == name && grant.ended_at.is_none() && now < grant.expires_at {
            grant.ended_at = Some(now);
            grant.end_reason = Some("retired".to_string());
            ended += 1;
        }
    }
    session
        .state
        .credentials
        .retain(|credential| credential.name != name);
    session
        .state
        .record(now, "retire", Some(name), None, None, "retired".to_string());
    session.publish()?;
    Ok(ended)
}

/// Grant one scope of one credential to a caller, DK-5 and DK-6.
pub fn grant(
    state_path: &Path,
    unlock: &Unlock,
    credential_name: &str,
    scope: &Scope,
    ttl: u64,
    run_id: Option<&str>,
    now: i64,
) -> Result<GrantReceipt, Error> {
    check_name("credential name", credential_name)?;
    check_scope(scope)?;
    if let Some(run) = run_id {
        check_name("run id", run)?;
    }
    if !(TTL_MIN..=TTL_MAX).contains(&ttl) {
        return Err(Error::Caller(format!(
            "the time to live must stand from {TTL_MIN} to {TTL_MAX} seconds"
        )));
    }
    check_instant(now)?;
    let expires_at = now.checked_add(ttl as i64).ok_or_else(|| {
        Error::Caller(
            "the grant expiry would pass the largest instant the broker keeps".to_string(),
        )
    })?;
    if expires_at > INSTANT_MAX {
        return Err(Error::Caller(
            "the grant expiry would pass the largest instant the broker keeps".to_string(),
        ));
    }
    let mut session = Session::open(state_path, unlock, now)?;
    let credential = session
        .state
        .credentials
        .iter()
        .find(|credential| credential.name == credential_name);
    let credential = match credential {
        Some(credential) => credential,
        None => {
            session.record_refusal(
                now,
                "grant",
                Some(credential_name),
                Some(scope),
                run_id,
                "refused, unknown credential".to_string(),
            )?;
            return Err(Error::Refusal(format!(
                "grant refused, no credential named {credential_name} stands"
            )));
        }
    };
    if !credential.scopes.contains(scope) {
        session.record_refusal(
            now,
            "grant",
            Some(credential_name),
            Some(scope),
            run_id,
            "refused, scope not enrolled".to_string(),
        )?;
        return Err(Error::Refusal(
            "grant refused, the credential does not carry the requested scope".to_string(),
        ));
    }
    let token = random_hex(32)?;
    let mut grant_id = random_hex(16)?;
    while session
        .state
        .grants
        .iter()
        .any(|grant| grant.id == grant_id)
    {
        grant_id = random_hex(16)?;
    }
    session.state.grants.push(Grant {
        id: grant_id.clone(),
        credential: credential_name.to_string(),
        resource: scope.resource.clone(),
        action: scope.action.clone(),
        run_id: run_id.map(str::to_string),
        token_hash: token_hash(&token),
        granted_at: now,
        expires_at,
        ended_at: None,
        end_reason: None,
    });
    session.state.record(
        now,
        "grant",
        Some(credential_name),
        Some(scope),
        run_id,
        "granted".to_string(),
    );
    session.publish()?;
    Ok(GrantReceipt {
        grant_id,
        token,
        expires_at,
    })
}

/// Redeem a token for the value it guards, DK-7. On success this
/// returns the credential value and nothing else.
pub fn redeem(
    state_path: &Path,
    unlock: &Unlock,
    token: &str,
    scope: &Scope,
    now: i64,
) -> Result<String, Error> {
    check_scope(scope)?;
    check_instant(now)?;
    let mut session = Session::open(state_path, unlock, now)?;
    let hash = token_hash(token);
    let position = session
        .state
        .grants
        .iter()
        .position(|grant| grant.token_hash == hash);
    let position = match position {
        Some(position) => position,
        None => {
            session.record_refusal(
                now,
                "redeem",
                None,
                Some(scope),
                None,
                "refused, unknown token".to_string(),
            )?;
            return Err(Error::Redeem(RedeemRefusal::UnknownToken));
        }
    };
    let grant = &session.state.grants[position];
    let refusal = if grant.ended_at.is_some() {
        Some(RedeemRefusal::Revoked)
    } else if now >= grant.expires_at {
        Some(RedeemRefusal::Expired)
    } else if grant.resource != scope.resource || grant.action != scope.action {
        Some(RedeemRefusal::ScopeMismatch)
    } else {
        None
    };
    let credential_name = session.state.grants[position].credential.clone();
    let run_id = session.state.grants[position].run_id.clone();
    if let Some(reason) = refusal {
        session.record_refusal(
            now,
            "redeem",
            Some(&credential_name),
            Some(scope),
            run_id.as_deref(),
            format!("refused, {}", reason.word()),
        )?;
        return Err(Error::Redeem(reason));
    }
    let value = session
        .state
        .credentials
        .iter()
        .find(|credential| credential.name == credential_name)
        .map(|credential| credential.value.clone())
        .ok_or_else(|| {
            Error::Corrupt("a live grant names a credential that does not stand".to_string())
        })?;
    session.state.record(
        now,
        "redeem",
        Some(&credential_name),
        Some(scope),
        run_id.as_deref(),
        "redeemed".to_string(),
    );
    session.publish()?;
    Ok(value)
}

/// End one grant by its id, DK-8.
pub fn revoke(state_path: &Path, unlock: &Unlock, grant_id: &str, now: i64) -> Result<(), Error> {
    check_instant(now)?;
    let mut session = Session::open(state_path, unlock, now)?;
    let position = session
        .state
        .grants
        .iter()
        .position(|grant| grant.id == grant_id);
    let position = match position {
        Some(position) => position,
        None => {
            session.record_refusal(
                now,
                "revoke",
                None,
                None,
                None,
                "refused, unknown grant".to_string(),
            )?;
            return Err(Error::Refusal(
                "revoke refused, no grant carries that id".to_string(),
            ));
        }
    };
    let (credential, scope, run_id, end_reason) = {
        let grant = &session.state.grants[position];
        (
            grant.credential.clone(),
            Scope {
                resource: grant.resource.clone(),
                action: grant.action.clone(),
            },
            grant.run_id.clone(),
            grant.end_reason.clone(),
        )
    };
    if let Some(reason) = end_reason {
        session.record_refusal(
            now,
            "revoke",
            Some(&credential),
            Some(&scope),
            run_id.as_deref(),
            "refused, grant already ended".to_string(),
        )?;
        return Err(Error::Refusal(format!(
            "revoke refused, the grant already ended by {reason}"
        )));
    }
    session.state.grants[position].ended_at = Some(now);
    session.state.grants[position].end_reason = Some("revoked".to_string());
    session.state.record(
        now,
        "revoke",
        Some(&credential),
        Some(&scope),
        run_id.as_deref(),
        "revoked".to_string(),
    );
    session.publish()?;
    Ok(())
}

/// End every live grant carrying one run id, DK-8. Returns how many
/// grants the act ended.
pub fn cutoff(state_path: &Path, unlock: &Unlock, run_id: &str, now: i64) -> Result<usize, Error> {
    check_name("run id", run_id)?;
    check_instant(now)?;
    let mut session = Session::open(state_path, unlock, now)?;
    if !session
        .state
        .grants
        .iter()
        .any(|grant| grant.run_id.as_deref() == Some(run_id))
    {
        session.record_refusal(
            now,
            "cutoff",
            None,
            None,
            Some(run_id),
            "refused, unknown run".to_string(),
        )?;
        return Err(Error::Refusal(
            "cutoff refused, no grant carries that run id".to_string(),
        ));
    }
    let mut ended = 0;
    for grant in session.state.grants.iter_mut() {
        if grant.run_id.as_deref() == Some(run_id)
            && grant.ended_at.is_none()
            && now < grant.expires_at
        {
            grant.ended_at = Some(now);
            grant.end_reason = Some("cutoff".to_string());
            ended += 1;
        }
    }
    session.state.record(
        now,
        "cutoff",
        None,
        None,
        Some(run_id),
        format!("cut off, {ended} ended"),
    );
    session.publish()?;
    Ok(ended)
}

/// Read the audit trail in sequence order, DK-9.
///
/// The instant stands in the signature because an audit that meets
/// a plaintext store adopts it under DK-23, and the adoption entry
/// names the instant of the act that adopted.
pub fn audit(state_path: &Path, unlock: &Unlock, now: i64) -> Result<Vec<AuditEntry>, Error> {
    let session = Session::open(state_path, unlock, now)?;
    Ok(session.state.audit.clone())
}
