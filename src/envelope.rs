//! The deadbolt-envelope/1 wrapper of DK-15 to DK-17.
//!
//! The state file of an encrypted store holds one envelope document
//! whose payload decrypts to one deadbolt-state/1 document. This
//! module renders envelopes, reads them strictly, seals a document
//! under a store key, and opens a sealed envelope under its key. It
//! names no custody and no route policy. The store layer in the crate
//! root decides which key an envelope opens under and what each
//! failure means, and words every refusal.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use serde::Deserialize;
use serde_json::value::RawValue;

use crate::custody::{
    StoreKey, ARGON2_MEMORY_MAX_KIB, ARGON2_MEMORY_MIN_KIB, ARGON2_TIME_MAX, ARGON2_TIME_MIN,
    SALT_LEN,
};
use crate::{hex, Error, Route, FORMAT};

/// The format name every envelope carries, DK-15.
pub const ENVELOPE_FORMAT: &str = "deadbolt-envelope/1";

/// The length in bytes of the cipher nonce, DK-16.
pub const NONCE_LEN: usize = 24;

/// The length in bytes of the authentication tag the cipher appends,
/// and so the shortest ciphertext the format carries, DK-17.
pub const TAG_LEN: usize = 16;

/// The KDF identifier every passphrase header names, DK-15.
pub const KDF_ALGORITHM: &str = "argon2id";

/// The corruption wording for an envelope that does not parse as its
/// format, in the pattern of DK-2.
fn envelope_unreadable() -> Error {
    Error::Corrupt("the envelope does not parse as the deadbolt-envelope/1 format".to_string())
}

/// The refusal wording for an authentication failure, DK-22. The one
/// wording answers a wrong passphrase, a wrong key, and a key derived
/// under edited parameters, because the tag check cannot tell them
/// apart and the broker does not pretend it can.
pub fn key_did_not_open() -> Error {
    Error::Refusal("the store is locked because the key did not open it".to_string())
}

/// The header of an envelope, standing in the clear.
///
/// The header carries exactly the fields its route uses and no
/// others, and it never carries key material in any form, DK-15.
#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    /// The format name of the inner document.
    pub payload: String,
    /// The route the store is bound to.
    pub route: Route,
    /// The store identifier as 64 lowercase hexadecimal characters.
    pub store: String,
    /// The derivation parameters, standing exactly on the passphrase
    /// route and nowhere else.
    pub kdf: Option<Kdf>,
}

/// The derivation parameters a passphrase header records, DK-15.
#[derive(Debug, Clone, PartialEq)]
pub struct Kdf {
    /// The memory cost in kibibytes.
    pub memory: u32,
    /// The time cost in iterations.
    pub time: u32,
    /// The salt as 16 bytes.
    pub salt: [u8; SALT_LEN],
}

impl Header {
    /// Render the header exactly as it stands inside an envelope.
    ///
    /// The rendering is the canonical compact form with keys sorted,
    /// the form section 1 of the design names for the envelope, and
    /// it is built once per seal so the bytes written are the bytes
    /// the associated data authenticates, DK-16.
    pub fn render(&self) -> String {
        let mut fields = serde_json::Map::new();
        if let Some(kdf) = &self.kdf {
            let mut kdf_fields = serde_json::Map::new();
            kdf_fields.insert(
                "algorithm".to_string(),
                serde_json::Value::String(KDF_ALGORITHM.to_string()),
            );
            kdf_fields.insert(
                "memory".to_string(),
                serde_json::Value::Number(kdf.memory.into()),
            );
            kdf_fields.insert(
                "salt".to_string(),
                serde_json::Value::String(hex(&kdf.salt)),
            );
            kdf_fields.insert(
                "time".to_string(),
                serde_json::Value::Number(kdf.time.into()),
            );
            fields.insert("kdf".to_string(), serde_json::Value::Object(kdf_fields));
        }
        fields.insert(
            "payload".to_string(),
            serde_json::Value::String(self.payload.clone()),
        );
        fields.insert(
            "route".to_string(),
            serde_json::Value::String(self.route.name().to_string()),
        );
        fields.insert(
            "store".to_string(),
            serde_json::Value::String(self.store.clone()),
        );
        serde_json::Value::Object(fields).to_string()
    }
}

/// One strictly read envelope.
///
/// The header stands twice, once as the raw bytes the envelope
/// carries and once parsed, because the associated data is the raw
/// bytes exactly as written and any re-rendering would authenticate
/// bytes that never stood in the file, DK-16.
#[derive(Debug)]
pub struct Sealed {
    /// The parsed header.
    pub header: Header,
    /// The header bytes exactly as the envelope carries them.
    pub header_raw: String,
    /// The nonce the ciphertext was sealed under.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext with its authentication tag.
    pub ciphertext: Vec<u8>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeWire {
    format: String,
    header: Box<RawValue>,
    nonce: String,
    ciphertext: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HeaderWire {
    payload: String,
    route: String,
    store: String,
    kdf: Option<KdfWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfWire {
    algorithm: String,
    memory: u32,
    time: u32,
    salt: String,
}

/// Whether a state file's text stands in the envelope family at all.
///
/// Classification peeks at the format value before any strict read. A
/// document naming the envelope format, or any successor under the
/// same prefix, belongs to the envelope reading path and its
/// corruption class. Anything else is read under the plaintext rules
/// the landed broker has always used, so a corrupt plaintext store
/// keeps the wordings it has always drawn.
pub fn names_envelope(text: &str) -> bool {
    let value: serde_json::Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(_) => return false,
    };
    match value.get("format").and_then(|format| format.as_str()) {
        Some(format) => format.starts_with("deadbolt-envelope/"),
        None => false,
    }
}

/// Strictly read an envelope, DK-17.
///
/// Every shape failure is corruption naming the envelope, and the
/// reading happens before any custody call, so corruption is
/// reported even when the key would also have failed, DK-22.
pub fn parse_envelope(text: &str) -> Result<Sealed, Error> {
    let wire: EnvelopeWire = serde_json::from_str(text).map_err(|_| envelope_unreadable())?;
    if wire.format != ENVELOPE_FORMAT {
        return Err(envelope_unreadable());
    }
    let header_raw = wire.header.get().to_string();
    let header_wire: HeaderWire =
        serde_json::from_str(wire.header.get()).map_err(|_| envelope_unreadable())?;
    if header_wire.payload != FORMAT {
        return Err(Error::Corrupt(
            "the envelope names a payload format this broker does not read".to_string(),
        ));
    }
    let route = match header_wire.route.as_str() {
        "keychain" => Route::Keychain,
        "passphrase" => Route::Passphrase,
        _ => {
            return Err(Error::Corrupt(
                "the envelope names a route the format does not carry".to_string(),
            ))
        }
    };
    if !store_id_shape_ok(&header_wire.store) {
        return Err(Error::Corrupt(
            "the envelope carries a store identifier that is not 64 lowercase hexadecimal characters".to_string(),
        ));
    }
    let kdf = match (route, header_wire.kdf) {
        (Route::Keychain, None) => None,
        (Route::Passphrase, Some(wire_kdf)) => {
            if wire_kdf.algorithm != KDF_ALGORITHM {
                return Err(Error::Corrupt(
                    "the envelope names a KDF algorithm this broker does not carry".to_string(),
                ));
            }
            if !(ARGON2_MEMORY_MIN_KIB..=ARGON2_MEMORY_MAX_KIB).contains(&wire_kdf.memory)
                || !(ARGON2_TIME_MIN..=ARGON2_TIME_MAX).contains(&wire_kdf.time)
            {
                return Err(Error::Corrupt(
                    "the envelope carries KDF parameters outside the range the reader accepts"
                        .to_string(),
                ));
            }
            let salt = decode_hex(&wire_kdf.salt).ok_or_else(|| {
                Error::Corrupt(
                    "the envelope carries a salt that does not decode as hexadecimal".to_string(),
                )
            })?;
            let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| {
                Error::Corrupt(
                    "the envelope carries a salt that does not decode to 16 bytes".to_string(),
                )
            })?;
            Some(Kdf {
                memory: wire_kdf.memory,
                time: wire_kdf.time,
                salt,
            })
        }
        _ => {
            return Err(Error::Corrupt(
                "the envelope header field set does not match its route".to_string(),
            ))
        }
    };
    let nonce = decode_hex(&wire.nonce).ok_or_else(|| {
        Error::Corrupt(
            "the envelope carries a nonce that does not decode as hexadecimal".to_string(),
        )
    })?;
    let nonce: [u8; NONCE_LEN] = nonce.try_into().map_err(|_| {
        Error::Corrupt("the envelope carries a nonce that does not decode to 24 bytes".to_string())
    })?;
    let ciphertext = decode_hex(&wire.ciphertext).ok_or_else(|| {
        Error::Corrupt(
            "the envelope carries a ciphertext that does not decode as hexadecimal".to_string(),
        )
    })?;
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Corrupt(
            "the envelope carries a ciphertext shorter than its authentication tag".to_string(),
        ));
    }
    Ok(Sealed {
        header: Header {
            payload: header_wire.payload,
            route,
            store: header_wire.store,
            kdf,
        },
        header_raw,
        nonce,
        ciphertext,
    })
}

/// Whether a store identifier stands in the shape DK-15 records, 64
/// lowercase hexadecimal characters.
pub fn store_id_shape_ok(store_id: &str) -> bool {
    store_id.len() == 64
        && store_id
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

/// Seal a document under a store key and render the whole envelope.
///
/// The header renders once and the envelope text is built around
/// those exact bytes, so the associated data is the header as it
/// stands in the file, DK-16. Publication discipline, the rename and
/// the mode, belongs to the store layer and not to this function.
pub fn seal(header: &Header, key: &StoreKey, plaintext: &[u8]) -> Result<String, Error> {
    let header_raw = header.render();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)
        .map_err(|_| Error::Io(std::io::Error::other("the random source refused")))?;
    let ciphertext = encrypt(key, &nonce, header_raw.as_bytes(), plaintext)?;
    Ok(format!(
        "{{\"ciphertext\":\"{}\",\"format\":\"{ENVELOPE_FORMAT}\",\"header\":{header_raw},\"nonce\":\"{}\"}}",
        hex(&ciphertext),
        hex(&nonce)
    ))
}

/// Authenticate and decrypt a strictly read envelope under a key.
///
/// A tag failure is the one authentication refusal of DK-22. This
/// function serves both the open path and the adoption proof, which
/// decrypts a freshly sealed envelope in memory before anything is
/// replaced, DK-23.
pub fn open_sealed(sealed: &Sealed, key: &StoreKey) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    cipher
        .decrypt(
            XNonce::from_slice(&sealed.nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: sealed.header_raw.as_bytes(),
            },
        )
        .map_err(|_| key_did_not_open())
}

fn encrypt(
    key: &StoreKey,
    nonce: &[u8; NONCE_LEN],
    header_raw: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = XChaCha20Poly1305::new(chacha20poly1305::Key::from_slice(key.as_bytes()));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: header_raw,
            },
        )
        .map_err(|_| Error::Corrupt("the document could not be sealed in its envelope".to_string()))
}

/// Decode hexadecimal text into bytes, accepting both cases.
///
/// DK-15 records the fields in lowercase, and the writer always
/// writes lowercase. The reader accepts an uppercase digit in the
/// nonce, salt, and ciphertext because case there changes no
/// meaning, while the store field's lowercase is a shape rule of its
/// own and is checked separately in [`store_id_shape_ok`].
pub fn decode_hex(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(text.len() / 2);
    let mut index = 0;
    while index < bytes.len() {
        let high = hex_digit(bytes[index])?;
        let low = hex_digit(bytes[index + 1])?;
        out.push((high << 4) | low);
        index += 2;
    }
    Some(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
