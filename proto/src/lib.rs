//! Shared by the relay worker, the host CLI (`cldp`) and the phone app.
//!
//! - [`api`]: the JSON bodies on the wire and their limits.
//! - [`totp`]: RFC 6238 codes, as shown by any authenticator app.
//! - [`gate`]: how many pairing attempts the worker lets through.
//! - [`client`]: a blocking HTTP client for the API (feature `client`).

pub mod api;
pub mod gate;
pub mod totp;

#[cfg(feature = "client")]
pub mod client;

use sha2::{Digest, Sha256};

/// Lowercase hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// What the worker stores in place of a device token: a leaked table does
/// not hand out working tokens.
pub fn token_digest(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// The statements of an SQL script: `--` comments dropped, split on `;`.
/// Good for scripts whose string literals hold no `;` or `--`.
pub fn sql_statements(script: &str) -> Vec<String> {
    let code: String = script
        .lines()
        .map(|line| line.split("--").next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n");
    code.split(';')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Compare two secrets without stopping at the first difference.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_encodes_each_byte() {
        assert_eq!(hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    #[test]
    fn token_digest_is_sha256_hex() {
        assert_eq!(
            token_digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn sql_statements_drop_comments_and_blanks() {
        let script = "-- header; with a semicolon\nCREATE TABLE a (\n    x TEXT NOT NULL DEFAULT '[]' -- note\n);\n\nINSERT OR IGNORE INTO a VALUES ('1');\n";
        assert_eq!(
            sql_statements(script),
            vec![
                "CREATE TABLE a (\n    x TEXT NOT NULL DEFAULT '[]' \n)",
                "INSERT OR IGNORE INTO a VALUES ('1')",
            ]
        );
    }

    #[test]
    fn constant_time_eq_matches_plain_eq() {
        assert!(constant_time_eq(b"secret", b"secret"));
        assert!(!constant_time_eq(b"secret", b"secreT"));
        assert!(!constant_time_eq(b"secret", b"secret!"));
    }
}
