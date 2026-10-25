//! Time-based one-time codes (RFC 6238 over RFC 4226 HOTP): HMAC-SHA1,
//! 30 second steps, 6 digits. These are the defaults every authenticator app
//! uses, so the secret can be added by scanning an `otpauth://` QR code.

use hmac::{Hmac, Mac};
use sha1::Sha1;

/// Seconds per code.
pub const STEP_SECS: u64 = 30;
/// Digits per code.
pub const DIGITS: usize = 6;
/// Secret length in bytes (160 bits, the RFC 4226 recommendation).
pub const SECRET_LEN: usize = 20;

/// The HOTP value for one counter.
pub fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = Hmac::<Sha1>::new_from_slice(secret).expect("HMAC takes any key length");
    mac.update(&counter.to_be_bytes());
    let h = mac.finalize().into_bytes();
    // Dynamic truncation: the low nibble of the last byte picks 4 bytes.
    let off = (h[h.len() - 1] & 0x0f) as usize;
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    bin % 10u32.pow(DIGITS as u32)
}

/// The time step that `unix_secs` falls in.
pub fn step_at(unix_secs: u64) -> u64 {
    unix_secs / STEP_SECS
}

/// The code an authenticator shows at `unix_secs`, zero padded.
pub fn code_at(secret: &[u8], unix_secs: u64) -> String {
    format!("{:0width$}", hotp(secret, step_at(unix_secs)), width = DIGITS)
}

/// The step `code` belongs to, if it is the current code or one step either
/// side of it (phone and server clocks drift by a few seconds, and a code
/// typed at the end of its step arrives in the next one).
pub fn matching_step(secret: &[u8], code: &str, unix_secs: u64) -> Option<u64> {
    let code = code.trim();
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let want: u32 = code.parse().ok()?;
    let now = step_at(unix_secs);
    [Some(now), now.checked_sub(1), now.checked_add(1)]
        .into_iter()
        .flatten()
        .find(|&step| hotp(secret, step) == want)
}

/// Base32 (RFC 4648, no padding): the form authenticator apps take.
pub fn encode_secret(secret: &[u8]) -> String {
    data_encoding::BASE32_NOPAD.encode(secret)
}

/// Parse a base32 secret, forgiving case, spaces and trailing `=`.
pub fn decode_secret(text: &str) -> Option<Vec<u8>> {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    let bytes = data_encoding::BASE32_NOPAD.decode(clean.as_bytes()).ok()?;
    (!bytes.is_empty()).then_some(bytes)
}

/// The `otpauth://` URI an authenticator app imports from a QR code.
pub fn otpauth_uri(secret: &[u8], issuer: &str, account: &str) -> String {
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
        percent(issuer),
        percent(account),
        encode_secret(secret),
        percent(issuer),
        DIGITS,
        STEP_SECS
    )
}

/// Percent-encode everything but unreserved characters.
fn percent(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn rfc4226_hotp_vectors() {
        // RFC 4226 appendix D, 6 digit values.
        let want = [
            755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, code) in want.iter().enumerate() {
            assert_eq!(hotp(RFC_SECRET, counter as u64), *code, "counter {counter}");
        }
    }

    #[test]
    fn rfc6238_sha1_vectors_truncated_to_six_digits() {
        // RFC 6238 appendix B (SHA1), last 6 of the 8 digit values.
        for (t, code) in [
            (59, "287082"),
            (1111111109, "081804"),
            (1111111111, "050471"),
            (1234567890, "005924"),
            (2000000000, "279037"),
        ] {
            assert_eq!(code_at(RFC_SECRET, t), code, "t = {t}");
        }
    }

    #[test]
    fn neighbor_steps_match_and_farther_ones_do_not() {
        let t = 1_700_000_000;
        let now = step_at(t);
        for (offset, expect) in [(-2i64, false), (-1, true), (0, true), (1, true), (2, false)] {
            let step = (now as i64 + offset) as u64;
            let code = format!("{:06}", hotp(RFC_SECRET, step));
            let got = matching_step(RFC_SECRET, &code, t);
            assert_eq!(got.is_some(), expect, "offset {offset}");
            if expect {
                assert_eq!(got, Some(step));
            }
        }
    }

    #[test]
    fn malformed_codes_never_match() {
        let t = 59;
        assert_eq!(matching_step(RFC_SECRET, " 287082 ", t), Some(1));
        for bad in ["", "28708", "2870822", "28708a", "-87082", "+87082"] {
            assert_eq!(matching_step(RFC_SECRET, bad, t), None, "{bad:?}");
        }
    }

    #[test]
    fn secret_base32_round_trip_is_forgiving() {
        let enc = encode_secret(RFC_SECRET);
        assert_eq!(enc, "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(decode_secret(&enc).unwrap(), RFC_SECRET);
        let messy = "gezd gnbv gy3t qojq gezd gnbv gy3t qojq==";
        assert_eq!(decode_secret(messy).unwrap(), RFC_SECRET);
        assert_eq!(decode_secret("not base32 1"), None);
        assert_eq!(decode_secret(""), None);
    }

    #[test]
    fn otpauth_uri_escapes_the_label() {
        let uri = otpauth_uri(RFC_SECRET, "cld phone", "me@host");
        assert_eq!(
            uri,
            "otpauth://totp/cld%20phone:me%40host?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=cld%20phone&algorithm=SHA1&digits=6&period=30"
        );
    }
}
