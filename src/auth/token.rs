//! The engine's session token: `base64url(claimsJSON) "." base64url(HMAC-SHA256(key, base64url(claimsJSON)))`.
//! Mirrors `Vekrel-Engine/apps/server/src/auth/SessionStore.ts` (`SessionClaims`, `verify`) and `auth/utils.ts`.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

/// `SessionClaims` from `SessionStore.ts`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Payload {
    pub v: u8,
    pub kind: String,
    pub sid: String,
    pub sub: String,
    pub scopes: Vec<String>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jkt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtc: Option<String>,
    /// Epoch milliseconds.
    pub iat: i64,
    /// Epoch milliseconds.
    pub exp: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Malformed,
    BadSignature,
}

/// Signature and claims shape only; expiry and revocation are the caller's (as in `SessionStore.verify`).
pub fn verify(token: &str, key: &[u8; 32]) -> Result<Payload, TokenError> {
    // Node does `token.split(".")` and uses the first two parts, so extra dots are ignored.
    let mut parts = token.split('.');
    let (enc, sig) = match (parts.next(), parts.next()) {
        (Some(e), Some(s)) if !e.is_empty() && !s.is_empty() => (e, s),
        _ => return Err(TokenError::Malformed),
    };
    let sig = node_base64_decode(sig);
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(enc.as_bytes());
    mac.verify_slice(&sig)
        .map_err(|_| TokenError::BadSignature)?;
    let json = B64
        .decode(enc.trim_end_matches('='))
        .map_err(|_| TokenError::Malformed)?;
    let p: Payload = serde_json::from_slice(&json).map_err(|_| TokenError::Malformed)?;
    if p.kind != "session" || !matches!(p.v, 1 | 2) {
        return Err(TokenError::Malformed);
    }
    Ok(p)
}

/// `Buffer.from(s, "base64url")` as `timingSafeEqualBase64Url` uses it: both alphabets, other
/// characters skipped, stops at `=`, leftover bits dropped. A strict decoder would reject
/// signatures Node accepts (e.g. a changed final character that only flips unused bits).
fn node_base64_decode(s: &str) -> Vec<u8> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            _ => continue,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Reproduces `SessionStore.issue`: sign the base64url payload string, not the JSON.
    pub(crate) fn mint(p: &Payload, key: &[u8; 32]) -> String {
        let enc = B64.encode(serde_json::to_vec(p).unwrap());
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(enc.as_bytes());
        format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()))
    }

    pub(crate) fn payload() -> Payload {
        Payload {
            v: 1,
            kind: "session".into(),
            sid: "6f1c0d3e-0000-4000-8000-000000000001".into(),
            sub: "browser".into(),
            scopes: vec!["orchestration:read".into()],
            method: "browser-session-cookie".into(),
            jkt: None,
            rtc: None,
            iat: 1,
            exp: i64::MAX,
        }
    }

    const K: [u8; 32] = [7; 32];

    #[test]
    fn round_trips_a_minted_token() {
        assert_eq!(verify(&mint(&payload(), &K), &K), Ok(payload()));
    }

    #[test]
    fn wrong_key_is_bad_signature() {
        assert_eq!(
            verify(&mint(&payload(), &K), &[8; 32]),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn tampered_payload_is_bad_signature() {
        let t = mint(&payload(), &K);
        let (_, sig) = t.split_once('.').unwrap();
        let mut p = payload();
        p.scopes.push("admin".into());
        let forged = B64.encode(serde_json::to_vec(&p).unwrap());
        assert_eq!(
            verify(&format!("{forged}.{sig}"), &K),
            Err(TokenError::BadSignature)
        );
    }

    #[test]
    fn signature_decodes_like_node_buffer() {
        // Expected values from `Buffer.from(s, "base64url").toString("hex")` on Node 22.
        let hex = |s: &str| {
            node_base64_decode(s)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        };
        for (s, want) in [
            ("AQ", "01"),
            ("AR", "01"),
            ("AQ==", "01"),
            ("A!Q", "01"),
            ("A Q", "01"),
            ("+/", "fb"),
            ("-_", "fb"),
            ("AQ=AQ", "01"),
            ("AQID", "010203"),
            ("A=QID", ""),
        ] {
            assert_eq!(hex(s), want, "{s}");
        }
    }

    #[test]
    fn signature_with_flipped_unused_bits_verifies_as_in_node() {
        let t = mint(&payload(), &K);
        // 32-byte MAC = 43 chars; the last one carries 2 unused bits.
        let last = t.chars().last().unwrap();
        let idx = B64_ALPHABET.find(last).unwrap();
        let flipped = B64_ALPHABET.as_bytes()[idx ^ 1] as char;
        let forged = format!("{}{flipped}", &t[..t.len() - 1]);
        assert_ne!(forged, t);
        assert!(verify(&forged, &K).is_ok());
    }

    const B64_ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    #[test]
    fn missing_dot_is_malformed() {
        assert_eq!(verify("abc", &K), Err(TokenError::Malformed));
        assert_eq!(verify(".abc", &K), Err(TokenError::Malformed));
    }

    #[test]
    fn signed_garbage_payload_is_malformed() {
        let enc = B64.encode(b"not json");
        let mut mac = Hmac::<Sha256>::new_from_slice(&K).unwrap();
        mac.update(enc.as_bytes());
        let t = format!("{enc}.{}", B64.encode(mac.finalize().into_bytes()));
        assert_eq!(verify(&t, &K), Err(TokenError::Malformed));
    }
}
