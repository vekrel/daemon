//! The engine's websocket ticket (`wsTicket` on `/ws`): the session token's format and key with
//! `WebSocketClaims` (`SessionStore.ts` `issueWebSocketToken` / `verifyWebSocketToken`).
use super::token::{TokenError, sign, signed_json};
use serde::{Deserialize, Serialize};

/// `DEFAULT_WEBSOCKET_TOKEN_TTL` (`SessionStore.ts`), in milliseconds.
pub const TTL_MS: i64 = 5 * 60_000;

/// `WebSocketClaims`, fields in schema order (the encoded JSON is what gets signed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    pub v: u8,
    pub kind: String,
    pub sid: String,
    /// Epoch milliseconds.
    pub iat: i64,
    /// Epoch milliseconds.
    pub exp: i64,
}

/// Signature and claims shape only; expiry and the session row are the caller's.
pub fn verify(ticket: &str, key: &[u8; 32]) -> Result<Claims, TokenError> {
    let c: Claims =
        serde_json::from_slice(&signed_json(ticket, key)?).map_err(|_| TokenError::Malformed)?;
    if c.v != 1 || c.kind != "websocket" {
        return Err(TokenError::Malformed);
    }
    Ok(c)
}

/// `SessionStore.issueWebSocketToken`: a ticket for `sid` issued at `iat_ms`; returns it and its `exp`.
pub fn issue(sid: &str, iat_ms: i64, key: &[u8; 32]) -> (String, i64) {
    let exp = iat_ms + TTL_MS;
    let c = Claims {
        v: 1,
        kind: "websocket".into(),
        sid: sid.into(),
        iat: iat_ms,
        exp,
    };
    (
        sign(&serde_json::to_vec(&c).expect("serializable"), key),
        exp,
    )
}

/// Node's `searchParams.get("wsTicket")`, only where Rust is sure of it.
#[derive(Debug, PartialEq, Eq)]
pub enum InQuery<'a> {
    Absent,
    Ticket(&'a str),
    /// A `%`/`+`-encoded key or value, a repeated or blank ticket.
    Unsure,
}

pub fn from_query(query: Option<&str>) -> InQuery<'_> {
    let mut found = None;
    for pair in query.unwrap_or("").split('&') {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k.contains(['%', '+']) {
            return InQuery::Unsure;
        }
        if k == "wsTicket" {
            // shortcut: a blank ticket sends Node down the cookie/bearer path; Rust just defers.
            if found.is_some() || v.is_empty() || v.contains(['%', '+']) {
                return InQuery::Unsure;
            }
            found = Some(v);
        }
    }
    found.map_or(InQuery::Absent, InQuery::Ticket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_extraction() {
        assert_eq!(from_query(None), InQuery::Absent);
        assert_eq!(from_query(Some("orchestrationProtocol=2")), InQuery::Absent);
        assert_eq!(
            from_query(Some("a=1&wsTicket=x.y&b")),
            InQuery::Ticket("x.y")
        );
        for q in [
            "wsTicket=a&wsTicket=a",
            "wsTicket=",
            "wsTicket",
            "wsTicket=a%2E",
            "wsTicket=a+",
            "ws%54icket=a",
        ] {
            assert_eq!(from_query(Some(q)), InQuery::Unsure, "{q}");
        }
    }
}
