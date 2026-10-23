//! `POST /api/auth/websocket-ticket` (`auth/http.ts` `webSocketTicket`): a stateless ticket signed
//! with the engine's session key, so Node's `/ws` accepts it.
use super::{
    HandlerCtx,
    auth_session::{AuthSession, iso_millis},
};
use crate::{
    auth::ticket,
    cookies, http_auth,
    http_seam::{Compare, RouteHandler},
};
use axum::{
    body::Bytes,
    http::{Method, Response, StatusCode, request::Parts},
};
use futures_util::{FutureExt, future::BoxFuture};
use serde::Serialize;
use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// `AuthWebSocketTicketResult`, fields in schema order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Issued {
    ticket: String,
    expires_at: String,
}

pub struct WsTicket(pub Arc<AuthSession>);

impl RouteHandler for WsTicket {
    fn default_mode(&self) -> crate::config::Mode {
        crate::config::Mode::Serve
    }

    fn method_path(&self) -> (Method, &'static str) {
        (Method::POST, "/api/auth/websocket-ticket")
    }

    fn compare(&self) -> Compare {
        Compare {
            ignore: &["$.ticket"],
            times: &["$.expiresAt"],
            headers: Compare::AUTH_HEADERS,
            enrich: &[],
        }
    }

    fn handle<'a>(
        &'a self,
        req: &'a Parts,
        _ctx: &'a HandlerCtx,
    ) -> BoxFuture<'a, Option<Response<Bytes>>> {
        async move {
            // Middleware 401s come before the handler, so they carry no `no-store`.
            let p = match http_auth::authenticate(&self.0, req).await? {
                Ok(p) => p,
                Err(r) => return Some(r),
            };
            // Reusable dev-token sessions stay on Node.
            if p.session_id.starts_with("dev-auth-") {
                return None;
            }
            let key = self.0.files().key()?;
            let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?;
            let (ticket, exp) = ticket::issue(&p.session_id, now.as_millis() as i64, &key);
            let body = Issued {
                ticket,
                expires_at: iso_millis(exp),
            };
            let mut r = crate::http_errors::json(StatusCode::OK, &body);
            cookies::no_store(r.headers_mut());
            Some(r)
        }
        .boxed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::{
            ticket,
            token::tests::{mint, payload},
        },
        http_auth::tests::{AUTH, COOKIE, KEY, env, rejected, req},
    };
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::time::{SystemTime, UNIX_EPOCH};

    const PATH: &str = "/api/auth/websocket-ticket";

    async fn ask(e: &crate::http_auth::tests::Env, h: &[(&str, &str)]) -> Option<Response<Bytes>> {
        WsTicket(e.1.clone())
            .handle(&req(PATH, h), &HandlerCtx::default())
            .await
    }

    fn now_ms() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as i64
    }

    /// Node's `verifyWebSocketToken` up to the claims decode: HMAC of the encoded half, then JSON.
    fn node_verify(t: &str, key: &[u8; 32]) -> String {
        let (enc, sig) = t.split_once('.').unwrap();
        let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
        mac.update(enc.as_bytes());
        assert_eq!(sig, B64.encode(mac.finalize().into_bytes()));
        String::from_utf8(B64.decode(enc).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn issues_nodes_response_and_a_ticket_both_verifiers_accept() {
        let e = env();
        let cookie = format!("{COOKIE}={}", mint(&payload(), &KEY));
        let before = now_ms();
        let r = ask(&e, &[("cookie", &cookie)]).await.unwrap();
        let after = now_ms();
        assert_eq!(r.status(), 200);
        let h: Vec<_> = r
            .headers()
            .iter()
            .map(|(k, v)| format!("{k}: {}", v.to_str().unwrap()))
            .collect();
        assert_eq!(
            h,
            [
                "content-type: application/json",
                "vary: Accept-Encoding",
                "access-control-allow-origin: *",
                "cache-control: no-store",
                "pragma: no-cache",
            ]
        );
        let body: serde_json::Value = serde_json::from_slice(r.body()).unwrap();
        let t = body["ticket"].as_str().unwrap();
        let c = ticket::verify(t, &KEY).unwrap();
        assert_eq!(
            (c.sid.as_str(), c.exp - c.iat),
            (payload().sid.as_str(), 300_000)
        );
        assert!((before..=after).contains(&c.iat));
        // Schema order, exact bytes.
        let want = format!(r#"{{"ticket":"{t}","expiresAt":"{}"}}"#, iso_millis(c.exp));
        assert_eq!(std::str::from_utf8(r.body()).unwrap(), want);
        assert_eq!(
            node_verify(t, &KEY),
            format!(
                r#"{{"v":1,"kind":"websocket","sid":"{}","iat":{},"exp":{}}}"#,
                c.sid, c.iat, c.exp
            )
        );
        // Bearer works too.
        let bearer = format!("Bearer {}", mint(&payload(), &KEY));
        assert_eq!(
            ask(&e, &[("authorization", &bearer)])
                .await
                .unwrap()
                .status(),
            200
        );
    }

    #[tokio::test]
    async fn unauthenticated_and_mcp_subject_are_nodes_401() {
        let e = env();
        let r = ask(&e, &[]).await.unwrap();
        assert!(r.headers().get("cache-control").is_none());
        assert_eq!(
            rejected(r),
            (401, format!(r#"{AUTH}"missing_credential""#), None)
        );
        let mut mcp = payload();
        mcp.sub = "mcp-client".into();
        let bearer = format!("Bearer {}", mint(&mcp, &KEY));
        let r = ask(&e, &[("authorization", &bearer)]).await.unwrap();
        assert!(r.headers().get("cache-control").is_none());
        assert_eq!(
            rejected(r),
            (401, format!(r#"{AUTH}"invalid_credential""#), None)
        );
    }

    #[tokio::test]
    async fn declines_what_node_owns_and_answers_unbound_dpop() {
        let e = env();
        let t = mint(&payload(), &KEY);
        // DPoP on an unbound token: Node's middleware 401 (proof checks: `http_auth`).
        let dpop = format!("DPoP {t}");
        let r = ask(&e, &[("authorization", &dpop), ("dpop", "p")])
            .await
            .unwrap();
        assert_eq!(
            rejected(r),
            (
                401,
                format!(r#"{AUTH}"invalid_credential","dpopFailureReason":"invalid_proof""#),
                Some("DPoP".into())
            )
        );
        // Legacy-cookie and dev-token callers are `http_auth`'s / below; key gone: decline.
        let mut dev = payload();
        dev.sid = "dev-auth-1".into();
        let c = rusqlite::Connection::open(e.0.path().join("db.sqlite")).unwrap();
        c.execute(
            "INSERT INTO auth_sessions (session_id, subject, scopes, method, issued_at, expires_at)
             VALUES ('dev-auth-1', 'browser', '[]', 'browser-session-cookie', '2026-01-01T00:00:00.000Z', '2099-01-01T00:00:00.000Z')",
            [],
        )
        .unwrap();
        let dev = format!("Bearer {}", mint(&dev, &KEY));
        assert!(ask(&e, &[("authorization", &dev)]).await.is_none());
        std::fs::remove_file(e.0.path().join("key.bin")).unwrap();
        let bearer = format!("Bearer {t}");
        assert!(ask(&e, &[("authorization", &bearer)]).await.is_none());
    }
}
