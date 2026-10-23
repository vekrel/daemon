//! Node's machine error bodies (contracts `machineHttp.ts:136-247`), keys in schema order
//! (`_tag` first), with a Rust-generated `traceId` (Node's is its OTel trace id).
use axum::{
    body::Bytes,
    http::{Response, StatusCode, header},
};
use serde::Serialize;
use std::hash::{BuildHasher, Hasher, RandomState};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Error<'a> {
    #[serde(rename = "_tag")]
    tag: &'a str,
    code: &'a str,
    reason: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    dpop_failure_reason: Option<&'a str>,
    trace_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ScopeRequired<'a> {
    #[serde(rename = "_tag")]
    tag: &'a str,
    code: &'a str,
    required_scope: &'a str,
    required_permission: &'a str,
    trace_id: String,
}

/// 32 lowercase hex chars, like an OTel trace id. Not secret, so `RandomState`'s keys suffice.
pub fn trace_id() -> String {
    let half = || RandomState::new().build_hasher().finish();
    format!("{:016x}{:016x}", half(), half())
}

/// A JSON response with the headers Node sends on machine routes besides length/date.
pub fn json(status: StatusCode, body: &impl Serialize) -> Response<Bytes> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::VARY, "Accept-Encoding")
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")
        .body(serde_json::to_vec(body).expect("serializable").into())
        .expect("valid response")
}

fn error(status: u16, tag: &str, code: &str, reason: &str, dpop: Option<&str>) -> Response<Bytes> {
    let body = Error {
        tag,
        code,
        reason,
        dpop_failure_reason: dpop,
        trace_id: trace_id(),
    };
    json(StatusCode::from_u16(status).expect("valid status"), &body)
}

/// 401 `MachineAuthInvalidError` (`missing_credential` / `invalid_credential`). The
/// `www-authenticate: DPoP` header is the caller's (`http_auth::unauthorized`).
pub fn auth_invalid(reason: &str, dpop_failure_reason: Option<&str>) -> Response<Bytes> {
    let tag = "MachineAuthInvalidError";
    error(401, tag, "auth_invalid", reason, dpop_failure_reason)
}

/// 400 `MachineRequestInvalidError`.
pub fn invalid_request(reason: &str) -> Response<Bytes> {
    error(
        400,
        "MachineRequestInvalidError",
        "invalid_request",
        reason,
        None,
    )
}

/// 403 `MachineOperationForbiddenError`.
pub fn operation_forbidden(reason: &str) -> Response<Bytes> {
    let tag = "MachineOperationForbiddenError";
    error(403, tag, "operation_forbidden", reason, None)
}

/// 500 `MachineInternalError`.
pub fn internal_error(reason: &str) -> Response<Bytes> {
    error(500, "MachineInternalError", "internal_error", reason, None)
}

/// 403 `MachineScopeRequiredError` with `authScopeRequiredResponse` (contracts `auth.ts:113`).
pub fn scope_required(permission: &str) -> Response<Bytes> {
    let body = ScopeRequired {
        tag: "MachineScopeRequiredError",
        code: "insufficient_scope",
        required_scope: legacy_parent(permission).unwrap_or(permission),
        required_permission: permission,
        trace_id: trace_id(),
    };
    json(StatusCode::FORBIDDEN, &body)
}

/// `legacyParents` (contracts `auth.ts`).
fn legacy_parent(scope: &str) -> Option<&'static str> {
    Some(match scope {
        "filesystem:read" | "diagnostics:read" => "orchestration:read",
        "settings:write"
        | "providers:manage"
        | "machine:maintain"
        | "preview:operate"
        | "source-control:write"
        | "filesystem:write" => "orchestration:operate",
        "terminal:read" => "terminal:operate",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// (status, body with the trace id replaced by `T`) after checking the id's shape.
    fn parts(r: Response<Bytes>) -> (u16, String) {
        assert_eq!(r.headers()["content-type"], "application/json");
        let body = String::from_utf8(r.body().to_vec()).unwrap();
        let (head, id) = body.rsplit_once(r#""traceId":""#).unwrap();
        let id = id.strip_suffix(r#""}"#).unwrap();
        assert!(id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        (r.status().as_u16(), format!(r#"{head}"traceId":"T"}}"#))
    }

    // Expected bytes: `HttpServerResponse.schemaJson` of each `Schema.TaggedError` (`_tag`, then
    // the fields in declaration order; `dpopFailureReason` is `optionalKey`, omitted when absent).
    #[test]
    fn error_bodies_match_node_bytes() {
        let cases = [
            (
                auth_invalid("missing_credential", None),
                401,
                r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"missing_credential","traceId":"T"}"#,
            ),
            (
                auth_invalid("invalid_credential", Some("invalid_proof")),
                401,
                r#"{"_tag":"MachineAuthInvalidError","code":"auth_invalid","reason":"invalid_credential","dpopFailureReason":"invalid_proof","traceId":"T"}"#,
            ),
            (
                invalid_request("invalid_scope"),
                400,
                r#"{"_tag":"MachineRequestInvalidError","code":"invalid_request","reason":"invalid_scope","traceId":"T"}"#,
            ),
            (
                operation_forbidden("current_session_revoke_not_allowed"),
                403,
                r#"{"_tag":"MachineOperationForbiddenError","code":"operation_forbidden","reason":"current_session_revoke_not_allowed","traceId":"T"}"#,
            ),
            (
                internal_error("websocket_ticket_issuance_failed"),
                500,
                r#"{"_tag":"MachineInternalError","code":"internal_error","reason":"websocket_ticket_issuance_failed","traceId":"T"}"#,
            ),
            (
                scope_required("access:write"),
                403,
                r#"{"_tag":"MachineScopeRequiredError","code":"insufficient_scope","requiredScope":"access:write","requiredPermission":"access:write","traceId":"T"}"#,
            ),
            (
                scope_required("filesystem:write"),
                403,
                r#"{"_tag":"MachineScopeRequiredError","code":"insufficient_scope","requiredScope":"orchestration:operate","requiredPermission":"filesystem:write","traceId":"T"}"#,
            ),
        ];
        for (r, status, want) in cases {
            assert_eq!(parts(r), (status, want.to_owned()));
        }
    }

    #[test]
    fn trace_ids_differ() {
        assert_ne!(trace_id(), trace_id());
    }
}
