//! DPoP proof verification, byte-compatible with the engine's `verifyDpopProof`
//! (`packages/shared/src/dpop.ts`) and `mapDpopFailureReason` (`apps/server/src/auth/dpop.ts`).
//! Whatever Rust cannot be sure Node would decide the same way is `Decline`: callers then leave
//! the request to Node, which is only safe because nothing has been written yet.
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use p256::ecdsa::{Signature, VerifyingKey, signature::hazmat::PrehashVerifier};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// `DPOP_MAX_CLOCK_SKEW_SECONDS`.
const MAX_SKEW_S: i64 = 300;
/// `Number.MAX_SAFE_INTEGER` (`Schema.Int` is `isSafeInteger`).
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// A proof that passed every check but the replay marker.
#[derive(Debug, Clone, PartialEq)]
pub struct Proof {
    pub thumbprint: String,
    pub jti: String,
    pub iat: i64,
}

#[derive(Debug, PartialEq)]
pub enum Verdict {
    Ok(Proof),
    /// Node rejects the proof; the value is its `dpopFailureReason`.
    Fail(&'static str),
    /// Rust cannot be sure what Node decides: Node answers.
    Decline,
}

/// `b64url(sha256(s))`: `computeDpopAccessTokenHash` and the replay marker key.
pub fn b64_sha256(s: &str) -> String {
    B64.encode(Sha256::digest(s.as_bytes()))
}

/// `computeDpopJwkThumbprint`: RFC 7638 members in code-unit order, `JSON.stringify` strings.
pub fn thumbprint(crv: &str, kty: &str, x: &str, y: &str) -> String {
    let j = |s: &str| serde_json::to_string(s).expect("string");
    b64_sha256(&format!(
        r#"{{"crv":{},"kty":{},"x":{},"y":{}}}"#,
        j(crv),
        j(kty),
        j(x),
        j(y)
    ))
}

/// `normalizeDpopHtu`: the WHATWG URL without query and fragment.
pub fn normalize_htu(url: &str) -> Option<String> {
    let mut u = url::Url::parse(url).ok()?;
    u.set_query(None);
    u.set_fragment(None);
    Some(u.into())
}

/// `HttpServerRequest.toURL` for `host` (`localhost` when absent) and an origin-form target,
/// over plain HTTP: the daemon's public port does not speak TLS.
pub fn request_url(host: Option<&str>, path_and_query: &str) -> Option<String> {
    let base = url::Url::parse(&format!("http://{}", host.unwrap_or("localhost"))).ok()?;
    Some(base.join(path_and_query).ok()?.into())
}

fn part(s: &str) -> Option<Map<String, Value>> {
    // Node's decoders are laxer (and replace bad UTF-8); only strict input is ours.
    let bytes = B64.decode(s).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn non_empty<'a>(m: &'a Map<String, Value>, k: &str) -> Option<&'a str> {
    m.get(k)?.as_str().filter(|s| !s.is_empty())
}

/// `verifyDpopProof` with Node's check order; `url` is the request URL as Node builds it.
pub fn verify(
    proof: Option<&str>,
    method: &str,
    url: &str,
    now_s: i64,
    expected_thumbprint: Option<&str>,
    expected_token: Option<&str>,
) -> Verdict {
    use Verdict::{Decline, Fail};
    const INVALID: Verdict = Fail("invalid_proof");
    let Some(proof) = proof.filter(|p| !p.trim().is_empty()) else {
        return INVALID;
    };
    let parts: Vec<&str> = proof.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return INVALID;
    }
    // A header that fails the schema (unknown alg, malformed JWK) or JSON Rust parses differently
    // (lone surrogates, huge numbers): Node's answer.
    let (Some(h), Some(p)) = (part(parts[0]), part(parts[1])) else {
        return Decline;
    };
    let jwk = match h.get("jwk") {
        Some(Value::Object(j)) => j,
        _ => return Decline,
    };
    let (Some(x), Some(y)) = (non_empty(jwk, "x"), non_empty(jwk, "y")) else {
        return Decline;
    };
    if h.get("typ").and_then(Value::as_str) != Some("dpop+jwt")
        || h.get("alg").and_then(Value::as_str) != Some("ES256")
        || jwk.get("kty").and_then(Value::as_str) != Some("EC")
        || jwk.get("crv").and_then(Value::as_str) != Some("P-256")
        || jwk.contains_key("d")
    {
        return Decline;
    }
    let iat = match p.get("iat") {
        Some(Value::Number(n)) => match n.as_f64() {
            Some(f) if f.fract() == 0.0 && f.abs() <= MAX_SAFE => f as i64,
            _ => return INVALID,
        },
        _ => return INVALID,
    };
    let (Some(htm), Some(htu), Some(jti)) = (
        non_empty(&p, "htm"),
        non_empty(&p, "htu"),
        non_empty(&p, "jti"),
    ) else {
        return INVALID;
    };
    let ath = match p.get("ath") {
        None => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => return INVALID,
    };

    let thumb = thumbprint("P-256", "EC", x, y);
    if expected_thumbprint.is_some_and(|e| !e.is_empty() && e != thumb) {
        return Fail("key_mismatch");
    }
    // JS `toUpperCase` is Unicode-aware; only ASCII is certain to agree.
    if !htm.is_ascii() || !method.is_ascii() {
        return Decline;
    }
    if !htm.eq_ignore_ascii_case(method) {
        return Fail("request_mismatch");
    }
    if normalize_htu(url).as_deref() != Some(htu) {
        return Fail("request_mismatch");
    }
    if let Some(t) = expected_token.filter(|t| !t.is_empty())
        && ath != Some(b64_sha256(t).as_str())
    {
        return Fail("token_mismatch");
    }

    let (Ok(sig), Ok(xb), Ok(yb)) = (B64.decode(parts[2]), B64.decode(x), B64.decode(y)) else {
        return Decline;
    };
    if sig.len() != 64 || xb.len() != 32 || yb.len() != 32 {
        return INVALID;
    }
    let sec1 = [&[4u8][..], &xb, &yb].concat();
    let (Ok(key), Ok(sig)) = (
        VerifyingKey::from_sec1_bytes(&sec1),
        Signature::from_slice(&sig),
    ) else {
        return INVALID;
    };
    // noble `p256.verify(sig, sha256(h.p), key, {prehash: false})`, high-S included.
    let digest = Sha256::digest(format!("{}.{}", parts[0], parts[1]).as_bytes());
    if key.verify_prehash(&digest, &sig).is_err() {
        return INVALID;
    }
    if (i128::from(now_s) - i128::from(iat)).abs() > i128::from(MAX_SKEW_S) {
        return Fail("time_window");
    }
    Verdict::Ok(Proof {
        thumbprint: thumb,
        jti: jti.to_owned(),
        iat,
    })
}

/// Whether Node, building `htu` from the proxy's rewritten Host (`node_url`), rejects a proof
/// that is right for the URL the client used (`client_url`).
pub fn node_htu_host_mismatch(proof: &str, client_url: &str, node_url: &str) -> bool {
    let htu = proof
        .split('.')
        .nth(1)
        .and_then(part)
        .and_then(|p| p.get("htu")?.as_str().map(str::to_owned));
    let (c, n) = (normalize_htu(client_url), normalize_htu(node_url));
    htu.is_some() && htu == c && htu != n
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    /// A client key and what its proofs carry; shared by the DPoP tests in this crate.
    pub(crate) struct Client(pub SigningKey);

    impl Client {
        pub(crate) fn new(seed: u8) -> Self {
            Client(SigningKey::from_slice(&[seed; 32]).unwrap())
        }
        fn xy(&self) -> (String, String) {
            let p = self.0.verifying_key().to_sec1_point(false);
            let b = p.as_bytes();
            (B64.encode(&b[1..33]), B64.encode(&b[33..65]))
        }
        pub(crate) fn thumbprint(&self) -> String {
            let (x, y) = self.xy();
            thumbprint("P-256", "EC", &x, &y)
        }
        /// An ES256 proof over `header` overrides and `payload` (JSON object text members).
        pub(crate) fn proof_with(&self, alg: &str, payload: &str) -> String {
            let (x, y) = self.xy();
            let h = format!(
                r#"{{"typ":"dpop+jwt","alg":"{alg}","jwk":{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}}}"#
            );
            let hp = format!("{}.{}", B64.encode(h), B64.encode(payload));
            let sig: Signature = self.0.sign(hp.as_bytes());
            format!("{hp}.{}", B64.encode(sig.to_bytes()))
        }
        /// A proof for `htm`/`htu` now, bound to `token` (`ath`).
        pub(crate) fn proof(&self, htm: &str, htu: &str, jti: &str, token: &str) -> String {
            let iat = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let ath = b64_sha256(token);
            self.proof_with(
                "ES256",
                &format!(
                    r#"{{"htm":"{htm}","htu":"{htu}","jti":"{jti}","iat":{iat},"ath":"{ath}"}}"#
                ),
            )
        }
    }

    fn vectors() -> Value {
        serde_json::from_str(include_str!("../../tests/fixtures/dpop/vectors.json")).unwrap()
    }

    /// Node rejects these with `invalid_proof` (a header or JSON Rust does not judge): Rust leaves
    /// them to Node, which is safe because no marker was written.
    const DECLINED: [&str; 6] = [
        "private_jwk_d",
        "malformed_header_json",
        "malformed_payload_json",
        "typ_wrong",
        "alg_es384",
        "kty_rsa",
    ];

    #[test]
    fn node_vectors_get_nodes_verdict() {
        let v = vectors();
        let all = v["vectors"].as_array().unwrap();
        assert!(all.len() >= 37);
        for c in all {
            let name = c["name"].as_str().unwrap();
            let got = verify(
                c["proof"].as_str(),
                c["method"].as_str().unwrap(),
                c["url"].as_str().unwrap(),
                c["now"].as_i64().unwrap(),
                c["expectedThumbprint"].as_str(),
                c["expectedAccessToken"].as_str(),
            );
            let node = &c["node"];
            let want = if node["ok"] == true {
                Verdict::Ok(Proof {
                    thumbprint: node["thumbprint"].as_str().unwrap().into(),
                    jti: node["jti"].as_str().unwrap().into(),
                    iat: node["iat"].as_i64().unwrap(),
                })
            } else if DECLINED.contains(&name) {
                assert_eq!(node["dpopFailureReason"], "invalid_proof", "{name}");
                Verdict::Decline
            } else {
                let r = node["dpopFailureReason"].as_str().unwrap();
                Verdict::Fail(Box::leak(r.to_owned().into_boxed_str()))
            };
            assert_eq!(got, want, "{name}");
            if let Verdict::Ok(p) = &got {
                // Node's marker name for this proof.
                let m = crate::auth::replay::marker_path(
                    std::path::Path::new(""),
                    &p.thumbprint,
                    &p.jti,
                );
                assert_eq!(
                    m.to_str().unwrap(),
                    format!("{}.bin", node["marker"].as_str().unwrap()),
                    "{name}"
                );
            }
        }
    }

    #[test]
    fn high_s_vector_really_is_high_s() {
        let v = vectors();
        let c = v["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "valid_high_s")
            .unwrap();
        let sig = B64
            .decode(c["proof"].as_str().unwrap().rsplit('.').next().unwrap())
            .unwrap();
        let half_n = hex("7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8");
        assert!(sig[32..] > half_n[..], "s must exceed n/2");
        assert!(
            Signature::from_slice(&sig).unwrap().normalize_s()
                != Signature::from_slice(&sig).unwrap()
        );
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn thumbprints_ath_and_htu_match_node() {
        let v = vectors();
        for t in v["thumbprints"].as_array().unwrap() {
            let j = &t["jwk"];
            let s = |k: &str| j[k].as_str().unwrap();
            assert_eq!(
                thumbprint(s("crv"), s("kty"), s("x"), s("y")),
                t["thumbprint"]
            );
        }
        assert_eq!(
            b64_sha256(v["ath"]["token"].as_str().unwrap()),
            v["ath"]["ath"]
        );
        for h in v["htu"].as_array().unwrap() {
            assert_eq!(
                normalize_htu(h["input"].as_str().unwrap()).as_deref(),
                h["output"].as_str(),
                "{}",
                h["input"]
            );
        }
    }

    #[test]
    fn request_url_uses_the_given_host_over_http() {
        let u = |h, p| request_url(h, p);
        assert_eq!(
            u(Some("127.0.0.1:3789"), "/api/x?y=1").as_deref(),
            Some("http://127.0.0.1:3789/api/x?y=1")
        );
        assert_eq!(u(None, "/ws").as_deref(), Some("http://localhost/ws"));
        assert_eq!(
            u(Some("LocalHost:80"), "/a/../b").as_deref(),
            Some("http://localhost/b")
        );
        assert_eq!(u(Some("a b"), "/"), None);
    }

    #[test]
    fn rust_signed_proofs_verify_and_unknown_alg_declines() {
        let c = Client::new(3);
        let p = c.proof("GET", "http://h/x", "j", "tok");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let ok = verify(
            Some(&p),
            "get",
            "http://h/x?q",
            now,
            Some(&c.thumbprint()),
            Some("tok"),
        );
        assert!(matches!(ok, Verdict::Ok(_)), "{ok:?}");
        let es384 = c.proof_with(
            "ES384",
            r#"{"htm":"GET","htu":"http://h/x","jti":"j","iat":1}"#,
        );
        assert_eq!(
            verify(Some(&es384), "GET", "http://h/x", 1, None, None),
            Verdict::Decline
        );
    }

    #[test]
    fn node_htu_host_mismatch_only_for_public_url_proofs() {
        let c = Client::new(3);
        let public = c.proof("GET", "http://127.0.0.1:3773/api/auth/session", "j", "t");
        let engine = c.proof("GET", "http://127.0.0.1:3783/api/auth/session", "j", "t");
        let (cu, nu) = (
            "http://127.0.0.1:3773/api/auth/session?x",
            "http://127.0.0.1:3783/api/auth/session",
        );
        assert!(node_htu_host_mismatch(&public, cu, nu));
        assert!(!node_htu_host_mismatch(&engine, cu, nu));
        assert!(!node_htu_host_mismatch("garbage", cu, nu));
    }
}
