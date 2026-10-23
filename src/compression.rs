//! Response compression as the engine applies it to every HTTP route: Effect 4.0.5's
//! `HttpMiddleware.compression()` with defaults (`http.ts:254`) over Node's zlib
//! (`NodeHttpCompression`): preference `br`, `gzip`, `deflate`; 1024-byte threshold; levels
//! gzip/deflate 6, brotli quality 4 with the body size as hint; one-shot, so `content-length`.
//! The encoding and headers match Node's; the compressed bytes need not (another encoder).
use axum::{
    body::Bytes,
    http::{HeaderMap, HeaderValue, Response, header},
};
use std::io::Write;

const MIN_SIZE: usize = 1024;

/// Node's `req.headers["accept-encoding"]`: repeated headers joined with `, `.
pub fn accept_encoding(h: &HeaderMap) -> Option<String> {
    let all: Vec<_> = h.get_all(header::ACCEPT_ENCODING).iter().collect();
    if all.is_empty() {
        return None;
    }
    // A non-ASCII value fails Effect's member regex, which disables compression: same as "".
    let parts: Option<Vec<&str>> = all.iter().map(|v| v.to_str().ok()).collect();
    Some(parts.map_or(String::new(), |p| p.join(", ")))
}

/// `negotiate(header, ["br", "gzip", "deflate"], node's zlib algorithms)`.
pub fn negotiate(accept: Option<&str>) -> Option<&'static str> {
    let accepted = parse_accept_encoding(accept?)?;
    let q = |name: &str| {
        accepted
            .iter()
            .rev()
            .find(|(n, _)| n == name)
            .map(|(_, q)| *q)
    };
    ["br", "gzip", "deflate"]
        .into_iter()
        .find(|a| q(a).or_else(|| q("*")) == Some(true))
}

/// `parseAcceptEncoding`: (coding, q > 0) per member; `None` if any member is malformed.
fn parse_accept_encoding(h: &str) -> Option<Vec<(String, bool)>> {
    let ows = |c: char| c == ' ' || c == '\t';
    let h = h.trim_matches(ows);
    if h.is_empty() {
        return None;
    }
    let token = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&b))
    };
    let mut out = Vec::new();
    for part in h.split(',') {
        // `.trim().toLowerCase().replace(/[ \t]*;[ \t]*/g, ";")`
        let m = part.trim_matches(ows).to_ascii_lowercase();
        let m: Vec<&str> = m.split(';').map(|p| p.trim_matches(ows)).collect();
        let positive = match m[..] {
            [name] if token(name) => true,
            [name, q] if token(name) => match q.strip_prefix("q=")? {
                q if q == "0" || q.starts_with("0.") => {
                    let f = &q[q.len().min(2)..];
                    if f.len() > 3 || !f.bytes().all(|b| b.is_ascii_digit()) {
                        return None;
                    }
                    f.bytes().any(|b| b != b'0')
                }
                q if q == "1" || q.starts_with("1.") => {
                    let f = &q[q.len().min(2)..];
                    if f.len() > 3 || !f.bytes().all(|b| b == b'0') {
                        return None;
                    }
                    true
                }
                _ => return None,
            },
            _ => return None,
        };
        out.push((m[0].to_owned(), positive));
    }
    Some(out)
}

/// `varyWith(headers, "Accept-Encoding")`.
fn vary_with(h: &HeaderMap) -> HeaderValue {
    let vary: Vec<&str> = h
        .get_all(header::VARY)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect();
    if vary.is_empty() {
        return HeaderValue::from_static("Accept-Encoding");
    }
    let vary = vary.join(", ");
    let has = vary
        .split(',')
        .map(|m| m.trim().to_ascii_lowercase())
        .any(|m| m == "*" || m == "accept-encoding");
    let v = if has {
        vary
    } else {
        format!("{vary}, Accept-Encoding")
    };
    HeaderValue::from_str(&v).expect("valid vary")
}

/// `defaultCompressible`.
fn compressible(ct: &str) -> bool {
    let t = ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    t.starts_with("text/")
        || matches!(
            t.as_str(),
            "application/json"
                | "application/javascript"
                | "application/xml"
                | "image/svg+xml"
                | "application/wasm"
        )
        || t.ends_with("+json")
        || t.ends_with("+xml")
}

/// `r` as Node would send it to a client that sent `accept` (see `accept_encoding`).
pub fn compress(accept: Option<&str>, mut r: Response<Bytes>) -> Response<Bytes> {
    let s = r.status().as_u16();
    if s < 200 || matches!(s, 204 | 206 | 304) {
        return r;
    }
    let h = r.headers_mut();
    if let Some(enc) = h.get(header::CONTENT_ENCODING) {
        if enc
            .to_str()
            .is_ok_and(|e| e.trim().eq_ignore_ascii_case("identity"))
        {
            h.remove(header::CONTENT_ENCODING);
        }
        return r;
    }
    // An empty body is Effect's `Empty` (Rust handlers never send an empty `Uint8Array`).
    // `/(?:^|[\s,])no-transform(?:$|[\s,;])/i`
    let no_transform = h.get_all(header::CACHE_CONTROL).iter().any(|v| {
        let v = v.as_bytes().to_ascii_lowercase();
        let sep = |b: u8, end: &[u8]| b.is_ascii_whitespace() || end.contains(&b);
        v.windows(12).enumerate().any(|(i, w)| {
            w == b"no-transform"
                && (i == 0 || sep(v[i - 1], b","))
                && v.get(i + 12).is_none_or(|&b| sep(b, b",;"))
        })
    });
    let ct = h.get(header::CONTENT_TYPE).and_then(|v| v.to_str().ok());
    let eligible = !no_transform && ct.is_some_and(compressible);
    if r.body().is_empty() || !eligible {
        return r;
    }
    let vary = vary_with(r.headers());
    r.headers_mut().insert(header::VARY, vary);
    let Some(alg) = negotiate(accept) else {
        return r;
    };
    if r.body().len() < MIN_SIZE {
        return r;
    }
    let body = encode(alg, r.body());
    let h = r.headers_mut();
    h.insert(header::CONTENT_ENCODING, HeaderValue::from_static(alg));
    h.insert(header::CONTENT_LENGTH, HeaderValue::from(body.len()));
    if let Some(etag) = h.get(header::ETAG).and_then(|e| e.to_str().ok())
        && !etag.starts_with("W/")
    {
        let weak = HeaderValue::from_str(&format!("W/{etag}")).expect("valid etag");
        h.insert(header::ETAG, weak);
    }
    *r.body_mut() = body.into();
    r
}

/// Node's `zlib.gzip` / `deflate` (level 6) and `brotliCompress` (quality 4, size hint).
fn encode(alg: &str, data: &[u8]) -> Vec<u8> {
    let level = flate2::Compression::new(6);
    match alg {
        "gzip" => {
            let mut e = flate2::write::GzEncoder::new(Vec::new(), level);
            e.write_all(data).expect("in memory");
            e.finish().expect("in memory")
        }
        "deflate" => {
            let mut e = flate2::write::ZlibEncoder::new(Vec::new(), level);
            e.write_all(data).expect("in memory");
            e.finish().expect("in memory")
        }
        _ => {
            let params = brotli::enc::BrotliEncoderParams {
                quality: 4,
                lgwin: 22,
                size_hint: data.len(),
                ..Default::default()
            };
            let mut out = Vec::new();
            brotli::BrotliCompress(&mut &data[..], &mut out, &params).expect("in memory");
            out
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn negotiation_follows_effect() {
        let n = |h: Option<&str>| negotiate(h);
        let cases: [(Option<&str>, Option<&str>); 22] = [
            (None, None),
            (Some(""), None),
            (Some("  "), None),
            (Some("gzip"), Some("gzip")),
            (Some("br"), Some("br")),
            (Some("deflate"), Some("deflate")),
            (Some("gzip, br"), Some("br")),
            (Some("gzip, deflate, br, zstd"), Some("br")),
            (Some("br;q=0, gzip"), Some("gzip")),
            (Some("gzip;q=0.5, deflate;q=0.9"), Some("gzip")),
            (Some("identity"), None),
            (Some("*"), Some("br")),
            (Some("*;q=0"), None),
            (Some("br;q=0, *"), Some("gzip")),
            (Some("GZIP"), Some("gzip")),
            (Some("gzip;q=0.000"), None),
            (Some("gzip;Q=0.001"), Some("gzip")),
            (Some("gzip ; q=1.000"), Some("gzip")),
            (Some("gzip;q=1.5, br"), None),
            (Some("gzip;level=1, br"), None),
            (Some("gzip, gzip;q=0"), None),
            (Some("x-gzip, g zip"), None),
        ];
        for (h, want) in cases {
            assert_eq!(n(h), want, "{h:?}");
        }
        assert_eq!(n(Some("gzip;q=0.")), None);
        assert_eq!(n(Some("gzip;q=1.")), Some("gzip"));
        assert_eq!(n(Some("gzip;q=0.0001")), None, "malformed");
        assert_eq!(n(Some("gzip;q=")), None);
        assert_eq!(n(Some("gzip,")), None, "empty member");
    }

    fn json(len: usize, extra: &[(&str, &str)]) -> Response<Bytes> {
        let mut b = Response::builder().header("content-type", "application/json");
        for (k, v) in extra {
            b = b.header(*k, *v);
        }
        let body = format!("[\"{}\"]", "x".repeat(len - 4));
        b.body(Bytes::from(body)).unwrap()
    }

    fn decode(enc: &str, b: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        match enc {
            "gzip" => flate2::read::GzDecoder::new(b).read_to_end(&mut out),
            "deflate" => flate2::read::ZlibDecoder::new(b).read_to_end(&mut out),
            _ => brotli::Decompressor::new(b, 4096).read_to_end(&mut out),
        }
        .unwrap();
        out
    }

    #[test]
    fn compresses_from_the_threshold_with_nodes_headers() {
        for alg in ["br", "gzip", "deflate"] {
            let small = compress(Some(alg), json(1023, &[]));
            assert_eq!(small.headers().get("content-encoding"), None);
            assert_eq!(small.headers()["vary"], "Accept-Encoding");
            assert_eq!(small.body().len(), 1023);
            let plain = json(1024, &[]);
            let big = compress(Some(alg), plain.clone());
            assert_eq!(big.headers()["content-encoding"], alg);
            assert_eq!(big.headers()["vary"], "Accept-Encoding");
            assert_eq!(
                big.headers()["content-length"],
                big.body().len().to_string()
            );
            assert!(big.body().len() < 1024);
            assert_eq!(decode(alg, big.body()), plain.body()[..]);
        }
        // Not accepted: identity, but Vary still says it depends on Accept-Encoding.
        let none = compress(None, json(4096, &[]));
        assert_eq!(none.headers().get("content-encoding"), None);
        assert_eq!(none.headers()["vary"], "Accept-Encoding");
    }

    #[test]
    fn skips_what_effect_skips() {
        let unchanged = |r: Response<Bytes>| {
            let (h, len) = (r.headers().clone(), r.body().len());
            let out = compress(Some("gzip"), r);
            assert_eq!((out.headers(), out.body().len()), (&h, len));
        };
        unchanged(json(2048, &[("cache-control", "private, no-transform")]));
        unchanged(json(2048, &[("content-encoding", "br")]));
        let mut r = json(2048, &[]);
        r.headers_mut().remove("content-type");
        unchanged(r);
        let mut r = json(2048, &[]);
        r.headers_mut()
            .insert("content-type", HeaderValue::from_static("image/png"));
        unchanged(r);
        let mut r = json(2048, &[]);
        *r.status_mut() = axum::http::StatusCode::NO_CONTENT;
        unchanged(r);
        unchanged(
            Response::builder()
                .header("content-type", "application/json")
                .body(Bytes::new())
                .unwrap(),
        );
        // `identity` opts out and is stripped.
        let id = compress(
            Some("gzip"),
            json(2048, &[("content-encoding", "Identity ")]),
        );
        assert_eq!(id.headers().get("content-encoding"), None);
        assert_eq!(id.body().len(), 2048);
        // `no-transform` only as a whole directive.
        let x = compress(
            Some("gzip"),
            json(2048, &[("cache-control", "no-transformx")]),
        );
        assert_eq!(x.headers()["content-encoding"], "gzip");
        let y = compress(
            Some("gzip"),
            json(2048, &[("cache-control", "x;no-transform")]),
        );
        assert_eq!(y.headers()["content-encoding"], "gzip");
        unchanged(json(2048, &[("cache-control", "No-Transform;x")]));
    }

    #[test]
    fn vary_and_etag_like_effect() {
        let r = compress(
            Some("gzip"),
            json(2048, &[("vary", "Origin"), ("etag", "\"abc\"")]),
        );
        assert_eq!(r.headers()["vary"], "Origin, Accept-Encoding");
        assert_eq!(r.headers()["etag"], "W/\"abc\"");
        let r = compress(
            Some("gzip"),
            json(2048, &[("vary", "*"), ("etag", "W/\"abc\"")]),
        );
        assert_eq!(r.headers()["vary"], "*");
        assert_eq!(r.headers()["etag"], "W/\"abc\"");
        let r = compress(Some("gzip"), json(10, &[("vary", "accept-encoding")]));
        assert_eq!(r.headers()["vary"], "accept-encoding");
        assert!(compressible("Text/Plain; charset=utf-8"));
        assert!(compressible("application/problem+json"));
        assert!(!compressible("application/octet-stream"));
    }

    #[test]
    fn accept_encoding_joins_repeats_like_node() {
        let mut h = HeaderMap::new();
        assert_eq!(accept_encoding(&h), None);
        h.append("accept-encoding", HeaderValue::from_static("br;q=0"));
        h.append("accept-encoding", HeaderValue::from_static("gzip"));
        assert_eq!(accept_encoding(&h).as_deref(), Some("br;q=0, gzip"));
        h.append("accept-encoding", HeaderValue::from_bytes(b"\xe9").unwrap());
        assert_eq!(negotiate(accept_encoding(&h).as_deref()), None);
    }
}
