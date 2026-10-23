//! Node's session `Set-Cookie` values (`auth/http.ts:202-217`, `318-334`, serialized by Effect's
//! `Cookies.serializeCookie`) and its credential response headers.
use crate::handlers::auth_session::iso_millis;
use axum::http::{HeaderMap, HeaderValue, header};

/// `<name>=<token>; Path=/; Expires=<toUTCString>; HttpOnly; SameSite=Lax` (no Secure, no
/// Max-Age). `expires_ms`: epoch milliseconds.
pub fn session_cookie(name: &str, token: &str, expires_ms: i64) -> HeaderValue {
    let v = format!(
        "{name}={}; Path=/; Expires={}; HttpOnly; SameSite=Lax",
        encode_uri_component(token),
        utc_string(expires_ms)
    );
    HeaderValue::from_str(&v).expect("ASCII cookie")
}

/// `Cookies.expireCookie(name, {httpOnly, path: "/", sameSite: "lax"})`.
pub fn clear_cookie(name: &str) -> HeaderValue {
    let v = format!(
        "{name}=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
    );
    HeaderValue::from_str(&v).expect("ASCII cookie")
}

/// `CREDENTIAL_RESPONSE_HEADERS` (`auth/http.ts:41-44`).
pub fn no_store(h: &mut HeaderMap) {
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

/// `new Date(ms).toUTCString()` for years 0000-9999 (milliseconds dropped).
pub fn utc_string(ms: i64) -> String {
    const DAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    // "YYYY-MM-DDTHH:MM:SS.sssZ"
    let iso = iso_millis(ms);
    let month: usize = iso[5..7].parse().expect("month");
    format!(
        "{}, {} {} {} {} GMT",
        DAYS[ms.div_euclid(86_400_000).rem_euclid(7) as usize],
        &iso[8..10],
        MONTHS[month - 1],
        &iso[..4],
        &iso[11..19]
    )
}

/// JS `encodeURIComponent` (Effect encodes cookie values with it).
fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
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

    #[test]
    fn utc_string_matches_date_to_utc_string() {
        // Expected values from Node's `new Date(ms).toUTCString()`.
        assert_eq!(utc_string(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(
            utc_string(1_792_742_400_999),
            "Fri, 23 Oct 2026 08:00:00 GMT"
        );
        assert_eq!(utc_string(951_782_400_000), "Tue, 29 Feb 2000 00:00:00 GMT");
        assert_eq!(
            utc_string(1_893_456_000_123),
            "Tue, 01 Jan 2030 00:00:00 GMT"
        );
        assert_eq!(utc_string(-1), "Wed, 31 Dec 1969 23:59:59 GMT");
    }

    #[test]
    fn cookie_strings_match_effect_serializer() {
        let c = session_cookie(
            "t3_session_3789_fb52c29e3256",
            "eyJ2Ijox.c2ln-_",
            1_792_742_400_000,
        );
        assert_eq!(
            c,
            "t3_session_3789_fb52c29e3256=eyJ2Ijox.c2ln-_; Path=/; Expires=Fri, 23 Oct 2026 08:00:00 GMT; HttpOnly; SameSite=Lax"
        );
        // `encodeURIComponent("a b=;")`.
        assert!(
            session_cookie("n", "a b=;", 0)
                .to_str()
                .unwrap()
                .starts_with("n=a%20b%3D%3B; ")
        );
        assert_eq!(
            clear_cookie("t3_session_3789_fb52c29e3256"),
            "t3_session_3789_fb52c29e3256=; Max-Age=0; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax"
        );
    }

    #[test]
    fn no_store_sets_both_headers() {
        let mut h = HeaderMap::new();
        no_store(&mut h);
        assert_eq!(
            (&h["cache-control"], &h["pragma"]),
            (
                &"no-store".parse::<HeaderValue>().unwrap(),
                &"no-cache".parse::<HeaderValue>().unwrap()
            )
        );
        assert_eq!(h.len(), 2);
    }
}
