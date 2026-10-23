//! JSON bytes as the engine writes them: `JSON.stringify` of Effect's encoded value. Key order is
//! the serde field order (declare fields in schema order; `skip_serializing_if` for keys Effect
//! omits), numbers use JS `Number#toString`, strings JS escaping (`js_string::JsString` for text
//! with lone surrogates). `parse` is `JSON.parse` for JSON columns Effect decodes and re-encodes.
use serde::Serialize;
use serde_json::{Map, Value};
use std::io::{self, Write};

/// `JSON.stringify` bytes of `v`.
pub fn to_vec<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
    let mut out = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut out, Js);
    v.serialize(&mut ser).expect("serializable");
    out
}

/// Integers above 2^53 are doubles in JS: printed from the nearest one, as `JSON.parse` keeps them.
const SAFE: u64 = 1 << 53;

struct Js;

impl serde_json::ser::Formatter for Js {
    fn write_f64<W: ?Sized + Write>(&mut self, w: &mut W, v: f64) -> io::Result<()> {
        w.write_all(number(v).as_bytes())
    }
    fn write_f32<W: ?Sized + Write>(&mut self, w: &mut W, v: f32) -> io::Result<()> {
        w.write_all(number(v as f64).as_bytes())
    }
    fn write_u64<W: ?Sized + Write>(&mut self, w: &mut W, v: u64) -> io::Result<()> {
        match v > SAFE {
            true => w.write_all(number(v as f64).as_bytes()),
            false => write!(w, "{v}"),
        }
    }
    fn write_i64<W: ?Sized + Write>(&mut self, w: &mut W, v: i64) -> io::Result<()> {
        match v.unsigned_abs() > SAFE {
            true => w.write_all(number(v as f64).as_bytes()),
            false => write!(w, "{v}"),
        }
    }
}

/// `JSON.stringify(v)` for a finite number (ECMAScript `Number::toString`); `null` otherwise.
pub fn number(v: f64) -> String {
    if !v.is_finite() {
        return "null".into();
    }
    if v == 0.0 {
        return "0".into(); // -0 too
    }
    // Rust's `{:e}` prints the shortest digits that round-trip, as JS does.
    let e = format!("{:e}", v.abs());
    let (mantissa, exp) = e.split_once('e').expect("exponent");
    let digits = mantissa.replace('.', "");
    let (k, n) = (
        digits.len() as i32,
        exp.parse::<i32>().expect("exponent") + 1,
    );
    let sign = if v < 0.0 { "-" } else { "" };
    let body = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat((n - k) as usize))
    } else if 0 < n && n <= 21 {
        format!("{}.{}", &digits[..n as usize], &digits[n as usize..])
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat(-n as usize))
    } else {
        let (x, s) = (n - 1, if n - 1 < 0 { '-' } else { '+' });
        match &digits[1..] {
            "" => format!("{digits}e{s}{}", x.abs()),
            rest => format!("{}.{rest}e{s}{}", &digits[..1], x.abs()),
        }
    };
    format!("{sign}{body}")
}

/// `JSON.parse(text)` as JS holds it: duplicate keys keep the first position and the last value,
/// and array-index keys come first in ascending order (V8's property order). `None` where serde
/// rejects text JS accepts (lone surrogate escapes, nesting past 128): callers decline.
pub fn parse(text: &str) -> Option<Value> {
    let mut v = serde_json::from_str(text).ok()?;
    js_order(&mut v);
    Some(v)
}

fn js_order(v: &mut Value) {
    match v {
        Value::Array(a) => a.iter_mut().for_each(js_order),
        Value::Object(m) => {
            if m.keys().any(|k| array_index(k).is_some()) {
                let mut entries: Vec<_> = std::mem::take(m).into_iter().collect();
                // Stable: non-index keys keep insertion order after the indexes.
                entries.sort_by_key(|(k, _)| array_index(k).map_or((1, 0), |i| (0, i)));
                *m = entries.into_iter().collect::<Map<_, _>>();
            }
            m.values_mut().for_each(js_order);
        }
        _ => {}
    }
}

/// A canonical array index: `0` or no leading zero, at most 2^32 - 2.
fn array_index(k: &str) -> Option<u64> {
    if k.is_empty() || k.len() > 10 || (k.len() > 1 && k.starts_with('0')) {
        return None;
    }
    let i: u64 = k
        .bytes()
        .all(|b| b.is_ascii_digit())
        .then(|| k.parse().ok())??;
    (i < u32::MAX as u64).then_some(i)
}

/// A `Schema.DateTimeUtc` text column as Effect re-encodes it (`toISOString`). Only canonical
/// `YYYY-MM-DDTHH:MM:SS.sssZ` passes.
/// shortcut: other forms `DateTime.make` accepts (no millis, offsets, no zone) give `None` (decline); port its parser if real rows hold them.
pub fn date(s: &str) -> Option<&str> {
    let ms = crate::http_seam::parse_iso(s)?;
    (crate::handlers::auth_session::iso_millis(ms) == s).then_some(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::js_string::{JsString, units};

    // Expected bytes: Node 26 `JSON.stringify` of the same values.
    #[test]
    fn numbers_print_like_js() {
        let cases: [(f64, &str); 15] = [
            (0.0, "0"),
            (-0.0, "0"),
            (1.0, "1"),
            (1.5, "1.5"),
            (-2.5e-7, "-2.5e-7"),
            (1e21, "1e+21"),
            (1e-7, "1e-7"),
            (123456789012345680000.0, "123456789012345680000"),
            (0.1 + 0.2, "0.30000000000000004"),
            (5e-324, "5e-324"),
            (f64::MAX, "1.7976931348623157e+308"),
            (100.0, "100"),
            (1e20, "100000000000000000000"),
            (123e-20, "1.23e-18"),
            (0.000001, "0.000001"),
        ];
        for (v, want) in cases {
            assert_eq!(String::from_utf8(to_vec(&v)).unwrap(), want, "{v:e}");
        }
        assert_eq!(to_vec(&f64::NAN), b"null");
        assert_eq!(to_vec(&12345678901234567890u64), b"12345678901234567000");
        assert_eq!(to_vec(&-9007199254740993i64), b"-9007199254740992");
        assert_eq!(to_vec(&9007199254740992u64), b"9007199254740992");
    }

    #[test]
    fn parse_then_write_is_json_parse_then_stringify() {
        let rt = |s: &str| String::from_utf8(to_vec(&parse(s).unwrap())).unwrap();
        assert_eq!(
            rt(r#"{"b":1,"10":2,"2":3,"a":4,"01":5,"4294967295":6,"4294967294":7,"-1":8,"b":9}"#),
            r#"{"2":3,"10":2,"4294967294":7,"b":9,"a":4,"01":5,"4294967295":6,"-1":8}"#
        );
        assert_eq!(
            rt("[1.0,-0.0,1e2,12345678901234567890,0.30000000000000004]"),
            "[1,0,100,12345678901234567000,0.30000000000000004]"
        );
        assert_eq!(
            rt(r#"{"x":{"1":" ","0":null}}"#),
            "{\"x\":{\"0\":null,\"1\":\"\u{2028}\"}}"
        );
        assert_eq!(parse(r#""\ud800""#), None, "lone surrogate escape: decline");
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct Shape<'a> {
        z_first: u8,
        #[serde(skip_serializing_if = "Option::is_none")]
        optional_key: Option<&'a str>,
        null_or: Option<&'a str>,
        snippet: JsString,
        raw: Value,
    }

    #[test]
    fn structs_keep_field_order_omit_absent_keys_and_carry_lone_surrogates() {
        let s = Shape {
            z_first: 1,
            optional_key: None,
            null_or: None,
            snippet: JsString(units("a\u{1F600}")[..2].to_vec()),
            raw: parse(r#"{"n":2.50}"#).unwrap(),
        };
        assert_eq!(
            String::from_utf8(to_vec(&s)).unwrap(),
            r#"{"zFirst":1,"nullOr":null,"snippet":"a\ud83d","raw":{"n":2.5}}"#
        );
    }

    #[test]
    fn dates_pass_only_in_to_iso_string_form() {
        assert_eq!(
            date("2026-10-23T08:00:00.000Z"),
            Some("2026-10-23T08:00:00.000Z")
        );
        for bad in [
            "2026-10-23T08:00:00Z",
            "2026-10-23T08:00:00.000+00:00",
            "2026-10-23 08:00:00.000Z",
            "2026-02-30T08:00:00.000Z",
            "2026-10-23T08:00:00.0000Z",
        ] {
            assert_eq!(date(bad), None, "{bad}");
        }
    }
}
