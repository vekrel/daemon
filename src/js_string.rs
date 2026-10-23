//! JavaScript string semantics that ported engine code depends on: UTF-16 code units (`length`,
//! `slice`, `indexOf`), ECMAScript `\s` and `String.prototype.trim`. A slice may split a
//! surrogate pair, as in JS; `JsString` carries such text into `effect_json` output.
use serde::{Serialize, Serializer};

/// The UTF-16 code units of `s` (JS `length` is their count).
pub fn units(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// ECMAScript WhiteSpace or LineTerminator: what `\s` and `trim()` match. Not `char::is_whitespace`
/// (which has U+0085 and lacks U+FEFF).
pub fn is_space(u: u16) -> bool {
    matches!(
        u,
        0x09..=0x0d
            | 0x20
            | 0xa0
            | 0x1680
            | 0x2000..=0x200a
            | 0x2028
            | 0x2029
            | 0x202f
            | 0x205f
            | 0x3000
            | 0xfeff
    )
}

/// `s.trim()`.
pub fn trim(s: &[u16]) -> &[u16] {
    let start = s.iter().position(|&u| !is_space(u)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&u| !is_space(u))
        .map_or(start, |i| i + 1);
    &s[start..end]
}

/// `s.replace(/\s+/g, " ")`.
pub fn collapse_space(s: &[u16]) -> Vec<u16> {
    let mut out = Vec::with_capacity(s.len());
    let mut in_run = false;
    for &u in s {
        let space = is_space(u);
        if !space {
            out.push(u);
        } else if !in_run {
            out.push(0x20);
        }
        in_run = space;
    }
    out
}

/// `s.slice(start, end)` on code units: negative indexes count from the end, both are clamped.
pub fn slice(s: &[u16], start: i64, end: i64) -> &[u16] {
    let len = s.len() as i64;
    let at = |i: i64| if i < 0 { (len + i).max(0) } else { i.min(len) } as usize;
    let (from, to) = (at(start), at(end));
    if from >= to { &[] } else { &s[from..to] }
}

/// `hay.indexOf(needle)` in code units; -1 when absent.
pub fn index_of(hay: &[u16], needle: &[u16]) -> i64 {
    if needle.is_empty() {
        return 0;
    }
    hay.windows(needle.len())
        .position(|w| w == needle)
        .map_or(-1, |i| i as i64)
}

/// A JS string (UTF-16, possibly with lone surrogates). Serializes as `JSON.stringify` would, so
/// only through `effect_json::to_vec` (a `serde_json::Value` cannot hold a lone surrogate).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JsString(pub Vec<u16>);

impl Serialize for JsString {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let raw = serde_json::value::RawValue::from_string(json_literal(&self.0))
            .map_err(serde::ser::Error::custom)?;
        raw.serialize(s)
    }
}

/// `JSON.stringify(s)` (well-formed: a lone surrogate is a lowercase `\udxxx` escape).
pub fn json_literal(s: &[u16]) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for r in char::decode_utf16(s.iter().copied()) {
        match r {
            Ok('"') => out.push_str("\\\""),
            Ok('\\') => out.push_str("\\\\"),
            Ok('\u{8}') => out.push_str("\\b"),
            Ok('\u{c}') => out.push_str("\\f"),
            Ok('\n') => out.push_str("\\n"),
            Ok('\r') => out.push_str("\\r"),
            Ok('\t') => out.push_str("\\t"),
            Ok(c) if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            Ok(c) => out.push(c),
            Err(e) => out.push_str(&format!("\\u{:04x}", e.unpaired_surrogate())),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn js(s: &[u16]) -> String {
        json_literal(s)
    }

    // Expected strings: `JSON.stringify(...)` of the same expression in Node 26.
    #[test]
    fn slice_counts_utf16_units_and_may_split_a_pair() {
        let s = units("a\u{1F600}b");
        assert_eq!(s.len(), 4);
        assert_eq!(js(slice(&s, 0, 2)), r#""a\ud83d""#);
        assert_eq!(js(slice(&s, 2, 4)), r#""\ude00b""#);
        assert_eq!(js(slice(&s, -2, 99)), r#""\ude00b""#);
        assert_eq!(js(slice(&s, 3, 1)), r#""""#);
        assert_eq!(js(slice(&s, 0, 4)), "\"a\u{1F600}b\"");
        assert_eq!(index_of(&s, &units("b")), 3);
        assert_eq!(index_of(&s, &units("c")), -1);
        assert_eq!(index_of(&s, &[]), 0);
    }

    #[test]
    fn trim_and_collapse_use_ecmascript_whitespace() {
        let t = units("\u{a0}\u{feff} x\u{2028}\u{2029}y \u{85}\u{180e}\t\n");
        assert_eq!(js(trim(&t)), "\"x\u{2028}\u{2029}y \u{85}\u{180e}\"");
        let c = units("a \u{a0}\u{2028} b\u{3000}\u{205f}c");
        assert_eq!(js(&collapse_space(&c)), r#""a b c""#);
        assert_eq!(js(&collapse_space(&units("  x  "))), r#"" x ""#);
        assert_eq!(js(trim(&units(" \t "))), r#""""#);
        // U+0085 is whitespace to Rust, not to JS.
        assert_eq!(js(trim(&units("x\u{85}"))), "\"x\u{85}\"");
        assert_eq!(js(&collapse_space(&units("a\u{85}b"))), "\"a\u{85}b\"");
    }

    #[test]
    fn literal_escapes_like_json_stringify() {
        let s = units("\u{0}\u{1f}\u{7f}\"\\/\u{8}\u{c}\n\r\t\u{2028} é");
        assert_eq!(
            js(&s),
            "\"\\u0000\\u001f\u{7f}\\\"\\\\/\\b\\f\\n\\r\\t\u{2028} é\""
        );
    }
}
