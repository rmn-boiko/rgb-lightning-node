//! Minimal JSON value, parser and serializer for the gateway wire format.
//!
//! Hand-written so the crate keeps its dependency set to `bitcoin`, `bip39`,
//! `uniffi` and `thiserror`: `serde_json` stays a dev-dependency (the plan's
//! dependency-creep guard asserts it never reaches the library graph).
//!
//! Everything parsed here comes from the network and is treated as hostile:
//! the parser never panics, bounds nesting depth, keeps numbers as their raw
//! token (so `as_u64` is an exact integer parse with no float round trip),
//! and reports every malformation as a plain error string. Serialization
//! matches `JSON.stringify` for the value shapes the TypeScript client emits
//! (integers, booleans, strings, arrays, objects; `undefined` fields are
//! simply not emitted).

use std::fmt::Write as _;

/// Maximum nesting depth accepted by the parser. The gateway's deepest
/// response (`wallet/balances`) nests four levels; anything past this bound
/// is a hostile or broken body, not a real document.
const MAX_DEPTH: usize = 32;

/// A JSON document. Objects preserve key order; lookups return the **last**
/// occurrence of a duplicated key, matching `JSON.parse`.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// Raw number token exactly as it appeared (`-12`, `1.5`, `1e3`).
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    /// Object field lookup (`None` for non-objects and missing keys).
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(fields) => fields.iter().rev().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// Exact non-negative integer. Fractions, exponents and negatives are
    /// `None`: every amount on the wire is an integer count of units.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(raw) => raw.parse::<u64>().ok(),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(fields) => Some(fields),
            _ => None,
        }
    }

    /// Unsigned integer literal.
    pub fn u64(value: u64) -> Json {
        Json::Number(value.to_string())
    }

    /// Serialize compactly, exactly as `JSON.stringify` would.
    pub fn to_json_string(&self) -> String {
        let mut out = String::new();
        self.write_to(&mut out);
        out
    }

    fn write_to(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Number(raw) => out.push_str(raw),
            Json::String(s) => write_string(s, out),
            Json::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_to(out);
                }
                out.push(']');
            }
            Json::Object(fields) => {
                out.push('{');
                for (i, (key, value)) in fields.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write_to(out);
                }
                out.push('}');
            }
        }
    }
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::String(s.to_owned())
    }
}

impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::String(s)
    }
}

impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}

impl From<u64> for Json {
    fn from(n: u64) -> Json {
        Json::u64(n)
    }
}

impl From<u32> for Json {
    fn from(n: u32) -> Json {
        Json::u64(u64::from(n))
    }
}

impl From<Vec<String>> for Json {
    fn from(items: Vec<String>) -> Json {
        Json::Array(items.into_iter().map(Json::String).collect())
    }
}

/// Builder for request bodies: `undefined` (unset optional) fields are left
/// out, exactly as `JSON.stringify` drops them.
#[derive(Debug, Default)]
pub struct ObjectBuilder {
    fields: Vec<(String, Json)>,
}

impl ObjectBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn field(mut self, key: &str, value: impl Into<Json>) -> Self {
        self.fields.push((key.to_owned(), value.into()));
        self
    }

    /// Emit the field only when the caller set it.
    pub fn optional<T: Into<Json>>(self, key: &str, value: Option<T>) -> Self {
        match value {
            Some(v) => self.field(key, v),
            None => self,
        }
    }

    pub fn build(self) -> Json {
        Json::Object(self.fields)
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                // `write!` into a String cannot fail.
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Parse a complete JSON document. Trailing non-whitespace is an error.
pub fn parse(text: &str) -> Result<Json, String> {
    let mut parser = Parser {
        bytes: text.as_bytes(),
        pos: 0,
    };
    parser.skip_ws();
    let value = parser.value(0)?;
    parser.skip_ws();
    if parser.pos != parser.bytes.len() {
        return Err(format!("trailing characters at offset {}", parser.pos));
    }
    Ok(value)
}

struct Parser<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn expect_literal(&mut self, literal: &str) -> Result<(), String> {
        let end = self.pos + literal.len();
        if self.bytes.get(self.pos..end) == Some(literal.as_bytes()) {
            self.pos = end;
            Ok(())
        } else {
            Err(format!("expected {literal} at offset {}", self.pos))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, String> {
        if depth > MAX_DEPTH {
            return Err(format!("nesting deeper than {MAX_DEPTH}"));
        }
        match self.peek() {
            None => Err("unexpected end of input".into()),
            Some(b'n') => self.expect_literal("null").map(|_| Json::Null),
            Some(b't') => self.expect_literal("true").map(|_| Json::Bool(true)),
            Some(b'f') => self.expect_literal("false").map(|_| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::String),
            Some(b'[') => self.array(depth),
            Some(b'{') => self.object(depth),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(other) => Err(format!(
                "unexpected byte 0x{other:02x} at offset {}",
                self.pos
            )),
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => self.digits(),
            _ => return Err(format!("malformed number at offset {start}")),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("malformed number at offset {start}"));
            }
            self.digits();
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(format!("malformed number at offset {start}"));
            }
            self.digits();
        }
        let raw = std::str::from_utf8(&self.bytes[start..self.pos])
            .map_err(|_| format!("malformed number at offset {start}"))?;
        Ok(Json::Number(raw.to_owned()))
    }

    fn digits(&mut self) {
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
    }

    fn hex4(&mut self) -> Result<u32, String> {
        let end = self.pos + 4;
        let slice = self
            .bytes
            .get(self.pos..end)
            .ok_or_else(|| "truncated \\u escape".to_string())?;
        // `from_str_radix` accepts a leading sign; JSON.parse does not.
        if !slice.iter().all(u8::is_ascii_hexdigit) {
            return Err("malformed \\u escape".to_string());
        }
        let text = std::str::from_utf8(slice).map_err(|_| "malformed \\u escape".to_string())?;
        let value =
            u32::from_str_radix(text, 16).map_err(|_| "malformed \\u escape".to_string())?;
        self.pos = end;
        Ok(value)
    }

    fn string(&mut self) -> Result<String, String> {
        // Opening quote.
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            let chunk = std::str::from_utf8(&self.bytes[start..self.pos])
                .map_err(|_| "invalid UTF-8 in string".to_string())?;
            out.push_str(chunk);
            match self.peek() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.pos += 1;
                    let escaped = self
                        .peek()
                        .ok_or_else(|| "unterminated escape".to_string())?;
                    self.pos += 1;
                    match escaped {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let mut code = self.hex4()?;
                            if (0xD800..0xDC00).contains(&code) {
                                // High surrogate: a low surrogate must follow.
                                self.expect_literal("\\u")
                                    .map_err(|_| "unpaired surrogate".to_string())?;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err("unpaired surrogate".into());
                                }
                                code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00);
                            }
                            let c = char::from_u32(code)
                                .ok_or_else(|| "invalid unicode escape".to_string())?;
                            out.push(c);
                        }
                        other => return Err(format!("invalid escape \\{}", other as char)),
                    }
                }
                Some(_) => return Err("control character in string".into()),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Json::Array(items));
        }
        loop {
            self.skip_ws();
            items.push(self.value(depth + 1)?);
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Json::Array(items));
                }
                _ => return Err(format!("expected , or ] at offset {}", self.pos)),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Result<Json, String> {
        self.pos += 1;
        let mut fields = Vec::new();
        self.skip_ws();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Json::Object(fields));
        }
        loop {
            self.skip_ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected object key at offset {}", self.pos));
            }
            let key = self.string()?;
            self.skip_ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected : at offset {}", self.pos));
            }
            self.pos += 1;
            self.skip_ws();
            let value = self.value(depth + 1)?;
            fields.push((key, value));
            self.skip_ws();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Json::Object(fields));
                }
                _ => return Err(format!("expected , or }} at offset {}", self.pos)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_the_shapes_the_gateway_uses() {
        let text = r#"{"a":[1,2,{"b":null}],"c":"x\"y\\z\n\u00e9\ud83d\ude00","d":true,"e":false,"f":-3,"g":1.5e2}"#;
        let parsed = parse(text).unwrap();
        assert_eq!(parsed.get("c").and_then(Json::as_str), Some("x\"y\\z\né😀"));
        assert_eq!(parsed.get("d").and_then(Json::as_bool), Some(true));
        assert_eq!(parsed.get("f").and_then(Json::as_u64), None);
        assert_eq!(parsed.get("g").and_then(Json::as_u64), None);
        let a = parsed.get("a").and_then(Json::as_array).unwrap();
        assert_eq!(a[0].as_u64(), Some(1));
        assert!(a[2].get("b").is_some_and(Json::is_null));
        // Serialization is compact and escapes like JSON.stringify.
        let again = parse(&parsed.to_json_string()).unwrap();
        assert_eq!(again, parsed);
        assert_eq!(
            Json::from("tab\t\u{1}").to_json_string(),
            "\"tab\\t\\u0001\""
        );
    }

    #[test]
    fn duplicate_keys_resolve_to_the_last_like_json_parse() {
        let parsed = parse(r#"{"k":1,"k":2}"#).unwrap();
        assert_eq!(parsed.get("k").and_then(Json::as_u64), Some(2));
    }

    #[test]
    fn malformed_documents_are_errors_not_panics() {
        for bad in [
            "",
            " ",
            "{",
            "}",
            "[1,]",
            "{\"a\":}",
            "{a:1}",
            "\"unterminated",
            "\"bad\\q\"",
            "\"\\ud83d\"",
            "\"\\ud83dx\"",
            "\"\\u12\"",
            "\"\\u+041\"",
            "\"\\u-041\"",
            "tru",
            "nul",
            "01",
            "-",
            "1.",
            "1e",
            "1 2",
            "\u{1}",
            "\"\u{1}\"",
            &"[".repeat(MAX_DEPTH + 2),
            &format!(
                "{}1{}",
                "[".repeat(MAX_DEPTH + 1),
                "]".repeat(MAX_DEPTH + 1)
            ),
        ] {
            assert!(parse(bad).is_err(), "{bad:?} should not parse");
        }
        // Depth exactly at the bound still parses.
        let ok = format!("{}1{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn builder_omits_unset_optionals() {
        let body = ObjectBuilder::new()
            .field("mode", "blind")
            .optional("assetId", None::<String>)
            .optional("amount", Some(5u64))
            .build();
        assert_eq!(body.to_json_string(), r#"{"mode":"blind","amount":5}"#);
    }

    #[test]
    fn as_u64_is_an_exact_integer_parse() {
        assert_eq!(
            Json::Number("18446744073709551615".into()).as_u64(),
            Some(u64::MAX)
        );
        assert_eq!(Json::Number("18446744073709551616".into()).as_u64(), None);
        assert_eq!(Json::Number("1e3".into()).as_u64(), None);
        assert_eq!(Json::String("5".into()).as_u64(), None);
    }
}
