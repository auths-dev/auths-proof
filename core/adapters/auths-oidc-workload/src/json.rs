extern crate alloc;

use alloc::{string::String, vec::Vec};

use crate::ClaimError;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum JsonValue {
    String(String),
    Integer(u64),
    OneStringArray(String),
}

pub(crate) fn flat_object(input: &[u8]) -> Result<Vec<(String, JsonValue)>, ClaimError> {
    let mut parser = Parser { input, cursor: 0 };
    parser.ws();
    parser.byte(b'{')?;
    parser.ws();
    let mut members = Vec::new();
    if parser.peek() == Some(b'}') {
        parser.cursor += 1;
    } else {
        loop {
            parser.ws();
            let name = parser.string()?;
            if members.iter().any(|(prior, _)| prior == &name) {
                return Err(ClaimError::DuplicateMember);
            }
            parser.ws();
            parser.byte(b':')?;
            parser.ws();
            let value = match parser.peek().ok_or(ClaimError::Syntax)? {
                b'"' => JsonValue::String(parser.string()?),
                b'0'..=b'9' => JsonValue::Integer(parser.integer()?),
                b'[' => JsonValue::OneStringArray(parser.one_string_array()?),
                _ => return Err(ClaimError::UnsupportedType),
            };
            members.push((name, value));
            parser.ws();
            match parser.peek() {
                Some(b',') => parser.cursor += 1,
                Some(b'}') => {
                    parser.cursor += 1;
                    break;
                }
                _ => return Err(ClaimError::Syntax),
            }
        }
    }
    parser.ws();
    if parser.cursor != input.len() {
        return Err(ClaimError::Syntax);
    }
    Ok(members)
}

struct Parser<'a> {
    input: &'a [u8],
    cursor: usize,
}
impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.input.get(self.cursor).copied()
    }
    fn ws(&mut self) {
        while self
            .peek()
            .is_some_and(|b| matches!(b, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.cursor += 1;
        }
    }
    fn byte(&mut self, expected: u8) -> Result<(), ClaimError> {
        if self.peek() != Some(expected) {
            return Err(ClaimError::Syntax);
        }
        self.cursor += 1;
        Ok(())
    }
    fn integer(&mut self) -> Result<u64, ClaimError> {
        let start = self.cursor;
        while self.peek().is_some_and(|b| b.is_ascii_digit()) {
            self.cursor += 1;
        }
        let bytes = self
            .input
            .get(start..self.cursor)
            .ok_or(ClaimError::Syntax)?;
        if bytes.len() > 1 && bytes[0] == b'0' {
            return Err(ClaimError::Syntax);
        }
        let text = core::str::from_utf8(bytes).map_err(|_| ClaimError::Syntax)?;
        text.parse().map_err(|_| ClaimError::InvalidValue)
    }
    fn one_string_array(&mut self) -> Result<String, ClaimError> {
        self.byte(b'[')?;
        self.ws();
        let value = self.string()?;
        self.ws();
        self.byte(b']')?;
        Ok(value)
    }
    fn string(&mut self) -> Result<String, ClaimError> {
        self.byte(b'"')?;
        let mut output = String::new();
        loop {
            let byte = self.peek().ok_or(ClaimError::Syntax)?;
            self.cursor += 1;
            match byte {
                b'"' => return Ok(output),
                b'\\' => self.escape(&mut output)?,
                0x00..=0x1f => return Err(ClaimError::Syntax),
                0x20..=0x7f => output.push(char::from(byte)),
                _ => {
                    let start = self.cursor - 1;
                    let remaining = core::str::from_utf8(&self.input[start..])
                        .map_err(|_| ClaimError::Syntax)?;
                    let character = remaining.chars().next().ok_or(ClaimError::Syntax)?;
                    output.push(character);
                    self.cursor = start + character.len_utf8();
                }
            }
        }
    }
    fn escape(&mut self, output: &mut String) -> Result<(), ClaimError> {
        let escape = self.peek().ok_or(ClaimError::Syntax)?;
        self.cursor += 1;
        match escape {
            b'"' => output.push('"'),
            b'\\' => output.push('\\'),
            b'/' => output.push('/'),
            b'b' => output.push('\u{0008}'),
            b'f' => output.push('\u{000c}'),
            b'n' => output.push('\n'),
            b'r' => output.push('\r'),
            b't' => output.push('\t'),
            b'u' => {
                let first = self.hex4()?;
                let scalar = if (0xd800..=0xdbff).contains(&first) {
                    if self.input.get(self.cursor..self.cursor + 2) != Some(b"\\u") {
                        return Err(ClaimError::Syntax);
                    }
                    self.cursor += 2;
                    let second = self.hex4()?;
                    if !(0xdc00..=0xdfff).contains(&second) {
                        return Err(ClaimError::Syntax);
                    }
                    0x1_0000 + ((u32::from(first) - 0xd800) << 10) + (u32::from(second) - 0xdc00)
                } else if (0xdc00..=0xdfff).contains(&first) {
                    return Err(ClaimError::Syntax);
                } else {
                    u32::from(first)
                };
                output.push(char::from_u32(scalar).ok_or(ClaimError::Syntax)?);
            }
            _ => return Err(ClaimError::Syntax),
        }
        Ok(())
    }
    fn hex4(&mut self) -> Result<u16, ClaimError> {
        let bytes = self
            .input
            .get(self.cursor..self.cursor + 4)
            .ok_or(ClaimError::Syntax)?;
        self.cursor += 4;
        let mut value = 0_u16;
        for byte in bytes {
            value = value.checked_mul(16).ok_or(ClaimError::Syntax)? + u16::from(hex(*byte)?);
        }
        Ok(value)
    }
}

fn hex(byte: u8) -> Result<u8, ClaimError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ClaimError::Syntax),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_duplicates_nested_values_and_unpaired_surrogates() {
        assert_eq!(
            flat_object(br#"{"a":"x","a":"y"}"#),
            Err(ClaimError::DuplicateMember)
        );
        assert_eq!(
            flat_object(br#"{"a":{"b":1}}"#),
            Err(ClaimError::UnsupportedType)
        );
        assert_eq!(flat_object(br#"{"a":"\uD800"}"#), Err(ClaimError::Syntax));
        assert!(flat_object(br#"{"aud":["one"],"exp":7}"#).is_ok());
    }
}
