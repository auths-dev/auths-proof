//! The definite-length CBOR primitives used by the V1 codec.
//!
//! Object decoders still validate their schema and compare the final encoding
//! with the complete input. The primitive reader deliberately accepts wider
//! integer heads, as the previous tokenizer did: the enclosing canonical
//! comparison owns their stable `NonCanonical` result.

use alloc::vec::Vec;

/// A primitive failure; object codecs map it to their existing typed error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Error;

/// The wire categories inspected by the object decoder.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Type {
    U8,
    U16,
    U32,
    U64,
    Bytes,
    String,
    Null,
    Other,
}

/// One bounded CBOR head, without interpretation of its argument as a length.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Head {
    pub(crate) major: u8,
    pub(crate) argument: u64,
    pub(crate) next: usize,
}

/// Reads at most eight argument bytes. Each byte is checked before use.
fn read_tail(
    input: &[u8],
    mut position: usize,
    mut remaining: u8,
    mut value: u64,
) -> Result<(u64, usize), Error> {
    while remaining > 0 {
        let byte = match input.get(position) {
            Some(byte) => *byte,
            None => return Err(Error),
        };
        let shifted = match value.checked_mul(256) {
            Some(shifted) => shifted,
            None => return Err(Error),
        };
        value = match shifted.checked_add(u64::from(byte)) {
            Some(value) => value,
            None => return Err(Error),
        };
        position += 1;
        remaining -= 1;
    }
    Ok((value, position))
}

/// Decodes a definite CBOR head without allocating or reading a payload.
///
/// On success `next` is at most `input.len()` and is one to nine bytes after
/// `position`. Reserved and indefinite heads are rejected.
pub(crate) fn read_head(input: &[u8], position: usize) -> Result<Head, Error> {
    let first = match input.get(position) {
        Some(first) => *first,
        None => return Err(Error),
    };
    let additional = first % 32;
    let start = position + 1;
    let (argument, next) = match additional {
        0..=23 => (u64::from(additional), start),
        24 => read_tail(input, start, 1, 0)?,
        25 => read_tail(input, start, 2, 0)?,
        26 => read_tail(input, start, 4, 0)?,
        27 => read_tail(input, start, 8, 0)?,
        _ => return Err(Error),
    };
    Ok(Head {
        major: first / 32,
        argument,
        next,
    })
}

fn append_tail(mut output: Vec<u8>, value: u64, mut remaining: u8) -> Vec<u8> {
    while remaining > 0 {
        remaining -= 1;
        output.push((value >> (u32::from(remaining) * 8)) as u8);
    }
    output
}

/// Encodes the unique shortest head for one major type and unsigned argument.
pub(crate) fn encode_head(major: u8, argument: u64) -> Result<Vec<u8>, Error> {
    if major > 7 {
        return Err(Error);
    }
    let prefix = major * 32;
    let mut output = Vec::with_capacity(9);
    let width = if argument <= 23 {
        output.push(prefix + argument as u8);
        return Ok(output);
    } else if argument <= 255 {
        output.push(prefix + 24);
        1
    } else if argument <= 65_535 {
        output.push(prefix + 25);
        2
    } else if argument <= 4_294_967_295 {
        output.push(prefix + 26);
        4
    } else {
        output.push(prefix + 27);
        8
    };
    Ok(append_tail(output, argument, width))
}

/// Borrowed, allocation-free cursor into one bounded object input.
pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    pub(crate) const fn position(&self) -> usize {
        self.position
    }

    fn head(&mut self, major: u8) -> Result<u64, Error> {
        let head = read_head(self.input, self.position)?;
        if head.major != major {
            return Err(Error);
        }
        self.position = head.next;
        Ok(head.argument)
    }

    fn collection(&mut self, major: u8) -> Result<Option<u64>, Error> {
        if self.input.get(self.position) == Some(&((major << 5) | 31)) {
            self.position += 1;
            return Ok(None);
        }
        self.head(major).map(Some)
    }

    pub(crate) fn map(&mut self) -> Result<Option<u64>, Error> {
        self.collection(5)
    }

    pub(crate) fn array(&mut self) -> Result<Option<u64>, Error> {
        self.collection(4)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, Error> {
        self.head(0)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, Error> {
        self.u64()?.try_into().map_err(|_| Error)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, Error> {
        self.u64()?.try_into().map_err(|_| Error)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, Error> {
        self.u64()?.try_into().map_err(|_| Error)
    }

    fn payload(&mut self, major: u8) -> Result<&'a [u8], Error> {
        let length = usize::try_from(self.head(major)?).map_err(|_| Error)?;
        let end = self.position.checked_add(length).ok_or(Error)?;
        let bytes = self.input.get(self.position..end).ok_or(Error)?;
        self.position = end;
        Ok(bytes)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], Error> {
        self.payload(2)
    }

    pub(crate) fn str(&mut self) -> Result<&'a str, Error> {
        core::str::from_utf8(self.payload(3)?).map_err(|_| Error)
    }

    pub(crate) fn bool(&mut self) -> Result<bool, Error> {
        let value = match self.input.get(self.position) {
            Some(244) => false,
            Some(245) => true,
            _ => return Err(Error),
        };
        self.position += 1;
        Ok(value)
    }

    pub(crate) fn null(&mut self) -> Result<(), Error> {
        if self.input.get(self.position) != Some(&246) {
            return Err(Error);
        }
        self.position += 1;
        Ok(())
    }

    pub(crate) fn datatype(&self) -> Result<Type, Error> {
        let first = self.input.get(self.position).ok_or(Error)?;
        Ok(match *first {
            0..=24 => Type::U8,
            25 => Type::U16,
            26 => Type::U32,
            27 => Type::U64,
            64..=91 => Type::Bytes,
            96..=123 => Type::String,
            246 => Type::Null,
            _ => Type::Other,
        })
    }
}

/// The V1 encoder writes only shortest, definite heads into its owned buffer.
pub(crate) struct Encoder {
    output: Vec<u8>,
}

impl Encoder {
    pub(crate) const fn new(output: Vec<u8>) -> Self {
        Self { output }
    }

    pub(crate) fn into_writer(self) -> Vec<u8> {
        self.output
    }

    fn head(&mut self, major: u8, argument: u64) -> Result<&mut Self, Error> {
        self.output
            .extend_from_slice(&encode_head(major, argument)?);
        Ok(self)
    }

    pub(crate) fn map(&mut self, entries: u64) -> Result<&mut Self, Error> {
        self.head(5, entries)
    }

    pub(crate) fn array(&mut self, entries: u64) -> Result<&mut Self, Error> {
        self.head(4, entries)
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<&mut Self, Error> {
        self.head(0, value)
    }

    pub(crate) fn u32(&mut self, value: u32) -> Result<&mut Self, Error> {
        self.u64(u64::from(value))
    }

    pub(crate) fn u16(&mut self, value: u16) -> Result<&mut Self, Error> {
        self.u64(u64::from(value))
    }

    pub(crate) fn u8(&mut self, value: u8) -> Result<&mut Self, Error> {
        self.u64(u64::from(value))
    }

    fn payload(&mut self, major: u8, bytes: &[u8]) -> Result<&mut Self, Error> {
        self.head(major, u64::try_from(bytes.len()).map_err(|_| Error)?)?;
        self.output.extend_from_slice(bytes);
        Ok(self)
    }

    pub(crate) fn bytes(&mut self, bytes: &[u8]) -> Result<&mut Self, Error> {
        self.payload(2, bytes)
    }

    pub(crate) fn str(&mut self, text: &str) -> Result<&mut Self, Error> {
        self.payload(3, text.as_bytes())
    }

    pub(crate) fn bool(&mut self, value: bool) -> Result<&mut Self, Error> {
        self.output.push(if value { 245 } else { 244 });
        Ok(self)
    }

    pub(crate) fn null(&mut self) -> Result<&mut Self, Error> {
        self.output.push(246);
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, Encoder, encode_head, read_head};
    use alloc::{vec, vec::Vec};
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn every_head_round_trips(major in 0_u8..=7, argument: u64) {
            let bytes = encode_head(major, argument).unwrap();
            let head = read_head(&bytes, 0).unwrap();
            prop_assert_eq!(head.major, major);
            prop_assert_eq!(head.argument, argument);
            prop_assert_eq!(head.next, bytes.len());
            prop_assert!(bytes.len() <= 9);
            let mut oracle = minicbor::Encoder::new(Vec::new());
            if major == 0 {
                oracle.u64(argument).unwrap();
                prop_assert_eq!(&bytes, &oracle.into_writer());
            }
        }

        #[test]
        fn head_cursor_never_exceeds_input(input: Vec<u8>, position: usize) {
            if let Ok(head) = read_head(&input, position) {
                prop_assert!(position < head.next);
                prop_assert!(head.next <= input.len());
                prop_assert!(head.next - position <= 9);
            }
        }

        #[test]
        fn byte_payload_matches_previous_codec(bytes: Vec<u8>) {
            let mut encoder = Encoder::new(Vec::new());
            encoder.bytes(&bytes).unwrap();
            let wire = encoder.into_writer();
            let mut oracle = minicbor::Encoder::new(Vec::new());
            oracle.bytes(&bytes).unwrap();
            prop_assert_eq!(&wire, &oracle.into_writer());
            let mut decoder = Decoder::new(&wire);
            prop_assert_eq!(decoder.bytes().unwrap(), bytes.as_slice());
            prop_assert_eq!(decoder.position(), wire.len());
        }

        #[test]
        fn hostile_primitive_inputs_agree_with_previous_codec(input: Vec<u8>) {
            prop_assert_eq!(Decoder::new(&input).u64().ok(), minicbor::Decoder::new(&input).u64().ok());
            prop_assert_eq!(Decoder::new(&input).u32().ok(), minicbor::Decoder::new(&input).u32().ok());
            prop_assert_eq!(Decoder::new(&input).u16().ok(), minicbor::Decoder::new(&input).u16().ok());
            prop_assert_eq!(Decoder::new(&input).u8().ok(), minicbor::Decoder::new(&input).u8().ok());
            prop_assert_eq!(Decoder::new(&input).map().ok(), minicbor::Decoder::new(&input).map().ok());
            prop_assert_eq!(Decoder::new(&input).array().ok(), minicbor::Decoder::new(&input).array().ok());
            prop_assert_eq!(Decoder::new(&input).bytes().ok(), minicbor::Decoder::new(&input).bytes().ok());
            prop_assert_eq!(Decoder::new(&input).str().ok(), minicbor::Decoder::new(&input).str().ok());
            prop_assert_eq!(Decoder::new(&input).bool().ok(), minicbor::Decoder::new(&input).bool().ok());
            prop_assert_eq!(Decoder::new(&input).null().ok(), minicbor::Decoder::new(&input).null().ok());
        }
    }

    #[test]
    fn reserved_truncated_and_overflowing_inputs_fail() {
        for additional in 28..=31 {
            assert!(read_head(&[additional], 0).is_err());
        }
        for (first, width) in [(24, 1), (25, 2), (26, 4), (27, 8)] {
            for available in 0..width {
                let mut bytes = vec![first];
                bytes.resize(available + 1, 0);
                assert!(read_head(&bytes, 0).is_err());
            }
        }
        assert!(
            Decoder::new(&[0x5b, 255, 255, 255, 255, 255, 255, 255, 255])
                .bytes()
                .is_err()
        );
        assert!(read_head(&[0], usize::MAX).is_err());
    }

    #[test]
    fn primitive_reader_preserves_noncanonical_integer_detection_boundary() {
        let mut decoder = Decoder::new(&[0x18, 0]);
        assert_eq!(decoder.u8().unwrap(), 0);
        assert_eq!(decoder.position(), 2);
        assert_eq!(encode_head(0, 0).unwrap(), vec![0]);
    }

    #[test]
    fn text_and_simple_values_are_exact() {
        assert!(Decoder::new(&[0x61, 0xff]).str().is_err());
        assert!(Decoder::new(&[0xf8, 20]).bool().is_err());
        assert!(!Decoder::new(&[0xf4]).bool().unwrap());
        assert!(Decoder::new(&[0xf5]).bool().unwrap());
        assert!(Decoder::new(&[0xf6]).null().is_ok());
    }
}
