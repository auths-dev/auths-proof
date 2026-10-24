//! Source fixtures for the universal FnOnce Output projection. Construction
//! and all final source/ABI/body assertions remain separate evidence gates.
pub struct Reader<'de>(pub &'de [u8]);

fn as_bytes<'de, 's, 'f>(_: &'s Reader<'de>, bytes: &'f [u8]) -> &'f [u8] {
    bytes
}

fn apply<'de, 's, F>(reader: &'s Reader<'de>, bytes: &[u8], callback: F) -> usize
where
    F: for<'f> FnOnce(&'s Reader<'de>, &'f [u8]) -> &'f [u8],
{
    callback(reader, bytes).len()
}

pub fn function_item(reader: &Reader<'_>, bytes: &[u8]) -> usize {
    apply(reader, bytes, as_bytes)
}

pub fn captured_closure(reader: &Reader<'_>, bytes: &[u8]) -> usize {
    let captured = reader.0.len();
    apply(reader, bytes, move |reader, bytes| {
        if captured == 0 {
            bytes
        } else {
            as_bytes(reader, bytes)
        }
    })
}
