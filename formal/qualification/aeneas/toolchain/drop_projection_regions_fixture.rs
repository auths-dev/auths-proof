//! Source regression for projected types in real and conditional destructor
//! pointers. The final compiler replay must retain both normal and unwind
//! paths and the observable destructor, rather than replacing drops by no-ops.

pub struct Error<'a> {
    pub message: &'a str,
}

pub trait Reader<'de> {
    type Error;
    fn next(&mut self) -> Result<String, Self::Error>;
}

pub struct BorrowedReader<'a> {
    pub message: &'a str,
    pub fail: bool,
}

impl<'de, 'a> Reader<'de> for BorrowedReader<'a> {
    type Error = Error<'a>;

    fn next(&mut self) -> Result<String, Self::Error> {
        if self.fail {
            Err(Error {
                message: self.message,
            })
        } else {
            Ok(String::from(self.message))
        }
    }
}

pub struct CountDrop<'a>(pub &'a mut usize);

impl Drop for CountDrop<'_> {
    fn drop(&mut self) {
        *self.0 += 1;
    }
}

pub fn consume<'de, R: Reader<'de>>(
    reader: &mut R,
    drops: &mut usize,
    keep: bool,
) -> Result<usize, R::Error> {
    let guard = CountDrop(drops);
    let pending = reader.next();
    let another = reader.next();
    if keep {
        let value = pending?;
        drop(another);
        drop(guard);
        Ok(value.len())
    } else {
        drop(pending);
        drop(another);
        drop(guard);
        Ok(0)
    }
}

pub fn borrowed<'a>(message: &'a str, drops: &mut usize, fail: bool) -> Result<usize, Error<'a>> {
    consume(&mut BorrowedReader { message, fail }, drops, true)
}
