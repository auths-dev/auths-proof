//! A source-fixed object lifetime is distinct from a borrowed input lifetime.
//! Final frontend assertions must preserve both rather than making every
//! erased/body lifetime static to satisfy a desired trait predicate.
use std::error::Error;
use std::fmt::{self, Display, Formatter};

pub fn owned_error(message: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, message)
}

pub fn owned_object(message: &str) -> Box<dyn Error + Send + Sync + 'static> {
    message.into()
}

pub fn owned_pair(first: &str, second: &str) -> (std::io::Error, std::io::Error) {
    (owned_error(first), owned_error(second))
}

#[derive(Debug)]
pub struct BorrowedError<'a>(pub &'a str);

impl Display for BorrowedError<'_> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for BorrowedError<'_> {}

pub fn borrowed_object<'a>(message: &'a str) -> Box<dyn Error + Send + Sync + 'a> {
    Box::new(BorrowedError(message))
}
