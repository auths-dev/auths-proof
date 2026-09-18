//! Reusable owned containers with protocol cardinality bounds.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

/// Failure while constructing a bounded value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BoundError {
    /// The value is required to contain at least one item or byte.
    Empty,
    /// The configured maximum was exceeded.
    AboveMaximum,
    /// A canonical set contained the same value more than once.
    Duplicate,
}

impl fmt::Display for BoundError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Empty => "bounded value is empty",
            Self::AboveMaximum => "bounded value exceeds its maximum",
            Self::Duplicate => "bounded set contains a duplicate",
        })
    }
}

/// Canonically sorted, duplicate-free, non-empty set with a fixed maximum.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedSet<T: Ord, const MAX: usize>(Vec<T>);

impl<T: Ord, const MAX: usize> BoundedSet<T, MAX> {
    /// Sorts and validates one owned set.
    ///
    /// # Errors
    ///
    /// Returns [`BoundError::Empty`] for no items,
    /// [`BoundError::AboveMaximum`] before normalization when `MAX` is
    /// exceeded, and [`BoundError::Duplicate`] after canonical sorting.
    pub fn new(mut items: Vec<T>) -> Result<Self, BoundError> {
        if items.is_empty() {
            return Err(BoundError::Empty);
        }
        if items.len() > MAX {
            return Err(BoundError::AboveMaximum);
        }
        items.sort();
        if items.windows(2).any(|window| window[0] == window[1]) {
            return Err(BoundError::Duplicate);
        }
        Ok(Self(items))
    }

    /// Returns the canonical items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Returns the number of items.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the set is empty. Valid instances are always non-empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Reports whether the set contains an item.
    #[must_use]
    pub fn contains(&self, item: &T) -> bool {
        self.0.binary_search(item).is_ok()
    }

    /// Reports whether every item is present in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.0.iter().all(|item| other.contains(item))
    }

    /// Consumes the wrapper and returns its canonical items.
    #[must_use]
    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

/// Non-empty owned bytes with a fixed maximum.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Hash)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    /// Constructs bounded bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BoundError::Empty`] or [`BoundError::AboveMaximum`].
    pub fn new(bytes: Vec<u8>) -> Result<Self, BoundError> {
        if bytes.is_empty() {
            return Err(BoundError::Empty);
        }
        if bytes.len() > MAX {
            return Err(BoundError::AboveMaximum);
        }
        Ok(Self(bytes))
    }

    /// Returns the exact bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the byte count.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Reports whether the byte string is empty. Valid instances are non-empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Consumes the wrapper and returns its bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BoundError {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn set_sorts_and_rejects_duplicates_before_normalization() {
        assert_eq!(
            BoundedSet::<u8, 4>::new(vec![3, 1, 2]).unwrap().as_slice(),
            &[1, 2, 3]
        );
        assert_eq!(
            BoundedSet::<u8, 4>::new(vec![1, 2, 1]),
            Err(BoundError::Duplicate)
        );
        assert_eq!(
            BoundedSet::<u8, 2>::new(vec![1, 1, 1]),
            Err(BoundError::AboveMaximum)
        );
    }

    #[test]
    fn bytes_enforce_non_empty_maximum() {
        assert_eq!(BoundedBytes::<2>::new(vec![]), Err(BoundError::Empty));
        assert_eq!(
            BoundedBytes::<2>::new(vec![1, 2, 3]),
            Err(BoundError::AboveMaximum)
        );
        assert_eq!(
            BoundedBytes::<2>::new(vec![1, 2]).unwrap().as_slice(),
            &[1, 2]
        );
    }
}
