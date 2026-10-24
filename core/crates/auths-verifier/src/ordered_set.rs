//! Ordered-vector sets used by the extractable verifier graph.
//!
//! Inputs are bounded by the verifier's object/participant limits. The search
//! uses a shrinking interval and overflow-safe midpoint; insertion preserves
//! strict order and keeps each value once. No tree traversal or runtime
//! comparison callback is part of the verifier's set representation.

use alloc::vec::Vec;
use core::cmp::Ordering;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OrderedSet<T> {
    values: Vec<T>,
}

fn lower_bound<T: Ord>(values: &[T], target: &T) -> usize {
    let mut lower = 0;
    let mut upper = values.len();
    while lower < upper {
        let middle = lower + (upper - lower) / 2;
        match values[middle].cmp(target) {
            Ordering::Less => lower = middle + 1,
            Ordering::Equal | Ordering::Greater => upper = middle,
        }
    }
    lower
}

impl<T: Ord> OrderedSet<T> {
    pub(crate) const fn new() -> Self {
        Self { values: Vec::new() }
    }

    #[cfg(test)]
    pub(crate) fn from_vec(mut input: Vec<T>) -> Self {
        let mut output = Self::new();
        while let Some(value) = input.pop() {
            output.insert(value);
        }
        output
    }

    pub(crate) const fn len(&self) -> usize {
        self.values.len()
    }

    pub(crate) fn contains(&self, value: &T) -> bool {
        let position = lower_bound(&self.values, value);
        position < self.values.len() && self.values[position].cmp(value) == Ordering::Equal
    }

    /// Returns whether the set gained a distinct value.
    pub(crate) fn insert(&mut self, value: T) -> bool {
        let position = lower_bound(&self.values, &value);
        if position < self.values.len() && self.values[position].cmp(&value) == Ordering::Equal {
            false
        } else {
            self.values.insert(position, value);
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{collections::BTreeSet, string::String, vec};

    #[test]
    fn every_small_input_and_insertion_prefix_matches_the_tree_oracle() {
        for length in 0..=7u32 {
            for mut code in 0..4usize.pow(length) {
                let mut actual = OrderedSet::new();
                let mut expected = BTreeSet::new();
                let mut input = Vec::new();
                for _ in 0..length {
                    let value = code % 4;
                    code /= 4;
                    input.push(value);
                    assert_eq!(actual.insert(value), expected.insert(value));
                    assert_eq!(actual.len(), expected.len());
                    assert_eq!(actual.values, expected.iter().copied().collect::<Vec<_>>());
                    for probe in 0..=4 {
                        assert_eq!(actual.contains(&probe), expected.contains(&probe));
                    }
                }
                assert_eq!(OrderedSet::from_vec(input), actual);
            }
        }
    }

    #[test]
    fn text_and_extreme_scalar_values_keep_exact_order_and_membership() {
        let text = vec![String::from("é"), String::from("a"), String::from(""),
            String::from("a"), String::from("😀"), String::from("中")];
        let expected: BTreeSet<_> = text.iter().cloned().collect();
        let actual = OrderedSet::from_vec(text);
        assert_eq!(actual.values, expected.into_iter().collect::<Vec<_>>());
        let values = vec![u64::MAX, 0, 1, u64::MAX - 1, 0, u64::MAX];
        let actual = OrderedSet::from_vec(values.clone());
        let expected: BTreeSet<_> = values.into_iter().collect();
        assert_eq!(actual.values, expected.into_iter().collect::<Vec<_>>());
    }
}
