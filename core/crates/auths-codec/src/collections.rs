//! First-error, bounded collection loops for concrete protocol codecs.
//!
//! These macros expand to ordinary loops in each caller. Their reader/writer
//! expressions are source syntax, never function pointers or runtime callbacks.
//! Keeping `?` outside the loop gives extraction one explicit bounded traversal
//! and preserves the previous first-error result and cursor/output prefix.

macro_rules! read_items {
    ($count:expr, $read:expr) => {{
        let mut remaining = $count;
        let mut values = alloc::vec::Vec::with_capacity(remaining);
        let mut failure = None;
        while remaining > 0 && failure.is_none() {
            match $read {
                Ok(value) => values.push(value),
                Err(error) => failure = Some(error),
            }
            remaining -= 1;
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(values),
        }
    }};
}

macro_rules! write_items {
    ($items:expr, $item:pat => $write:expr) => {
        $crate::collections::write_items!($items, _position, $item => $write)
    };
    ($items:expr, $index:ident, $item:pat => $write:expr) => {{
        let values = $items;
        let mut position = 0;
        let mut failure = None;
        while position < values.len() && failure.is_none() {
            let $index = position;
            let $item = &values[position];
            if let Err(error) = $write {
                failure = Some(error);
            }
            position += 1;
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }};
}

macro_rules! try_fold_items {
    ($items:expr, $initial:expr, $state:ident, $index:ident, $item:pat => $step:expr) => {{
        let values = $items;
        let mut outcome = Ok($initial);
        let mut position = 0;
        while position < values.len() && outcome.is_ok() {
            let $index = position;
            let $item = &values[position];
            outcome = match outcome {
                Ok($state) => $step,
                Err(error) => Err(error),
            };
            position += 1;
        }
        outcome
    }};
}

macro_rules! borrowed_items {
    ($items:expr) => {{
        let values = $items;
        let mut output = alloc::vec::Vec::with_capacity(values.len());
        let mut position = 0;
        while position < values.len() {
            output.push(&values[position]);
            position += 1;
        }
        output
    }};
}

pub(crate) use borrowed_items;
pub(crate) use read_items;
pub(crate) use try_fold_items;
pub(crate) use write_items;
