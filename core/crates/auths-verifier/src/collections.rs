//! Concrete first-error verification folds. Expressions expand in the caller;
//! no runtime callback or function pointer carries verification semantics.

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

pub(crate) use try_fold_items;
