//! Concrete bounded scans used by the status-snapshot constructors.
//!
//! Snapshot order intentionally uses a partial statement key. Equal full
//! statements can therefore be separated by distinct statements with that key;
//! adjacent equality alone cannot establish global statement uniqueness.

use crate::{SignedGrantStatus, SignedPrincipalStatus, Timestamp};
use alloc::vec::Vec;
use core::cmp::Ordering;

pub(crate) fn principal_equal(left: &SignedPrincipalStatus, right: &SignedPrincipalStatus) -> bool {
    left.statement() == right.statement()
}

pub(crate) fn grant_equal(left: &SignedGrantStatus, right: &SignedGrantStatus) -> bool {
    left.statement() == right.statement()
}

pub(crate) fn principal_order(
    left: &SignedPrincipalStatus,
    right: &SignedPrincipalStatus,
) -> Ordering {
    let left = left.statement();
    let right = right.statement();
    let principal = left.principal().cmp(right.principal());
    if principal != Ordering::Equal {
        return principal;
    }
    let method = left.method().cmp(right.method());
    if method != Ordering::Equal {
        return method;
    }
    let sequence = left.sequence().cmp(&right.sequence());
    if sequence != Ordering::Equal {
        return sequence;
    }
    left.issuer().cmp(right.issuer())
}

pub(crate) fn grant_order(left: &SignedGrantStatus, right: &SignedGrantStatus) -> Ordering {
    let left = left.statement();
    let right = right.statement();
    let grant = left.grant_id().cmp(&right.grant_id());
    if grant != Ordering::Equal {
        return grant;
    }
    let method = left.method().cmp(right.method());
    if method != Ordering::Equal {
        return method;
    }
    let sequence = left.sequence().cmp(&right.sequence());
    if sequence != Ordering::Equal {
        return sequence;
    }
    left.issuer().cmp(right.issuer())
}

// These consuming boundaries expose the complete stable-sort result to the
// constructor proofs. They neither validate nor discard signed statements.
pub(crate) fn sort_principal(
    mut statements: Vec<SignedPrincipalStatus>,
) -> Vec<SignedPrincipalStatus> {
    statements.sort_by(principal_order);
    statements
}

pub(crate) fn sort_grant(mut statements: Vec<SignedGrantStatus>) -> Vec<SignedGrantStatus> {
    statements.sort_by(grant_order);
    statements
}

macro_rules! statement_scans {
    ($prefix:ident, $duplicate:ident, $covers:ident, $kind:ty, $equal:ident) => {
        fn $prefix(values: &[$kind], current: usize) -> bool {
            if current >= values.len() {
                return false;
            }
            let mut previous = 0;
            let mut duplicate = false;
            while previous < current && !duplicate {
                duplicate = $equal(&values[previous], &values[current]);
                previous += 1;
            }
            duplicate
        }

        pub(crate) fn $duplicate(values: &[$kind]) -> bool {
            let mut current = 0;
            let mut duplicate = false;
            while current < values.len() && !duplicate {
                duplicate = $prefix(values, current);
                current += 1;
            }
            duplicate
        }

        pub(crate) fn $covers(
            values: &[$kind],
            observed_at: Timestamp,
            valid_until: Timestamp,
        ) -> bool {
            let mut current = 0;
            let mut covers = true;
            while current < values.len() && covers {
                let statement = values[current].statement();
                covers = statement.observed_at() <= observed_at
                    && valid_until <= statement.valid_until();
                current += 1;
            }
            covers
        }
    };
}

statement_scans!(
    principal_matches_before,
    principal_has_duplicate,
    principal_windows_cover,
    SignedPrincipalStatus,
    principal_equal
);
statement_scans!(
    grant_matches_before,
    grant_has_duplicate,
    grant_windows_cover,
    SignedGrantStatus,
    grant_equal
);
