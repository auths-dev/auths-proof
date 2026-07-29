//! Stripe-local merchant-payment aggregate budget values.

use serde::{Deserialize, Serialize};

use super::{MerchantOperation, MerchantValidationError};
use crate::types::Currency;

const MAX_MERCHANT_WINDOW_SECONDS: u64 = 366 * 24 * 60 * 60;
const MAX_MONEY_MINOR: u64 = 99_999_999;

/// Explicit aggregate merchant-payment budget window.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum MerchantBudgetWindow {
    /// Fixed inclusive-start, exclusive-end window.
    Fixed {
        /// Window start.
        starts_at: u64,
        /// Window end.
        ends_at: u64,
    },
    /// Rolling whole-second window ending at evaluation time.
    Rolling {
        /// Window duration.
        duration_seconds: u64,
    },
}

impl MerchantBudgetWindow {
    pub(super) fn validate(&self) -> Result<(), MerchantValidationError> {
        match self {
            Self::Fixed { starts_at, ends_at }
                if *starts_at < *ends_at
                    && ends_at.saturating_sub(*starts_at) <= MAX_MERCHANT_WINDOW_SECONDS =>
            {
                Ok(())
            }
            Self::Rolling { duration_seconds }
                if (1..=MAX_MERCHANT_WINDOW_SECONDS).contains(duration_seconds) =>
            {
                Ok(())
            }
            _ => Err(MerchantValidationError::InvalidPolicy),
        }
    }

    /// Resolves the exact applicable window at trusted time.
    ///
    /// # Errors
    ///
    /// Rejects inactive fixed windows and checked timestamp overflow.
    pub fn identity(&self, now: u64) -> Result<MerchantWindowIdentity, MerchantValidationError> {
        self.validate()?;
        match self {
            Self::Fixed { starts_at, ends_at } if (*starts_at..*ends_at).contains(&now) => {
                Ok(MerchantWindowIdentity {
                    starts_at: *starts_at,
                    ends_at: *ends_at,
                    kind: "fixed".into(),
                })
            }
            Self::Fixed { .. } => Err(MerchantValidationError::InvalidPolicy),
            Self::Rolling { duration_seconds } => {
                let starts_at = now.saturating_sub(duration_seconds.saturating_sub(1));
                let ends_at = now
                    .checked_add(1)
                    .ok_or(MerchantValidationError::InvalidPolicy)?;
                Ok(MerchantWindowIdentity {
                    starts_at,
                    ends_at,
                    kind: "rolling".into(),
                })
            }
        }
    }
}

/// Exact resolved merchant-payment window identity.
#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantWindowIdentity {
    /// Inclusive start.
    pub starts_at: u64,
    /// Exclusive end.
    pub ends_at: u64,
    /// `fixed` or `rolling`.
    pub kind: String,
}

/// One operation- and currency-specific aggregate budget.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAggregateBudget {
    budget_id: String,
    operation: MerchantOperation,
    currency: Currency,
    limit_minor: u64,
    window: MerchantBudgetWindow,
}

impl MerchantAggregateBudget {
    /// Builds one explicit merchant-payment budget.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers, unsupported amounts, or invalid windows.
    pub fn new(
        budget_id: impl Into<String>,
        operation: MerchantOperation,
        currency: Currency,
        limit_minor: u64,
        window: MerchantBudgetWindow,
        now_for_validation: u64,
    ) -> Result<Self, MerchantValidationError> {
        let value = Self {
            budget_id: budget_id.into(),
            operation,
            currency,
            limit_minor,
            window,
        };
        value.validate(now_for_validation)?;
        Ok(value)
    }

    pub(super) fn validate(&self, now_for_validation: u64) -> Result<(), MerchantValidationError> {
        if !super::valid_local_id(&self.budget_id)
            || self.limit_minor == 0
            || self.limit_minor > MAX_MONEY_MINOR
            || self.window.identity(now_for_validation).is_err()
        {
            return Err(MerchantValidationError::InvalidPolicy);
        }
        Ok(())
    }

    /// Stable budget identifier.
    #[must_use]
    pub fn budget_id(&self) -> &str {
        &self.budget_id
    }

    /// Operation whose exposure is counted.
    #[must_use]
    pub const fn operation(&self) -> MerchantOperation {
        self.operation
    }

    /// Currency whose exposure is counted.
    #[must_use]
    pub const fn currency(&self) -> &Currency {
        &self.currency
    }

    /// Inclusive limit in minor units.
    #[must_use]
    pub const fn limit_minor(&self) -> u64 {
        self.limit_minor
    }

    /// Explicit fixed or rolling window.
    #[must_use]
    pub const fn window(&self) -> &MerchantBudgetWindow {
        &self.window
    }
}

/// One resolved operation-aware aggregate usage projection.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAggregateUsage {
    /// Stable budget identifier.
    pub budget_id: String,
    /// Operation is part of aggregate identity.
    pub operation: MerchantOperation,
    /// Currency is part of aggregate identity.
    pub currency: Currency,
    /// Exact resolved window.
    pub window: MerchantWindowIdentity,
    /// Provider-observed or committed amount.
    pub committed_minor: u64,
    /// Reserved but not yet sent amount.
    pub reserved_minor: u64,
    /// Capacity retained for ambiguous delivery.
    pub outcome_unknown_minor: u64,
    /// Active manual-authorization exposure.
    pub active_authorization_minor: u64,
}

/// Complete aggregate state used by a profile-specific evaluator.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantAggregateSnapshot {
    /// Sorted operation-aware budget usages.
    pub usages: Vec<MerchantAggregateUsage>,
}

/// Atomic reservation intent returned by a profile-specific evaluator.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MerchantReservationIntent {
    /// Stable budget identifier.
    pub budget_id: String,
    /// Operation is part of reservation identity.
    pub operation: MerchantOperation,
    /// Currency is part of reservation identity.
    pub currency: Currency,
    /// Exact resolved window.
    pub window: MerchantWindowIdentity,
    /// Configured limit.
    pub limit_minor: u64,
    /// Requested amount.
    pub amount_minor: u64,
    /// Available amount before reservation.
    pub available_before_minor: u64,
}
