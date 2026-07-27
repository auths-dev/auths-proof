//! Bounded diagnostics emitted from the principal-method execution boundary.

use crate::{ControlEvidence, PrincipalControlError};
use alloc::{vec, vec::Vec};
use auths_model::{AdapterConfigurationId, PrincipalMethodId};

/// Whether adapter diagnostic facts are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticMode {
    /// Execute normally and discard diagnostic facts.
    Discard,
    /// Retain bounded, non-secret facts.
    Collect,
}

/// Configuration-bound adapter fact.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlFact {
    method: PrincipalMethodId,
    configuration: AdapterConfigurationId,
    result: ControlFactResult,
}

impl ControlFact {
    /// Principal method that produced the fact.
    #[must_use]
    pub const fn method(&self) -> &PrincipalMethodId {
        &self.method
    }

    /// Exact immutable adapter configuration consulted.
    #[must_use]
    pub const fn configuration(&self) -> AdapterConfigurationId {
        self.configuration
    }

    /// Sanitized result of the adapter evaluation.
    #[must_use]
    pub const fn result(&self) -> ControlFactResult {
        self.result
    }
}

/// Sanitized adapter result class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlFactResult {
    /// Control was established.
    Satisfied,
    /// Available evidence contradicted control.
    Contradicted,
    /// Required historical or external state was unavailable.
    Unavailable,
}

/// Unified adapter result and diagnostic facts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlEvaluation {
    result: Result<ControlEvidence, PrincipalControlError>,
    diagnostics: Vec<ControlFact>,
}

impl ControlEvaluation {
    pub(crate) fn from_result(
        result: Result<ControlEvidence, PrincipalControlError>,
        mode: DiagnosticMode,
        method: PrincipalMethodId,
        configuration: AdapterConfigurationId,
    ) -> Self {
        let diagnostics = if mode == DiagnosticMode::Collect {
            let fact_result = match result {
                Ok(_) => ControlFactResult::Satisfied,
                Err(PrincipalControlError::HistoricalStateUnavailable) => {
                    ControlFactResult::Unavailable
                }
                Err(_) => ControlFactResult::Contradicted,
            };
            vec![ControlFact {
                method,
                configuration,
                result: fact_result,
            }]
        } else {
            Vec::new()
        };
        Self {
            result,
            diagnostics,
        }
    }

    /// Returns the adapter outcome.
    pub const fn result(&self) -> &Result<ControlEvidence, PrincipalControlError> {
        &self.result
    }

    /// Returns bounded non-secret diagnostic facts.
    #[must_use]
    pub fn diagnostics(&self) -> &[ControlFact] {
        &self.diagnostics
    }

    /// Consumes the evaluation and returns the ordinary adapter result.
    ///
    /// # Errors
    ///
    /// Returns the principal-control error produced by the adapter.
    pub fn into_result(self) -> Result<ControlEvidence, PrincipalControlError> {
        self.result
    }
}
