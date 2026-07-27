use crate::explanation::{ExplanationError, ExplanationReport};

/// Renders stable pretty JSON.
///
/// # Errors
///
/// Returns a typed serialization error.
pub fn render_json(report: &ExplanationReport) -> Result<String, ExplanationError> {
    serde_json::to_string_pretty(report)
        .map_err(|error| ExplanationError::Encoding(error.to_string()))
}
