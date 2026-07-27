//! WASM timing boundary for serialized benchmark inputs.

#![forbid(unsafe_code)]

/// Publication browser clock in nanoseconds.
#[cfg(target_arch = "wasm32")]
#[must_use]
pub fn monotonic_now_ns() -> f64 {
    web_sys::window()
        .and_then(|window| window.performance())
        .map_or(0.0, |performance| performance.now() * 1_000_000.0)
}

/// Identifies the runtime boundary in native workspace checks.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub const fn runtime_boundary() -> &'static str {
    "wasm32-only"
}

/// Validates that WASM receives the exact shared benchmark input schema.
///
/// # Errors
///
/// Returns a serialization error for malformed or empty input suites.
pub fn validate_inputs(bytes: &[u8]) -> Result<usize, String> {
    let inputs: Vec<auths_bench_model::BenchmarkInput> =
        serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if inputs.is_empty() {
        return Err("benchmark input suite is empty".to_owned());
    }
    Ok(inputs.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use auths_bench_model::{BenchmarkProfile, generate_suite};

    #[test]
    fn shared_benchmark_schema_round_trips_at_wasm_boundary() {
        let inputs = generate_suite(&BenchmarkProfile::developer()).unwrap();
        let bytes = serde_json::to_vec(&inputs).unwrap();
        assert_eq!(validate_inputs(&bytes), Ok(inputs.len()));
        assert!(validate_inputs(b"[]").is_err());
    }
}
