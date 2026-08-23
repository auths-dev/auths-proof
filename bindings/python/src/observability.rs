use auths_production_client::project_sdk_event_v2;
use pyo3::prelude::*;

#[pyfunction]
fn project_sdk_event_json_v2(input: &str) -> PyResult<String> {
    project_sdk_event_v2(input).map_err(crate::errors::malformed_input)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(project_sdk_event_json_v2, module)?)?;
    Ok(())
}
