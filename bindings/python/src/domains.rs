use auths_profile_api::ActionProfile;
use auths_profile_domains::{EdgeAction, EdgeProfile, reference_canonicalize_edge};
use pyo3::{exceptions::PyValueError, prelude::*, types::PyBytes};

#[pyclass(name = "DomainActionProjection", frozen, module = "auths._native")]
pub struct PyDomainActionProjection {
    media_type: String,
    body: Vec<u8>,
    capability: String,
    resource: String,
    budget: Option<(String, u64)>,
    review_title: String,
    review_fields: Vec<(String, String)>,
}

#[pymethods]
impl PyDomainActionProjection {
    #[getter]
    fn media_type(&self) -> &str {
        &self.media_type
    }

    #[getter]
    fn body<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.body)
    }

    #[getter]
    fn capability(&self) -> &str {
        &self.capability
    }

    #[getter]
    fn resource(&self) -> &str {
        &self.resource
    }

    #[getter]
    fn budget(&self) -> Option<(String, u64)> {
        self.budget.clone()
    }

    #[getter]
    fn review_title(&self) -> &str {
        &self.review_title
    }

    #[getter]
    fn review_fields(&self) -> Vec<(String, String)> {
        self.review_fields.clone()
    }
}

#[pyfunction]
fn canonicalize_edge_action_v1(
    fleet: String,
    device: String,
    command: String,
    sequence: u64,
    state_digest: Option<String>,
) -> PyResult<PyDomainActionProjection> {
    let input = serde_json::to_vec(&EdgeAction::new(
        fleet,
        device,
        command,
        sequence,
        state_digest,
    ))
    .map_err(value_error)?;
    project_edge(&input)
}

#[pyfunction]
fn parse_canonical_edge_action_v1(body: &[u8]) -> PyResult<PyDomainActionProjection> {
    let projection = project_edge(body)?;
    if projection.body != body {
        return Err(PyValueError::new_err("edge action is not canonical"));
    }
    Ok(projection)
}

fn project_edge(input: &[u8]) -> PyResult<PyDomainActionProjection> {
    let action = reference_canonicalize_edge(input).map_err(value_error)?;
    let review = EdgeProfile::default()
        .review_display(&action)
        .map_err(value_error)?;
    Ok(PyDomainActionProjection {
        media_type: action.media_type().as_str().to_owned(),
        body: action.body().to_vec(),
        capability: action.permission().capability().as_str().to_owned(),
        resource: action.permission().resource().as_str().to_owned(),
        budget: action
            .requested_budget()
            .map(|value| (value.algebra().as_str().to_owned(), value.value())),
        review_title: review.title().to_owned(),
        review_fields: review.fields().to_vec(),
    })
}

fn value_error(error: impl core::fmt::Display) -> PyErr {
    PyValueError::new_err(error.to_string())
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyDomainActionProjection>()?;
    module.add_function(wrap_pyfunction!(canonicalize_edge_action_v1, module)?)?;
    module.add_function(wrap_pyfunction!(parse_canonical_edge_action_v1, module)?)?;
    Ok(())
}
