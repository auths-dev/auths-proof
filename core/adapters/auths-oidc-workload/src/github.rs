extern crate alloc;

use alloc::format;

use crate::{
    ClaimError, OidcError,
    identity::{GitRef, Repository, WorkflowPath, WorkflowRef},
};

pub(crate) fn workflow_ref(value: &str) -> Result<WorkflowRef, ClaimError> {
    let marker = "/.github/workflows/";
    let index = value.find(marker).ok_or(ClaimError::InvalidValue)?;
    let repository = Repository::parse(&value[..index]).map_err(map)?;
    let remainder = &value[index + 1..];
    let at = remainder.rfind('@').ok_or(ClaimError::InvalidValue)?;
    let path = WorkflowPath::parse(&remainder[..at]).map_err(map)?;
    let git_ref = GitRef::parse(&remainder[at + 1..]).map_err(map)?;
    if format!("{}@{}", path.as_str(), git_ref.as_str()) != remainder {
        return Err(ClaimError::InvalidValue);
    }
    Ok(WorkflowRef {
        repository,
        path,
        git_ref,
    })
}

fn map(_: OidcError) -> ClaimError {
    ClaimError::InvalidValue
}
