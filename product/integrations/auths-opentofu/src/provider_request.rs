use serde::{Deserialize, Serialize};

use crate::{
    action::OpenTofuSavedPlanApplyV1,
    canonical::{canonical_digest, canonical_json},
    errors::ValidationError,
    lifecycle::PROVIDER_CONTRACT_ID,
    types::DigestHex,
};

const MAX_PROVIDER_REQUEST_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixedApplyRequestV1 {
    contract: String,
    argv: [String; 4],
    workspace: String,
    plan_digest: DigestHex,
    plan_projection_digest: DigestHex,
    expected_state_digest: DigestHex,
}

impl FixedApplyRequestV1 {
    pub fn derive(action: &OpenTofuSavedPlanApplyV1) -> Result<Self, ValidationError> {
        action.validate()?;
        Ok(Self {
            contract: PROVIDER_CONTRACT_ID.into(),
            argv: [
                "apply".into(),
                "-input=false".into(),
                "-auto-approve".into(),
                "{protected-saved-plan}".into(),
            ],
            workspace: action.workspace().into(),
            plan_digest: action.opaque_plan_digest().clone(),
            plan_projection_digest: action.plan_projection_digest().clone(),
            expected_state_digest: action.state_digest().clone(),
        })
    }

    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.contract != PROVIDER_CONTRACT_ID
            || self.argv
                != [
                    "apply",
                    "-input=false",
                    "-auto-approve",
                    "{protected-saved-plan}",
                ]
            || self.workspace.is_empty()
            || self.workspace.len() > 128
        {
            return Err(ValidationError::Malformed);
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, ValidationError> {
        self.validate()?;
        let bytes = canonical_json(self).map_err(|_| ValidationError::Malformed)?;
        if bytes.len() > MAX_PROVIDER_REQUEST_BYTES {
            return Err(ValidationError::LimitExceeded);
        }
        Ok(bytes)
    }

    pub fn digest(&self) -> Result<DigestHex, ValidationError> {
        self.validate()?;
        canonical_digest(self).map_err(|_| ValidationError::Malformed)
    }

    #[must_use]
    pub fn argv(&self) -> [&str; 4] {
        self.argv.each_ref().map(String::as_str)
    }

    #[must_use]
    pub fn workspace(&self) -> &str {
        &self.workspace
    }

    #[must_use]
    pub const fn plan_digest(&self) -> &DigestHex {
        &self.plan_digest
    }

    #[must_use]
    pub const fn plan_projection_digest(&self) -> &DigestHex {
        &self.plan_projection_digest
    }

    #[must_use]
    pub const fn expected_state_digest(&self) -> &DigestHex {
        &self.expected_state_digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_has_one_frozen_argument_shape() {
        let fixture = crate::test_support::fixture();
        let request = FixedApplyRequestV1::derive(&fixture.action).unwrap();
        assert_eq!(
            request.argv(),
            [
                "apply",
                "-input=false",
                "-auto-approve",
                "{protected-saved-plan}",
            ]
        );
        let mut value: serde_json::Value =
            serde_json::from_slice(&request.canonical_bytes().unwrap()).unwrap();
        value["argv"][1] = serde_json::json!("-destroy");
        let changed: FixedApplyRequestV1 = serde_json::from_value(value).unwrap();
        assert!(changed.validate().is_err());
    }
}
