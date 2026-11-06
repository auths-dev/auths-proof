//! Private native creation provenance. Serialization is audit data only; the
//! compiler receives instances from protected history, and entry revalidates
//! the original source/read/allocation under its own writer fence.
use super::EffectBindingError;
use crate::participant_enrollment::{
    EnrollmentResourceBinding, EnrollmentScopePins, ParentEnrollmentPins,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CreatedLineage {
    pub(crate) schema: String,
    pub(crate) producer_namespace: String,
    pub(crate) producer_partition: String,
    pub(crate) producer_epoch: u64,
    pub(crate) producer_operation: String,
    pub(crate) producer_recipe: String,
    pub(crate) parent_scope: String,
    pub(crate) connection: [u8; 32],
    pub(crate) root: [u8; 32],
    pub(crate) engagement: [u8; 32],
    pub(crate) authority_epoch: u64,
    pub(crate) producer_key: [u8; 32],
    pub(crate) producer_effect: [u8; 32],
    pub(crate) producer_revision: u64,
    pub(crate) acquisition_key: [u8; 32],
    pub(crate) acquisition_effect: [u8; 32],
    pub(crate) acquisition_revision: u64,
    pub(crate) allocation_key: [u8; 32],
    pub(crate) resource: String,
}
impl std::fmt::Debug for CreatedLineage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CreatedLineage { private: [redacted] }")
    }
}
impl CreatedLineage {
    pub(crate) fn validate(&self) -> Result<(), EffectBindingError> {
        use crate::participant_enrollment::{MAX_JSON_INTEGER, identifier};
        if self.schema != "auths.created-resource-lineage/1"
            || crate::OperatorNamespace::parse(&self.producer_namespace).is_err()
            || !identifier(&self.producer_partition)
            || !(1..=MAX_JSON_INTEGER).contains(&self.producer_epoch)
            || !(1..=MAX_JSON_INTEGER).contains(&self.authority_epoch)
            || crate::LogicalOperationId::parse(&self.producer_operation).is_err()
            || ![&self.producer_recipe, &self.parent_scope].iter().all(|s| {
                s.len() == 64
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || !(3..=crate::store::MAX_OPERATION_REVISIONS).contains(&self.producer_revision)
            || !(3..=crate::store::MAX_OPERATION_REVISIONS).contains(&self.acquisition_revision)
            || self.producer_key == self.acquisition_key
            || !crate::resource_identity::valid_handle(&self.resource)
        {
            return Err(EffectBindingError::Invalid);
        }
        Ok(())
    }
    pub(crate) fn admits(&self, root: &ParentEnrollmentPins, scope: &EnrollmentScopePins) -> bool {
        self.validate().is_ok()
            && self.root == root.enrollment_commitment
            && self.engagement == root.engagement_commitment
            && self.authority_epoch == root.partition_generation
            && self.connection == scope.connection_binding
            && self.matches_resource(&scope.resource)
    }
    pub(crate) fn matches_resource(&self, resource: &EnrollmentResourceBinding) -> bool {
        matches!(resource,EnrollmentResourceBinding::CreatedChild{
                create_namespace,create_partition,create_epoch,create_operation_id,create_recipe_digest,parent_scope_id
            } if create_namespace==&self.producer_namespace && create_partition==&self.producer_partition && *create_epoch==self.producer_epoch
                && create_operation_id==&self.producer_operation && create_recipe_digest==&self.producer_recipe && parent_scope_id==&self.parent_scope)
    }
    pub(crate) fn dependencies(&self) -> Vec<(crate::GatewayRecordKind, crate::GatewayAttemptKey)> {
        use crate::{GatewayAttemptKey as Key, GatewayRecordKind as Kind};
        vec![
            (Kind::Attempt, Key::from_bytes(self.producer_key)),
            (Kind::Attempt, Key::from_bytes(self.acquisition_key)),
            (Kind::EffectAllocation, Key::from_bytes(self.allocation_key)),
        ]
    }
}
