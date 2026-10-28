//! Signed engagement limits, independent of any particular enrollment proof.

use crate::participant_enrollment::{
    EnrollmentChannelPins, MAX_JSON_INTEGER, MAX_PARTICIPANTS, identifier,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Immutable operator-approved delegation envelope selected by a task card.
/// This is permission to propose bounded enrollments, never an enrollment or
/// execution permit. Native grant authority and durable admission are separate.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TaskDelegationPolicy {
    pub(crate) partition_generation: u64,
    pub(crate) root_instance_generation: u64,
    pub(crate) max_depth: u16,
    pub(crate) permitted_channels: BTreeMap<String, EnrollmentChannelPins>,
}

impl TaskDelegationPolicy {
    pub(super) fn valid_for(&self, agent: &str, channel: &str, approver: &str) -> bool {
        let exact_generation = |value| (1..=MAX_JSON_INTEGER).contains(&value);
        let mut principals = BTreeSet::new();
        exact_generation(self.partition_generation)
            && exact_generation(self.root_instance_generation)
            && (1..=MAX_PARTICIPANTS).contains(&self.permitted_channels.len())
            && usize::from(self.max_depth) < self.permitted_channels.len()
            && self.permitted_channels.iter().all(|(name, pin)| {
                identifier(name)
                    && exact_generation(pin.instance_generation)
                    && pin.principal.as_str() != approver
                    && principals.insert(&pin.principal)
            })
            && self.permitted_channels.get(channel).is_some_and(|pin| {
                pin.principal.as_str() == agent
                    && pin.instance_generation == self.root_instance_generation
            })
    }

    pub(super) fn narrows(&self, installed: &Self) -> bool {
        self.partition_generation == installed.partition_generation
            && self.root_instance_generation == installed.root_instance_generation
            && self.max_depth <= installed.max_depth
            && self
                .permitted_channels
                .iter()
                .all(|(name, pin)| installed.permitted_channels.get(name) == Some(pin))
    }

    #[cfg(test)]
    pub(crate) fn single(agent: &auths_model::PrincipalId, channel: &str) -> Self {
        Self {
            partition_generation: 1,
            root_instance_generation: 1,
            max_depth: 0,
            permitted_channels: BTreeMap::from([(
                channel.to_owned(),
                EnrollmentChannelPins {
                    principal: agent.clone(),
                    instance_generation: 1,
                },
            )]),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::harness::Signer;

    #[test]
    fn task_delegation_limits_channels_depth_and_exact_json_generations() {
        let root = Signer::new(0x44);
        let human = Signer::new(0x22);
        let mut policy = TaskDelegationPolicy::single(&root.principal, "root-channel");
        for seed in 1..16 {
            policy.permitted_channels.insert(
                format!("child-{seed}"),
                EnrollmentChannelPins {
                    principal: Signer::new(seed).principal,
                    instance_generation: (1 << 53) - 1,
                },
            );
        }
        policy.max_depth = 15;
        policy.partition_generation = (1 << 53) - 1;
        let valid = |policy: &TaskDelegationPolicy| {
            policy.valid_for(
                root.principal.as_str(),
                "root-channel",
                human.principal.as_str(),
            )
        };
        assert!(valid(&policy));
        policy.max_depth = 16;
        assert!(!valid(&policy));
        policy.max_depth = 15;
        policy.permitted_channels.insert(
            "extra".into(),
            EnrollmentChannelPins {
                principal: Signer::new(0x66).principal,
                instance_generation: 1,
            },
        );
        assert!(!valid(&policy));
        policy.permitted_channels.remove("extra");
        policy.partition_generation += 1;
        assert!(!valid(&policy));
        policy.partition_generation -= 1;
        policy
            .permitted_channels
            .get_mut("child-1")
            .expect("channel")
            .instance_generation += 1;
        assert!(!valid(&policy));
    }
}
