use crate::*;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeProfileInventory {
    schema: u32,
    inventory: StripeInventoryMetadata,
    boundary: StripeInventoryBoundary,
    families: Vec<StripePolicyFamily>,
    profiles: Vec<StripeProfile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeInventoryMetadata {
    id: String,
    product_package: String,
    implementation_plan: String,
    spec_numbers: Vec<u16>,
    allowed_statuses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeInventoryBoundary {
    generic_policy_language_forbidden: bool,
    runtime_operation_dispatch_forbidden: bool,
    union_action_forbidden: bool,
    generic_provider_gateway_forbidden: bool,
    generic_credential_scope_forbidden: bool,
    authorization_is_not_execution: bool,
    provider_success_requires_observation: bool,
    unknown_outcomes_hold_capacity: bool,
    profile_receipts_required: bool,
    profile_fixtures_required: bool,
    profile_live_demos_required: bool,
    shared_mechanisms: Vec<String>,
    profile_owned_surfaces: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripePolicyFamily {
    id: String,
    evaluator: String,
    owner_spec: u16,
    members: Vec<String>,
    shared_semantics: Vec<String>,
    forbidden_shared_semantics: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StripeProfile {
    spec: u16,
    spec_path: String,
    status: String,
    profile: String,
    family: String,
    evaluator: String,
    module: String,
    action_type: String,
    evaluator_entrypoint: String,
    verified_command: String,
    lifecycle_transition: String,
    state_store: String,
    receipt_type: String,
    provider_gateway: String,
    credential_scope: String,
    effect: String,
    demo: String,
    fixture_dir: String,
    depends_on: Vec<String>,
}

fn stripe_require_unique_nonempty(label: &str, values: &[String]) -> Result<(), String> {
    let unique: BTreeSet<_> = values.iter().map(String::as_str).collect();
    if unique.len() != values.len() || values.iter().any(|value| value.trim().is_empty()) {
        return Err(format!("{label} must be unique and non-empty"));
    }
    Ok(())
}

pub(crate) fn stripe_profiles() -> Result<(), String> {
    let inventory_path = root().join("stripe-profiles.toml");
    let source = fs::read_to_string(&inventory_path)
        .map_err(|error| format!("could not read {}: {error}", inventory_path.display()))?;
    let inventory: StripeProfileInventory = toml::from_str(&source)
        .map_err(|error| format!("invalid stripe-profiles.toml: {error}"))?;
    if inventory.schema != 1 {
        return Err("stripe-profiles.toml must declare schema = 1".to_owned());
    }
    if inventory.inventory.id != "auths-proof-stripe-profile-inventory"
        || inventory.inventory.product_package != "product/integrations/auths-stripe"
    {
        return Err("Stripe inventory identity or product package changed".to_owned());
    }
    let expected_specs: Vec<u16> = (13..=23).collect();
    if inventory.inventory.spec_numbers != expected_specs {
        return Err(format!(
            "Stripe inventory must cover specifications 0013 through 0023 in order, found {:?}",
            inventory.inventory.spec_numbers
        ));
    }
    stripe_require_unique_nonempty(
        "Stripe inventory allowed statuses",
        &inventory.inventory.allowed_statuses,
    )?;
    if inventory.inventory.allowed_statuses != ["specified", "implemented"] {
        return Err(
            "Stripe inventory statuses must be exactly specified and implemented".to_owned(),
        );
    }
    let plan = root().join(&inventory.inventory.implementation_plan);
    if !plan.is_file() {
        return Err(format!(
            "Stripe implementation plan is absent: {}",
            plan.display()
        ));
    }

    let required_boundaries = [
        (
            "generic_policy_language_forbidden",
            inventory.boundary.generic_policy_language_forbidden,
        ),
        (
            "runtime_operation_dispatch_forbidden",
            inventory.boundary.runtime_operation_dispatch_forbidden,
        ),
        (
            "union_action_forbidden",
            inventory.boundary.union_action_forbidden,
        ),
        (
            "generic_provider_gateway_forbidden",
            inventory.boundary.generic_provider_gateway_forbidden,
        ),
        (
            "generic_credential_scope_forbidden",
            inventory.boundary.generic_credential_scope_forbidden,
        ),
        (
            "authorization_is_not_execution",
            inventory.boundary.authorization_is_not_execution,
        ),
        (
            "provider_success_requires_observation",
            inventory.boundary.provider_success_requires_observation,
        ),
        (
            "unknown_outcomes_hold_capacity",
            inventory.boundary.unknown_outcomes_hold_capacity,
        ),
        (
            "profile_receipts_required",
            inventory.boundary.profile_receipts_required,
        ),
        (
            "profile_fixtures_required",
            inventory.boundary.profile_fixtures_required,
        ),
        (
            "profile_live_demos_required",
            inventory.boundary.profile_live_demos_required,
        ),
    ];
    if let Some((name, _)) = required_boundaries.iter().find(|(_, enabled)| !enabled) {
        return Err(format!(
            "Stripe profile boundary {name} must remain enabled"
        ));
    }
    stripe_require_unique_nonempty(
        "Stripe shared mechanisms",
        &inventory.boundary.shared_mechanisms,
    )?;
    stripe_require_unique_nonempty(
        "Stripe profile-owned surfaces",
        &inventory.boundary.profile_owned_surfaces,
    )?;

    let mut families = BTreeMap::new();
    for family in &inventory.families {
        if family.members.is_empty() {
            return Err(format!("Stripe policy family {} has no members", family.id));
        }
        stripe_require_unique_nonempty(
            &format!("Stripe policy family {} members", family.id),
            &family.members,
        )?;
        stripe_require_unique_nonempty(
            &format!("Stripe policy family {} shared semantics", family.id),
            &family.shared_semantics,
        )?;
        stripe_require_unique_nonempty(
            &format!("Stripe policy family {} forbidden semantics", family.id),
            &family.forbidden_shared_semantics,
        )?;
        if family.evaluator.trim().is_empty() {
            return Err(format!(
                "Stripe policy family {} has no evaluator",
                family.id
            ));
        }
        if families.insert(family.id.as_str(), family).is_some() {
            return Err(format!("duplicate Stripe policy family {}", family.id));
        }
    }

    if inventory.profiles.len() != expected_specs.len() {
        return Err(format!(
            "Stripe inventory must contain {} profiles, found {}",
            expected_specs.len(),
            inventory.profiles.len()
        ));
    }
    let mut profiles = BTreeMap::new();
    let mut specs = BTreeSet::new();
    let mut modules = BTreeSet::new();
    let mut actions = BTreeSet::new();
    let mut evaluators = BTreeSet::new();
    let mut commands = BTreeSet::new();
    let mut transitions = BTreeSet::new();
    let mut receipts = BTreeSet::new();
    let mut gateways = BTreeSet::new();
    let mut credential_scopes = BTreeSet::new();
    let mut effects = BTreeSet::new();
    let mut demos = BTreeSet::new();
    let mut fixture_directories = BTreeSet::new();

    for profile in &inventory.profiles {
        if !inventory
            .inventory
            .allowed_statuses
            .contains(&profile.status)
        {
            return Err(format!(
                "Stripe profile {} has invalid status {}",
                profile.profile, profile.status
            ));
        }
        if !specs.insert(profile.spec) {
            return Err(format!("duplicate Stripe specification {}", profile.spec));
        }
        if profiles.insert(profile.profile.as_str(), profile).is_some() {
            return Err(format!("duplicate Stripe profile {}", profile.profile));
        }
        for (label, value, values) in [
            ("module", &profile.module, &mut modules),
            ("action type", &profile.action_type, &mut actions),
            (
                "evaluator entry point",
                &profile.evaluator_entrypoint,
                &mut evaluators,
            ),
            ("verified command", &profile.verified_command, &mut commands),
            (
                "lifecycle transition",
                &profile.lifecycle_transition,
                &mut transitions,
            ),
            ("receipt type", &profile.receipt_type, &mut receipts),
            ("provider gateway", &profile.provider_gateway, &mut gateways),
            (
                "credential scope",
                &profile.credential_scope,
                &mut credential_scopes,
            ),
            ("provider effect", &profile.effect, &mut effects),
            ("demo", &profile.demo, &mut demos),
            (
                "fixture directory",
                &profile.fixture_dir,
                &mut fixture_directories,
            ),
        ] {
            if value.trim().is_empty() || !values.insert(value.as_str()) {
                return Err(format!(
                    "Stripe profile {} has an empty or duplicate {label}: {value}",
                    profile.profile
                ));
            }
        }
        if profile.state_store.trim().is_empty() {
            return Err(format!(
                "Stripe profile {} has no state store",
                profile.profile
            ));
        }
        stripe_require_unique_nonempty(
            &format!("Stripe profile {} dependencies", profile.profile),
            &profile.depends_on,
        )?;

        let family = families.get(profile.family.as_str()).ok_or_else(|| {
            format!(
                "Stripe profile {} names undeclared family {}",
                profile.profile, profile.family
            )
        })?;
        if profile.evaluator != family.evaluator {
            return Err(format!(
                "Stripe profile {} evaluator {} differs from family evaluator {}",
                profile.profile, profile.evaluator, family.evaluator
            ));
        }

        let spec_path = root().join(&profile.spec_path);
        let spec = fs::read_to_string(&spec_path)
            .map_err(|error| format!("could not read {}: {error}", spec_path.display()))?;
        for (label, expected) in [
            ("exact action profile", profile.profile.as_str()),
            ("policy family", profile.family.as_str()),
            ("evaluator", profile.evaluator.as_str()),
            (
                "product package",
                inventory.inventory.product_package.as_str(),
            ),
            ("demo", profile.demo.as_str()),
        ] {
            if !spec.contains(expected) {
                return Err(format!(
                    "{} does not declare inventoried {label} {expected}",
                    profile.spec_path
                ));
            }
        }

        if profile.status == "implemented" {
            for (label, path) in [
                ("demo", root().join(&profile.demo)),
                ("fixture directory", root().join(&profile.fixture_dir)),
            ] {
                if !path.is_dir() {
                    return Err(format!(
                        "implemented Stripe profile {} {label} is absent: {}",
                        profile.profile,
                        path.display()
                    ));
                }
            }
        }
    }

    if specs != expected_specs.iter().copied().collect() {
        return Err(format!(
            "Stripe profile specification set differs from inventory header: {specs:?}"
        ));
    }
    for profile in &inventory.profiles {
        for dependency in &profile.depends_on {
            if dependency == &profile.profile || !profiles.contains_key(dependency.as_str()) {
                return Err(format!(
                    "Stripe profile {} has invalid dependency {dependency}",
                    profile.profile
                ));
            }
        }
    }
    for family in &inventory.families {
        let actual_members: BTreeSet<_> = inventory
            .profiles
            .iter()
            .filter(|profile| profile.family == family.id)
            .map(|profile| profile.profile.as_str())
            .collect();
        let declared_members: BTreeSet<_> = family.members.iter().map(String::as_str).collect();
        if actual_members != declared_members {
            return Err(format!(
                "Stripe policy family {} member inventory drifted",
                family.id
            ));
        }
        if !inventory.profiles.iter().any(|profile| {
            profile.spec == family.owner_spec
                && profile.family == family.id
                && family.members.contains(&profile.profile)
        }) {
            return Err(format!(
                "Stripe policy family {} owner specification {} is not a member",
                family.id, family.owner_spec
            ));
        }
    }

    println!(
        "Stripe profile boundary passed ({} families, {} profiles)",
        inventory.families.len(),
        inventory.profiles.len()
    );
    Ok(())
}
