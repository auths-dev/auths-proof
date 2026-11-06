//! Two independently compiled recipes in one real native root/sibling tree.
//! Fixed public fixture keys only; this is not a key-containment claim.
use super::*;

#[allow(
    clippy::too_many_lines,
    reason = "sign complete native control, acceptance and per-recipe resource suffixes together"
)]
pub(crate) fn cross_recipe_fixture(
    recipes: [&crate::CompiledRecipe; 2],
    connections: [&auths_connections::ConnectionRecord; 2],
    arguments: [&Map<String, Value>; 2],
    engagement: [u8; 32],
) -> (EffectScopeFixture, [Submission; 2]) {
    let mut fixture = Fixture::with_depth(0x44, 1);
    fixture.pins.engagement_commitment = engagement;
    let sibling = Signer::new(0x55);
    let tools = recipes.map(|recipe| recipe.review().tool().to_owned());
    let audiences = recipes.map(|recipe| {
        resource_audience(
            &engagement,
            fixture.pins.partition_generation,
            &recipe.digest_hex(),
        )
        .unwrap()
    });
    let resource_grants: Vec<_> = recipes
        .iter()
        .enumerate()
        .map(|(index, recipe)| {
            let parent = grant_for_audiences(
                &fixture.root,
                &fixture.parent,
                recipe.service(),
                &[&tools[index]],
                None,
                1,
                vec![audiences[index].clone()],
            );
            let parent_id = grant_id(parent.statement()).unwrap();
            let children = [&fixture.child, &sibling].map(|child| {
                grant_for_audiences(
                    &fixture.parent,
                    child,
                    recipe.service(),
                    &[&tools[index]],
                    Some(parent_id),
                    0,
                    vec![audiences[index].clone()],
                )
            });
            (parent, children)
        })
        .collect();
    let sibling_control = grant(
        &fixture.parent,
        &sibling,
        PARTICIPANT_SERVICE,
        CONTROL_TOOLS,
        Some(grant_id(fixture.parent_control.statement()).unwrap()),
        0,
    );
    let mut profiles: Vec<_> = CONTROL_TOOLS
        .iter()
        .map(|tool| (PARTICIPANT_SERVICE, *tool))
        .collect();
    profiles.extend(
        recipes
            .iter()
            .enumerate()
            .map(|(i, recipe)| (recipe.service(), tools[i].as_str())),
    );
    let observer = GatewayObserver::from_test_seed(0x33);
    fixture.context = harness::context_for_profiles_and_audiences(
        &[&fixture.root],
        observer.principal(),
        None,
        NOW,
        2,
        CompositionRequirement::new(None, 1, 1, 1).unwrap(),
        &[auths_raw_key::RAW_KEY_V1],
        &profiles,
        &audiences,
    )
    .unwrap();
    let base = fixture.pins.scopes[0].clone();
    fixture.pins.scopes = recipes
        .iter()
        .enumerate()
        .map(|(index, recipe)| {
            let mut scope = base.clone();
            scope.scope_id = format!("recipe-{index}");
            scope.recipe_digest = recipe.digest_hex();
            scope.connection_binding = crate::effect::commitment(
                "auths.effect-installation/1",
                &connections[index].to_canonical_cbor().unwrap(),
            )
            .unwrap();
            scope.service = recipe.service().into();
            scope.tool = tools[index].clone();
            scope.parent_grant = grant_id(resource_grants[index].0.statement()).unwrap();
            scope.resource = EnrollmentResourceBinding::Exact {
                handle: arguments[index]["record_id"].as_str().unwrap().into(),
            };
            scope
        })
        .collect();
    fixture.pins.permitted_channels.insert(
        "sibling-channel".into(),
        EnrollmentChannelPins {
            channel_binding: [0x77; 32],
            principal: sibling.principal.clone(),
            instance_generation: 1,
        },
    );
    fixture.commit_root();
    let activation = fixture.root_activation(&fixture.pins);
    let witness = |recipe_index: usize, child_index: Option<usize>| {
        let (parent, children) = &resource_grants[recipe_index];
        match child_index {
            None => chained(
                &[&fixture.root, &fixture.parent],
                &[parent],
                recipes[recipe_index].service(),
                &tools[recipe_index],
                arguments[recipe_index],
            ),
            Some(index) => chained(
                &[
                    &fixture.root,
                    &fixture.parent,
                    [&fixture.child, &sibling][index],
                ],
                &[parent, &children[index]],
                recipes[recipe_index].service(),
                &tools[recipe_index],
                arguments[recipe_index],
            ),
        }
    };
    let root_resources: Vec<_> = (0..2).map(|index| witness(index, None)).collect();
    let resources: Vec<_> = fixture
        .pins
        .scopes
        .iter()
        .zip(&root_resources)
        .map(|(scope, proof)| EnrollmentResourceWitness {
            scope_id: &scope.scope_id,
            invocation: invocation(proof),
        })
        .collect();
    let mut tree = EnrollmentTree::bootstrap(
        &fixture.context,
        &fixture.pins,
        NOW,
        &RootEnrollmentProofs {
            activation: invocation(&activation),
            resources: &resources,
        },
    )
    .unwrap();
    let mut children = Vec::new();
    for (child_index, (signer, control)) in [
        (&fixture.child, &fixture.child_control),
        (&sibling, &sibling_control),
    ]
    .into_iter()
    .enumerate()
    {
        let mut descriptor = child_descriptor(
            signer,
            control,
            &resource_grants[0].1[child_index],
            &fixture.pins,
        );
        descriptor.scopes = fixture
            .pins
            .scopes
            .iter()
            .enumerate()
            .map(|(index, scope)| ParticipantScopeGrant {
                scope_id: scope.scope_id.clone(),
                grant_id: *grant_id(resource_grants[index].1[child_index].statement())
                    .unwrap()
                    .as_bytes(),
            })
            .collect();
        if child_index == 1 {
            descriptor.enrollment_id = "sibling".into();
            descriptor.delivery_channel = "sibling-channel".into();
        }
        let parent = fixture.parent_proof(&descriptor);
        let child = chained(
            &[&fixture.root, &fixture.parent, signer],
            &[&fixture.parent_control, control],
            PARTICIPANT_SERVICE,
            ACCEPT_PARTICIPANT_TOOL,
            json!({"enrollment_commitment":descriptor.commitment().unwrap()})
                .as_object()
                .unwrap(),
        );
        let proofs: Vec<_> = (0..2)
            .map(|index| witness(index, Some(child_index)))
            .collect();
        let resources: Vec<_> = fixture
            .pins
            .scopes
            .iter()
            .zip(&proofs)
            .map(|(scope, proof)| EnrollmentResourceWitness {
                scope_id: &scope.scope_id,
                invocation: invocation(proof),
            })
            .collect();
        tree.enroll(
            &fixture.context,
            fixture.pins.enrollment_commitment,
            NOW,
            &ParticipantEnrollmentProofs {
                parent: invocation(&parent),
                child: invocation(&child),
                resources: &resources,
            },
        )
        .unwrap();
        children.push((fixture.pins.enrollment_commitment, parent, child, proofs));
    }
    let actions = [witness(0, Some(0)), witness(1, Some(1))];
    let action = Submission {
        proof: actions[0].proof.clone(),
        action: actions[0].action.clone(),
        commitment: actions[0].commitment,
    };
    let withdrawal = fixture.withdraw_as_parent(fixture.pins.enrollment_commitment);
    (
        EffectScopeFixture {
            root: fixture.pins,
            tree,
            context: fixture.context,
            action,
            activation,
            root_resources,
            children,
            withdrawal,
        },
        actions,
    )
}
