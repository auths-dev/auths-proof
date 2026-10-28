//! AP073 phase-one reference for one engagement's authority partition.
//!
//! Test-only: this is neither an enrollment verifier nor a durable store. Inputs
//! assume native grant verification, child possession and operator channel
//! resolution have already succeeded. The production cutover must establish
//! those facts and refine these transitions under the existing ledger lock.

use std::collections::BTreeMap;

const MAX_PARTICIPANTS: usize = 16;
const MAX_OPERATIONS: usize = 64;
type Commitment = [u8; 32];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Units {
    provider_reads: u64,
    disclosures: u64,
    disclosure_bytes: u64,
    writes: u64,
}

impl Units {
    fn checked_add(self, rhs: Self) -> Result<Self, Refusal> {
        Ok(Self {
            provider_reads: self
                .provider_reads
                .checked_add(rhs.provider_reads)
                .ok_or(Refusal::Capacity)?,
            disclosures: self
                .disclosures
                .checked_add(rhs.disclosures)
                .ok_or(Refusal::Capacity)?,
            disclosure_bytes: self
                .disclosure_bytes
                .checked_add(rhs.disclosure_bytes)
                .ok_or(Refusal::Capacity)?,
            writes: self
                .writes
                .checked_add(rhs.writes)
                .ok_or(Refusal::Capacity)?,
        })
    }

    fn within(self, ceiling: Self) -> bool {
        self.provider_reads <= ceiling.provider_reads
            && self.disclosures <= ceiling.disclosures
            && self.disclosure_bytes <= ceiling.disclosure_bytes
            && self.writes <= ceiling.writes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Participant {
    parent: Option<u8>,
    principal: Commitment,
    generation: u64,
    channel: Commitment,
    not_before: u64,
    expires_at: u64,
    remaining_depth: u8,
    ceiling: Units,
    /// Scope indexes refer to immutable root resource/account/recipe pins.
    /// Values are native grant IDs, not newly invented participant authority.
    grants: BTreeMap<u8, Commitment>,
    revoked: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Effect {
    Read,
    Write,
}

impl Effect {
    fn debit(self) -> Units {
        match self {
            Self::Read => Units {
                provider_reads: 1,
                ..Units::default()
            },
            Self::Write => Units {
                writes: 1,
                ..Units::default()
            },
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Binding {
    engagement: Commitment,
    partition_generation: u64,
    executor: Commitment,
    participant: u8,
    instance_generation: u64,
    principal: Commitment,
    channel: Commitment,
    scope: u8,
    action: Commitment,
    request: Commitment,
    effect: Effect,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Reserved,
    ProviderEntered,
    ReadReady,
    DisclosureEntered,
    Succeeded,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Charge {
    Reserved,
    Spent,
    Uncertain,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Operation {
    binding: Binding,
    stage: Stage,
    provider_charge: Charge,
    disclosure: Option<(u64, Charge)>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Partition {
    engagement: Commitment,
    generation: u64,
    executor: Commitment,
    participants: BTreeMap<u8, Participant>,
    operations: BTreeMap<u64, Operation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Refusal {
    Binding,
    Inactive,
    Capacity,
    Replay,
    Stage,
}

impl Partition {
    fn ancestry(&self, mut id: u8) -> Result<Vec<u8>, Refusal> {
        let mut path = Vec::new();
        loop {
            if path.len() == MAX_PARTICIPANTS || path.contains(&id) {
                return Err(Refusal::Binding);
            }
            path.push(id);
            let node = self.participants.get(&id).ok_or(Refusal::Binding)?;
            if let Some(parent) = node.parent {
                id = parent;
            } else {
                path.reverse();
                return Ok(path);
            }
        }
    }

    fn active_path(&self, id: u8, now: u64) -> Result<Vec<u8>, Refusal> {
        let path = self.ancestry(id)?;
        for ancestor in &path {
            let node = &self.participants[ancestor];
            if node.revoked || now < node.not_before || now >= node.expires_at {
                return Err(Refusal::Inactive);
            }
        }
        Ok(path)
    }

    /// Native verification supplies one parent-linked child grant per scope.
    /// Independent read/write grants are pinned separately; an enrollment
    /// action's authority must never stand in for resource authority.
    fn enroll(
        &mut self,
        id: u8,
        child: Participant,
        parent_grants: &BTreeMap<u8, Commitment>,
        now: u64,
    ) -> Result<(), Refusal> {
        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err(Refusal::Capacity);
        }
        let parent_id = child.parent.ok_or(Refusal::Binding)?;
        self.active_path(parent_id, now)?;
        let parent = &self.participants[&parent_id];
        if self.participants.contains_key(&id)
            || self
                .participants
                .values()
                .any(|node| node.principal == child.principal)
            || child.generation == 0
            || child.revoked
            || child.not_before < parent.not_before
            || child.expires_at > parent.expires_at
            || child.not_before >= child.expires_at
            || child.remaining_depth >= parent.remaining_depth
            || !child.ceiling.within(parent.ceiling)
            || child.grants.is_empty()
            || child.grants.len() > 16
            || child.grants.keys().ne(parent_grants.keys())
            || parent_grants
                .iter()
                .any(|(scope, grant)| parent.grants.get(scope) != Some(grant))
        {
            return Err(Refusal::Binding);
        }
        self.participants.insert(id, child);
        Ok(())
    }

    fn revoke(&mut self, id: u8) -> Result<(), Refusal> {
        self.participants
            .get_mut(&id)
            .ok_or(Refusal::Binding)?
            .revoked = true;
        Ok(())
    }

    fn usage(&self, ancestor: u8, category: Charge) -> Result<Units, Refusal> {
        let mut used = Units::default();
        for operation in self.operations.values() {
            if !self
                .ancestry(operation.binding.participant)?
                .contains(&ancestor)
            {
                continue;
            }
            if operation.provider_charge == category {
                used = used.checked_add(operation.binding.effect.debit())?;
            }
            if let Some((bytes, charge)) = operation.disclosure
                && charge == category
            {
                used = used.checked_add(Units {
                    disclosures: 1,
                    disclosure_bytes: bytes,
                    ..Units::default()
                })?;
            }
        }
        Ok(used)
    }

    fn capacity(&self, path: &[u8], debit: Units) -> Result<(), Refusal> {
        for id in path {
            let total = self
                .usage(*id, Charge::Reserved)?
                .checked_add(self.usage(*id, Charge::Spent)?)?
                .checked_add(self.usage(*id, Charge::Uncertain)?)?
                .checked_add(debit)?;
            if !total.within(self.participants[id].ceiling) {
                return Err(Refusal::Capacity);
            }
        }
        Ok(())
    }

    fn reserve(
        &mut self,
        operation_id: u64,
        binding: Binding,
        native_path: &[Commitment],
        now: u64,
    ) -> Result<(), Refusal> {
        if self.operations.contains_key(&operation_id) {
            return Err(Refusal::Replay);
        }
        if self.operations.len() >= MAX_OPERATIONS {
            return Err(Refusal::Capacity);
        }
        let path = self.binding_path(&binding, now)?;
        let expected = path
            .iter()
            .map(|id| {
                self.participants[id]
                    .grants
                    .get(&binding.scope)
                    .copied()
                    .ok_or(Refusal::Binding)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if native_path.len() > 16 || !native_path.ends_with(&expected) {
            return Err(Refusal::Binding);
        }
        self.capacity(&path, binding.effect.debit())?;
        self.operations.insert(
            operation_id,
            Operation {
                binding,
                stage: Stage::Reserved,
                provider_charge: Charge::Reserved,
                disclosure: None,
            },
        );
        Ok(())
    }

    fn binding_path(&self, binding: &Binding, now: u64) -> Result<Vec<u8>, Refusal> {
        let path = self.active_path(binding.participant, now)?;
        let node = &self.participants[&binding.participant];
        if binding.engagement != self.engagement
            || binding.partition_generation != self.generation
            || binding.executor != self.executor
            || binding.principal != node.principal
            || binding.instance_generation != node.generation
            || binding.channel != node.channel
        {
            return Err(Refusal::Binding);
        }
        Ok(path)
    }

    fn enter(&mut self, operation_id: u64, binding: &Binding, now: u64) -> Result<(), Refusal> {
        let operation = self.operations.get(&operation_id).ok_or(Refusal::Binding)?;
        if operation.binding != *binding {
            return Err(Refusal::Binding);
        }
        if operation.stage != Stage::Reserved {
            return Err(Refusal::Stage);
        }
        self.binding_path(binding, now)?;
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(Refusal::Binding)?;
        operation.stage = Stage::ProviderEntered;
        operation.provider_charge = Charge::Uncertain;
        Ok(())
    }

    /// An authenticated response can finish an already entered operation even
    /// after revocation. It never authorizes a new entry or refunds a charge.
    fn observed(&mut self, operation_id: u64) -> Result<(), Refusal> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(Refusal::Binding)?;
        if operation.stage != Stage::ProviderEntered {
            return Err(Refusal::Stage);
        }
        operation.provider_charge = Charge::Spent;
        operation.stage = match operation.binding.effect {
            Effect::Read => Stage::ReadReady,
            Effect::Write => Stage::Succeeded,
        };
        Ok(())
    }

    fn disclose(&mut self, operation_id: u64, bytes: u64, now: u64) -> Result<(), Refusal> {
        let operation = self.operations.get(&operation_id).ok_or(Refusal::Binding)?;
        if operation.stage != Stage::ReadReady {
            return Err(Refusal::Stage);
        }
        let path = self.binding_path(&operation.binding, now)?;
        self.capacity(
            &path,
            Units {
                disclosures: 1,
                disclosure_bytes: bytes,
                ..Units::default()
            },
        )?;
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(Refusal::Binding)?;
        operation.disclosure = Some((bytes, Charge::Uncertain));
        operation.stage = Stage::DisclosureEntered;
        Ok(())
    }

    fn acknowledge(&mut self, operation_id: u64) -> Result<(), Refusal> {
        let operation = self
            .operations
            .get_mut(&operation_id)
            .ok_or(Refusal::Binding)?;
        if operation.stage != Stage::DisclosureEntered {
            return Err(Refusal::Stage);
        }
        let (bytes, _) = operation.disclosure.ok_or(Refusal::Binding)?;
        operation.disclosure = Some((bytes, Charge::Spent));
        operation.stage = Stage::Succeeded;
        Ok(())
    }

    fn recover(&mut self) {
        for operation in self.operations.values_mut() {
            if matches!(
                operation.stage,
                Stage::ProviderEntered | Stage::DisclosureEntered
            ) {
                operation.stage = Stage::Unknown;
            }
        }
    }
}

fn root() -> Partition {
    Partition {
        engagement: [1; 32],
        generation: 1,
        executor: [2; 32],
        participants: BTreeMap::from([(
            0,
            Participant {
                parent: None,
                principal: [3; 32],
                generation: 1,
                channel: [4; 32],
                not_before: 10,
                expires_at: 100,
                remaining_depth: 15,
                ceiling: Units {
                    provider_reads: 64,
                    disclosures: 64,
                    disclosure_bytes: 1024,
                    writes: 64,
                },
                grants: BTreeMap::from([(0, [5; 32]), (1, [6; 32])]),
                revoked: false,
            },
        )]),
        operations: BTreeMap::new(),
    }
}

fn child(state: &Partition, parent: u8, id: u8) -> Participant {
    let mut node = state.participants[&parent].clone();
    node.parent = Some(parent);
    node.principal = [id + 10; 32];
    node.channel = [id + 30; 32];
    node.remaining_depth -= 1;
    node.grants = BTreeMap::from([(0, [id + 50; 32]), (1, [id + 70; 32])]);
    node
}

fn enroll(state: &mut Partition, parent: u8, id: u8) {
    let node = child(state, parent, id);
    let grants = state.participants[&parent].grants.clone();
    state.enroll(id, node, &grants, 20).unwrap();
}

fn binding(state: &Partition, participant: u8, effect: Effect) -> Binding {
    let node = &state.participants[&participant];
    Binding {
        engagement: state.engagement,
        partition_generation: state.generation,
        executor: state.executor,
        participant,
        instance_generation: node.generation,
        principal: node.principal,
        channel: node.channel,
        scope: 0,
        action: [80; 32],
        request: [81; 32],
        effect,
    }
}

fn reserve(
    state: &mut Partition,
    id: u64,
    participant: u8,
    effect: Effect,
) -> Result<Binding, Refusal> {
    let binding = binding(state, participant, effect);
    let path: Vec<_> = state
        .ancestry(participant)?
        .iter()
        .map(|id| state.participants[id].grants[&0])
        .collect();
    state.reserve(id, binding.clone(), &path, 20)?;
    Ok(binding)
}

#[test]
fn reference_siblings_share_every_ancestor_and_unknown_never_refunds() {
    let mut state = root();
    state.participants.get_mut(&0).unwrap().ceiling.writes = 1;
    enroll(&mut state, 0, 1);
    enroll(&mut state, 0, 2);
    let first = reserve(&mut state, 1, 1, Effect::Write).unwrap();
    let reserved = state.clone();
    assert_eq!(
        reserve(&mut state, 2, 2, Effect::Write),
        Err(Refusal::Capacity)
    );
    assert_eq!(state, reserved);
    state.enter(1, &first, 20).unwrap();
    assert_eq!(state.usage(0, Charge::Reserved).unwrap().writes, 0);
    assert_eq!(state.usage(0, Charge::Uncertain).unwrap().writes, 1);
    state.recover();
    assert_eq!(state.enter(1, &first, 21), Err(Refusal::Stage));
    assert_eq!(
        reserve(&mut state, 2, 2, Effect::Write),
        Err(Refusal::Capacity)
    );
    state.revoke(1).unwrap();
    assert_eq!(
        reserve(&mut state, 3, 2, Effect::Write),
        Err(Refusal::Capacity)
    );
}

#[test]
fn reference_revocation_orders_entry_and_disclosure_separately() {
    let mut state = root();
    enroll(&mut state, 0, 1);
    enroll(&mut state, 1, 2);
    let write = reserve(&mut state, 1, 2, Effect::Write).unwrap();
    let blocked_write = reserve(&mut state, 2, 2, Effect::Write).unwrap();
    let read = reserve(&mut state, 3, 2, Effect::Read).unwrap();
    state.enter(1, &write, 20).unwrap();
    state.enter(3, &read, 20).unwrap();
    state.observed(3).unwrap();
    state.revoke(1).unwrap();
    assert_eq!(state.enter(2, &blocked_write, 21), Err(Refusal::Inactive));
    assert_eq!(state.disclose(3, 64, 21), Err(Refusal::Inactive));
    assert_eq!(
        reserve(&mut state, 4, 2, Effect::Read),
        Err(Refusal::Inactive)
    );
    state.observed(1).unwrap();
    assert_eq!(state.usage(0, Charge::Spent).unwrap().writes, 1);
    assert_eq!(state.usage(0, Charge::Reserved).unwrap().writes, 1);
}

#[test]
fn reference_disclosure_ack_and_crash_conserve_bytes() {
    let mut state = root();
    enroll(&mut state, 0, 1);
    for id in 1..=2 {
        let read = reserve(&mut state, id, 1, Effect::Read).unwrap();
        state.enter(id, &read, 20).unwrap();
        state.observed(id).unwrap();
        state.disclose(id, 512, 20).unwrap();
    }
    state.acknowledge(1).unwrap();
    state.recover();
    assert_eq!(state.usage(0, Charge::Spent).unwrap().disclosure_bytes, 512);
    assert_eq!(
        state.usage(0, Charge::Uncertain).unwrap().disclosure_bytes,
        512
    );
    assert_eq!(state.disclose(2, 512, 21), Err(Refusal::Stage));
    let read = reserve(&mut state, 3, 1, Effect::Read).unwrap();
    state.enter(3, &read, 20).unwrap();
    state.observed(3).unwrap();
    let before = state.clone();
    assert_eq!(state.disclose(3, 1, 20), Err(Refusal::Capacity));
    assert_eq!(state, before);
}

#[test]
fn reference_replay_is_engagement_wide_and_entry_binds_the_exact_request() {
    let mut state = root();
    enroll(&mut state, 0, 1);
    enroll(&mut state, 0, 2);
    let request = reserve(&mut state, 1, 1, Effect::Read).unwrap();
    assert_eq!(
        reserve(&mut state, 1, 2, Effect::Write),
        Err(Refusal::Replay)
    );
    let mut mutations = vec![request.clone(); 8];
    mutations[0].request = [90; 32];
    mutations[1].action = [90; 32];
    mutations[2].executor = [90; 32];
    mutations[3].engagement = [90; 32];
    mutations[4].partition_generation += 1;
    mutations[5].instance_generation += 1;
    mutations[6].channel = [90; 32];
    mutations[7].scope = 1;
    for mutation in mutations {
        assert_eq!(state.enter(1, &mutation, 20), Err(Refusal::Binding));
    }
    state.enter(1, &request, 20).unwrap();
}

#[test]
fn reference_participant_and_mixed_operation_bounds_include_terminal_records() {
    let mut state = root();
    for id in 1..16 {
        enroll(&mut state, 0, id);
    }
    state.revoke(15).unwrap();
    let node = child(&state, 0, 16);
    assert_eq!(
        state.enroll(16, node, &state.participants[&0].grants.clone(), 20),
        Err(Refusal::Capacity)
    );
    for id in 0..64 {
        let effect = if id % 2 == 0 {
            Effect::Read
        } else {
            Effect::Write
        };
        let request = reserve(&mut state, id, 1, effect).unwrap();
        state.enter(id, &request, 20).unwrap();
        state.observed(id).unwrap();
    }
    assert_eq!(
        reserve(&mut state, 65, 2, Effect::Write),
        Err(Refusal::Capacity)
    );
}

#[test]
fn reference_enrollment_and_grant_path_cannot_widen_or_splice() {
    let mut state = root();
    let parent_grants = state.participants[&0].grants.clone();
    let original = child(&state, 0, 1);
    let mut mutations = vec![original.clone(); 6];
    mutations[0].ceiling.writes += 1;
    mutations[1].expires_at += 1;
    mutations[2].remaining_depth += 1;
    mutations[3].principal = state.participants[&0].principal;
    mutations[4].generation = 0;
    mutations[5].grants.insert(2, [55; 32]);
    for mutation in mutations {
        assert_eq!(
            state.enroll(1, mutation, &parent_grants, 20),
            Err(Refusal::Binding)
        );
        assert_eq!(state.participants.len(), 1);
    }
    enroll(&mut state, 0, 1);
    enroll(&mut state, 1, 2);
    let request = binding(&state, 2, Effect::Read);
    let path = [parent_grants[&0], state.participants[&2].grants[&0]];
    assert_eq!(state.reserve(1, request, &path, 20), Err(Refusal::Binding));
    assert_eq!(
        Units {
            disclosure_bytes: u64::MAX,
            ..Units::default()
        }
        .checked_add(Units {
            disclosure_bytes: 1,
            ..Units::default()
        }),
        Err(Refusal::Capacity)
    );
}

#[test]
fn reference_current_generation_and_expiry_gate_entry_and_disclosure() {
    let mut state = root();
    enroll(&mut state, 0, 1);
    let request = reserve(&mut state, 1, 1, Effect::Read).unwrap();
    let mut restored = state.clone();
    restored.generation += 1;
    assert_eq!(restored.enter(1, &request, 20), Err(Refusal::Binding));
    let mut replaced = state.clone();
    replaced.participants.get_mut(&1).unwrap().generation += 1;
    assert_eq!(replaced.enter(1, &request, 20), Err(Refusal::Binding));
    assert_eq!(state.enter(1, &request, 100), Err(Refusal::Inactive));
    assert_eq!(state.enter(1, &request, 9), Err(Refusal::Inactive));
    state.enter(1, &request, 20).unwrap();
    state.observed(1).unwrap();
    state.generation += 1;
    assert_eq!(state.disclose(1, 1, 21), Err(Refusal::Binding));
}

fn step(state: &mut Partition, selector: u8, id: u8, bytes: u16) -> Result<(), Refusal> {
    let operation = u64::from(id % 12);
    match selector % 8 {
        0 => reserve(state, operation, 1 + id % 2, Effect::Read).map(|_| ()),
        1 => reserve(state, operation, 1 + id % 2, Effect::Write).map(|_| ()),
        2 => {
            let binding = state
                .operations
                .get(&operation)
                .ok_or(Refusal::Binding)?
                .binding
                .clone();
            state.enter(operation, &binding, 20)
        }
        3 => state.observed(operation),
        4 => state.disclose(operation, u64::from(bytes), 20),
        5 => state.acknowledge(operation),
        6 => state.revoke(1 + id % 2),
        _ => {
            state.recover();
            Ok(())
        }
    }
}

proptest::proptest! {
    #[test]
    fn reference_arbitrary_histories_conserve_capacity_and_refusals_are_atomic(
        history in proptest::collection::vec((0u8..8, 0u8..24, 0u16..32), 1..96)
    ) {
        let mut state = root();
        state.participants.get_mut(&0).unwrap().ceiling = Units {
            provider_reads: 4, writes: 3, disclosures: 3, disclosure_bytes: 12,
        };
        enroll(&mut state, 0, 1);
        enroll(&mut state, 0, 2);
        for (selector, id, bytes) in history {
            let before = state.clone();
            if step(&mut state, selector, id, bytes).is_err() {
                proptest::prop_assert_eq!(&state, &before);
            }
            for (id, node) in &state.participants {
                let total = state.usage(*id, Charge::Spent).unwrap()
                    .checked_add(state.usage(*id, Charge::Reserved).unwrap()).unwrap()
                    .checked_add(state.usage(*id, Charge::Uncertain).unwrap()).unwrap();
                proptest::prop_assert!(total.within(node.ceiling));
            }
            let mut restarted = state.clone();
            restarted.recover();
            let once = restarted.clone();
            restarted.recover();
            proptest::prop_assert_eq!(restarted, once);
        }
    }
}
