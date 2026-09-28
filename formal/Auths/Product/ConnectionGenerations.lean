/-!
# Connection record generations

A connection record carries two generations. `generation` advances on every
change. `credentialGeneration` is the generation of the last install or
rotation, at which the current secret is stored and its reference
commitment computed. Install and rotation set both to the new generation; a
state change (disable, enable, revoke) advances only `generation`.

Each gateway process keeps its own credential store, a list of entries
`(generation, secret)`. A process leases for a record only the secret stored
at the newest stored generation not after the record's generation, and only
when that is the credential generation and the entry's commitment equals the
record's. The model treats the reference commitment as injective in the
generation and the secret (a collision-resistant hash), so a commitment
comparison at the credential generation is a comparison of secrets.

The system runs any sequence of install, join, rotate, disable, enable, and
revoke over one shared record and any number of hosts. A rotation through a
host that holds the current secret commits a new generation; through a host
that does not, it takes the committed secret only when it matches, which is
also what a join does. The model keeps superseded entries that the gateway
deletes; a lease reads only the newest entry not after the record's
generation, which the gateway never deletes.

The leaves work over `Nat` with the machine bound `generationMax`; the
refinement theorems of the translated leaves map `u64` to its value.
-/

namespace Auths.Product.ConnectionGenerations

/-! ## The generation leaves -/

/-- The largest machine generation, `u64::MAX`. -/
def generationMax : Nat := 18446744073709551615

/-- The next generation, absent when it would exceed the machine bound. -/
def nextGeneration (generation : Nat) : Option Nat :=
  if generation + 1 ≤ generationMax then some (generation + 1) else none

/-- The two generations of one record. -/
structure Generations where
  generation : Nat
  credentialGeneration : Nat
  deriving DecidableEq, Repr

/-- A state change: the generation advances; the credential generation is
kept, because no secret is stored. -/
def stateChange (current : Generations) : Option Generations :=
  match nextGeneration current.generation with
  | some generation => some ⟨generation, current.credentialGeneration⟩
  | none => none

/-- A rotation: both generations advance to the next generation, at which the
new secret is stored. -/
def rotation (current : Generations) : Option Generations :=
  match nextGeneration current.generation with
  | some generation => some ⟨generation, generation⟩
  | none => none

/-- One step of the retained-entry search: keep the newest candidate not
after `record`. -/
def retainStep (record : Nat) (best : Option Nat) (candidate : Nat) : Option Nat :=
  if candidate ≤ record then
    match best with
    | none => some candidate
    | some current => if current < candidate then some candidate else some current
  else best

/-- The newest stored generation not after `record`. -/
def retainedGeneration (record : Nat) (stored : List Nat) : Option Nat :=
  stored.foldl (retainStep record) none

/-- The stored generation a lease may use: the retained generation, only when
it is the credential generation. -/
def leaseGeneration (record credential : Nat) (stored : List Nat) : Option Nat :=
  match retainedGeneration record stored with
  | some retained => if retained = credential then some retained else none
  | none => none

theorem retainStep_ge (record : Nat) (best : Option Nat) (candidate : Nat) :
    (candidate ≤ record → ∃ result, retainStep record best candidate = some result ∧
        candidate ≤ result) ∧
      (∀ current, best = some current →
        ∃ result, retainStep record best candidate = some result ∧ current ≤ result) := by
  constructor
  · intro within
    unfold retainStep
    rcases best with _ | current
    · exact ⟨candidate, by simp [within], Nat.le_refl _⟩
    · by_cases newer : current < candidate
      · exact ⟨candidate, by simp [within, newer], Nat.le_refl _⟩
      · exact ⟨current, by simp [within, newer], by omega⟩
  · intro current known
    subst known
    unfold retainStep
    by_cases within : candidate ≤ record
    · by_cases newer : current < candidate
      · exact ⟨candidate, by simp [within, newer], by omega⟩
      · exact ⟨current, by simp [within, newer], Nat.le_refl _⟩
    · exact ⟨current, by simp [within], Nat.le_refl _⟩

theorem retained_fold_member (record : Nat) (stored : List Nat) :
    ∀ (best : Option Nat) (result : Nat),
      stored.foldl (retainStep record) best = some result →
        best = some result ∨ (result ∈ stored ∧ result ≤ record) := by
  induction stored with
  | nil => intro best result folded; exact Or.inl folded
  | cons candidate rest ih =>
      intro best result folded
      rcases ih (retainStep record best candidate) result folded with stepped | found
      · unfold retainStep at stepped
        by_cases within : candidate ≤ record
        · rcases best with _ | current
          · simp only [within, if_true, Option.some.injEq] at stepped
            exact Or.inr ⟨by simp [stepped], by omega⟩
          · by_cases newer : current < candidate
            · simp only [within, newer, if_true, Option.some.injEq] at stepped
              exact Or.inr ⟨by simp [stepped], by omega⟩
            · simp only [within, newer, if_true, if_false] at stepped
              exact Or.inl stepped
        · simp only [within, if_false] at stepped
          exact Or.inl stepped
      · exact Or.inr ⟨List.mem_cons_of_mem _ found.1, found.2⟩

theorem retained_fold_upper (record : Nat) (stored : List Nat) :
    ∀ (best : Option Nat) (result : Nat),
      stored.foldl (retainStep record) best = some result →
        (∀ x ∈ stored, x ≤ record → x ≤ result) ∧
          (∀ current, best = some current → current ≤ result) := by
  induction stored with
  | nil =>
      intro best result folded
      simp only [List.foldl_nil] at folded
      refine ⟨by simp, ?_⟩
      intro current known
      rw [known] at folded
      simp only [Option.some.injEq] at folded
      omega
  | cons candidate rest ih =>
      intro best result folded
      obtain ⟨later, earlier⟩ := ih (retainStep record best candidate) result folded
      obtain ⟨newGe, keptGe⟩ := retainStep_ge record best candidate
      refine ⟨?_, ?_⟩
      · intro x member within
        rcases List.mem_cons.mp member with same | inRest
        · subst same
          obtain ⟨stepped, steppedEq, ge⟩ := newGe within
          have := earlier stepped steppedEq
          omega
        · exact later x inRest within
      · intro current known
        obtain ⟨stepped, steppedEq, ge⟩ := keptGe current known
        have := earlier stepped steppedEq
        omega

theorem retained_fold_none (record : Nat) (stored : List Nat) :
    ∀ best : Option Nat,
      stored.foldl (retainStep record) best = none ↔
        best = none ∧ ∀ x ∈ stored, record < x := by
  induction stored with
  | nil => intro best; simp
  | cons candidate rest ih =>
      intro best
      rw [List.foldl_cons, ih]
      simp only [List.mem_cons, forall_eq_or_imp]
      unfold retainStep
      by_cases within : candidate ≤ record
      · have notBeyond : ¬ record < candidate := by omega
        rcases best with _ | current
        · simp [within, notBeyond]
        · by_cases newer : current < candidate <;> simp [within, newer, notBeyond]
      · simp only [within, if_false]
        constructor
        · rintro ⟨known, beyond⟩
          exact ⟨known, by omega, beyond⟩
        · rintro ⟨known, _, beyond⟩
          exact ⟨known, beyond⟩

/-- The retained generation is exactly the newest stored generation not after
the record's generation. -/
theorem retained_generation_exact (record : Nat) (stored : List Nat) (result : Nat) :
    retainedGeneration record stored = some result ↔
      result ∈ stored ∧ result ≤ record ∧ ∀ x ∈ stored, x ≤ record → x ≤ result := by
  unfold retainedGeneration
  constructor
  · intro folded
    rcases retained_fold_member record stored none result folded with impossible | found
    · cases impossible
    · exact ⟨found.1, found.2, (retained_fold_upper record stored none result folded).1⟩
  · rintro ⟨member, within, newest⟩
    cases folded : stored.foldl (retainStep record) none with
    | none =>
        have := ((retained_fold_none record stored none).mp folded).2 result member
        omega
    | some other =>
        rcases retained_fold_member record stored none other folded with impossible | found
        · cases impossible
        · have upper := (retained_fold_upper record stored none other folded).1
          have first := upper result member within
          have second := newest other found.1 found.2
          have : result = other := by omega
          rw [this]

/-- The lease leaf selects exactly the credential generation, when it is
stored, not after the record's generation, and no newer stored generation is
also not after it. -/
theorem lease_generation_exact (record credential : Nat) (stored : List Nat) (result : Nat) :
    leaseGeneration record credential stored = some result ↔
      result = credential ∧ credential ∈ stored ∧ credential ≤ record ∧
        ∀ x ∈ stored, x ≤ record → x ≤ credential := by
  unfold leaseGeneration
  cases retained : retainedGeneration record stored with
  | none =>
      simp only [reduceCtorEq, false_iff, not_and]
      intro _ member within _
      cases folded : retainedGeneration record stored with
      | none =>
          unfold retainedGeneration at folded
          have := ((retained_fold_none record stored none).mp folded).2 credential member
          omega
      | some other => rw [retained] at folded; cases folded
  | some retainedValue =>
      have exact := (retained_generation_exact record stored retainedValue).mp retained
      by_cases same : retainedValue = credential
      · subst same
        simp only [if_true, Option.some.injEq]
        constructor
        · intro equal; exact ⟨equal.symm, exact⟩
        · intro holds; exact holds.1.symm
      · simp only [same, if_false, reduceCtorEq, false_iff, not_and]
        intro _ member within newest
        have first := newest retainedValue exact.1 exact.2.1
        have second := exact.2.2 credential member within
        omega

/-! ## The system -/

/-- Administrative state. -/
inductive ConnectionState
  | active
  | disabled
  | revoked
  deriving DecidableEq, Repr

/-- The shared record. `secret` is the secret its credential-reference
commitment names at the credential generation. -/
structure Record where
  generations : Generations
  state : ConnectionState
  secret : Nat
  deriving DecidableEq, Repr

/-- One process's credential store: entries `(generation, secret)`. -/
abbrev Store := List (Nat × Nat)

/-- The secret stored at `generation`. -/
def entryAt (generation : Nat) : Store → Option Nat
  | [] => none
  | entry :: rest => if entry.1 = generation then some entry.2 else entryAt generation rest

/-- Stores `secret` at `generation`, unless an entry for it exists: a store
never replaces a stored secret. -/
def insertAbsent (generation secret : Nat) (store : Store) : Store :=
  match entryAt generation store with
  | some _ => store
  | none => (generation, secret) :: store

/-- The lease rule: the generation leaf, then the commitment of the entry at
that generation. -/
def leaseCore (record : Record) (store : Store) : Option Nat :=
  match leaseGeneration record.generations.generation record.generations.credentialGeneration
      (store.map Prod.fst) with
  | some selected => if entryAt selected store = some record.secret then some selected else none
  | none => none

/-- A credential lease of any purpose. A revoked record refuses every lease,
reconciliation included. -/
def lease (record : Record) (store : Store) : Option Nat :=
  if record.state = .revoked then none else leaseCore record store

/-- The shared record and every host's credential store. -/
structure System where
  record : Record
  stores : Nat → Store

/-- The first host installs `secret` at generation 1. -/
def install (host secret : Nat) : System where
  record := { generations := ⟨1, 1⟩, state := .active, secret := secret }
  stores := fun other => if other = host then [(1, secret)] else []

/-- One administrative event. -/
inductive Event
  | disable
  | enable
  | revoke (host : Nat)
  | rotate (host secret : Nat)
  | join (host secret : Nat)

/-- Replaces one host's store. -/
def update (stores : Nat → Store) (host : Nat) (store : Store) : Nat → Store :=
  fun other => if other = host then store else stores other

/-- A state change to `target` through the generation leaf; unchanged when the
generation would overflow. -/
def changeState (σ : System) (target : ConnectionState) : System :=
  match stateChange σ.record.generations with
  | some generations =>
      { σ with record := { σ.record with generations := generations, state := target } }
  | none => σ

/-- A host takes `secret` at the credential generation only when it is the
secret the record commits to. -/
def accept (σ : System) (host secret : Nat) : System :=
  if secret = σ.record.secret then
    let stored := insertAbsent σ.record.generations.credentialGeneration secret (σ.stores host)
    { σ with stores := update σ.stores host stored }
  else σ

/-- A rotation committed through `host`: the secret is stored at the next
generation, which becomes the credential generation. -/
def commitRotation (σ : System) (host secret : Nat) : System :=
  match rotation σ.record.generations with
  | some generations =>
      { record := { σ.record with generations := generations, secret := secret }
        stores := update σ.stores host (insertAbsent generations.generation secret (σ.stores host)) }
  | none => σ

/-- One event. A refused event leaves the system unchanged. -/
def step (σ : System) : Event → System
  | .disable => if σ.record.state = .active then changeState σ .disabled else σ
  | .enable => if σ.record.state = .disabled then changeState σ .active else σ
  | .revoke host =>
      if σ.record.state = .revoked then { σ with stores := update σ.stores host [] }
      else
        match stateChange σ.record.generations with
        | some generations =>
            { record := { σ.record with generations := generations, state := .revoked }
              stores := update σ.stores host [] }
        | none => σ
  | .rotate host secret =>
      if σ.record.state = .revoked then σ
      else if (leaseCore σ.record (σ.stores host)).isSome then
        if σ.record.state = .active then commitRotation σ host secret else σ
      else accept σ host secret
  | .join host secret => if σ.record.state = .revoked then σ else accept σ host secret

/-- Every system an install and any sequence of events reach. -/
inductive Reachable : System → Prop
  | install (host secret : Nat) : Reachable (install host secret)
  | step {σ : System} (event : Event) : Reachable σ → Reachable (step σ event)

/-- Runs a sequence of events. -/
def run (σ : System) (events : List Event) : System :=
  events.foldl step σ

/-- A state change that stores no secret. -/
inductive StateChange
  | disable
  | enable

/-- The event of a state change. -/
def StateChange.event : StateChange → Event
  | .disable => .disable
  | .enable => .enable

/-- Runs a sequence of state changes. -/
def applyChanges (σ : System) (changes : List StateChange) : System :=
  changes.foldl (fun current change => step current change.event) σ

/-! ## Store lemmas -/

theorem entryAt_mem {generation secret : Nat} :
    ∀ {store : Store}, entryAt generation store = some secret → (generation, secret) ∈ store
  | [], found => by cases found
  | entry :: rest, found => by
      unfold entryAt at found
      by_cases same : entry.1 = generation
      · simp only [same, if_true, Option.some.injEq] at found
        subst found
        rw [← same]
        exact List.mem_cons_self
      · simp only [same, if_false] at found
        exact List.mem_cons_of_mem _ (entryAt_mem found)

theorem entryAt_none {generation : Nat} :
    ∀ {store : Store}, entryAt generation store = none → ∀ entry ∈ store, entry.1 ≠ generation
  | [], _ => by simp
  | head :: rest, absent => by
      unfold entryAt at absent
      by_cases same : head.1 = generation
      · simp [same] at absent
      · simp only [same, if_false] at absent
        intro entry member
        rcases List.mem_cons.mp member with isHead | inRest
        · subst isHead; exact same
        · exact entryAt_none absent entry inRest

theorem mem_insertAbsent {generation secret : Nat} {store : Store} {entry : Nat × Nat}
    (member : entry ∈ insertAbsent generation secret store) :
    entry ∈ store ∨ entry = (generation, secret) := by
  unfold insertAbsent at member
  cases found : entryAt generation store with
  | some _ => rw [found] at member; exact Or.inl member
  | none =>
      rw [found] at member
      rcases List.mem_cons.mp member with isNew | old
      · exact Or.inr isNew
      · exact Or.inl old

theorem mem_insertAbsent_old {generation secret : Nat} {store : Store} {entry : Nat × Nat}
    (member : entry ∈ store) : entry ∈ insertAbsent generation secret store := by
  unfold insertAbsent
  cases entryAt generation store with
  | some _ => exact member
  | none => exact List.mem_cons_of_mem _ member

theorem mem_update {stores : Nat → Store} {host other : Nat} {store : Store} {entry : Nat × Nat}
    (member : entry ∈ update stores host store other) :
    (other = host ∧ entry ∈ store) ∨ entry ∈ stores other := by
  unfold update at member
  by_cases same : other = host
  · simp only [same, if_true] at member
    exact Or.inl ⟨same, member⟩
  · simp only [same, if_false] at member
    exact Or.inr member

/-! ## The invariant -/

/-- What every reachable system keeps: the credential generation is at most
the generation, every stored generation is at most the credential
generation, and every entry at the credential generation holds the secret
the record commits to. -/
structure Invariant (σ : System) : Prop where
  credential_le : σ.record.generations.credentialGeneration ≤ σ.record.generations.generation
  stored_le : ∀ host entry, entry ∈ σ.stores host →
    entry.1 ≤ σ.record.generations.credentialGeneration
  stored_secret : ∀ host entry, entry ∈ σ.stores host →
    entry.1 = σ.record.generations.credentialGeneration → entry.2 = σ.record.secret

theorem install_invariant (host secret : Nat) : Invariant (install host secret) where
  credential_le := by simp [install]
  stored_le := by
    intro other entry member
    simp only [install] at member ⊢
    split at member
    · simp only [List.mem_singleton] at member; subst member; simp
    · simp at member
  stored_secret := by
    intro other entry member _
    simp only [install] at member ⊢
    split at member
    · simp only [List.mem_singleton] at member; subst member; rfl
    · simp at member

theorem stateChange_spec {current next : Generations} (changed : stateChange current = some next) :
    next.generation = current.generation + 1 ∧
      next.credentialGeneration = current.credentialGeneration := by
  unfold stateChange nextGeneration at changed
  split at changed <;> rename_i found
  · split at found
    · simp only [Option.some.injEq] at found changed
      subst found; subst changed
      exact ⟨rfl, rfl⟩
    · cases found
  · cases changed

theorem rotation_spec {current next : Generations} (rotated : rotation current = some next) :
    next.generation = current.generation + 1 ∧ next.credentialGeneration = next.generation := by
  unfold rotation nextGeneration at rotated
  split at rotated <;> rename_i found
  · split at found
    · simp only [Option.some.injEq] at found rotated
      subst found; subst rotated
      exact ⟨rfl, rfl⟩
    · cases found
  · cases rotated

theorem changeState_invariant {σ : System} (target : ConnectionState) (holds : Invariant σ) :
    Invariant (changeState σ target) := by
  unfold changeState
  cases changed : stateChange σ.record.generations with
  | none => exact holds
  | some next =>
      obtain ⟨nextGeneration, kept⟩ := stateChange_spec changed
      exact {
        credential_le := by simp only; have := holds.credential_le; omega
        stored_le := by simpa [kept] using holds.stored_le
        stored_secret := by simpa [kept] using holds.stored_secret }

theorem accept_invariant {σ : System} (host secret : Nat) (holds : Invariant σ) :
    Invariant (accept σ host secret) := by
  unfold accept
  by_cases agrees : secret = σ.record.secret
  · simp only [agrees, if_true]
    refine { credential_le := holds.credential_le, stored_le := ?_, stored_secret := ?_ }
    · intro other entry member
      rcases mem_update member with ⟨same, inserted⟩ | old
      · rcases mem_insertAbsent inserted with previous | isNew
        · subst same; exact holds.stored_le other entry previous
        · subst isNew; exact Nat.le_refl _
      · exact holds.stored_le other entry old
    · intro other entry member atCredential
      rcases mem_update member with ⟨same, inserted⟩ | old
      · rcases mem_insertAbsent inserted with previous | isNew
        · subst same; exact holds.stored_secret other entry previous atCredential
        · subst isNew; rfl
      · exact holds.stored_secret other entry old atCredential
  · simp only [agrees, if_false]; exact holds

theorem commitRotation_invariant {σ : System} (host secret : Nat) (holds : Invariant σ) :
    Invariant (commitRotation σ host secret) := by
  unfold commitRotation
  cases rotated : rotation σ.record.generations with
  | none => exact holds
  | some next =>
      obtain ⟨nextGeneration, credentialIsNext⟩ := rotation_spec rotated
      refine { credential_le := ?_, stored_le := ?_, stored_secret := ?_ }
      · simp only; omega
      · intro other entry member
        simp only at member ⊢
        rcases mem_update member with ⟨same, inserted⟩ | old
        · rcases mem_insertAbsent inserted with previous | isNew
          · subst same
            have := holds.stored_le other entry previous
            have := holds.credential_le
            omega
          · subst isNew; simp [credentialIsNext]
        · have := holds.stored_le other entry old
          have := holds.credential_le
          omega
      · intro other entry member atCredential
        simp only at member atCredential ⊢
        rcases mem_update member with ⟨same, inserted⟩ | old
        · rcases mem_insertAbsent inserted with previous | isNew
          · subst same
            have := holds.stored_le other entry previous
            have := holds.credential_le
            omega
          · subst isNew; rfl
        · have := holds.stored_le other entry old
          have := holds.credential_le
          omega

theorem step_invariant {σ : System} (event : Event) (holds : Invariant σ) :
    Invariant (step σ event) := by
  cases event with
  | disable =>
      simp only [step]
      split
      · exact changeState_invariant _ holds
      · exact holds
  | enable =>
      simp only [step]
      split
      · exact changeState_invariant _ holds
      · exact holds
  | revoke host =>
      simp only [step]
      split
      · refine { credential_le := holds.credential_le, stored_le := ?_, stored_secret := ?_ }
        · intro other entry member
          rcases mem_update member with ⟨_, empty⟩ | old
          · simp at empty
          · exact holds.stored_le other entry old
        · intro other entry member atCredential
          rcases mem_update member with ⟨_, empty⟩ | old
          · simp at empty
          · exact holds.stored_secret other entry old atCredential
      · split
        · rename_i next changed
          obtain ⟨nextGeneration, kept⟩ := stateChange_spec changed
          refine { credential_le := ?_, stored_le := ?_, stored_secret := ?_ }
          · simp only; have := holds.credential_le; omega
          · intro other entry member
            simp only [kept]
            rcases mem_update member with ⟨_, empty⟩ | old
            · simp at empty
            · exact holds.stored_le other entry old
          · intro other entry member atCredential
            simp only [kept] at atCredential ⊢
            rcases mem_update member with ⟨_, empty⟩ | old
            · simp at empty
            · exact holds.stored_secret other entry old atCredential
        · exact holds
  | rotate host secret =>
      simp only [step]
      split
      · exact holds
      · split
        · split
          · exact commitRotation_invariant host secret holds
          · exact holds
        · exact accept_invariant host secret holds
  | join host secret =>
      simp only [step]
      split
      · exact holds
      · exact accept_invariant host secret holds

theorem reachable_invariant {σ : System} (reachable : Reachable σ) : Invariant σ := by
  induction reachable with
  | install host secret => exact install_invariant host secret
  | step event _ holds => exact step_invariant event holds

/-! ## Theorems -/

/-- Every reachable record's credential generation is at most its
generation. -/
theorem credential_generation_le_generation {σ : System} (reachable : Reachable σ) :
    σ.record.generations.credentialGeneration ≤ σ.record.generations.generation :=
  (reachable_invariant reachable).credential_le

/-- A disable or an enable changes only the record's generation and state:
the credential generation, the committed secret, and every host's store are
kept, and the generation advances by one when the change applies. The
generation leaf keeps the credential generation. -/
theorem state_change_preserves_credential_generation :
    (∀ current next : Generations, stateChange current = some next →
        next.generation = current.generation + 1 ∧
          next.credentialGeneration = current.credentialGeneration) ∧
      ∀ (σ : System) (change : StateChange),
        ∃ generation state,
          (step σ change.event).record =
              { σ.record with
                generations := { σ.record.generations with generation := generation }
                state := state } ∧
            (step σ change.event).stores = σ.stores ∧
            (generation = σ.record.generations.generation ∨
              generation = σ.record.generations.generation + 1) := by
  refine ⟨fun _ _ changed => stateChange_spec changed, ?_⟩
  have changeShape : ∀ (σ : System) (target : ConnectionState),
      ∃ generation state,
        (changeState σ target).record =
            { σ.record with
              generations := { σ.record.generations with generation := generation }
              state := state } ∧
          (changeState σ target).stores = σ.stores ∧
          (generation = σ.record.generations.generation ∨
            generation = σ.record.generations.generation + 1) := by
    intro σ target
    unfold changeState
    cases changed : stateChange σ.record.generations with
    | none => exact ⟨σ.record.generations.generation, σ.record.state, by simp, rfl, Or.inl rfl⟩
    | some next =>
        obtain ⟨nextGeneration, kept⟩ := stateChange_spec changed
        refine ⟨next.generation, target, ?_, rfl, Or.inr nextGeneration⟩
        cases next
        simp only at kept
        simp [kept]
  intro σ change
  cases change with
  | disable =>
      simp only [StateChange.event, step]
      split
      · exact changeShape σ _
      · exact ⟨σ.record.generations.generation, σ.record.state, by simp, rfl, Or.inl rfl⟩
  | enable =>
      simp only [StateChange.event, step]
      split
      · exact changeShape σ _
      · exact ⟨σ.record.generations.generation, σ.record.state, by simp, rfl, Or.inl rfl⟩

theorem leaseCore_iff {σ : System} (holds : Invariant σ) (host selected : Nat) :
    leaseCore σ.record (σ.stores host) = some selected ↔
      selected = σ.record.generations.credentialGeneration ∧
        (σ.record.generations.credentialGeneration, σ.record.secret) ∈ σ.stores host := by
  unfold leaseCore
  have leaf := lease_generation_exact σ.record.generations.generation
    σ.record.generations.credentialGeneration ((σ.stores host).map Prod.fst)
  cases leased : leaseGeneration σ.record.generations.generation
      σ.record.generations.credentialGeneration ((σ.stores host).map Prod.fst) with
  | none =>
      constructor
      · intro impossible; cases impossible
      intro ⟨_, member⟩
      have := (leaf σ.record.generations.credentialGeneration).mpr
        ⟨rfl, List.mem_map.mpr ⟨_, member, rfl⟩, holds.credential_le, by
          intro x mapped _
          obtain ⟨entry, entryMember, entryKey⟩ := List.mem_map.mp mapped
          rw [← entryKey]
          exact holds.stored_le host entry entryMember⟩
      rw [leased] at this
      cases this
  | some chosen =>
      have chosenIs := ((leaf chosen).mp leased).1
      subst chosenIs
      dsimp only
      constructor
      · intro accepted
        split at accepted
        · rename_i atCredential
          simp only [Option.some.injEq] at accepted
          exact ⟨accepted.symm, entryAt_mem atCredential⟩
        · cases accepted
      · rintro ⟨selectedIs, member⟩
        subst selectedIs
        cases found : entryAt σ.record.generations.credentialGeneration (σ.stores host) with
        | none =>
            have := entryAt_none found _ member
            exact absurd rfl this
        | some stored =>
            have storedIs := holds.stored_secret host _ (entryAt_mem found) rfl
            simp only at storedIs
            simp [storedIs]

/-- In every reachable system, a lease succeeds exactly when the record is
not revoked and the host's store holds the credential generation with the
record's commitment, and it returns that generation. -/
theorem lease_selects_credential_generation {σ : System} (reachable : Reachable σ)
    (host selected : Nat) :
    lease σ.record (σ.stores host) = some selected ↔
      σ.record.state ≠ .revoked ∧ selected = σ.record.generations.credentialGeneration ∧
        (σ.record.generations.credentialGeneration, σ.record.secret) ∈ σ.stores host := by
  unfold lease
  by_cases revoked : σ.record.state = .revoked
  · simp [revoked]
  · simp only [revoked, if_false, ne_eq, not_false_eq_true, true_and]
    exact leaseCore_iff (reachable_invariant reachable) host selected

theorem applyChanges_keeps {σ : System} (reachable : Reachable σ) (notRevoked : σ.record.state ≠ .revoked) :
    ∀ changes : List StateChange,
      Reachable (applyChanges σ changes) ∧
        (applyChanges σ changes).record.state ≠ .revoked ∧
        (applyChanges σ changes).record.secret = σ.record.secret ∧
        (applyChanges σ changes).record.generations.credentialGeneration =
          σ.record.generations.credentialGeneration := by
  intro changes
  induction changes generalizing σ with
  | nil => exact ⟨reachable, notRevoked, rfl, rfl⟩
  | cons change rest ih =>
      have next : Reachable (step σ change.event) := Reachable.step _ reachable
      obtain ⟨generation, state, recordIs, _, _⟩ :=
        state_change_preserves_credential_generation.2 σ change
      have stateOk : (step σ change.event).record.state ≠ .revoked := by
        cases change with
        | disable =>
            simp only [StateChange.event, step]
            split
            · unfold changeState
              split <;> simp_all
            · exact notRevoked
        | enable =>
            simp only [StateChange.event, step]
            split
            · unfold changeState
              split <;> simp_all
            · exact notRevoked
      obtain ⟨reached, notRevoked', secretKept, credentialKept⟩ := ih next stateOk
      refine ⟨reached, notRevoked', ?_, ?_⟩
      · simp only [applyChanges, List.foldl_cons] at secretKept ⊢
        rw [secretKept, recordIs]
      · simp only [applyChanges, List.foldl_cons] at credentialKept ⊢
        rw [credentialKept, recordIs]

/-- A host that joins after any sequence of disables and enables, holding
the installed or rotated secret the record commits to, leases at the
credential generation. This is the case the credential generation exists
for: the commitment is recomputed under it, not under the current
generation. -/
theorem join_after_state_changes {σ : System} (reachable : Reachable σ)
    (notRevoked : σ.record.state ≠ .revoked) (changes : List StateChange) (host : Nat) :
    lease (step (applyChanges σ changes) (.join host σ.record.secret)).record
        ((step (applyChanges σ changes) (.join host σ.record.secret)).stores host) =
      some σ.record.generations.credentialGeneration := by
  obtain ⟨reached, notRevoked', secretKept, credentialKept⟩ :=
    applyChanges_keeps reachable notRevoked changes
  generalize changedIs : applyChanges σ changes = changed at reached notRevoked' secretKept credentialKept
  have joined : Reachable (step changed (.join host σ.record.secret)) := Reachable.step _ reached
  rw [lease_selects_credential_generation joined]
  have holds := reachable_invariant reached
  have stepIs : step changed (.join host σ.record.secret) = accept changed host σ.record.secret := by
    simp [step, notRevoked']
  rw [stepIs]
  unfold accept
  simp only [← secretKept, if_true]
  refine ⟨notRevoked', credentialKept.symm, ?_⟩
  simp only [update, if_true, secretKept]
  unfold insertAbsent
  cases found : entryAt changed.record.generations.credentialGeneration (changed.stores host) with
  | none => exact List.mem_cons_self
  | some stored =>
      have member := entryAt_mem found
      have storedIs := holds.stored_secret host _ member rfl
      simp only at storedIs
      rw [storedIs, secretKept] at member
      simpa [secretKept] using member

theorem step_keeps_revoked {σ : System} (revoked : σ.record.state = .revoked) (event : Event) :
    (step σ event).record.state = .revoked := by
  cases event <;> simp [step, revoked]

/-- After revocation, no sequence of events produces a lease on any host. -/
theorem revoked_never_leases {σ : System} (revoked : σ.record.state = .revoked)
    (events : List Event) (host : Nat) :
    lease (run σ events).record ((run σ events).stores host) = none := by
  have stays : ∀ (events : List Event) (current : System),
      current.record.state = .revoked → (run current events).record.state = .revoked := by
    intro events
    induction events with
    | nil => intro current known; exact known
    | cons event rest ih =>
        intro current known
        exact ih (step current event) (step_keeps_revoked known event)
  simp [lease, stays events σ revoked]

end Auths.Product.ConnectionGenerations
