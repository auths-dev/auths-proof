import Auths.Product.AdmissionHistory
namespace Auths.Product.AdmissionHistory

structure SingleOwner (state : State) : Prop where
  handleClaimed : ∀ operation worker, state.handles operation = some worker → state.claims operation = some worker
  pending : ∀ operation worker, state.handles operation = some worker → operation ∉ state.entries.map Prod.fst
  unique : (state.entries.map Prod.fst).Nodup
  entryClaimed : ∀ entry ∈ state.entries, state.claims entry.1 = some entry.2

theorem admitted_claim_stays (policy : Policy) (state : State) (request : Request)
    (acknowledged : Bool) (operation : Operation) (worker : Worker)
    (known : state.claims operation = some worker) :
    (admit policy state request acknowledged).claims operation = some worker := by
  unfold admit
  split
  · rename_i admitted
    have different : operation ≠ request.operation := by
      intro same
      have absent := admitted.1
      rw [← same, known] at absent
      contradiction
    simp [Function.update, different, known]
  · exact known

theorem admit_preserves_owner (policy : Policy) (state : State) (request : Request)
    (acknowledged : Bool) (valid : SingleOwner state) :
    SingleOwner (admit policy state request acknowledged) := by
  unfold admit
  split
  · rename_i admitted
    have fresh : request.operation ∉ state.entries.map Prod.fst := by
      intro member
      obtain ⟨entry, included, same⟩ := List.mem_map.mp member
      have occupied := valid.entryClaimed entry included
      rw [same, admitted.1] at occupied
      contradiction
    constructor
    · intro operation worker handle
      by_cases same : operation = request.operation
      · subst operation
        cases acknowledged with
        | false => simp at handle
        | true =>
          have sameWorker : request.worker = worker := by simpa using handle
          simp [sameWorker]
      · have previous : state.handles operation = some worker := by simpa [Function.update, same] using handle
        simpa [Function.update, same] using valid.handleClaimed operation worker previous
    · intro operation worker handle
      by_cases same : operation = request.operation
      · simpa only [same] using fresh
      · exact valid.pending operation worker (by simpa [Function.update, same] using handle)
    · exact valid.unique
    · intro entry included
      have previous := valid.entryClaimed entry included
      have different : entry.1 ≠ request.operation := by
        intro same
        rw [same, admitted.1] at previous
        contradiction
      simpa [Function.update, different] using previous
  · exact valid

theorem enter_preserves_owner (state : State) (operation : Operation) (worker : Worker)
    (valid : SingleOwner state) : SingleOwner (enter state operation worker) := by
  unfold enter
  split
  · rename_i handle
    have fresh := valid.pending operation worker handle
    constructor
    · intro other owner present
      have different : other ≠ operation := by
        intro same; simp [same] at present
      exact valid.handleClaimed other owner (by simpa [Function.update, different] using present)
    · intro other owner present
      have different : other ≠ operation := by
        intro same; simp [same] at present
      have absent := valid.pending other owner (by simpa [Function.update, different] using present)
      simpa [List.map_append, List.mem_append, different] using absent
    · simp only [List.map_append, List.map_cons, List.map_nil, List.nodup_append]
      refine ⟨valid.unique, by simp, ?_⟩
      intro prior priorMember new newMember equal
      have same : new = operation := by simpa using newMember
      have priorIsOperation : prior = operation := equal.trans same
      exact fresh (priorIsOperation ▸ priorMember)
    · intro entry included
      rcases List.mem_append.mp included with previous | newEntry
      · exact valid.entryClaimed entry previous
      · have same := List.mem_singleton.mp newEntry
        subst entry
        exact valid.handleClaimed operation worker handle
  · exact valid

theorem crash_preserves_owner (state : State) (worker : Worker) (valid : SingleOwner state) :
    SingleOwner (crash state worker) := by
  constructor
  · intro operation owner handle
    change (if state.handles operation = some worker then none else state.handles operation) = some owner at handle
    split_ifs at handle
    exact valid.handleClaimed operation owner handle
  · intro operation owner handle
    change (if state.handles operation = some worker then none else state.handles operation) = some owner at handle
    split_ifs at handle
    exact valid.pending operation owner handle
  · exact valid.unique
  · exact valid.entryClaimed

theorem step_preserves_owner (policy : Policy) (state : State) (event : Event)
    (valid : SingleOwner state) : SingleOwner (step policy state event) := by
  cases event with
  | admission request acknowledged => exact admit_preserves_owner policy state request acknowledged valid
  | collection cutoff =>
    exact ⟨valid.handleClaimed, valid.pending, valid.unique, valid.entryClaimed⟩
  | processCrash worker => exact crash_preserves_owner state worker valid
  | writeEntry operation worker => exact enter_preserves_owner state operation worker valid
  | readOnlyRecovery => exact valid
  | failedBeforeCommit => exact valid
  | terminalRefusal operation worker =>
    exact admit_preserves_owner policy state ⟨operation, worker, []⟩ false valid

theorem run_preserves_owner (policy : Policy) (events : List Event) (initial : State)
    (valid : SingleOwner initial) : SingleOwner (run policy initial events) := by
  induction events generalizing initial with
  | nil => exact valid
  | cons event rest ih => exact ih _ (step_preserves_owner policy initial event valid)

theorem claim_has_one_owner (policy : Policy) (events : List Event) :
    SingleOwner (run policy empty events) := by
  apply run_preserves_owner
  constructor
  · intros; contradiction
  · intros; contradiction
  · exact List.nodup_nil
  · simp [empty]

/-- Lost acknowledgements never grant a volatile handle, including on the
    successful-commit branch; replay cannot recover that write capability. -/
theorem unacknowledged_has_no_new_handle (policy : Policy) (state : State) (request : Request)
    (valid : SingleOwner state) (fresh : state.claims request.operation = none) :
    (admit policy state request false).handles request.operation = none := by
  have previous : state.handles request.operation = none := by
    cases handle : state.handles request.operation with
    | none => rfl
    | some worker =>
      have occupied := valid.handleClaimed request.operation worker handle
      rw [fresh] at occupied
      contradiction
  unfold admit
  split
  · simp
  · exact previous

theorem recovery_mints_no_handle (policy : Policy) (state : State) :
    (step policy state .readOnlyRecovery).handles = state.handles := rfl

/-- A durable logical identity blocks the entire repeated admission, even
when another worker supplies different debit vectors or acknowledgement state. -/
theorem an_existing_claim_blocks_every_repeated_admission
    (policy : Policy) (state : State) (request : Request) (acknowledged : Bool) (owner : Worker)
    (claimed : state.claims request.operation = some owner) :
    admit policy state request acknowledged = state := by
  simp [admit, claimed]

theorem step_preserves_durable_claim (policy : Policy) (state : State) (event : Event)
    (operation : Operation) (owner : Worker) (claimed : state.claims operation = some owner) :
    (step policy state event).claims operation = some owner := by
  cases event with
  | admission request acknowledged => exact admitted_claim_stays policy state request acknowledged operation owner claimed
  | collection cutoff => exact claimed
  | processCrash worker => exact claimed
  | writeEntry target worker =>
    unfold step enter
    split <;> exact claimed
  | readOnlyRecovery => exact claimed
  | failedBeforeCommit => exact claimed
  | terminalRefusal target worker =>
    exact admitted_claim_stays policy state ⟨target, worker, []⟩ false operation owner claimed

/-- Arbitrarily many later workers, crashes, collection events and read-only
recoveries cannot remove or transfer a durable claim. -/
theorem every_history_suffix_preserves_durable_claim
    (policy : Policy) (events : List Event) (initial : State) (operation : Operation) (owner : Worker)
    (claimed : initial.claims operation = some owner) :
    (run policy initial events).claims operation = some owner := by
  induction events generalizing initial with
  | nil => exact claimed
  | cons event rest ih =>
    exact ih _ (step_preserves_durable_claim policy initial event operation owner claimed)

theorem a_claimed_prefix_cannot_reopen_in_a_suffix
    (policy : Policy) (prefix suffix : List Event) (operation : Operation) (owner : Worker)
    (claimed : (run policy empty prefix).claims operation = some owner) :
    (run policy empty (prefix ++ suffix)).claims operation = some owner := by
  simpa [run, List.foldl_append] using
    every_history_suffix_preserves_durable_claim policy suffix (run policy empty prefix) operation owner claimed

/-- A post-commit acknowledgement loss preserves the same claim, charges and
entry history as acknowledged success. Only the volatile handle differs. -/
theorem acknowledgement_loss_preserves_every_durable_admission_field
    (policy : Policy) (state : State) (request : Request) :
    (admit policy state request false).claims = (admit policy state request true).claims ∧
    (admit policy state request false).slots = (admit policy state request true).slots ∧
    (admit policy state request false).historical = (admit policy state request true).historical ∧
    (admit policy state request false).entries = (admit policy state request true).entries ∧
    (admit policy state request false).collectedThrough = (admit policy state request true).collectedThrough := by
  unfold admit
  split_ifs <;> exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem committed_unacknowledged_claim_survives_every_later_history
    (policy : Policy) (state : State) (request : Request) (later : List Event)
    (fresh : state.claims request.operation = none) (fits : fits policy state request = true) :
    (run policy (admit policy state request false) later).claims request.operation = some request.worker := by
  apply every_history_suffix_preserves_durable_claim
  simp [admit, fresh, fits]

/-- Even a successful committed-but-unacknowledged reservation grants no
new execution entry on its own; a later crash or recovery cannot restore one. -/
theorem committed_unacknowledged_has_no_entry_handle
    (policy : Policy) (state : State) (request : Request)
    (valid : SingleOwner state) (fresh : state.claims request.operation = none) :
    (enter (admit policy state request false) request.operation request.worker).entries = state.entries := by
  have absent := unacknowledged_has_no_new_handle policy state request valid fresh
  have entries : (admit policy state request false).entries = state.entries := by
    unfold admit
    split <;> rfl
  simpa [enter, absent] using entries

theorem admission_preserves_a_claimed_absent_handle
    (policy : Policy) (state : State) (request : Request) (acknowledged : Bool)
    (operation : Operation) (owner : Worker)
    (claimed : state.claims operation = some owner) (absent : state.handles operation = none) :
    (admit policy state request acknowledged).handles operation = none := by
  unfold admit
  split
  · rename_i admitted
    have different : operation ≠ request.operation := by
      intro same
      have fresh := admitted.1
      rw [← same, claimed] at fresh
      contradiction
    simp [Function.update, different, absent]
  · exact absent

theorem step_preserves_a_claimed_absent_handle
    (policy : Policy) (state : State) (event : Event) (operation : Operation) (owner : Worker)
    (claimed : state.claims operation = some owner) (absent : state.handles operation = none) :
    (step policy state event).handles operation = none := by
  cases event with
  | admission request acknowledged =>
    exact admission_preserves_a_claimed_absent_handle policy state request acknowledged operation owner claimed absent
  | collection cutoff => exact absent
  | processCrash worker => simp [step, crash, absent]
  | writeEntry target worker =>
    unfold step enter
    split
    · by_cases same : operation = target
      · simp [Function.update, same]
      · simpa [Function.update, same] using absent
    · exact absent
  | readOnlyRecovery => exact absent
  | failedBeforeCommit => exact absent
  | terminalRefusal target worker =>
    exact admission_preserves_a_claimed_absent_handle policy state ⟨target, worker, []⟩ false operation owner claimed absent

theorem every_history_suffix_preserves_a_claimed_absent_handle
    (policy : Policy) (events : List Event) (initial : State) (operation : Operation) (owner : Worker)
    (claimed : initial.claims operation = some owner) (absent : initial.handles operation = none) :
    (run policy initial events).handles operation = none := by
  induction events generalizing initial with
  | nil => exact absent
  | cons event rest ih =>
    exact ih _
      (step_preserves_durable_claim policy initial event operation owner claimed)
      (step_preserves_a_claimed_absent_handle policy initial event operation owner claimed absent)

/-- The lost-acknowledgement branch is not permission to retry a provider write:
no later worker, recovery, collection, crash or replay restores its lost handle. -/
theorem a_committed_lost_ack_never_mints_a_later_handle
    (policy : Policy) (state : State) (request : Request) (later : List Event)
    (valid : SingleOwner state) (fresh : state.claims request.operation = none)
    (accepted : fits policy state request = true) :
    (run policy (admit policy state request false) later).handles request.operation = none := by
  have claimed : (admit policy state request false).claims request.operation = some request.worker := by
    simp [admit, fresh, accepted]
  exact every_history_suffix_preserves_a_claimed_absent_handle policy later
    (admit policy state request false) request.operation request.worker claimed
    (unacknowledged_has_no_new_handle policy state request valid fresh)

end Auths.Product.AdmissionHistory
