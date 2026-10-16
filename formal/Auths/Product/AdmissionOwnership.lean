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

end Auths.Product.AdmissionHistory
