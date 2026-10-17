import Auths.Product.ConnectionEntry
import Auths.Product.Refinement.SchemaIndex
open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.SchemaIndex.Refinement
namespace Auths.Product.ConnectionEntry.Refinement
set_option maxHeartbeats 4000000
abbrev bytes (values : List Std.U8) : List Nat := values.map (·.val)
theorem bytes_injective (left right : List Std.U8) : bytes left = bytes right ↔ left = right :=
  Auths.Product.Refinement.Gateway.byteList_inj
def profileView (value : entry_authorization.EntryProfile) : Profile :=
  ⟨bytes value.id.val, value.version.val⟩
def profilesView (values : Slice entry_authorization.EntryProfile) : List Profile := values.val.map profileView

def stateView : entry_authorization.EntryState → State
  | .Active => .active
  | .Disabled => .disabled
  | .Revoked => .revoked

@[step] theorem profile_allowed_exact (profiles : Slice entry_authorization.EntryProfile)
    (requested : entry_authorization.EntryProfile) :
    entry_authorization.profile_allowed profiles requested ⦃ actual =>
      actual = decide (profileView requested ∈ profilesView profiles) ⦄ := by
  unfold entry_authorization.profile_allowed entry_authorization.profile_allowed_loop
  apply loop.spec_decr_nat
    (measure := fun index => profiles.val.length - index.val)
    (inv := fun index => index.val ≤ profiles.val.length ∧
      ∀ position, position < index.val → (profilesView profiles)[position]? ≠ some (profileView requested))
  · intro index processed
    unfold entry_authorization.profile_allowed_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < profiles.val.length := by simpa using within
      step as ⟨profile, profileAt⟩
      have atModel : (profilesView profiles)[index.val]? = some (profileView profile) := by
        simp [profilesView, List.getElem?_map, List.getElem?_eq_getElem inside, profileAt]
      split <;> rename_i versionEq
      · step with field_name_equal_exact as ⟨sameId, idMeaning⟩
        cases sameId
        · simp only [Bool.false_eq_true, ↓reduceIte]
          step as ⟨next, nextEq⟩
          refine ⟨by omega, ?_, by omega⟩
          intro position before
          by_cases earlier : position < index.val
          · exact processed.2 position earlier
          · have current : position = index.val := by omega
            subst position
            rw [atModel]
            intro same
            have ids := congrArg Profile.id (Option.some.inj same)
            have equalIds := (bytes_injective _ _).mp ids
            simp [alloc.vec.Vec.deref, equalIds] at idMeaning
        · simp only [↓reduceIte, spec_ok]
          have same : profileView profile = profileView requested := by
            have equalIds : profile.id.val = requested.id.val := by simpa [alloc.vec.Vec.deref] using idMeaning.symm
            have equalVersions : profile.version.val = requested.version.val := congrArg UScalar.val versionEq
            simp [profileView, equalIds, equalVersions]
          have member : profileView requested ∈ profilesView profiles :=
            List.mem_iff_getElem?.mpr ⟨index.val, by simpa [same] using atModel⟩
          simp [member]
      · step as ⟨next, nextEq⟩
        refine ⟨by omega, ?_, by omega⟩
        intro position before
        by_cases earlier : position < index.val
        · exact processed.2 position earlier
        · have current : position = index.val := by omega
          subst position
          rw [atModel]
          intro same
          have versions := congrArg Profile.version (Option.some.inj same)
          have nativeSame : profile.version = requested.version := (UScalar.eq_equiv _ _).mpr versions
          exact versionEq nativeSame
    · simp only [spec_ok]
      have atEnd : profiles.val.length ≤ index.val := by simpa using within
      have absent : profileView requested ∉ profilesView profiles := by
        intro member
        obtain ⟨position, atPosition⟩ := List.mem_iff_getElem?.mp member
        have inside : position < (profilesView profiles).length := (List.getElem?_eq_some_iff.mp atPosition).1
        have before : position < index.val := by simpa only [profilesView, List.length_map] using (show position < profiles.val.length by simpa [profilesView] using inside) |> fun bound => lt_of_lt_of_le bound atEnd
        exact processed.2 position before atPosition
      simp [absent]
  · exact ⟨by simp, by simp⟩


@[step] theorem entry_allows_exact (state : entry_authorization.EntryState)
    (workloads : Slice (alloc.vec.Vec Std.U8)) (profiles : Slice entry_authorization.EntryProfile)
    (workload : Slice Std.U8) (profile : entry_authorization.EntryProfile) :
    entry_authorization.entry_allows state workloads profiles workload profile ⦃ actual =>
      actual = allows (stateView state) (namesView workloads) (profilesView profiles)
        (bytes workload.val) (profileView profile) ⦄ := by
  cases hstate : state with
  | Disabled => simp [entry_authorization.entry_allows, allows, valid, stateView]
  | Revoked => simp [entry_authorization.entry_allows, allows, valid, stateView]
  | Active =>
    unfold entry_authorization.entry_allows
    dsimp only
    step with field_index_spec as ⟨position, positionMeaning⟩
    cases position with
    | none =>
      simp only [spec_ok]
      have absent : bytes workload.val ∉ namesView workloads :=
        (SchemaIndex.absent_iff _ _).mp positionMeaning.symm
      simp [allows, valid, stateView, absent]
    | some index =>
      have atIndex := SchemaIndex.position_points_to_name _ _ index.val positionMeaning.symm
      have member : bytes workload.val ∈ namesView workloads :=
        List.mem_iff_getElem?.mpr ⟨index.val, atIndex⟩
      step with profile_allowed_exact as ⟨actual, profileMeaning⟩
      simpa [allows, valid, stateView, member] using profileMeaning


theorem source_entry_requires_active_workload_profile (state : entry_authorization.EntryState)
    (workloads : Slice (alloc.vec.Vec Std.U8)) (profiles : Slice entry_authorization.EntryProfile)
    (workload : Slice Std.U8) (profile : entry_authorization.EntryProfile) :
    entry_authorization.entry_allows state workloads profiles workload profile ⦃ actual =>
      actual = true → stateView state = .active ∧ bytes workload.val ∈ namesView workloads ∧
        profileView profile ∈ profilesView profiles ⦄ := by
  step with entry_allows_exact as ⟨actual, exactMeaning⟩
  rename_i accepted
  rw [accepted] at exactMeaning
  exact admitted_binds_all _ _ _ _ _ exactMeaning.symm

theorem source_disabled_refused (workloads : Slice (alloc.vec.Vec Std.U8))
    (profiles : Slice entry_authorization.EntryProfile) (workload : Slice Std.U8)
    (profile : entry_authorization.EntryProfile) :
    entry_authorization.entry_allows .Disabled workloads profiles workload profile ⦃ actual => actual = false ⦄ := by
  step with entry_allows_exact as ⟨actual, exactMeaning⟩
  simpa [allows, valid, stateView] using exactMeaning

theorem source_revoked_refused (workloads : Slice (alloc.vec.Vec Std.U8))
    (profiles : Slice entry_authorization.EntryProfile) (workload : Slice Std.U8)
    (profile : entry_authorization.EntryProfile) :
    entry_authorization.entry_allows .Revoked workloads profiles workload profile ⦃ actual => actual = false ⦄ := by
  step with entry_allows_exact as ⟨actual, exactMeaning⟩
  simpa [allows, valid, stateView] using exactMeaning

end Auths.Product.ConnectionEntry.Refinement


