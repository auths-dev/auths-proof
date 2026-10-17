import Mathlib.Data.String.Basic
import qualification.aeneas.generated.connections.Funs
import Auths.Product.StrictOrderRefinement
import Auths.Product.RecordTimesRefinement
import Auths.Product.StringConstructorsRefinement
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_connections
namespace Auths.Product.RecordShape.Refinement
abbrev Profile := auths_connections.model.ConnectionProfile
abbrev State := auths_connections.model.ConnectionState
abbrev Error := auths_connections.model.ConnectionRecordError

def textLess (a b : String) : Bool := decide (a < b)
def profileLess (a b : Profile) : Bool := decide (a.id < b.id ∨ (a.id = b.id ∧ a.version.val < b.version.val))

private theorem text_comparison (a b : String) :
    alloc.string.String.Insts.CoreCmpOrd.partialOrdInst.lt a b ⦃ actual => actual = textLess a b ⦄ := by
  simp only [alloc.string.String.Insts.CoreCmpOrd, alloc.string.String.Insts.CoreCmpPartialOrdString,
    auths_connections.core.cmp.PartialOrd.lt.default,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp, _root_.alloc.string.String.Insts.CoreCmpPartialOrdString.partial_cmp, bind_tc_ok, spec_ok, textLess]
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq]
  simpa only [Option.some.injEq] using (compare_lt_iff_lt (a := a) (b := b))

@[step] theorem text_order_exact (values : Slice String) :
    auths_connections.kernel.strictly_sorted_unique
      alloc.string.String.Insts.CoreCmpOrd values ⦃ actual =>
        actual = StrictOrder.Refinement.ordered textLess values.val ⦄ := by
  change _root_.auths_connections.kernel.strictly_sorted_unique _ values ⦃ actual => _ ⦄
  exact StrictOrder.Refinement.strict_order_exact _ textLess text_comparison values

private theorem profile_comparison (a b : Profile) :
    auths_connections.model.ConnectionProfile.Insts.CoreCmpOrd.partialOrdInst.lt a b
      ⦃ actual => actual = profileLess a b ⦄ := by
  simp only [auths_connections.model.ConnectionProfile.Insts.CoreCmpOrd,
    auths_connections.model.ConnectionProfile.Insts.CoreCmpPartialOrdConnectionProfile,
    auths_connections.core.cmp.PartialOrd.lt.default,
    Aeneas.Std.core.cmp.PartialOrd.lt.default, Aeneas.Std.core.cmp.PartialOrd.lt_body,
    auths_connections.model.ConnectionProfile.Insts.CoreCmpPartialOrdConnectionProfile.partial_cmp,
    auths_connections.model.ConnectionProfile.Insts.CoreCmpOrd.cmp,
    auths_connections.model.SemanticId.Insts.CoreCmpOrd.cmp,
    alloc.string.String.Insts.CoreCmpOrd.cmp, _root_.alloc.string.String.Insts.CoreCmpOrd.cmp,
    bind_tc_ok]
  cases compared : compare a.id b.id with
  | eq =>
    have same : a.id = b.id := compare_eq_iff_eq.mp compared
    simp [compared, profileLess, same, compare_lt_iff_lt, UScalar.lt_equiv]
  | lt =>
    have before : a.id < b.id := compare_lt_iff_lt.mp compared
    simp [compared, profileLess, before]
  | gt =>
    have after : b.id < a.id := compare_gt_iff_gt.mp compared
    have notBefore : ¬ a.id < b.id := not_lt_of_gt after
    have notSame : a.id ≠ b.id := ne_of_gt after
    simp [compared, profileLess, notBefore, notSame]

@[step] theorem profile_order_exact (values : Slice Profile) :
    kernel.strictly_sorted_unique model.ConnectionProfile.Insts.CoreCmpOrd values ⦃ actual =>
      actual = StrictOrder.Refinement.ordered profileLess values.val ⦄ := by
  exact StrictOrder.Refinement.strict_order_exact _ profileLess profile_comparison values

def textValid (value : String) : Prop :=
  ConnectionBytes.graphicValid (StringConstructors.Refinement.utf8Bytes value) 128
instance (value : String) : Decidable (textValid value) := inferInstanceAs (Decidable (ConnectionBytes.graphicValid _ _))

def allText : List String → Bool
  | [] => true
  | head :: tail => decide (textValid head) && allText tail

def workloadsValid (values : List String) : Bool :=
  decide (values ≠ [] ∧ values.length ≤ 256) && StrictOrder.Refinement.ordered textLess values && allText values

def profilesValid (values : List Profile) : Bool :=
  decide (values ≠ [] ∧ values.length ≤ 32) && StrictOrder.Refinement.ordered profileLess values

private theorem projected_bytes (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    ConnectionBytes.Refinement.bytes (toStr value bounded).val = StringConstructors.Refinement.utf8Bytes value := by
  simp only [ConnectionBytes.Refinement.bytes, toStr, StringConstructors.Refinement.utf8Bytes, List.map_map, List.map_inj_left]
  intro byte member
  cases byte
  rfl

private theorem graphic_delegation (value : String) (bounded : value.toByteArray.size ≤ U32.max) :
    auths_connections.kernel.ascii_graphic_valid (toStr value bounded) 128#usize
      ⦃ actual => actual = decide (textValid value) ⦄ := by
  change _root_.auths_connections.kernel.ascii_graphic_valid _ _ ⦃ actual => _ ⦄
  apply spec_mono (ConnectionBytes.Refinement.graphic_valid_exact (toStr value bounded) 128#usize)
  intro actual meaning
  rw [meaning]
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq, textValid, projected_bytes]
  have maximum : (128#usize).val = 128 := by scalar_tac
  rw [maximum]

private theorem text_suffix_exact (remaining : List String) (values : Slice String) (index : Std.Usize)
    (suffix : values.val.drop index.val = remaining)
    (bounded : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max) :
    kernel.workloads_valid_loop values index ⦃ actual => actual = allText remaining ⦄ := by
  induction remaining generalizing index with
  | nil =>
    have finished : ¬ index < values.len := by
      have size := congrArg List.length suffix
      simp only [List.length_drop, List.length_nil] at size
      simp only [UScalar.lt_equiv, Slice.len_val, Slice.length]
      omega
    unfold kernel.workloads_valid_loop
    rw [loop.eq_def]
    simp [kernel.workloads_valid_loop.body, finished, allText]
  | cons head rest ih =>
    obtain ⟨guard, indexed⟩ := Auths.StatusSelection.indexed_head values index head rest suffix
    obtain ⟨next, addition, nextValue, nextSuffix⟩ := Auths.StatusSelection.indexed_next values index head rest suffix
    have member : head ∈ values.val := by
      have inside : index.val < values.val.length := by simpa [Slice.length] using guard
      have equal := List.drop_eq_getElem_cons inside
      rw [suffix] at equal
      exact (List.cons.inj equal).1 ▸ List.getElem_mem inside
    have headBound := bounded head member
    obtain ⟨allowed, checked, meaning⟩ := spec_imp_exists (graphic_delegation head headBound)
    unfold kernel.workloads_valid_loop
    rw [loop.eq_def]
    simp only [kernel.workloads_valid_loop.body, guard, ↓reduceIte, indexed,
      alloc.string.String.as_bytes, _root_.alloc.string.String.as_bytes, headBound,
      ↓reduceDIte, checked, bind_tc_ok]
    cases accepted : allowed
    · simp [accepted, allText, ← meaning]
    · simp only [accepted, ↓reduceIte, addition, bind_tc_ok]
      change kernel.workloads_valid_loop values next ⦃ actual => actual = allText (head :: rest) ⦄
      simpa [allText, ← meaning, accepted] using ih next nextSuffix

@[step] theorem workloads_exact (values : Slice String)
    (bounded : ∀ value ∈ values.val, value.toByteArray.size ≤ U32.max) :
    kernel.workloads_valid values ⦃ actual => actual = workloadsValid values.val ⦄ := by
  have limit : model.MAX_WORKLOADS.val = 256 := by unfold model.MAX_WORKLOADS; scalar_tac
  unfold kernel.workloads_valid
  step as ⟨empty, emptyMeaning⟩
  cases empty
  · simp only [Bool.false_eq_true, ↓reduceIte]
    have nonempty : values.val ≠ [] := by simpa [Slice.length] using emptyMeaning.symm
    split <;> rename_i exceeds
    · have large : 256 < values.val.length := by simpa [Slice.length, limit] using exceeds
      simp [workloadsValid, large.not_ge]
    · have fits : values.val.length ≤ 256 := by simpa [Slice.length, limit] using exceeds
      step with text_order_exact as ⟨ordered, orderedMeaning⟩
      cases accepted : ordered
      · simp [accepted, workloadsValid, nonempty, fits, ← orderedMeaning]
      · simp only [accepted, ↓reduceIte]
        simpa [workloadsValid, nonempty, fits, ← orderedMeaning, accepted] using text_suffix_exact values.val values 0#usize (by simp) bounded
  · have empty : values.val = [] := by simpa [Slice.length] using emptyMeaning.symm
    simp [workloadsValid, empty]

@[step] theorem profiles_exact (values : Slice Profile) :
    kernel.profiles_valid values ⦃ actual => actual = profilesValid values.val ⦄ := by
  have limit : model.MAX_PROFILES.val = 32 := by unfold model.MAX_PROFILES; scalar_tac
  unfold kernel.profiles_valid
  step as ⟨empty, emptyMeaning⟩
  cases empty
  · simp only [Bool.false_eq_true, ↓reduceIte]
    have nonempty : values.val ≠ [] := by simpa [Slice.length] using emptyMeaning.symm
    split <;> rename_i fits
    · have bound : values.val.length ≤ 32 := by simpa [Slice.length, limit] using fits
      change _root_.auths_connections.kernel.strictly_sorted_unique _ values ⦃ actual => _ ⦄
      simpa [profilesValid, nonempty, bound] using StrictOrder.Refinement.strict_order_exact _ profileLess profile_comparison values
    · have large : ¬ values.val.length ≤ 32 := by simpa [Slice.length, limit] using fits
      simp [profilesValid, large]
  · have empty : values.val = [] := by simpa [Slice.length] using emptyMeaning.symm
    simp [profilesValid, empty]


def stateView : State → _root_.auths_connections.model.ConnectionState
  | .Active => .Active
  | .Disabled => .Disabled
  | .Revoked => .Revoked

@[step] private theorem times_exact (state : State) (created updated : Std.U64) (revoked : Option Std.U64) :
    auths_connections.kernel.record_times_valid state created updated revoked ⦃ actual =>
      actual = decide (RecordTimes.Refinement.valid (stateView state) created.val updated.val (revoked.map (·.val))) ⦄ := by
  have same : auths_connections.kernel.record_times_valid state created updated revoked =
      _root_.auths_connections.kernel.record_times_valid (stateView state) created updated revoked := by
    cases state <;> cases revoked <;> rfl
  rw [same]
  exact RecordTimes.Refinement.record_times_exact (stateView state) created updated revoked

def verdict (workloads : List String) (profiles : List Profile) (state : State)
    (created updated : Nat) (revoked : Option Nat) : core.result.Result Unit Error :=
  if workloadsValid workloads then
    if profilesValid profiles then
      if RecordTimes.Refinement.valid (stateView state) created updated revoked then .Ok ()
      else .Err .InvalidTimestamps
    else .Err .InvalidProfiles
  else .Err .InvalidWorkloads

@[step] theorem record_shape_exact (workloads : Slice String) (profiles : Slice Profile) (state : State)
    (created updated : Std.U64) (revoked : Option Std.U64)
    (bounded : ∀ value ∈ workloads.val, value.toByteArray.size ≤ U32.max) :
    kernel.validate_record_shape workloads profiles state created updated revoked ⦃ actual =>
      actual = verdict workloads.val profiles.val state created.val updated.val (revoked.map (·.val)) ⦄ := by
  unfold kernel.validate_record_shape
  step with workloads_exact workloads bounded as ⟨works, workMeaning⟩
  cases accepted : works
  · simp [accepted, verdict, ← workMeaning]
  · simp only [accepted, ↓reduceIte]
    step with profiles_exact as ⟨profs, profileMeaning⟩
    cases acceptedProfiles : profs
    · simp [acceptedProfiles, verdict, ← workMeaning, accepted, ← profileMeaning]
    · simp only [acceptedProfiles, ↓reduceIte]
      step with times_exact as ⟨times, timeMeaning⟩
      cases acceptedTimes : times <;>
        simp_all [verdict]

private theorem all_text_exact (values : List String) :
    allText values = true ↔ ∀ value ∈ values, textValid value := by
  induction values with
  | nil => simp [allText]
  | cons head rest ih => simp [allText, ih]

private theorem text_less_transitive (a b c : String) :
    textLess a b = true → textLess b c = true → textLess a c = true := by
  simp only [textLess, decide_eq_true_eq]
  exact lt_trans

private theorem text_less_irreflexive (value : String) : textLess value value = false := by
  simp [textLess]

private theorem profile_less_transitive (a b c : Profile) :
    profileLess a b = true → profileLess b c = true → profileLess a c = true := by
  simp only [profileLess, decide_eq_true_eq]
  intro left right
  rcases left with left | ⟨idsLeft, versionsLeft⟩ <;>
    rcases right with right | ⟨idsRight, versionsRight⟩
  · exact Or.inl (lt_trans left right)
  · exact Or.inl (idsRight ▸ left)
  · exact Or.inl (idsLeft.symm ▸ right)
  · exact Or.inr ⟨idsLeft.trans idsRight, by omega⟩

private theorem profile_less_irreflexive (value : Profile) : profileLess value value = false := by
  simp [profileLess]

/-- The record's collection/text/time requirements, stated without an algorithm
or its acceptance predicate. Ordering is global over every earlier/later pair. -/
def requirements (workloads : List String) (profiles : List Profile) (state : State)
    (created updated : Nat) (revoked : Option Nat) : Prop :=
  workloads ≠ [] ∧ workloads.length ≤ 256 ∧
  workloads.Pairwise (fun a b => a < b) ∧ (∀ value ∈ workloads, textValid value) ∧
  profiles ≠ [] ∧ profiles.length ≤ 32 ∧
  profiles.Pairwise (fun a b => a.id < b.id ∨ (a.id = b.id ∧ a.version.val < b.version.val)) ∧
  RecordTimes.Refinement.valid (stateView state) created updated revoked

private theorem ordered_of_pairwise {T : Type} (less : T → T → Bool)
    (values : List T) (sorted : values.Pairwise (fun a b => less a b = true)) :
    StrictOrder.Refinement.ordered less values = true := by
  induction values with
  | nil => rfl
  | cons first rest ih =>
    have facts := List.pairwise_cons.mp sorted
    have tailOrder := ih facts.2
    cases rest with
    | nil => rfl
    | cons next tail =>
      have firstNext := facts.1 next (by simp)
      simpa only [StrictOrder.Refinement.ordered, StrictOrder.Refinement.chain,
        Bool.and_eq_true] using And.intro firstNext tailOrder

private theorem ordered_iff_pairwise {T : Type} (less : T → T → Bool)
    (transitive : ∀ a b c, less a b = true → less b c = true → less a c = true)
    (values : List T) :
    StrictOrder.Refinement.ordered less values = true ↔ values.Pairwise (fun a b => less a b = true) :=
  ⟨StrictOrder.Refinement.ordered_implies_pairwise less transitive values, ordered_of_pairwise less values⟩

private theorem workloads_iff (values : List String) :
    workloadsValid values = true ↔ values ≠ [] ∧ values.length ≤ 256 ∧
      values.Pairwise (fun a b => a < b) ∧ ∀ value ∈ values, textValid value := by
  simp only [workloadsValid, Bool.and_eq_true, decide_eq_true_eq,
    ordered_iff_pairwise textLess text_less_transitive, textLess, all_text_exact]
  tauto

private theorem profiles_iff (values : List Profile) :
    profilesValid values = true ↔ values ≠ [] ∧ values.length ≤ 32 ∧
      values.Pairwise (fun a b => a.id < b.id ∨ (a.id = b.id ∧ a.version.val < b.version.val)) := by
  simp only [profilesValid, Bool.and_eq_true, decide_eq_true_eq,
    ordered_iff_pairwise profileLess profile_less_transitive, profileLess]
  tauto

private theorem verdict_iff (workloads : List String) (profiles : List Profile) (state : State)
    (created updated : Nat) (revoked : Option Nat) :
    verdict workloads profiles state created updated revoked = .Ok () ↔
      requirements workloads profiles state created updated revoked := by
  have meaning : requirements workloads profiles state created updated revoked ↔
      workloadsValid workloads = true ∧ profilesValid profiles = true ∧
      RecordTimes.Refinement.valid (stateView state) created updated revoked := by
    rw [workloads_iff, profiles_iff]
    unfold requirements
    tauto
  rw [meaning]
  unfold verdict
  cases works : workloadsValid workloads <;> cases profs : profilesValid profiles <;>
    simp only [works, profs, Bool.false_eq_true, ↓reduceIte, false_and, true_and]
  all_goals try split_ifs
  all_goals simp_all


private theorem success_invariants_core (workloads : Slice String) (profiles : Slice Profile) (state : State)
    (created updated : Std.U64) (revoked : Option Std.U64)
    (bounded : ∀ value ∈ workloads.val, value.toByteArray.size ≤ U32.max) :
    kernel.validate_record_shape workloads profiles state created updated revoked ⦃ actual =>
      actual = .Ok () →
        workloads.val ≠ [] ∧ workloads.val.length ≤ 256 ∧ workloads.val.Nodup ∧
        (∀ value ∈ workloads.val, textValid value) ∧
        profiles.val ≠ [] ∧ profiles.val.length ≤ 32 ∧ profiles.val.Nodup ∧
        RecordTimes.Refinement.valid (stateView state) created.val updated.val (revoked.map (·.val)) ⦄ := by
  step with record_shape_exact workloads profiles state created updated revoked bounded as ⟨actual, meaning⟩
  rename_i accepted
  rw [accepted] at meaning
  unfold verdict at meaning
  split at meaning <;> rename_i works
  · split at meaning <;> rename_i profs
    · split at meaning <;> rename_i times
      · have workFacts := works
        have profileFacts := profs
        simp only [workloadsValid, Bool.and_eq_true, decide_eq_true_eq] at workFacts
        simp only [profilesValid, Bool.and_eq_true, decide_eq_true_eq] at profileFacts
        exact ⟨workFacts.1.1.1, workFacts.1.1.2,
          StrictOrder.Refinement.ordered_implies_no_duplicates textLess text_less_transitive text_less_irreflexive _ workFacts.1.2,
          (all_text_exact _).mp workFacts.2,
          profileFacts.1.1, profileFacts.1.2,
          StrictOrder.Refinement.ordered_implies_no_duplicates profileLess profile_less_transitive profile_less_irreflexive _ profileFacts.2,
          times⟩
      · contradiction
    · contradiction
  · contradiction
/-- Exact acceptance against independent global requirements, together with the
success-earned bounds, text validity, duplicate absence and time shape. -/
theorem success_earns_all_invariants (workloads : Slice String) (profiles : Slice Profile) (state : State)
    (created updated : Std.U64) (revoked : Option Std.U64)
    (bounded : ∀ value ∈ workloads.val, value.toByteArray.size ≤ U32.max) :
    auths_connections.kernel.validate_record_shape workloads profiles state created updated revoked ⦃ actual =>
      (actual = .Ok () ↔ requirements workloads.val profiles.val state created.val updated.val (revoked.map (·.val))) ∧
      (actual = .Ok () →
        workloads.val ≠ [] ∧ workloads.val.length ≤ 256 ∧ workloads.val.Nodup ∧
        (∀ value ∈ workloads.val, textValid value) ∧
        profiles.val ≠ [] ∧ profiles.val.length ≤ 32 ∧ profiles.val.Nodup ∧
        RecordTimes.Refinement.valid (stateView state) created.val updated.val (revoked.map (·.val))) ⦄ := by
  obtain ⟨actual, evaluated, invariants⟩ := spec_imp_exists
    (success_invariants_core workloads profiles state created updated revoked bounded)
  have exactMeaning := record_shape_exact workloads profiles state created updated revoked bounded
  simp only [evaluated, spec_ok] at exactMeaning
  simp only [evaluated, spec_ok]
  constructor
  · rw [exactMeaning]
    exact verdict_iff _ _ _ _ _ _
  · exact invariants

end Auths.Product.RecordShape.Refinement
