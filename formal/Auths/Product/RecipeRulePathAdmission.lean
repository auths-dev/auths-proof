import Auths.Product.RecipeRuleAdmissionConsequences
import Auths.Product.NativeCompilerRuleNames

namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeConsumption RequestConstruction
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

/-- Presence is transported through the complete original map association,
then the original layout earns the exact byte-token rule. No selected field,
expected index or reduced map is supplied. -/
theorem field_test_earns_original_plan_name (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (test : ScalarProjection.Schema → Bool) (name : String) (admitted : fieldTest test fields name = true) :
    OperationIdentity.validToken (textBytes name) 64 = true ∧ textBytes name ∈ FieldProjection.names original := by
  have present := field_test_earns_presence test fields name admitted
  obtain ⟨entry, member, keyAt⟩ := List.mem_map.mp present
  obtain ⟨field, fieldMember, bytesAt, _⟩ := Rules.meaning_has_no_extra_entries original fields meaning entry member
  have originalName : textBytes name = field.name := by simpa only [keyAt] using bytesAt
  exact ⟨by simpa only [originalName] using layout.2.2 field fieldMember,
    List.mem_map.mpr ⟨field, fieldMember, originalName.symm⟩⟩

def SegmentPlanAdmitted (names : List Bytes) (role : PathRole) : Segment → Prop
  | .fixed value => PathCompiler.FixedValid (textBytes value)
  | .field name => OperationIdentity.validToken (textBytes name) 64 = true ∧ textBytes name ∈ names
  | .responseField _ _ => 0 < responseMaximum role
  | .echo => False

/-- The successful traversal earns each original fixed/name condition and
tracks whether response-bearing tags are possible for its actual path role.
The argument ledger/counter remains the traversal's real input. -/
theorem path_tail_success_earns_plan_segments (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (role : PathRole) (segments : List Segment) (responses : Nat) (state : State)
    (admitted : (pathTail fields role segments responses state).1 = .ok ()) :
    ∀ segment ∈ segments, SegmentPlanAdmitted (FieldProjection.names original) role segment := by
  induction segments generalizing responses state with
  | nil => simp
  | cons first rest ih =>
      cases first with
      | fixed value =>
          unfold pathTail at admitted
          split at admitted
          · rename_i literal
            intro segment member
            rcases List.mem_cons.mp member with rfl | later
            · exact literal
            · exact ih responses state admitted segment later
          · simp [refused] at admitted
      | field name =>
          unfold pathTail at admitted
          split at admitted
          · rename_i allowed
            have named := field_test_earns_original_plan_name original fields layout meaning pathSchema name
              (Bool.and_eq_true.mp allowed).1
            intro segment member
            rcases List.mem_cons.mp member with rfl | later
            · exact named
            · exact ih responses (consume state name) admitted segment later
          · simp [refused] at admitted
      | responseField pointer maximum =>
          unfold pathTail at admitted
          split at admitted
          · rename_i allowed
            intro segment member
            rcases List.mem_cons.mp member with rfl | later
            · unfold SegmentPlanAdmitted
              omega
            · exact ih (responses + 1) state admitted segment later
          · simp [refused] at admitted
      | echo => simp [pathTail, refused] at admitted

theorem path_success_earns_plan_segments (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (role : PathRole) (segments : List Segment) (state : State)
    (admitted : (path fields role segments state).1 = .ok ()) :
    0 < segments.length ∧ segments.length ≤ 16 ∧
      ∀ segment ∈ segments, SegmentPlanAdmitted (FieldProjection.names original) role segment := by
  unfold path at admitted
  split at admitted
  · rename_i count
    exact ⟨count.1, count.2, path_tail_success_earns_plan_segments original fields layout meaning role segments 0 state admitted⟩
  · simp [refused] at admitted

theorem path_without_response_has_plan_admission (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (role : PathRole) (segments : List Segment) (state : State)
    (admitted : (path fields role segments state).1 = .ok ())
    (ordinary : segments.any isResponseField = false) :
    PathCompiler.PathAdmissible (FieldProjection.names original)
      ((segments.map originalSegment).map RecipePlanModel.pathSegment) := by
  obtain ⟨positive, count, each⟩ := path_success_earns_plan_segments original fields layout meaning role segments state admitted
  have namesBound : (FieldProjection.names original).length ≤ 32 := by simpa [FieldProjection.names] using layout.1
  refine ⟨namesBound, by simpa using positive, by simpa using count, ?_⟩
  intro projected member
  obtain ⟨source, sourceMember, projectedAt⟩ := List.mem_map.mp member
  obtain ⟨segment, segmentMember, sourceAt⟩ := List.mem_map.mp sourceMember
  subst projected
  subst source
  cases segment with
  | fixed value => exact each _ segmentMember
  | field name => exact ⟨namesBound, each _ segmentMember⟩
  | echo => exact False.elim (each _ segmentMember)
  | responseField pointer maximum =>
      have present : segments.any isResponseField = true := List.any_eq_true.mpr
        ⟨.responseField pointer maximum, segmentMember, rfl⟩
      rw [ordinary] at present
      contradiction

theorem closed_role_path_has_plan_admission (original : List FieldProjection.Field) (fields : Fields)
    (layout : FieldProjection.LayoutValid original) (meaning : Rules.Meaning original fields)
    (role : PathRole) (closed : responseMaximum role = 0) (segments : List Segment) (state : State)
    (admitted : (path fields role segments state).1 = .ok ()) :
    PathCompiler.PathAdmissible (FieldProjection.names original)
      ((segments.map originalSegment).map RecipePlanModel.pathSegment) := by
  have each := (path_success_earns_plan_segments original fields layout meaning role segments state admitted).2.2
  apply path_without_response_has_plan_admission original fields layout meaning role segments state admitted
  cases result : segments.any isResponseField with
  | false => rfl
  | true =>
      obtain ⟨segment, member, response⟩ := List.any_eq_true.mp result
      cases segment <;> simp only [isResponseField] at response
      all_goals try contradiction
      have possible := each _ member
      simp [SegmentPlanAdmitted, closed] at possible

end Auths.Product.RecipeRuleAdmission
