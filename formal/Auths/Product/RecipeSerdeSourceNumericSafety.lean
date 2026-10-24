import Auths.Product.RecipeSerdeBodyNumericSafety
import Auths.Product.RecipeSerdeSourceUniqueness

/-!
Whole-source numeric safety from the original admitted native recipe. Every
serialized field, optional branch, map member and nested body participates.
The complete independent serialization is the object being proved safe; no
canonical bytes or successful native serializer result are premises. Actual
Serialize, integer casts, ryu formatting and canonicalizer adequacy remain
separate obligations.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler
open AuthsNativeRecipe.recipe

private abbrev Safe := FullJsonNumericSafety.SafeNumbers

@[simp] private theorem text_safe (value : String) : Safe (.text value) := .text value

@[simp] private theorem object_safe_iff (members : List (String × Json)) :
    Safe (.object members) ↔ ∀ member ∈ members, Safe member.2 := by
  constructor
  · intro safe; cases safe with | object members each => exact each
  · exact .object members

@[simp] private theorem unsigned_safe_iff (value : Aeneas.Std.U64) :
    Safe (unsigned value) ↔ value.val ≤ 9007199254740991 := by
  constructor
  · intro safe; cases safe with | unsigned value bounded => exact bounded
  · exact .unsigned value.val

private theorem vector_safe {T : Type} (encode : T → Json) (values : NativeVec T)
    (each : ∀ value ∈ values.val, Safe (encode value)) : Safe (vector encode values) := by
  apply FullJsonNumericSafety.SafeNumbers.array
  intro encoded member
  obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
  exact each original present

private theorem texts_safe (values : NativeVec String) : Safe (vector .text values) :=
  vector_safe _ _ (fun value _ => .text value)

theorem path_serialization_keeps_numeric_safety (input : source.PathSegment)
    (safe : match input with
      | .ResponseField _ maximum => 1 ≤ maximum.val ∧ maximum.val ≤ 255
      | _ => True) : Safe (pathSegment input) := by
  cases input with
  | Fixed value | Field name | Echo => simp [pathSegment, tagged]
  | ResponseField pointer maximum =>
      have bounded : maximum.val ≤ 9007199254740991 := by omega
      simp [pathSegment, tagged, bounded]

private theorem paths_safe (input : NativeVec source.PathSegment) (safe : PathNumbersSafe input) :
    Safe (vector pathSegment input) :=
  vector_safe _ _ (fun value present => path_serialization_keeps_numeric_safety value (safe value present))

theorem account_read_serialization_keeps_numeric_safety (input : source.AccountReadSource)
    (path : PathNumbersSafe input.path) (maximum : RecipeAdmissionAtoms.ReadBound input.maximum_response_bytes.val) :
    Safe (accountRead input) := by
  have bounded : input.maximum_response_bytes.val ≤ 9007199254740991 := by
    unfold RecipeAdmissionAtoms.ReadBound at maximum; omega
  simp [accountRead, paths_safe input.path path, bounded]

theorem denied_read_serialization_keeps_numeric_safety (input : source.DeniedReadSource)
    (path : PathNumbersSafe input.path)
    (statuses : ∀ status ∈ input.refused_status.val, RecipeAdmissionAtoms.RefusedStatus status.val) : Safe (deniedRead input) := by
  have numbers : Safe (vector unsigned input.refused_status) := by
    apply vector_safe
    intro status present
    have bounded := statuses status present
    apply unsigned_safe_iff.mpr
    unfold RecipeAdmissionAtoms.RefusedStatus at bounded
    omega
  simp [deniedRead, paths_safe input.path path, numbers]

theorem probe_serialization_keeps_numeric_safety (input : source.ProbeSource) (literal : Json)
    (path : PathNumbersSafe input.path) (maximum : RecipeAdmissionAtoms.ReadBound input.maximum_response_bytes.val)
    (safe : Safe literal) : Safe (probe input literal) := by
  have bounded : input.maximum_response_bytes.val ≤ 9007199254740991 := by
    unfold RecipeAdmissionAtoms.ReadBound at maximum; omega
  simp [probe, paths_safe input.path path, safe, bounded]

private theorem optional_members_safe {T : Type} (name : String) (encode : T → Json) (input : Option T)
    (each : ∀ value, input = some value → Safe (encode value)) :
    ∀ member ∈ optional name encode input, Safe member.2 := by
  cases selected : input with
  | none => simp [optional]
  | some value => simpa [optional] using each value selected

theorem guard_serialization_keeps_numeric_safety (input : source.GuardSource) (literal : Json)
    (domain : GuardNumericDomain input)
    (literalSafe : ∀ current, input.probe = some current → Safe literal) : Safe (guardValue input literal) := by
  have probes := optional_members_safe "probe" (fun value => probe value literal) input.probe (by
    intro current present
    have checked := domain.probe current present
    exact probe_serialization_keeps_numeric_safety current literal checked.1 checked.2.1 (literalSafe current present))
  have accounts := optional_members_safe "account" accountRead input.account (by
    intro current present
    have checked := domain.account current present
    exact account_read_serialization_keeps_numeric_safety current checked.1 checked.2)
  have denied := optional_members_safe "denied_reads" (vector deniedRead) input.denied_reads (by
    intro reads present
    apply vector_safe
    intro current member
    have checked := domain.denied reads present current member
    exact denied_read_serialization_keeps_numeric_safety current checked.1 checked.2)
  simpa [guardValue, List.mem_append, or_imp, forall_and, texts_safe] using
    And.intro (texts_safe input.prefixes) (And.intro probes (And.intro accounts denied))

theorem credential_serialization_keeps_numeric_safety (input : Credential) (literal : Json)
    (domain : ∀ guard, originalGuard input = some guard → GuardNumericDomain guard)
    (original : ProbeLiteralMeaning input literal) : Safe (credentialValue input literal) := by
  have guards : ∀ guard, guardOf input = some guard → Safe (guardValue guard literal) := by
    intro guard present
    have same : originalGuard input = guardOf input := by cases input <;> rfl
    have numeric := domain guard (same.trans present)
    apply guard_serialization_keeps_numeric_safety guard literal numeric
    intro current probeAt
    have slot : originalProbe input = some current := by simp [originalProbe, present, probeAt]
    exact original_probe_literal_keeps_numeric_safety current.equals literal (original current slot)
      (numeric.probe current probeAt).2.2
  cases input with
  | Bearer guard =>
      cases selected : guard with
      | none => simp [credentialValue, guardMembers, guardOf, optional, tagged, selected]
      | some current =>
          have safe := guards current (by simp [guardOf, selected])
          simpa [credentialValue, guardMembers, guardOf, optional, tagged, selected] using safe
  | HeaderApiKey header guard =>
      cases selected : guard with
      | none => simp [credentialValue, guardMembers, guardOf, optional, tagged, selected]
      | some current =>
          have safe := guards current (by simp [guardOf, selected])
          simpa [credentialValue, guardMembers, guardOf, optional, tagged, selected] using safe

theorem account_scope_serialization_has_safe_numbers (input : source.AccountScopeSource) : Safe (accountScope input) := by
  simp [accountScope]

theorem sum_bound_serialization_has_safe_numbers (input : source.SumBoundSource) : Safe (sumBound input) := by
  cases selected : input.partition <;> simp [sumBound, optional, selected]

theorem bounds_serialization_has_safe_numbers (input : source.BoundsSource) : Safe (bounds input) := by
  cases selected : input.sum <;> simp [bounds, optional, selected, sum_bound_serialization_has_safe_numbers]

theorem bind_serialization_has_safe_numbers (input : source.BindSource) : Safe (bindValue input) := by
  simp [bindValue]

theorem relative_ceiling_serialization_keeps_numeric_safety (input : source.RelativeCeilingSource)
    (basis : 1 ≤ input.basis_points.val ∧ input.basis_points.val ≤ 10000)
    (maximum : RecipeAdmissionAtoms.ReadBound input.maximum_response_bytes.val)
    (path : PathNumbersSafe input.path) : Safe (relativeCeiling input) := by
  have basisSafe : input.basis_points.val ≤ 9007199254740991 := by omega
  have maximumSafe : input.maximum_response_bytes.val ≤ 9007199254740991 := by
    unfold RecipeAdmissionAtoms.ReadBound at maximum; omega
  have bindings := fun values => vector_safe bindValue values (fun value _ => bind_serialization_has_safe_numbers value)
  cases subtractAt : input.subtract_pointer <;> cases bindAt : input.bind <;>
    simp [relativeCeiling, optional, subtractAt, bindAt, paths_safe input.path path, bindings, basisSafe, maximumSafe]

theorem location_serialization_has_safe_numbers (input : source.IdempotencyLocation) : Safe (idempotencyLocation input) := by
  cases jsonAt : input.json_pointer <;> cases formAt : input.form_field <;> cases pointerAt : input.pointer <;>
    simp [idempotencyLocation, optional, jsonAt, formAt, pointerAt]

theorem idempotency_serialization_keeps_numeric_safety (input : source.IdempotencySource)
    (retention : 1 ≤ nativeRetention input ∧ nativeRetention input ≤ 2592000) : Safe (idempotency input) := by
  cases input with
  | DerivedHeader seconds =>
      have bounded : seconds.val ≤ 9007199254740991 := by
        change 1 ≤ seconds.val ∧ seconds.val ≤ 2592000 at retention
        omega
      simp [idempotency, tagged, bounded]
  | OperationIdField location seconds =>
      have bounded : seconds.val ≤ 9007199254740991 := by
        change 1 ≤ seconds.val ∧ seconds.val ≤ 2592000 at retention
        omega
      simp [idempotency, tagged, bounded, location_serialization_has_safe_numbers]

private theorem method_safe (input : WriteMethod) : Safe (writeMethod input) := by cases input <;> simp [writeMethod]

theorem write_serialization_keeps_numeric_safety (input : source.WriteSource) (body : Json)
    (bodySafe : Safe body) (path : PathNumbersSafe input.path)
    (retention : ∀ current, input.idempotency = some current → 1 ≤ nativeRetention current ∧ nativeRetention current ≤ 2592000) :
    Safe (writeValue input body) := by
  have optionalSafe := optional_members_safe "idempotency" idempotency input.idempotency
    (fun current present => idempotency_serialization_keeps_numeric_safety current (retention current present))
  simpa [writeValue, List.mem_append, or_imp, forall_and, method_safe, paths_safe input.path path, bodySafe] using optionalSafe

theorem observation_serialization_keeps_numeric_safety (input : source.ObservationSource)
    (path : PathNumbersSafe input.path) (maximum : RecipeAdmissionAtoms.ReadBound input.maximum_response_bytes.val) :
    Safe (observation input) := by
  have bounded : input.maximum_response_bytes.val ≤ 9007199254740991 := by
    unfold RecipeAdmissionAtoms.ReadBound at maximum; omega
  have numberSafe : Safe (.number (.unsigned input.maximum_response_bytes.val)) := .unsigned _ bounded
  simp [observation, paths_safe input.path path, numberSafe]

theorem echo_placement_serialization_has_safe_numbers (input : source.EchoPlacement) : Safe (echoPlacement input) := by
  cases input <;> simp [echoPlacement, tagged]

theorem echo_serialization_has_safe_numbers (input : source.EchoSource) : Safe (echoValue input) := by
  simp [echoValue, echo_placement_serialization_has_safe_numbers]

theorem pre_entry_serialization_keeps_numeric_safety (input : source.PreEntrySource)
    (path : PathNumbersSafe input.path) (maximum : RecipeAdmissionAtoms.ReadBound input.maximum_response_bytes.val) :
    Safe (preEntry input) := by
  have bounded : input.maximum_response_bytes.val ≤ 9007199254740991 := by
    unfold RecipeAdmissionAtoms.ReadBound at maximum; omega
  simp [preEntry, paths_safe input.path path, texts_safe, bounded]

theorem preconditions_serialization_has_safe_numbers (input : source.PreconditionSource) : Safe (preconditions input) := by
  cases selected : input.read_back_subject <;> by_cases empty : input.verified.val.isEmpty <;>
    simp [preconditions, optional, selected, empty, texts_safe]

theorem provider_headers_serialization_has_safe_numbers (input : SourceMap String) : Safe (providerHeaders input) := by
  apply FullJsonNumericSafety.SafeNumbers.object
  intro member present
  obtain ⟨original, _, rfl⟩ := List.mem_map.mp present
  exact .text original.2

def FieldNumericSafe (field : String × Option Json) : Prop := ∀ value, field.2 = some value → Safe value

@[simp] private theorem present_field_safe (name : String) (value : Json) :
    FieldNumericSafe (name, some value) ↔ Safe value := by simp [FieldNumericSafe]

theorem mapped_field_numeric_safe {T : Type} (name : String) (encode : T → Json) (input : Option T)
    (each : ∀ value, input = some value → Safe (encode value)) : FieldNumericSafe (name, input.map encode) := by
  cases input with
  | none => simp [FieldNumericSafe]
  | some value => simpa [FieldNumericSafe] using each value rfl

theorem selected_fields_have_safe_numbers (fields : List (String × Option Json))
    (each : ∀ field ∈ fields, FieldNumericSafe field) : Safe (.object (selectedFields fields)) := by
  apply FullJsonNumericSafety.SafeNumbers.object
  intro member present
  obtain ⟨field, declared, _, valueOriginal⟩ := selected_field_keeps_original_value fields member present
  exact each field declared member.2 valueOriginal

theorem source_encoding_keeps_numeric_safety (input : Source) (serialized : Json)
    (encoded : SourceEncoding input serialized) (domain : SourceNumericDomain input) : Safe serialized := by
  cases encoded with
  | original bodyOriginal literalOriginal =>
      rw [sourceValue, ← source_fields_are_complete]
      apply selected_fields_have_safe_numbers
      intro field present
      simp only [sourceFields, List.mem_cons, List.not_mem_nil, or_false] at present
      rcases present with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
      · simp
      · simp
      · simp
      · simp
      · simp
      · simpa using credential_serialization_keeps_numeric_safety input.credential _ domain.guard literalOriginal
      · simp
      · exact mapped_field_numeric_safe _ _ _ (fun value _ => provider_headers_serialization_has_safe_numbers value)
      · exact mapped_field_numeric_safe _ _ _ (fun value _ => account_scope_serialization_has_safe_numbers value)
      · exact mapped_field_numeric_safe _ _ _ (fun value _ => bounds_serialization_has_safe_numbers value)
      · exact mapped_field_numeric_safe _ _ _ (by
          intro value atField
          have checked := domain.relativeCeiling value atField
          exact relative_ceiling_serialization_keeps_numeric_safety value checked.1 checked.2.1 checked.2.2)
      · simpa using write_serialization_keeps_numeric_safety input.write _
          (body_encoding_keeps_numeric_safety bodyOriginal domain.body) domain.writePath domain.idempotency
      · exact mapped_field_numeric_safe _ _ _ (by
          intro value atField
          have checked := domain.observation value atField
          exact observation_serialization_keeps_numeric_safety value checked.1 checked.2)
      · exact mapped_field_numeric_safe _ _ _ (fun value _ => echo_serialization_has_safe_numbers value)
      · exact mapped_field_numeric_safe _ _ _ (by
          intro value atField
          have checked := domain.preEntry value atField
          exact pre_entry_serialization_keeps_numeric_safety value checked.1 checked.2)
      · exact mapped_field_numeric_safe _ _ _ (fun value _ => preconditions_serialization_has_safe_numbers value)

/-- Successful complete rules earn safety of the complete same-source typed
serialization. The body meaning is original provenance, not a safe-body flag.
The statement does not replace the actual byte-entry/Serialize obligation. -/
theorem admitted_source_serialization_has_safe_numbers (fields : RecipeRuleAdmission.Fields)
    (input : Source) (body : TemplateAst.Body) (original : BodySourceMeaning input.write.body body)
    (admitted : (RecipeRuleAdmission.validate fields (ruleSource input body)).1 = .ok ())
    (serialized : Json) (encoded : SourceEncoding input serialized) : Safe serialized :=
  source_encoding_keeps_numeric_safety input serialized encoded
    (complete_original_rules_earn_native_numeric_domain fields input body original admitted)

theorem admitted_source_every_number_rounds_exactly (fields : RecipeRuleAdmission.Fields)
    (input : Source) (body : TemplateAst.Body) (original : BodySourceMeaning input.write.body body)
    (admitted : (RecipeRuleAdmission.validate fields (ruleSource input body)).1 = .ok ())
    (serialized : Json) (encoded : SourceEncoding input serialized) :
    ∀ number, FullJsonNumericSafety.NumberIn number serialized → FullJsonNumericSafety.RoundingExact number :=
  FullJsonNumericSafety.every_original_number_rounds_exactly serialized
    (admitted_source_serialization_has_safe_numbers fields input body original admitted serialized encoded)

end Auths.Product.RecipeSerde
