import Auths.Product.RecipeSerdeFields
import Auths.Product.RecipeSerdeBodyUniqueness
import Auths.Product.JcsUtf16Keys

/-!
Complete recursive object-name uniqueness of the independent typed source
serialization, earned from original decoded carrier provenance. No canonical
byte success, admitted recipe, supplied serialization uniqueness or field
truncation is assumed. Actual serde Serialize/library adequacy remains open.
-/
namespace Auths.Product.RecipeSerde
open NativeCompiler NativeSerde
open AuthsNativeRecipe.recipe

private theorem vector_unique {T : Type} (encode : T → Json) (values : NativeVec T)
    (each : ∀ value ∈ values.val, FullJsonValue.Unique (encode value)) :
    FullJsonValue.Unique (vector encode values) := by
  apply (FullJsonValue.array_unique_iff _).mpr
  intro encoded member
  obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
  exact each original present

@[simp] theorem path_serialization_has_unique_objects (input : source.PathSegment) :
    FullJsonValue.Unique (pathSegment input) := by cases input <;> simp [pathSegment, tagged, unsigned]

private theorem paths_unique (input : NativeVec source.PathSegment) :
    FullJsonValue.Unique (vector pathSegment input) := vector_unique _ _ (fun value _ => path_serialization_has_unique_objects value)

private theorem texts_unique (input : NativeVec String) : FullJsonValue.Unique (vector .text input) :=
  vector_unique _ _ (fun value _ => FullJsonValue.text_unique value)

private theorem unsigneds_unique (input : NativeVec Aeneas.Std.U64) : FullJsonValue.Unique (vector unsigned input) :=
  vector_unique _ _ (fun value _ => FullJsonValue.number_unique _)

@[simp] theorem account_read_serialization_has_unique_objects (input : source.AccountReadSource) :
    FullJsonValue.Unique (accountRead input) := by simp [accountRead, unsigned, paths_unique]

@[simp] theorem denied_read_serialization_has_unique_objects (input : source.DeniedReadSource) :
    FullJsonValue.Unique (deniedRead input) := by simp [deniedRead, paths_unique, unsigneds_unique]

theorem probe_serialization_has_unique_objects (input : source.ProbeSource) (literal : Json)
    (unique : FullJsonValue.Unique literal) : FullJsonValue.Unique (probe input literal) := by
  simp [probe, unsigned, paths_unique, unique]

theorem guard_serialization_has_unique_objects (input : source.GuardSource) (literal : Json)
    (unique : ∀ probe, input.probe = some probe → FullJsonValue.Unique literal) :
    FullJsonValue.Unique (guardValue input literal) := by
  have accounts := fun account => account_read_serialization_has_unique_objects account
  have denied := fun reads => vector_unique deniedRead reads
    (fun value _ => denied_read_serialization_has_unique_objects value)
  cases probeAt : input.probe with
  | none =>
      cases accountAt : input.account <;> cases deniedAt : input.denied_reads <;>
        simp [guardValue, optional, probeAt, accountAt, deniedAt, texts_unique, accounts, denied]
  | some original =>
      have probeUnique := probe_serialization_has_unique_objects original literal (unique original probeAt)
      cases accountAt : input.account <;> cases deniedAt : input.denied_reads <;>
        simp [guardValue, optional, probeAt, accountAt, deniedAt, texts_unique, accounts, denied, probeUnique]

def ProbeLiteralUnique (input : Credential) (literal : Json) : Prop :=
  ∀ original, originalProbe input = some original → FullJsonValue.Unique literal

theorem credential_serialization_has_unique_objects (input : Credential) (literal : Json)
    (unique : ProbeLiteralUnique input literal) : FullJsonValue.Unique (credentialValue input literal) := by
  cases input with
  | Bearer guard =>
      cases guard with
      | none => simp [credentialValue, guardMembers, guardOf, optional, tagged]
      | some guard =>
          have guardUnique := guard_serialization_has_unique_objects guard literal
            (fun probe present => unique probe (by simp [originalProbe, guardOf, present]))
          simpa [credentialValue, guardMembers, guardOf, optional, tagged] using guardUnique
  | HeaderApiKey header guard =>
      cases guard with
      | none => simp [credentialValue, guardMembers, guardOf, optional, tagged]
      | some guard =>
          have guardUnique := guard_serialization_has_unique_objects guard literal
            (fun probe present => unique probe (by simp [originalProbe, guardOf, present]))
          simpa [credentialValue, guardMembers, guardOf, optional, tagged] using guardUnique

@[simp] theorem account_scope_serialization_has_unique_objects (input : source.AccountScopeSource) :
    FullJsonValue.Unique (accountScope input) := by simp [accountScope]

@[simp] theorem sum_bound_serialization_has_unique_objects (input : source.SumBoundSource) :
    FullJsonValue.Unique (sumBound input) := by cases selected : input.partition <;> simp [sumBound, optional, selected]

@[simp] theorem bounds_serialization_has_unique_objects (input : source.BoundsSource) :
    FullJsonValue.Unique (bounds input) := by cases selected : input.sum <;> simp [bounds, optional, selected]

@[simp] theorem bind_serialization_has_unique_objects (input : source.BindSource) :
    FullJsonValue.Unique (bindValue input) := by simp [bindValue]

@[simp] theorem relative_ceiling_serialization_has_unique_objects (input : source.RelativeCeilingSource) :
    FullJsonValue.Unique (relativeCeiling input) := by
  have bindings := fun values => vector_unique bindValue values (fun value _ => bind_serialization_has_unique_objects value)
  cases subtractAt : input.subtract_pointer <;> cases bindAt : input.bind <;>
    simp [relativeCeiling, optional, subtractAt, bindAt, unsigned, paths_unique, bindings]

@[simp] theorem location_serialization_has_unique_objects (input : source.IdempotencyLocation) :
    FullJsonValue.Unique (idempotencyLocation input) := by
  cases jsonAt : input.json_pointer <;> cases formAt : input.form_field <;> cases pointerAt : input.pointer <;>
    simp [idempotencyLocation, optional, jsonAt, formAt, pointerAt]

@[simp] theorem idempotency_serialization_has_unique_objects (input : source.IdempotencySource) :
    FullJsonValue.Unique (idempotency input) := by cases input <;> simp [idempotency, tagged, unsigned]

@[simp] theorem method_serialization_has_unique_objects (input : WriteMethod) :
    FullJsonValue.Unique (writeMethod input) := by cases input <;> simp [writeMethod]

theorem write_serialization_has_unique_objects (input : source.WriteSource) (body : Json)
    (unique : FullJsonValue.Unique body) : FullJsonValue.Unique (writeValue input body) := by
  cases selected : input.idempotency <;> simp [writeValue, optional, selected, paths_unique, unique]

@[simp] theorem observation_serialization_has_unique_objects (input : source.ObservationSource) :
    FullJsonValue.Unique (observation input) := by simp [observation, paths_unique]

@[simp] theorem echo_placement_serialization_has_unique_objects (input : source.EchoPlacement) :
    FullJsonValue.Unique (echoPlacement input) := by cases input <;> simp [echoPlacement, tagged]

@[simp] theorem echo_serialization_has_unique_objects (input : source.EchoSource) :
    FullJsonValue.Unique (echoValue input) := by simp [echoValue]

@[simp] theorem pre_entry_serialization_has_unique_objects (input : source.PreEntrySource) :
    FullJsonValue.Unique (preEntry input) := by simp [preEntry, unsigned, paths_unique, texts_unique]

@[simp] theorem preconditions_serialization_has_unique_objects (input : source.PreconditionSource) :
    FullJsonValue.Unique (preconditions input) := by
  cases selected : input.read_back_subject <;> by_cases empty : input.verified.val.isEmpty <;>
    simp [preconditions, optional, selected, empty, texts_unique]

theorem provider_headers_serialization_has_unique_objects (input : SourceMap String)
    (names : (input.entries.val.map Prod.fst).Nodup) : FullJsonValue.Unique (providerHeaders input) := by
  apply (FullJsonValue.object_unique_iff _).mpr
  refine ⟨by simpa only [List.map_map, Function.comp_def] using names, ?_⟩
  intro member present
  obtain ⟨original, _, rfl⟩ := List.mem_map.mp present
  exact FullJsonValue.text_unique _

def sourceFields (input : Source) (body literal : Json) : List (String × Option Json) :=
  [("schema", some (.text input.schema)), ("profile_schema_digest", some (.text input.profile_schema_digest)),
    ("service", some (.text input.service)), ("tool", some (.text input.tool)),
    ("operator_namespace", some (.text input.operator_namespace)),
    ("credential", some (credentialValue input.credential literal)), ("origin", some (.text input.origin)),
    ("provider_headers", input.provider_headers.map providerHeaders),
    ("account_scope", input.account_scope.map accountScope), ("bounds", input.bounds.map bounds),
    ("relative_ceiling", input.relative_ceiling.map relativeCeiling),
    ("write", some (writeValue input.write body)), ("observation", input.observation.map observation),
    ("echo", input.echo.map echoValue), ("pre_entry", input.pre_entry.map preEntry),
    ("preconditions", input.preconditions.map preconditions)]

theorem source_fields_are_complete (input : Source) (body literal : Json) :
    selectedFields (sourceFields input body literal) = sourceMembers input body literal := by
  simp only [sourceFields, selectedFields, optional_identity_map]
  simp [sourceMembers, optional, List.append_assoc]

theorem source_fixed_names_are_distinct (input : Source) (body literal : Json) :
    ((sourceFields input body literal).map Prod.fst).Nodup := by
  change (["schema", "profile_schema_digest", "service", "tool", "operator_namespace", "credential", "origin",
    "provider_headers", "account_scope", "bounds", "relative_ceiling", "write", "observation", "echo",
    "pre_entry", "preconditions"] : List String).Nodup
  decide

theorem source_value_has_unique_objects (input : Source) (body literal : Json)
    (bodyUnique : FullJsonValue.Unique body) (literalUnique : ProbeLiteralUnique input.credential literal)
    (headerNames : ∀ headers, input.provider_headers = some headers → (headers.entries.val.map Prod.fst).Nodup) :
    FullJsonValue.Unique (sourceValue input body literal) := by
  rw [sourceValue, ← source_fields_are_complete]
  apply selected_fields_have_unique_objects _ (source_fixed_names_are_distinct input body literal)
  intro field present
  simp only [sourceFields, List.mem_cons, List.not_mem_nil, or_false] at present
  rcases present with rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl | rfl
  · simp
  · simp
  · simp
  · simp
  · simp
  · simpa using credential_serialization_has_unique_objects input.credential literal literalUnique
  · simp
  · exact mapped_field_unique _ _ _ (fun value present => provider_headers_serialization_has_unique_objects value (headerNames value present))
  · exact mapped_field_unique _ _ _ (fun value _ => account_scope_serialization_has_unique_objects value)
  · exact mapped_field_unique _ _ _ (fun value _ => bounds_serialization_has_unique_objects value)
  · exact mapped_field_unique _ _ _ (fun value _ => relative_ceiling_serialization_has_unique_objects value)
  · simpa using write_serialization_has_unique_objects input.write body bodyUnique
  · exact mapped_field_unique _ _ _ (fun value _ => observation_serialization_has_unique_objects value)
  · exact mapped_field_unique _ _ _ (fun value _ => echo_serialization_has_unique_objects value)
  · exact mapped_field_unique _ _ _ (fun value _ => pre_entry_serialization_has_unique_objects value)
  · exact mapped_field_unique _ _ _ (fun value _ => preconditions_serialization_has_unique_objects value)

theorem credential_probe_uniqueness_from_carrier (input : Credential)
    (unique : CarrierUnique (.internal .credential) input) (probe : source.ProbeSource)
    (present : originalProbe input = some probe) : JsonUnique probe.equals := by
  have selected : ∃ guard, guardOf input = some guard ∧ guard.probe = some probe := by
    cases guarded : guardOf input with
    | none => simp [originalProbe, guarded] at present
    | some guard => exact ⟨guard, guarded, by simpa [originalProbe, guarded] using present⟩
  obtain ⟨guard, guardAt, probeAt⟩ := selected
  have guardUnique : CarrierUnique (.record .guard) guard := by
    cases input with
    | Bearer declared =>
        exact unique_option_present (unique_variant_field unique (.option (.record .guard)) declared
          (by simp [variantSlots])) guard (by simpa [guardOf] using guardAt)
    | HeaderApiKey header declared =>
        exact unique_option_present (unique_variant_field unique (.option (.record .guard)) declared
          (by simp [variantSlots])) guard (by simpa [guardOf] using guardAt)
  have probeUnique := unique_option_present
    (unique_record_field guardUnique (.option (.record .probe)) guard.probe (by simp [recordSlots])) probe probeAt
  exact unique_json_original (unique_record_field probeUnique .json probe.equals (by simp [recordSlots]))

theorem source_encoding_has_unique_objects (input : Source) (serialized : Json)
    (encoded : SourceEncoding input serialized) (unique : CarrierUnique (.record .recipe) input) :
    FullJsonValue.Unique serialized := by
  cases encoded with
  | original bodyOriginal literalOriginal =>
      have writeUnique := unique_record_field unique (.record .write) input.write (by simp [recordSlots])
      have bodyUnique := unique_record_field writeUnique (.internal .body) input.write.body (by simp [recordSlots])
      have credentialUnique := unique_record_field unique (.internal .credential) input.credential (by simp [recordSlots])
      apply source_value_has_unique_objects input _ _ (body_encoding_has_unique_objects bodyOriginal bodyUnique)
      · intro probe present
        exact json_unique_earns_original_uniqueness probe.equals
          (credential_probe_uniqueness_from_carrier input.credential credentialUnique probe present) _
          (literalOriginal probe present)
      · intro headers present
        have headerOption := unique_record_field unique (.option (.map .text)) input.provider_headers (by simp [recordSlots])
        have headerUnique := unique_option_present headerOption headers present
        cases headerUnique with
        | map value names each => exact names

theorem decoded_source_serialization_has_unique_objects (raw : RawJson) (input : Source)
    (original : SourceMeaning raw input) (serialized : Json) (encoded : SourceEncoding input serialized) :
    FullJsonValue.Unique serialized :=
  source_encoding_has_unique_objects input serialized encoded (decoded_source_earns_carrier_uniqueness raw input original)

theorem decoded_lock_schema_has_unique_objects (raw : RawJson) (input : NativeRecord .lock)
    (original : LockMeaning raw input) (schema : Json) (meaning : FullJsonMeaning input.command_schema schema) :
    FullJsonValue.Unique schema := by
  have unique := decoded_lock_earns_carrier_uniqueness raw input original
  exact json_unique_earns_original_uniqueness input.command_schema
    (unique_json_original (unique_record_field unique .json input.command_schema (by simp [recordSlots]))) schema meaning

theorem serialized_object_has_unique_utf16_keys (members : List (String × Json))
    (unique : FullJsonValue.Unique (.object members)) :
    (members.map (fun member => JcsUtf16Keys.key member.1)).Nodup :=
  JcsUtf16Keys.distinct_members_have_distinct_keys members ((FullJsonValue.object_unique_iff _).mp unique).1

end Auths.Product.RecipeSerde
