import Auths.Product.NativeSerdeComponentFits

/-!
The complete decoded source/lock meaning earns the existing native compiler
representation domains. It earns NO source admission, canonical/hash outcome,
URL result, expected plan, resource-cost contract or authority decision.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std

private theorem text_field {name : Record} {input : NativeRecord name}
    (bounded : CarrierBounds (.record name) input) (text : String)
    (member : ⟨.text, text⟩ ∈ recordSlots name input) : TextFits text :=
  bounded_text_fits (bounded_record_field bounded .text text member)

private theorem source_optional (input : NativeRecord .recipe) (bounded : CarrierBounds (.record .recipe) input)
    (kind : Kind) (field : Option (NativeKind kind)) (member : ⟨.option kind, field⟩ ∈ recordSlots .recipe input)
    (actual : NativeKind kind) (present : field = some actual) : CarrierBounds kind actual :=
  bounded_option_present (bounded_record_field bounded (.option kind) field member) actual present

private theorem write_bounds (input : NativeRecord .recipe) (bounded : CarrierBounds (.record .recipe) input) :
    CarrierBounds (.record .write) input.write :=
  bounded_record_field bounded (.record .write) input.write (by simp [recordSlots])

theorem source_body_bounds_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : BodyBounds input.write.body :=
  body_bounds_from_carrier input.write.body
    (bounded_record_field (write_bounds input bounded) (.internal .body) input.write.body (by simp [recordSlots]))

theorem source_write_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : WriteGroupFits input := by
  have write := write_bounds input bounded
  refine ⟨path_vector_rule_fits
    (bounded_record_field write (.vector (.internal .path)) input.write.path (by simp [recordSlots])),
    source_body_bounds_from_carrier input bounded, ?_⟩
  intro current present
  have option := bounded_record_field write (.option (.internal .idempotency)) input.write.idempotency (by simp [recordSlots])
  exact idempotency_fits_from_carrier current (bounded_option_present option current present)

theorem source_response_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : ResponseGroupFits input := by
  refine ⟨source_body_bounds_from_carrier input bounded, ?_, ?_, ?_⟩
  · intro read present
    exact observation_fits_from_carrier read
      (source_optional input bounded (.record .observation) input.observation (by simp [recordSlots]) read present)
  · intro echo present
    exact echo_fits_from_carrier echo
      (source_optional input bounded (.record .echo) input.echo (by simp [recordSlots]) echo present)
  · intro read present
    exact pre_entry_fits_from_carrier read
      (source_optional input bounded (.record .preEntry) input.pre_entry (by simp [recordSlots]) read present)

theorem source_facts_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : FactGroupFits input := by
  refine ⟨?_, ?_⟩
  · intro current present
    exact relative_fits_from_carrier current
      (source_optional input bounded (.record .relativeCeiling) input.relative_ceiling (by simp [recordSlots]) current present)
  · intro current present
    exact preconditions_fits_from_carrier current
      (source_optional input bounded (.record .preconditions) input.preconditions (by simp [recordSlots]) current present)

private theorem source_reserved_paths (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : GuardSourcePathsFit input := by
  refine ⟨path_vector_guard_fits
    (bounded_record_field (write_bounds input bounded) (.vector (.internal .path)) input.write.path (by simp [recordSlots])), ?_, ?_, ?_⟩
  · intro read present
    have readBounds := source_optional input bounded (.record .observation) input.observation (by simp [recordSlots]) read present
    exact path_vector_guard_fits (bounded_record_field readBounds (.vector (.internal .path)) read.path (by simp [recordSlots]))
  · intro read present
    have readBounds := source_optional input bounded (.record .preEntry) input.pre_entry (by simp [recordSlots]) read present
    exact path_vector_guard_fits (bounded_record_field readBounds (.vector (.internal .path)) read.path (by simp [recordSlots]))
  · intro read present
    have readBounds := source_optional input bounded (.record .relativeCeiling) input.relative_ceiling (by simp [recordSlots]) read present
    exact path_vector_guard_fits (bounded_record_field readBounds (.vector (.internal .path)) read.path (by simp [recordSlots]))

theorem source_headers_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : HeaderGuardGroupFits input := by
  refine ⟨?_, ?_, source_reserved_paths input bounded⟩
  · intro headers present row member
    have mapBounds := source_optional input bounded (.map .text) input.provider_headers (by simp [recordSlots]) headers present
    have pair := bounded_map_members mapBounds row member
    exact ⟨pair.1, bounded_text_fits pair.2⟩
  · intro guard present
    have credential := bounded_record_field bounded (.internal .credential) input.credential (by simp [recordSlots])
    exact guard_fits_from_carrier guard (credential_guard_bounds_from_carrier input.credential credential guard present)

theorem source_rules_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : SourceRulesFit input := by
  refine ⟨source_write_fits_from_carrier input bounded, source_response_fits_from_carrier input bounded,
    source_facts_fits_from_carrier input bounded, source_headers_fits_from_carrier input bounded, ?_, ?_⟩
  · intro scope present
    have scopeBounds := source_optional input bounded (.record .accountScope) input.account_scope (by simp [recordSlots]) scope present
    exact ⟨text_field scopeBounds scope.header (by simp [recordSlots]), text_field scopeBounds scope.field (by simp [recordSlots])⟩
  · intro current present
    exact bounds_fits_from_carrier current
      (source_optional input bounded (.record .bounds) input.bounds (by simp [recordSlots]) current present)

theorem constructor_fits_from_carrier (input : NativeRecord .recipe)
    (bounded : CarrierBounds (.record .recipe) input) : ConstructorSourceFits input := by
  refine ⟨text_field bounded input.schema (by simp [recordSlots]),
    ⟨text_field bounded input.service (by simp [recordSlots]),
      text_field bounded input.tool (by simp [recordSlots]),
      text_field bounded input.profile_schema_digest (by simp [recordSlots])⟩,
    text_field bounded input.operator_namespace (by simp [recordSlots]),
    credential_fits_from_carrier input.credential
      (bounded_record_field bounded (.internal .credential) input.credential (by simp [recordSlots])),
    text_field bounded input.origin (by simp [recordSlots]), source_rules_fits_from_carrier input bounded⟩

theorem lock_fits_from_carrier (input : NativeRecord .lock) (bounded : CarrierBounds (.record .lock) input) :
    NativeProfileLockFits input :=
  ⟨text_field bounded input.schema (by simp [recordSlots]),
    text_field bounded input.profile (by simp [recordSlots]),
    text_field bounded input.service (by simp [recordSlots]),
    text_field bounded input.tool (by simp [recordSlots]),
    text_field bounded input.schema_digest (by simp [recordSlots])⟩

theorem lock_schema_bounds_from_carrier (input : NativeRecord .lock)
    (bounded : CarrierBounds (.record .lock) input) : JsonBounds input.command_schema :=
  bounded_json_fits (bounded_record_field bounded .json input.command_schema (by simp [recordSlots]))

theorem decoded_source_earns_constructor_domain (raw : RawJson) (input : NativeRecord .recipe)
    (original : SourceMeaning raw input) : ConstructorSourceFits input :=
  constructor_fits_from_carrier input (native_decode_earns_carrier_bounds original.2)

theorem decoded_lock_earns_compiler_domain (raw : RawJson) (input : NativeRecord .lock)
    (original : LockMeaning raw input) : NativeProfileLockFits input ∧ JsonBounds input.command_schema := by
  have bounded := native_decode_earns_carrier_bounds original.2
  exact ⟨lock_fits_from_carrier input bounded, lock_schema_bounds_from_carrier input bounded⟩

end Auths.Product.NativeSerde
