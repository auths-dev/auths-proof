import Auths.Product.NativeSerdeBodyBounds
import Auths.Product.NativeCompilerConstructorStages

/-!
Existing compiler component domains earned from original decoded carriers.
These theorems only discharge representation premises. Every semantic policy,
admission/error decision, canonical outcome and library contract is unchanged.
-/
namespace Auths.Product.NativeSerde
open RecipeSerdeGrammar NativeCompiler
open Aeneas Aeneas.Std

private theorem text_field {name : Record} {input : NativeRecord name}
    (bounded : CarrierBounds (.record name) input) (text : String)
    (member : ⟨.text, text⟩ ∈ recordSlots name input) : TextFits text :=
  bounded_text_fits (bounded_record_field bounded .text text member)

private theorem optional_field {name : Record} {input : NativeRecord name}
    (bounded : CarrierBounds (.record name) input) (kind : Kind) (field : Option (NativeKind kind))
    (member : ⟨.option kind, field⟩ ∈ recordSlots name input) (actual : NativeKind kind)
    (present : field = some actual) : CarrierBounds kind actual :=
  bounded_option_present (bounded_record_field bounded (.option kind) field member) actual present

theorem path_rule_fits_from_carrier (input : NativePathSource) (bounded : CarrierBounds (.internal .path) input) :
    RulePathFits input := by
  cases input with
  | Fixed text =>
      exact bounded_text_fits (bounded_variant_field bounded .text text (by simp [variantSlots]))
  | Field text =>
      exact bounded_text_fits (bounded_variant_field bounded .text text (by simp [variantSlots]))
  | ResponseField pointer maximum =>
      exact bounded_text_fits (bounded_variant_field bounded .text pointer (by simp [variantSlots]))
  | Echo => trivial

theorem path_guard_fits_from_carrier (input : NativePathSource) (bounded : CarrierBounds (.internal .path) input) :
    GuardPathFits input := by
  cases input with
  | Fixed text => exact path_rule_fits_from_carrier _ bounded
  | Field _ | ResponseField _ _ | Echo => trivial

theorem path_vector_rule_fits {input : NativeVec NativePathSource}
    (bounded : CarrierBounds (.vector (.internal .path)) input) : ∀ segment ∈ input.val, RulePathFits segment := by
  intro segment member
  exact path_rule_fits_from_carrier segment (bounded_vector_elements bounded segment member)

theorem path_vector_guard_fits {input : NativeVec NativePathSource}
    (bounded : CarrierBounds (.vector (.internal .path)) input) : ∀ segment ∈ input.val, GuardPathFits segment := by
  intro segment member
  exact path_guard_fits_from_carrier segment (bounded_vector_elements bounded segment member)

theorem text_vector_fits {input : NativeVec String} (bounded : CarrierBounds (.vector .text) input) :
    ∀ text ∈ input.val, TextFits text := by
  intro text member
  exact bounded_text_fits (bounded_vector_elements bounded text member)

theorem binding_fits_from_carrier (input : NativeRecord .binding) (bounded : CarrierBounds (.record .binding) input) :
    BindFits input :=
  ⟨text_field bounded input.pointer (by simp [recordSlots]), text_field bounded input.field (by simp [recordSlots])⟩

theorem location_fits_from_carrier (input : NativeRecord .idempotencyLocation)
    (bounded : CarrierBounds (.record .idempotencyLocation) input) : LocationFits input := by
  refine ⟨?_, ?_, ?_⟩
  · intro pointer present
    exact bounded_text_fits (optional_field bounded .text input.json_pointer (by simp [recordSlots]) pointer present)
  · intro name present
    exact bounded_text_fits (optional_field bounded .text input.form_field (by simp [recordSlots]) name present)
  · intro pointer present
    exact bounded_text_fits (optional_field bounded .text input.pointer (by simp [recordSlots]) pointer present)

theorem idempotency_fits_from_carrier (input : NativeEnum .idempotency)
    (bounded : CarrierBounds (.internal .idempotency) input) : IdempotencyFits input := by
  cases input with
  | DerivedHeader retention => trivial
  | OperationIdField location retention =>
      exact location_fits_from_carrier location
        (bounded_variant_field bounded (.record .idempotencyLocation) location (by simp [variantSlots]))

theorem observation_fits_from_carrier (input : NativeRecord .observation)
    (bounded : CarrierBounds (.record .observation) input) : ObservationAdmissionFits input :=
  ⟨path_vector_rule_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots])),
    text_field bounded input.json_pointer (by simp [recordSlots]),
    text_field bounded input.expected_field (by simp [recordSlots])⟩

theorem pre_entry_fits_from_carrier (input : NativeRecord .preEntry)
    (bounded : CarrierBounds (.record .preEntry) input) : PreEntryAdmissionFits input :=
  ⟨path_vector_rule_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots])),
    text_vector_fits (bounded_record_field bounded (.vector .text) input.pointers (by simp [recordSlots]))⟩

theorem preconditions_fits_from_carrier (input : NativeRecord .preconditions)
    (bounded : CarrierBounds (.record .preconditions) input) : PreconditionsAdmissionFits input := by
  refine ⟨?_, text_vector_fits (bounded_record_field bounded (.vector .text) input.verified (by simp [recordSlots]))⟩
  intro subject present
  exact bounded_text_fits (optional_field bounded .text input.read_back_subject (by simp [recordSlots]) subject present)

theorem relative_fits_from_carrier (input : NativeRecord .relativeCeiling)
    (bounded : CarrierBounds (.record .relativeCeiling) input) : RelativeFits input := by
  refine ⟨text_field bounded input.argument (by simp [recordSlots]),
    text_field bounded input.json_pointer (by simp [recordSlots]), ?_, ?_,
    path_vector_rule_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots]))⟩
  · intro pointer present
    exact bounded_text_fits (optional_field bounded .text input.subtract_pointer (by simp [recordSlots]) pointer present)
  · intro bindings present binding member
    have values := optional_field bounded (.vector (.record .binding)) input.bind (by simp [recordSlots]) bindings present
    exact binding_fits_from_carrier binding (bounded_vector_elements values binding member)

theorem echo_placement_fits_from_carrier (input : NativeEnum .echoPlacement)
    (bounded : CarrierBounds (.internal .echoPlacement) input) : NativeEchoFits input := by
  cases input with
  | JsonPointer pointer =>
      exact bounded_text_fits (bounded_variant_field bounded .text pointer (by simp [variantSlots]))
  | FormField name =>
      exact bounded_text_fits (bounded_variant_field bounded .text name (by simp [variantSlots]))

theorem echo_fits_from_carrier (input : NativeRecord .echo) (bounded : CarrierBounds (.record .echo) input) : EchoFits input :=
  ⟨text_field bounded input.observe (by simp [recordSlots]),
    echo_placement_fits_from_carrier input.write
      (bounded_record_field bounded (.internal .echoPlacement) input.write (by simp [recordSlots]))⟩

theorem bounds_fits_from_carrier (input : NativeRecord .bounds) (bounded : CarrierBounds (.record .bounds) input) :
    BoundFieldsFit input := by
  intro sum present
  have sumBounds := optional_field bounded (.record .sumBound) input.sum (by simp [recordSlots]) sum present
  refine ⟨text_field sumBounds sum.argument (by simp [recordSlots]), ?_⟩
  intro partition present
  exact bounded_text_fits (optional_field sumBounds .text sum.partition (by simp [recordSlots]) partition present)

theorem credential_fits_from_carrier (input : NativeEnum .credential)
    (bounded : CarrierBounds (.internal .credential) input) : NativeSourceCredentialFits input := by
  cases input with
  | Bearer _ => trivial
  | HeaderApiKey header guard =>
      exact bounded_text_fits (bounded_variant_field bounded .text header (by simp [variantSlots]))

theorem probe_literal_fits_from_carrier (input : NativeCompiler.Json) (bounded : CarrierBounds .json input) :
    ProbeLiteralFits input := by
  have jsonBounds := bounded_json_fits bounded
  cases jsonBounds <;> simp_all [ProbeLiteralFits]

theorem probe_fits_from_carrier (input : NativeRecord .probe) (bounded : CarrierBounds (.record .probe) input) :
    GuardProbeFits input :=
  ⟨path_vector_guard_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots])),
    text_field bounded input.json_pointer (by simp [recordSlots]),
    probe_literal_fits_from_carrier input.equals (bounded_record_field bounded .json input.equals (by simp [recordSlots]))⟩

theorem account_read_fits_from_carrier (input : NativeRecord .accountRead)
    (bounded : CarrierBounds (.record .accountRead) input) : GuardAccountFits input :=
  ⟨path_vector_guard_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots])),
    text_field bounded input.json_pointer (by simp [recordSlots])⟩

theorem denied_read_fits_from_carrier (input : NativeRecord .deniedRead)
    (bounded : CarrierBounds (.record .deniedRead) input) : GuardDeniedReadFits input :=
  ⟨text_field bounded input.method (by simp [recordSlots]),
    path_vector_guard_fits (bounded_record_field bounded (.vector (.internal .path)) input.path (by simp [recordSlots]))⟩

theorem guard_fits_from_carrier (input : NativeRecord .guard) (bounded : CarrierBounds (.record .guard) input) :
    GuardAdmissionFits input := by
  refine ⟨text_vector_fits (bounded_record_field bounded (.vector .text) input.prefixes (by simp [recordSlots])), ?_, ?_, ?_⟩
  · intro probe present
    exact probe_fits_from_carrier probe (optional_field bounded (.record .probe) input.probe (by simp [recordSlots]) probe present)
  · intro account present
    exact account_read_fits_from_carrier account (optional_field bounded (.record .accountRead) input.account (by simp [recordSlots]) account present)
  · intro reads present read member
    have values := optional_field bounded (.vector (.record .deniedRead)) input.denied_reads (by simp [recordSlots]) reads present
    exact denied_read_fits_from_carrier read (bounded_vector_elements values read member)

theorem credential_guard_bounds_from_carrier (input : NativeEnum .credential)
    (bounded : CarrierBounds (.internal .credential) input) (guard : NativeRecord .guard)
    (present : originalGuard input = some guard) : CarrierBounds (.record .guard) guard := by
  cases input with
  | Bearer declared =>
      exact bounded_option_present
        (bounded_variant_field bounded (.option (.record .guard)) declared (by simp [variantSlots])) guard
        (by simpa [originalGuard] using present)
  | HeaderApiKey header declared =>
      exact bounded_option_present
        (bounded_variant_field bounded (.option (.record .guard)) declared (by simp [variantSlots])) guard
        (by simpa [originalGuard] using present)

end Auths.Product.NativeSerde
