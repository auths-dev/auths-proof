import Auths.Product.ScalarProjectionComposition

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway

namespace Auths.Product.ScalarProjection.Dispatch
open Refinement

def schemaView : scalars.ScalarSchema → Schema
  | .String minimum maximum => .text minimum.val maximum.val
  | .Enum variants => .enumeration (variants.val.map vecBytes)
  | .Integer minimum maximum => .integer minimum.val maximum.val
  | .Boolean => .boolean

def inputView : scalars.ScalarInput → Scalar
  | .Text bytes => .text (sliceBytes bytes)
  | .Integer value => .integer value.val
  | .Boolean value => .boolean value
  | .Unsupported => .unsupported

@[step] theorem form_schema_allowed_exact (schema : scalars.ScalarSchema) :
    scalars.form_schema_allowed schema ⦃ actual => actual = decide (FormScalarSchema (schemaView schema)) ⦄ := by
  cases schema <;> rfl

/-- Every schema/input pair is covered, including all unsupported and
wrong-kind refusals. This is the actual shipping dispatch, not an assumed
selection of one of the per-kind helpers. -/
@[step] theorem validation_exact (schema : scalars.ScalarSchema) (input : scalars.ScalarInput) :
    scalars.scalar_valid schema input ⦃ actual =>
      actual = decide (Accepts (schemaView schema) (inputView input)) ⦄ := by
  cases schema with
  | String minimum maximum =>
    cases input with
    | Text bytes =>
      simpa [scalars.scalar_valid, schemaView, inputView, Accepts] using string_valid_exact minimum maximum bytes
    | Integer _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Boolean _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
  | Enum variants =>
    cases input with
    | Text bytes =>
      simpa [scalars.scalar_valid, schemaView, inputView, Accepts,
        Auths.Product.SchemaIndex.Refinement.namesView, vecBytes] using
          enum_valid_exact (alloc.vec.Vec.deref variants) bytes
    | Integer _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Boolean _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
  | Integer minimum maximum =>
    cases input with
    | Text _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Integer value =>
      simpa [scalars.scalar_valid, schemaView, inputView, Accepts] using integer_valid_exact minimum maximum value
    | Boolean _ => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.scalar_valid, schemaView, inputView, Accepts]
  | Boolean => cases input <;> simp [scalars.scalar_valid, schemaView, inputView, Accepts]

/-- Complete actual projection earns scalar meaning and its allocation domain
without a successful-source, schema-validity or input-size premise. -/
@[step] theorem projection_exact (schema : scalars.ScalarSchema) (input : scalars.ScalarInput) :
    scalars.project_scalar schema input ⦃ actual =>
      (actual = none ↔ ¬Accepts (schemaView schema) (inputView input)) ∧
      ∀ output, actual = some output →
        Projects (schemaView schema) (inputView input) (argOf output) ∧
          PayloadLength (argOf output) ≤ 4096 ⦄ := by
  cases schema with
  | String minimum maximum =>
    cases input with
    | Text bytes =>
      simpa [scalars.project_scalar, schemaView, inputView, Accepts] using string_projection_sound minimum maximum bytes
    | Integer _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Boolean _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.project_scalar, schemaView, inputView, Accepts]
  | Enum variants =>
    cases input with
    | Text bytes =>
      simp only [scalars.project_scalar]
      apply spec_mono (enum_projection_sound (alloc.vec.Vec.deref variants) bytes)
      intro actual meaning
      constructor
      · simpa [schemaView, inputView, Accepts, Auths.Product.SchemaIndex.Refinement.namesView, vecBytes] using meaning.1
      · intro output accepted
        obtain ⟨projected, bounded⟩ := meaning.2 output accepted
        exact ⟨by simpa [schemaView, inputView, Auths.Product.SchemaIndex.Refinement.namesView, vecBytes] using projected, by omega⟩
    | Integer _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Boolean _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.project_scalar, schemaView, inputView, Accepts]
  | Integer minimum maximum =>
    cases input with
    | Text _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Integer value =>
      simp only [scalars.project_scalar]
      apply spec_mono (integer_projection_exact minimum maximum value)
      intro actual meaning
      constructor
      · exact meaning.1
      · intro output accepted
        obtain ⟨projected, bounded⟩ := meaning.2 output accepted
        exact ⟨projected, by omega⟩
    | Boolean _ => simp [scalars.project_scalar, schemaView, inputView, Accepts]
    | Unsupported => simp [scalars.project_scalar, schemaView, inputView, Accepts]
  | Boolean =>
    cases input <;>
      simp [scalars.project_scalar, scalars.boolean_value, schemaView, inputView,
        Accepts, Projects, argOf, PayloadLength]

theorem validation_projection_agree (schema : scalars.ScalarSchema) (input : scalars.ScalarInput) :
    (do
      let valid ← scalars.scalar_valid schema input
      let output ← scalars.project_scalar schema input
      ok (valid, output.isSome)) ⦃ actual => actual.1 = actual.2 ⦄ := by
  step with validation_exact as ⟨valid, meaning⟩
  step with projection_exact as ⟨output, refusal, projected⟩
  cases output with
  | none =>
    have invalid := refusal.mp rfl
    simp [invalid] at meaning
    simpa [meaning]
  | some output =>
    have accepted : Accepts (schemaView schema) (inputView input) := by
      by_contra invalid
      have impossible := refusal.mpr invalid
      contradiction
    simp [accepted] at meaning
    simpa [meaning]

/-- The actual static form-kind gate and complete scalar projector cannot
return a Boolean direct form value. No accepted projection is supplied by a
caller; wrong kinds and invalid values retain their normal refusal. -/
theorem source_form_projection_kind (schema : scalars.ScalarSchema) (input : scalars.ScalarInput) :
    (do
      let allowed ← scalars.form_schema_allowed schema
      if allowed then scalars.project_scalar schema input else ok none) ⦃ actual =>
      ∀ output, actual = some output → FormArgument (argOf output) ⦄ := by
  step with form_schema_allowed_exact as ⟨allowed, allowedMeaning⟩
  cases allowed with
  | false => simp
  | true =>
    have permitted : FormScalarSchema (schemaView schema) := by simpa using allowedMeaning.symm
    apply spec_mono (projection_exact schema input)
    intro actual meaning output returned
    exact projected_form_argument _ _ _ permitted ((meaning.2 output returned).1)

theorem unsupported_refuses (schema : scalars.ScalarSchema) :
    scalars.project_scalar schema .Unsupported = ok none := by
  cases schema <;> rfl

theorem semantic_refusal (schema : scalars.ScalarSchema) (input : scalars.ScalarInput)
    (invalid : ¬Accepts (schemaView schema) (inputView input)) :
    scalars.project_scalar schema input ⦃ actual => actual = none ⦄ := by
  apply spec_mono (projection_exact schema input)
  intro actual meaning
  exact meaning.1.mpr invalid

theorem semantic_acceptance (schema : scalars.ScalarSchema) (input : scalars.ScalarInput)
    (valid : Accepts (schemaView schema) (inputView input)) :
    scalars.project_scalar schema input ⦃ actual => ∃ output,
      actual = some output ∧ Projects (schemaView schema) (inputView input) (argOf output) ∧
        PayloadLength (argOf output) ≤ 4096 ⦄ := by
  apply spec_mono (projection_exact schema input)
  intro actual meaning
  cases actual with
  | none => exact False.elim (meaning.1.mp rfl valid)
  | some output => exact ⟨output, rfl, meaning.2 output rfl⟩

theorem source_earns_payload_bound (schema : scalars.ScalarSchema) (input : scalars.ScalarInput) :
    scalars.project_scalar schema input ⦃ actual =>
      ∀ output, actual = some output →
        ArgumentBinding.Refinement.payloadLength output < 4294967295 ⦄ := by
  apply spec_mono (projection_exact schema input)
  intro actual meaning output accepted
  have bound := (meaning.2 output accepted).2
  cases output <;>
    simp [argOf, PayloadLength, ArgumentBinding.Refinement.payloadLength, vecBytes, byteList] at bound ⊢ <;> omega

end Auths.Product.ScalarProjection.Dispatch
