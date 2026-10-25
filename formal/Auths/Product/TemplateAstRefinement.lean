import Auths.Product.TemplateAst
import Auths.Product.BodyCompilerResourcesRefinement
import Auths.Product.DecimalProjectionRefinement
import Auths.Product.RequestCompilerRefinement
import Auths.Product.TemplateMembersRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway
open Auths.Product.Refinement.ByteIdentity
open Auths.Product.BodyCompiler
open Auths.Product.BodyCompiler.Refinement

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def templateErrorOf : template_ast.TemplateError → Error
  | .Shape => .shape
  | .EchoConflict => .echoConflict
  | .Resources => .resources

def templateResult {α β : Type} (view : α → β) : core.result.Result α template_ast.TemplateError → Except Error β
  | .Ok value => .ok (view value)
  | .Err error => .error (templateErrorOf error)

def jsonBuildOf (value : template_ast.JsonBuild) : JsonBuild :=
  ⟨value.nodes.val, usageOf value.resources, value.pieces.val.map jsonSourceView⟩
def formBuildOf (value : template_ast.FormBuild) : FormBuild :=
  ⟨value.nodes.val, usageOf value.resources, value.pieces.val.map formSourceView⟩

def namedTemplateOf : template_ast.NamedTemplate → NamedTemplate
  | .Json pieces => .json (pieces.val.map jsonSourceView)
  | .Form pieces => .form (pieces.val.map formSourceView)

@[step] theorem member_error_exact (error : template_members.MemberError) :
    template_ast.member_error error ⦃ actual => templateErrorOf actual =
      memberError (TemplateMembers.Refinement.memberErrorOf error) ⦄ := by
  cases error <;> rfl

@[step] theorem named_body_view_exact (template : template_ast.NamedTemplate) :
    template_ast.NamedTemplate.source template ⦃ actual =>
      RequestCompiler.Refinement.bodySourceOf actual = namedBody (namedTemplateOf template) ⦄ := by
  cases template <;> rfl

@[step] private theorem field_name_equal_view_exact (left right : Slice U8) :
    construct.field_name_equal left right ⦃ actual => actual = decide (sliceBytes left = sliceBytes right) ⦄ := by
  apply spec_mono (field_name_equal_exact left right)
  intro actual meaning
  have equivalence : left.val = right.val ↔ sliceBytes left = sliceBytes right := by
    constructor
    · intro same
      simp [sliceBytes, same]
    · intro same
      exact byteList_inj.mp same
  simpa only [← equivalence] using meaning

@[step] theorem charge_node_exact (nodes depth : Usize) :
    template_ast.charge_node nodes depth ⦃ actual => templateResult UScalar.val actual = chargeNode nodes.val depth.val ⦄ := by
  unfold template_ast.charge_node template_ast.MAX_NODES template_ast.MAX_DEPTH
  by_cases exhausted : 64 ≤ nodes.val
  · have native : nodes ≥ 64#usize := by scalar_tac
    simp [native, chargeNode, Nat.not_lt.mpr exhausted, templateResult, templateErrorOf]
  · have nodesBound : nodes.val < 64 := by omega
    have nativeNodes : ¬nodes ≥ 64#usize := by scalar_tac
    by_cases tooDeep : 6 < depth.val
    · have native : depth > 6#usize := by scalar_tac
      simp [nativeNodes, native, chargeNode, Nat.not_le.mpr tooDeep, templateResult, templateErrorOf]
    · have depthBound : depth.val ≤ 6 := by omega
      have nativeDepth : ¬depth > 6#usize := by scalar_tac
      simp only [nativeNodes, nativeDepth, Bool.false_or, ↓reduceIte]
      step as ⟨next, nextValue⟩
      simp [chargeNode, nodesBound, depthBound, templateResult, nextValue]

theorem source_node_charge_earns_domain (nodes depth : Usize) :
    template_ast.charge_node nodes depth ⦃ actual => ∀ next, actual = .Ok next →
      nodes.val < 64 ∧ depth.val ≤ 6 ∧ next.val = nodes.val + 1 ∧ next.val ≤ 64 ⦄ := by
  apply spec_mono (charge_node_exact nodes depth)
  intro actual meaning next same
  rw [same] at meaning
  exact charge_node_earns_domain _ _ _ meaning.symm

@[step] theorem rendered_field_exact (name : Slice U8) :
    template_ast.rendered_field_allowed name ⦃ actual => actual = decide (RenderedField (sliceBytes name)) ⦄ := by
  unfold template_ast.rendered_field_allowed
  step with OperationIdentity.Refinement.token_exact as ⟨lexical, lexicalMeaning⟩
  cases lexical
  · have invalid : OperationIdentity.validToken (sliceBytes name) 64 ≠ true := by simpa using lexicalMeaning.symm
    simp [RenderedField, invalid]
  · have valid : OperationIdentity.validToken (sliceBytes name) 64 = true := by simpa using lexicalMeaning.symm
    step with field_name_equal_view_exact as ⟨namespace, namespaceMeaning⟩
    cases namespace
    · have distinct : sliceBytes name ≠ FieldProjection.namespaceName := by
        simpa [sliceBytes, byteList, FieldProjection.namespaceName] using namespaceMeaning.symm
      step with field_name_equal_view_exact as ⟨recipe, recipeMeaning⟩
      cases recipe
      · have recipeDistinct : sliceBytes name ≠ FieldProjection.recipeName := by
          simpa [sliceBytes, byteList, FieldProjection.recipeName] using recipeMeaning.symm
        simp [RenderedField, valid, distinct, recipeDistinct]
      · have equal : sliceBytes name = FieldProjection.recipeName := by
          simpa [sliceBytes, FieldProjection.recipeName, byteList] using recipeMeaning.symm
        simp [RenderedField, equal]
    · have equal : sliceBytes name = FieldProjection.namespaceName := by
        simpa [sliceBytes, FieldProjection.namespaceName, byteList] using namespaceMeaning.symm
      simp [RenderedField, equal]

/-- The actual arithmetic encoder equals one fixed pure decimal function on
every signed word. No rendered digit sequence is a caller premise. -/
@[step] theorem integer_literal_exact (value : I64) :
    scalars.integer_bytes value ⦃ actual => vecBytes actual = integerBytes value.val ⦄ := by
  apply spec_mono (DecimalProjection.Refinement.integer_bytes_exact value)
  intro actual meaning
  obtain ⟨power, lower, upper, same⟩ := meaning
  have atLeastOne : 1 ≤ 10 ^ power := Nat.one_le_pow power (by decide)
  have upper' : value.val.natAbs < 10 ^ power * 10 := by simpa only [pow_succ] using upper
  have upperMax : max 1 value.val.natAbs < 10 ^ (power + 1) := by
    rw [pow_succ]
    omega
  have logarithm : Nat.log 10 (max 1 value.val.natAbs) = power := Nat.log_eq_of_pow_le_of_lt_pow lower upperMax
  simpa [integerBytes, logarithm] using same

@[step] theorem json_start_exact (nodes : Usize) :
    template_ast.json_start nodes ⦃ actual => jsonBuildOf actual = jsonStart nodes.val ⦄ := by
  simp [template_ast.json_start, jsonBuildOf, jsonStart, usageOf, Resources.zero, alloc.vec.Vec.new]

@[step] theorem form_start_exact :
    template_ast.form_start ⦃ actual => formBuildOf actual = formStart ⦄ := by
  simp [template_ast.form_start, formBuildOf, formStart, usageOf, Resources.zero, alloc.vec.Vec.new]

@[step] theorem json_push_exact (output : template_ast.JsonBuild) (piece : body_compiler.NamedJsonPiece) :
    template_ast.json_push output piece ⦃ actual =>
      templateResult jsonBuildOf actual = pushJson (jsonBuildOf output) (jsonSourceView piece) ⦄ := by
  let pieceView := jsonSourceView piece
  unfold template_ast.json_push body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have native : output.pieces.len ≥ 256#usize := by scalar_tac
    have invalid : ¬(jsonBuildOf output).pieces.length < 256 := by simpa [jsonBuildOf] using Nat.not_lt.mpr full
    simp [native, pushJson, invalid, templateResult, templateErrorOf]
  · have count : output.pieces.val.length < 256 := by omega
    have native : ¬output.pieces.len ≥ 256#usize := by scalar_tac
    have modelCount : (jsonBuildOf output).pieces.length < 256 := by simpa [jsonBuildOf] using count
    have room : output.pieces.length < Usize.max := lt_usize_max (by change output.pieces.val.length < _; omega)
    simp only [native, ↓reduceIte]
    cases piece
    all_goals
      step with add_resources_exact as ⟨charged, chargedMeaning⟩
      cases charged with
      | none => simpa [pushJson, modelCount, jsonBuildOf, jsonSourceView, pieceView, Resources.jsonQuantity,
          jsonLiteralSize, jsonDynamicSize, vecBytes, byteList, templateResult, templateErrorOf] using
            congrArg (fun next => match next with | none => Except.error Error.resources | some resources =>
              .ok (JsonBuild.mk output.nodes.val resources ((jsonBuildOf output).pieces ++ [pieceView]))) chargedMeaning
      | some resources =>
        step as ⟨updated, updatedValue⟩
        simpa [pushJson, modelCount, jsonBuildOf, jsonSourceView, pieceView, Resources.jsonQuantity,
          jsonLiteralSize, jsonDynamicSize, vecBytes, byteList, templateResult, updatedValue, List.map_append] using
            congrArg (fun next => match next with | none => Except.error Error.resources | some resources =>
              .ok (JsonBuild.mk output.nodes.val resources ((jsonBuildOf output).pieces ++ [pieceView]))) chargedMeaning

@[step] theorem form_push_exact (output : template_ast.FormBuild) (piece : body_compiler.NamedFormPiece) :
    template_ast.form_push output piece ⦃ actual =>
      templateResult formBuildOf actual = pushForm (formBuildOf output) (formSourceView piece) ⦄ := by
  unfold template_ast.form_push body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have native : output.pieces.len ≥ 256#usize := by scalar_tac
    have invalid : ¬(formBuildOf output).pieces.length < 256 := by simpa [formBuildOf] using Nat.not_lt.mpr full
    simp [native, pushForm, invalid, templateResult, templateErrorOf]
  · have count : output.pieces.val.length < 256 := by omega
    have native : ¬output.pieces.len ≥ 256#usize := by scalar_tac
    have modelCount : (formBuildOf output).pieces.length < 256 := by simpa [formBuildOf] using count
    have room : output.pieces.length < Usize.max := lt_usize_max (by change output.pieces.val.length < _; omega)
    simp only [native, ↓reduceIte]
    step with form_piece_resources_exact as ⟨charged, chargedMeaning⟩
    cases charged with
    | none => simpa [pushForm, modelCount, templateResult, templateErrorOf] using
        congrArg (fun next => match next with | none => Except.error Error.resources | some resources =>
          .ok (FormBuild.mk output.nodes.val resources ((formBuildOf output).pieces ++ [formSourceView piece]))) chargedMeaning
    | some resources =>
      step as ⟨updated, updatedValue⟩
      simpa [pushForm, modelCount, formBuildOf, templateResult, updatedValue, List.map_append] using
        congrArg (fun next => match next with | none => Except.error Error.resources | some resources =>
          .ok (FormBuild.mk output.nodes.val resources ((formBuildOf output).pieces ++ [formSourceView piece]))) chargedMeaning

theorem source_json_push_preserves_resources (output : template_ast.JsonBuild) (piece : body_compiler.NamedJsonPiece)
    (invariant : JsonInvariant (jsonBuildOf output)) :
    template_ast.json_push output piece ⦃ actual => ∀ next, actual = .Ok next → JsonInvariant (jsonBuildOf next) ∧
      next.nodes = output.nodes ∧ (jsonBuildOf next).pieces = (jsonBuildOf output).pieces ++ [jsonSourceView piece] ⦄ := by
  apply spec_mono (json_push_exact output piece)
  intro actual meaning next same
  rw [same] at meaning
  obtain ⟨valid, nodes, pieces⟩ := json_push_preserves_invariant _ _ _ invariant meaning.symm
  exact ⟨valid, UScalar.eq_of_val_eq nodes, pieces⟩

theorem source_form_push_preserves_resources (output : template_ast.FormBuild) (piece : body_compiler.NamedFormPiece)
    (invariant : FormInvariant (formBuildOf output)) :
    template_ast.form_push output piece ⦃ actual => ∀ next, actual = .Ok next → FormInvariant (formBuildOf next) ∧
      next.nodes = output.nodes ∧ (formBuildOf next).pieces = (formBuildOf output).pieces ++ [formSourceView piece] ⦄ := by
  apply spec_mono (form_push_exact output piece)
  intro actual meaning next same
  rw [same] at meaning
  obtain ⟨valid, nodes, pieces⟩ := form_push_preserves_invariant _ _ _ invariant meaning.symm
  exact ⟨valid, UScalar.eq_of_val_eq nodes, pieces⟩

end Auths.Product.TemplateAst.Refinement
