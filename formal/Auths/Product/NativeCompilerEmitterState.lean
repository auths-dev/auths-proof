import Auths.Product.NativeCompilerBodyResources
import Auths.Product.NativeCompilerEcho
import Auths.Product.TemplateAst

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeTemplateError := AuthsNativeRecipe.auths_gateway_kernel.template_ast.TemplateError
abbrev NativeJsonBuild := AuthsNativeRecipe.auths_gateway_kernel.template_ast.JsonBuild
abbrev NativeFormBuild := AuthsNativeRecipe.auths_gateway_kernel.template_ast.FormBuild

def nativeTemplateError : NativeTemplateError → TemplateAst.Error
  | .Shape => .shape
  | .EchoConflict => .echoConflict
  | .Resources => .resources

def nativeTemplateResult {T V : Type} (view : T → V) :
    core.result.Result T NativeTemplateError → Except TemplateAst.Error V
  | .Ok output => .ok (view output)
  | .Err error => .error (nativeTemplateError error)

def nativeJsonBuild (input : NativeJsonBuild) : TemplateAst.JsonBuild :=
  ⟨input.nodes.val, nativeUsage input.resources, input.pieces.val.map nativeNamedJson⟩

def nativeFormBuild (input : NativeFormBuild) : TemplateAst.FormBuild :=
  ⟨input.nodes.val, nativeUsage input.resources, input.pieces.val.map nativeNamedForm⟩

def nativeTemplate : NativeNamedTemplate → TemplateAst.NamedTemplate
  | .Json pieces => .json (pieces.val.map nativeNamedJson)
  | .Form pieces => .form (pieces.val.map nativeNamedForm)

/-- The emitter returns mutated state beside its unit/error result. State is
observed on success. The outer compile function does not publish partial state
on refusal, and recursive helpers may already have charged nodes or prefixes. -/
def nativeJsonEffect (actual : core.result.Result Unit NativeTemplateError × NativeJsonBuild) :
    Except TemplateAst.Error TemplateAst.JsonBuild :=
  nativeTemplateResult (fun _ => nativeJsonBuild actual.2) actual.1

def nativeFormEffect (actual : core.result.Result Unit NativeTemplateError × NativeFormBuild) :
    Except TemplateAst.Error TemplateAst.FormBuild :=
  nativeTemplateResult (fun _ => nativeFormBuild actual.2) actual.1

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open TemplateAst
set_option maxHeartbeats 6000000
set_option maxRecDepth 4096

@[step] theorem native_member_error_exact (error : NativeMemberError) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.member_error error ⦃ actual =>
      nativeTemplateError actual = memberError (nativeMemberErrorMeaning error) ⦄ := by
  cases error <;> rfl

@[step] theorem native_node_charge_exact (nodes depth : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.charge_node nodes depth ⦃ actual =>
      nativeTemplateResult UScalar.val actual = chargeNode nodes.val depth.val ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.charge_node
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_NODES
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.MAX_DEPTH
  by_cases full : 64 ≤ nodes.val
  · have nativeFull : nodes >= 64#usize := by scalar_tac
    simp [nativeFull, chargeNode, Nat.not_lt.mpr full, nativeTemplateResult, nativeTemplateError]
  · have room : nodes.val < 64 := by omega
    have nativeRoom : ¬nodes >= 64#usize := by scalar_tac
    by_cases deep : 6 < depth.val
    · have nativeDeep : depth > 6#usize := by scalar_tac
      simp [nativeRoom, nativeDeep, chargeNode, Nat.not_le.mpr deep,
        nativeTemplateResult, nativeTemplateError]
    · have depthBound : depth.val ≤ 6 := by omega
      have nativeDepth : ¬depth > 6#usize := by scalar_tac
      simp only [nativeRoom, nativeDepth, ↓reduceIte]
      step as ⟨next, nextMeaning⟩
      simp [chargeNode, room, depthBound, nativeTemplateResult, nextMeaning]

theorem native_node_charge_earns_domain (nodes depth : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.charge_node nodes depth ⦃ actual =>
      ∀ next, actual = .Ok next → nodes.val < 64 ∧ depth.val ≤ 6 ∧
        next.val = nodes.val + 1 ∧ next.val ≤ 64 ⦄ := by
  apply spec_mono (native_node_charge_exact nodes depth)
  intro actual exact next accepted
  rw [accepted] at exact
  exact charge_node_earns_domain _ _ _ (by simpa only [nativeTemplateResult] using exact.symm)

@[step] theorem native_rendered_field_exact (name : Slice Std.U8) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.rendered_field_allowed name ⦃ actual =>
      actual = decide (RenderedField (schemaSliceBytes name)) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.rendered_field_allowed
  step with native_schema_token_exact name 64#usize as ⟨lexical, lexicalMeaning⟩
  cases lexical with
  | false => simp [RenderedField, ← lexicalMeaning]
  | true =>
      simp only [Bool.true_eq_true, ↓reduceIte]
      step as ⟨namespaceBytes, namespaceBytesMeaning⟩
      step with native_schema_byte_equality name namespaceBytes as ⟨namespace, namespaceMeaning⟩
      have namespaceSpec : namespace = decide (schemaSliceBytes name = FieldProjection.namespaceName) := by
        simpa [namespaceBytesMeaning, schemaSliceBytes, FieldProjection.namespaceName] using namespaceMeaning
      cases namespace with
      | true => simp [RenderedField, ← namespaceSpec]
      | false =>
          simp only [Bool.false_eq_true, ↓reduceIte]
          step as ⟨recipeBytes, recipeBytesMeaning⟩
          step with native_schema_byte_equality name recipeBytes as ⟨recipe, recipeMeaning⟩
          have recipeSpec : recipe = decide (schemaSliceBytes name = FieldProjection.recipeName) := by
            simpa [recipeBytesMeaning, schemaSliceBytes, FieldProjection.recipeName] using recipeMeaning
          cases recipe <;> simp [RenderedField, ← lexicalMeaning, ← namespaceSpec, ← recipeSpec]

@[step] theorem native_json_start_exact (nodes : Std.Usize) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_start nodes ⦃ actual =>
      nativeJsonBuild actual = jsonStart nodes.val ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_start, nativeJsonBuild,
    jsonStart, nativeUsage, BodyCompiler.Resources.zero, native_empty_contents]

@[step] theorem native_form_start_exact :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_start ⦃ actual =>
      nativeFormBuild actual = formStart ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_start, nativeFormBuild,
    formStart, nativeUsage, BodyCompiler.Resources.zero, native_empty_contents]

@[step] theorem native_json_finish_exact (output : NativeJsonBuild) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_finish output ⦃ actual =>
      actual.1 = output.pieces ∧ actual.2.nodes = output.nodes ∧
        actual.2.resources = output.resources ∧ actual.2.pieces.val = [] ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_finish,
    core.mem.replace, native_empty_contents]

@[step] theorem native_form_finish_exact (output : NativeFormBuild) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_finish output ⦃ actual =>
      actual.1 = output.pieces ∧ actual.2.nodes = output.nodes ∧
        actual.2.resources = output.resources ∧ actual.2.pieces.val = [] ⦄ := by
  simp [AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_finish,
    core.mem.replace, native_empty_contents]

@[step] theorem native_json_push_exact (output : NativeJsonBuild) (piece : NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_push output piece ⦃ actual =>
      nativeJsonEffect actual = pushJson (nativeJsonBuild output) (nativeNamedJson piece) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_push
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp [nativeFull, pushJson, nativeJsonEffect, nativeTemplateResult, nativeTemplateError,
      nativeJsonBuild, Nat.not_lt.mpr full]
  · have room : output.pieces.val.length < 256 := by omega
    have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp only [nativeRoom, ↓reduceIte]
    cases piece with
    | Raw value =>
        simp only [bind_tc_ok]
        step with native_resource_add_exact as ⟨charged, chargeMeaning⟩
        have quantity : charged.map nativeUsage = BodyCompiler.Resources.jsonCharge
            (nativeUsage output.resources) (nativeNamedJson (.Raw value)) := by
          simpa [BodyCompiler.Resources.jsonCharge, BodyCompiler.Resources.jsonQuantity,
            nativeNamedJson, BodyCompiler.jsonLiteralSize, BodyCompiler.jsonDynamicSize, bytes] using chargeMeaning
        cases charged with
        | none => simp [pushJson, nativeJsonBuild, room, ← quantity,
            BodyCompiler.Resources.jsonCharge, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
        | some next =>
            step with native_push_exact output.pieces (.Raw value) (by scalar_tac) as ⟨pieces, appended⟩
            simp [pushJson, nativeJsonBuild, room, ← quantity, BodyCompiler.Resources.jsonCharge,
              nativeJsonEffect, nativeTemplateResult, appended, List.map_append, List.map_singleton]
    | Field name =>
        simp only [bind_tc_ok]
        step with native_resource_add_exact as ⟨charged, chargeMeaning⟩
        have quantity : charged.map nativeUsage = BodyCompiler.Resources.jsonCharge
            (nativeUsage output.resources) (nativeNamedJson (.Field name)) := by
          simpa [BodyCompiler.Resources.jsonCharge, BodyCompiler.Resources.jsonQuantity,
            nativeNamedJson, BodyCompiler.jsonLiteralSize, BodyCompiler.jsonDynamicSize] using chargeMeaning
        cases charged with
        | none => simp [pushJson, nativeJsonBuild, room, ← quantity,
            BodyCompiler.Resources.jsonCharge, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
        | some next =>
            step with native_push_exact output.pieces (.Field name) (by scalar_tac) as ⟨pieces, appended⟩
            simp [pushJson, nativeJsonBuild, room, ← quantity, BodyCompiler.Resources.jsonCharge,
              nativeJsonEffect, nativeTemplateResult, appended, List.map_append, List.map_singleton]
    | Echo =>
        simp only [bind_tc_ok]
        step with native_resource_add_exact as ⟨charged, chargeMeaning⟩
        have quantity : charged.map nativeUsage = BodyCompiler.Resources.jsonCharge
            (nativeUsage output.resources) (nativeNamedJson .Echo) := by
          simpa [BodyCompiler.Resources.jsonCharge, BodyCompiler.Resources.jsonQuantity,
            nativeNamedJson, BodyCompiler.jsonLiteralSize, BodyCompiler.jsonDynamicSize] using chargeMeaning
        cases charged with
        | none => simp [pushJson, nativeJsonBuild, room, ← quantity,
            BodyCompiler.Resources.jsonCharge, nativeJsonEffect, nativeTemplateResult, nativeTemplateError]
        | some next =>
            step with native_push_exact output.pieces .Echo (by scalar_tac) as ⟨pieces, appended⟩
            simp [pushJson, nativeJsonBuild, room, ← quantity, BodyCompiler.Resources.jsonCharge,
              nativeJsonEffect, nativeTemplateResult, appended, List.map_append, List.map_singleton]

@[step] theorem native_form_push_exact (output : NativeFormBuild) (piece : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_push output piece ⦃ actual =>
      nativeFormEffect actual = pushForm (nativeFormBuild output) (nativeNamedForm piece) ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_push
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp [nativeFull, pushForm, nativeFormEffect, nativeTemplateResult, nativeTemplateError,
      nativeFormBuild, Nat.not_lt.mpr full]
  · have room : output.pieces.val.length < 256 := by omega
    have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp only [nativeRoom, ↓reduceIte]
    step with native_form_piece_resources_exact output.resources piece as ⟨charged, chargeMeaning⟩
    cases charged with
    | none =>
        simp [pushForm, nativeFormBuild, room, ← chargeMeaning,
          nativeFormEffect, nativeTemplateResult, nativeTemplateError]
    | some next =>
        step with native_push_exact output.pieces piece (by scalar_tac) as ⟨pieces, appended⟩
        simp [pushForm, nativeFormBuild, room, ← chargeMeaning,
          nativeFormEffect, nativeTemplateResult, appended, List.map_append, List.map_singleton]

theorem native_json_push_refusal_preserves_state (output : NativeJsonBuild) (piece : NativeNamedJson) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_push output piece ⦃ actual =>
      ∀ error, actual.1 = .Err error → actual.2 = output ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.json_push
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp [nativeFull]
  · have room : output.pieces.val.length < 256 := by omega
    have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp only [nativeRoom, ↓reduceIte]
    cases piece <;> simp only [bind_tc_ok]
    all_goals
      step with native_resource_add_exact as ⟨charged, _⟩
      cases charged with
      | none => simp
      | some next =>
          step with native_push_exact output.pieces _ (by scalar_tac) as ⟨pieces, _⟩
          simp

theorem native_form_push_refusal_preserves_state (output : NativeFormBuild) (piece : NativeNamedForm) :
    AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_push output piece ⦃ actual =>
      ∀ error, actual.1 = .Err error → actual.2 = output ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.template_ast.form_push
    AuthsNativeRecipe.auths_gateway_kernel.body_compiler.MAX_TEMPLATE_PIECES
  by_cases full : 256 ≤ output.pieces.val.length
  · have nativeFull : AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp [nativeFull]
  · have room : output.pieces.val.length < 256 := by omega
    have nativeRoom : ¬AuthsNativeRecipe.alloc.vec.Vec.len output.pieces >= 256#usize := by scalar_tac
    simp only [nativeRoom, ↓reduceIte]
    step with native_form_piece_resources_exact output.resources piece as ⟨charged, _⟩
    cases charged with
    | none => simp
    | some next =>
        step with native_push_exact output.pieces piece (by scalar_tac) as ⟨pieces, _⟩
        simp

end Auths.Product.NativeCompiler.Refinement
