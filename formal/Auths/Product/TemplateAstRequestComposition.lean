import Auths.Product.TemplateAstCompilerRefinement
import Auths.Product.RequestCompilerComposition

namespace Auths.Product.TemplateAst
open RequestConstruction

/-- Independent complete request meaning. Non-body recipe data uses its
original named interpretation; the body comes directly from the original AST.
The source's intermediate body template is not read. URL/body/header error
precedence is the existing complete writer's precedence. -/
def referenceRequest (source : RequestCompiler.Source) (body : Body) (placement : Option Echo)
    (environment : Bytes → Option Arg) (echo key : Bytes) : Except Error (Except ConstructError Request) :=
  (interpretBody body placement environment echo).map fun rendered => do
    let url ← PathCompiler.namedUrl source.origin environment source.path
    let body ← BodyCompiler.finishNamedBody rendered.valid rendered.bytes
    let headers ← HeaderCompiler.namedHeaders environment source.versions source.scope
    let headers := if source.idempotency then headers ++ [⟨RequestCompiler.idempotencyHeader, key⟩] else headers
    .ok ⟨source.method, url, headers, body⟩

theorem original_request_matches_compiled_body (source : RequestCompiler.Source) (body : Body) (placement : Option Echo)
    (template : NamedTemplate) (compiled : compileBody body placement = .ok template)
    (bodySource : source.body = namedBody template) (environment : Bytes → Option Arg) (echo key : Bytes) :
    referenceRequest source body placement environment echo key = .ok (RequestCompiler.namedRequest environment source echo key) := by
  have interpreted := compile_body_refines_original_ast body placement template compiled environment echo
  unfold referenceRequest
  rw [interpreted]
  cases template <;> simp [RequestCompiler.namedRequest, bodySource, namedBody, renderedTemplate,
    RequestCompiler.namedBody, Except.map]

end Auths.Product.TemplateAst

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement
open Auths.Product.RequestCompiler.Refinement

namespace Auths.Product.TemplateAst.Refinement
set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-- Actual AST compilation and template borrowing feed the actual complete
request compiler, reserved-value/operation binder, token encoders and writer.
Every returned construction outcome is interpreted from the original AST and
original named request frame, with the same projected namespace/digest/operation
and action arguments. Native decoded-source/profile/hash/approval and sealed
command/driver provenance remain explicit outer obligations. -/
theorem source_ast_bound_write_refines_original_request (body : template_ast.Body) (placement : Option template_ast.Echo)
    (fields : Slice field_projection.FieldSpec) (supplied : Slice field_projection.NamedInput)
    (source : request_compiler.WriteSource) (namespace recipe : Slice U8)
    (echoDigest keyDigest : Array U8 32#usize) :
    (do
      let template ← template_ast.compile_body body placement
      match template with
      | .Err _ => ok none
      | .Ok template => do
        let named ← template_ast.NamedTemplate.source template
        let compiled ← request_compiler.compile_write fields { source with body := named }
        match compiled with
        | .Err _ => ok none
        | .Ok compiled => do
          let projected ← field_projection.project_request fields supplied namespace recipe
          match projected with
          | .Err _ => ok none
          | .Ok accepted => do
            let echo ← derived_tokens.echo_token_bytes echoDigest
            let key ← derived_tokens.idempotency_token_bytes keyDigest
            let request ← construct.construct_write compiled.plan (alloc.vec.Vec.deref accepted.values)
              (alloc.vec.Vec.deref echo) (alloc.vec.Vec.deref key)
            ok (some (accepted, request))) ⦃ actual =>
      ∀ accepted request, actual = some (accepted, request) →
        RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace) (sliceBytes recipe)
          (.ok (boundArgumentsOf accepted)) ∧
        ∃ environment, RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          referenceRequest (sourceOf source) (bodyOf body) (placement.map echoOf)
            (fun name => ArgumentBinding.lookup name environment)
            (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes echoDigest))
            (DerivedTokens.token .idempotency (DerivedTokens.Refinement.digestBytes keyDigest)) = .ok (resultOf requestOf request) ⦄ := by
  step with compile_body_exact as ⟨template, templateMeaning⟩
  cases template with
  | Err error => simp
  | Ok template =>
    have astRun : compileBody (bodyOf body) (placement.map echoOf) = .ok (namedTemplateOf template) := by
      simpa [templateResult] using templateMeaning.symm
    step with named_body_view_exact as ⟨named, namedMeaning⟩
    apply spec_mono (source_bound_write_refines_named_request fields supplied { source with body := named }
      namespace recipe echoDigest keyDigest)
    intro actual outcome accepted request same
    obtain ⟨bound, environment, rows, requestMeaning⟩ := outcome accepted request same
    refine ⟨bound, environment, rows, ?_⟩
    have bodySource : (sourceOf { source with body := named }).body = namedBody (namedTemplateOf template) := by
      simpa [sourceOf] using namedMeaning
    have original := original_request_matches_compiled_body (sourceOf { source with body := named })
      (bodyOf body) (placement.map echoOf) (namedTemplateOf template) astRun bodySource
      (fun name => ArgumentBinding.lookup name environment)
      (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes echoDigest))
      (DerivedTokens.token .idempotency (DerivedTokens.Refinement.digestBytes keyDigest))
    have frame : referenceRequest (sourceOf { source with body := named }) = referenceRequest (sourceOf source) := rfl
    rw [frame, ← requestMeaning] at original
    exact original

end Auths.Product.TemplateAst.Refinement
