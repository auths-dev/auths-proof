import Auths.Product.RequestCompilerRefinement
import Auths.Product.DerivedTokensRefinement
import Auths.Product.RequestBindingRefinement

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.FieldProjection
open Auths.Product.FieldProjection.Refinement

namespace Auths.Product.RequestCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

private theorem rows_bound_environment (fields : List Field) (inputs : Inputs)
    (environment : ArgumentBinding.Environment) (rows : RowsMeaning fields inputs environment) :
    BodyCompiler.EnvironmentBounded (fun name => ArgumentBinding.lookup name environment) := by
  intro name value found
  exact rows_earn_payloads fields inputs environment rows (name, value)
    (ArgumentBinding.lookup_member name environment value found)

private theorem lowered_body_earns_fit (names : List Bytes) (source : SourceBody) (plan : BodyPlan)
    (values : List Arg) (environment : Bytes → Option Arg) (echo : Bytes)
    (aligned : SchemaIndex.Aligned names values environment)
    (bounded : BodyCompiler.EnvironmentBounded environment) (echoBound : echo.length ≤ 128)
    (run : lowerBody names source = .ok plan) : (renderBody values echo plan).length < 4294967295 := by
  cases source with
  | json source =>
    cases lowered : BodyCompiler.lowerJson names source with
    | error error => simp [lowerBody, lowered] at run
    | ok pieces =>
      have same : BodyPlan.json pieces = plan := by simpa [lowerBody, lowered] using run
      subst plan
      have domain := BodyCompiler.lower_json_earns_resources _ _ _ lowered
      have meaning := (BodyCompiler.lower_json_sound _ _ _ lowered).2.2
      have rendering := (BodyCompiler.json_list_named _ _ _ echo aligned _ _ meaning).1
      have fit := BodyCompiler.json_resource_domain_earns_writer_fit _ _ bounded echoBound _ domain
      simpa [renderBody, rendering] using fit
  | form source =>
    cases lowered : BodyCompiler.lowerForm names source with
    | error error => simp [lowerBody, lowered] at run
    | ok pieces =>
      have same : BodyPlan.form pieces = plan := by simpa [lowerBody, lowered] using run
      subst plan
      have domain := BodyCompiler.lower_form_earns_resources _ _ _ lowered
      have meaning := (BodyCompiler.lower_form_sound _ _ _ lowered).2.2
      have rendering := (BodyCompiler.form_list_named _ _ _ echo aligned _ _ meaning).1
      have fit := BodyCompiler.form_resource_domain_earns_writer_fit _ _ bounded echoBound _ domain
      simpa [renderBody, rendering] using fit

private theorem headers_earn_fit (names : List Bytes) (versions : Option HeaderCompiler.Versions)
    (scope : Option HeaderCompiler.ScopeSource) (plan : construct.HeaderPlan)
    (run : HeaderCompiler.lowerHeaders names versions scope = .ok (headerPlanOf plan)) : HeaderPlanFits plan := by
  obtain ⟨count, rows, accountBound⟩ := HeaderCompiler.lower_headers_earns_bounds _ _ _ _ run
  have nativeCount : plan.versions.val.length ≤ 2 := by simpa [headerPlanOf] using count
  refine ⟨by omega, ?_, ?_⟩
  · intro header member
    have bounds := rows (headerOf header) (List.mem_map.mpr ⟨header, member, rfl⟩)
    have nameBound : header.name.val.length ≤ 20 := by simpa [headerOf, vecBytes, byteList] using bounds.1
    have valueBound : header.value.val.length ≤ 64 := by simpa [headerOf, vecBytes, byteList] using bounds.2
    constructor <;> omega
  · intro account present
    have modelPresent : (headerPlanOf plan).scope = some (scopeOf account) := by simp [headerPlanOf, present]
    have size := accountBound _ modelPresent
    have nativeSize : account.name.val.length = 14 := by simpa [scopeOf, vecBytes, byteList] using size
    omega

private theorem complete_write_fits (fields : List Field) (inputs : Inputs) (source : Source)
    (compiled : request_compiler.CompiledWrite) (values : alloc.vec.Vec construct.ArgumentValue)
    (echo key : alloc.vec.Vec Std.U8)
    (compiledMeaning : CompilationMeaning fields source (compiledOf compiled))
    (object : ObjectOutcome fields inputs (.ok (values.val.map argOf)))
    (echoSize : echo.val.length = 73) (keySize : key.val.length = 73) :
    WriteFits compiled.plan (alloc.vec.Vec.deref values) (alloc.vec.Vec.deref echo) (alloc.vec.Vec.deref key) := by
  obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
  have valueBounds := object_output_payloads_bounded _ _ _ object
  have originBound : compiled.plan.origin.val.length ≤ 261 := by
    have size := PathCompiler.origin_matches_bound _ _ compiledMeaning.originFrame
    rw [← compiledMeaning.origin] at size
    simpa [compiledOf, writePlanOf, vecBytes, byteList] using size
  have pathRun := compiledMeaning.path
  unfold PathCompiler.lowerPath at pathRun
  have pathBound : (renderPath (values.val.map argOf) (compiled.plan.path.val.map segmentOf)).length ≤ 196624 := by
    split at pathRun
    · rename_i admitted
      have mapping := PathCompiler.lower_list_sound _ _ _ pathRun
      have size := PathCompiler.lowered_path_length_bound _ _ _ _ valueBounds mapping
      omega
    · contradiction
  have echoBound : (vecBytes echo).length ≤ 128 := by simp [vecBytes, byteList, echoSize]
  have bodyFit := lowered_body_earns_fit _ _ _ _ _ (vecBytes echo) aligned
    (rows_bound_environment _ _ _ rows) echoBound compiledMeaning.body
  have headerFit := headers_earn_fit _ _ _ compiled.plan.headers compiledMeaning.headers
  refine ⟨?_, ?_, headerFit, ?_, ?_⟩
  · change compiled.plan.origin.val.length +
      (renderPath (values.val.map argOf) (compiled.plan.path.val.map segmentOf)).length < 4294967295
    omega
  · simpa [compiledOf, writePlanOf, argsOf, vecBytes] using bodyFit
  · intro headerName present
    have modelPresent : (compiledOf compiled).plan.idempotency = some (vecBytes headerName) := by
      simp [compiledOf, writePlanOf, present]
    rw [compiledMeaning.idempotency] at modelPresent
    cases source.idempotency
    · simp at modelPresent
    · have same : vecBytes headerName = idempotencyHeader := by simpa using modelPresent.symm
      have size : headerName.val.length = 15 := by
        have lengths := congrArg List.length same
        simpa [vecBytes, byteList, idempotencyHeader] using lengths
      omega
  · simpa [keySize] using (show 73 < 4294967295 by omega)

/-- Actual whole compilation, complete object projection, both fixed-digest
token encoders and complete request construction compose to the original
named source. Every write-construction domain is earned from actual results;
there is no supplied success, aligned projection, bounded payload, expected
URL/header/body, size or rendered token premise. Native AST/profile/hash/
String/approval and sealed-to-driver provenance remain separate boundaries. -/
theorem source_complete_write_refines_named_request (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : request_compiler.WriteSource)
    (echoDigest keyDigest : Array Std.U8 32#usize) :
    (do
      let compiled ← request_compiler.compile_write fields source
      match compiled with
      | .Err _ => ok none
      | .Ok compiled => do
        let projected ← field_projection.project_object fields supplied
        match projected with
        | .Err _ => ok none
        | .Ok values => do
          let echo ← derived_tokens.echo_token_bytes echoDigest
          let key ← derived_tokens.idempotency_token_bytes keyDigest
          let request ← construct.construct_write compiled.plan (alloc.vec.Vec.deref values)
            (alloc.vec.Vec.deref echo) (alloc.vec.Vec.deref key)
          ok (some request)) ⦃ actual =>
      ∀ request, actual = some request → ∃ environment,
        RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf requestOf request = namedRequest (fun name => ArgumentBinding.lookup name environment)
            (sourceOf source) (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes echoDigest))
            (DerivedTokens.token .idempotency (DerivedTokens.Refinement.digestBytes keyDigest)) ⦄ := by
  step with compile_write_exact as ⟨compiled, compilerMeaning⟩
  cases compiled with
  | Err error => simp
  | Ok compiled =>
    have compilerRun : compile (fieldsView fields) (sourceOf source) = .ok (compiledOf compiled) := by
      simpa [compiledResult] using compilerMeaning.symm
    have meaning := compile_sound _ _ _ compilerRun
    step with project_object_exact as ⟨projected, objectMeaning⟩
    cases projected with
    | Err error => simp
    | Ok values =>
      have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (values.val.map argOf)) := objectMeaning
      obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
      step with DerivedTokens.Refinement.echo_token_exact as ⟨echo, echoMeaning⟩
      have echoSize : echo.val.length = 73 := by
        have size := DerivedTokens.token_length .echo _ (DerivedTokens.Refinement.digest_size echoDigest)
        rw [← echoMeaning] at size
        simpa [vecBytes, byteList] using size
      step with DerivedTokens.Refinement.idempotency_token_exact as ⟨key, keyMeaning⟩
      have keySize : key.val.length = 73 := by
        have size := DerivedTokens.token_length .idempotency _ (DerivedTokens.Refinement.digest_size keyDigest)
        rw [← keyMeaning] at size
        simpa [vecBytes, byteList] using size
      have fits := complete_write_fits _ _ _ compiled values echo key meaning object echoSize keySize
      have named := compiled_request_preserves_named_source _ _ _ _ _ (vecBytes echo) (vecBytes key) meaning aligned
      step with translated_construct_write_refines_model as ⟨request, requestMeaning⟩
      simp only [spec_ok]
      intro actual same
      have equal : actual = request := (Option.some.inj same).symm
      subst actual
      refine ⟨environment, rows, ?_⟩
      simpa [compiledOf, argsOf, vecBytes, named, echoMeaning, keyMeaning] using requestMeaning

/-- Complete source compilation and the actual namespace/digest/operation
binder feed one exact request. Reserved binding values and rendered arguments
come from the same object. Digest provenance, native JSON/AST/String adapters,
sealed authority and the driver remain explicit outer obligations. -/
theorem source_bound_write_refines_named_request (fields : Slice field_projection.FieldSpec)
    (supplied : Slice field_projection.NamedInput) (source : request_compiler.WriteSource)
    (namespace recipe : Slice Std.U8) (echoDigest keyDigest : Array Std.U8 32#usize) :
    (do
      let compiled ← request_compiler.compile_write fields source
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
        RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
          (sliceBytes recipe) (.ok (boundArgumentsOf accepted)) ∧
        ∃ environment, RowsMeaning (fieldsView fields) (inputsView supplied) environment ∧
          resultOf requestOf request = namedRequest (fun name => ArgumentBinding.lookup name environment)
            (sourceOf source) (DerivedTokens.token .echo (DerivedTokens.Refinement.digestBytes echoDigest))
            (DerivedTokens.token .idempotency (DerivedTokens.Refinement.digestBytes keyDigest)) ⦄ := by
  step with compile_write_exact as ⟨compiled, compilerMeaning⟩
  cases compiled with
  | Err error => simp
  | Ok compiled =>
    have compilerRun : compile (fieldsView fields) (sourceOf source) = .ok (compiledOf compiled) := by
      simpa [compiledResult] using compilerMeaning.symm
    have meaning := compile_sound _ _ _ compilerRun
    step with project_request_exact as ⟨projected, projectedMeaning⟩
    cases projected with
    | Err error => simp
    | Ok accepted =>
      have binding : RequestOutcome (fieldsView fields) (inputsView supplied) (sliceBytes namespace)
          (sliceBytes recipe) (.ok (boundArgumentsOf accepted)) := projectedMeaning
      have object : ObjectOutcome (fieldsView fields) (inputsView supplied) (.ok (accepted.values.val.map argOf)) := binding.2.1
      obtain ⟨environment, rows, aligned⟩ := object_result_earns_named_alignment _ _ _ object
      step with DerivedTokens.Refinement.echo_token_exact as ⟨echo, echoMeaning⟩
      have echoSize : echo.val.length = 73 := by
        have size := DerivedTokens.token_length .echo _ (DerivedTokens.Refinement.digest_size echoDigest)
        rw [← echoMeaning] at size
        simpa [vecBytes, byteList] using size
      step with DerivedTokens.Refinement.idempotency_token_exact as ⟨key, keyMeaning⟩
      have keySize : key.val.length = 73 := by
        have size := DerivedTokens.token_length .idempotency _ (DerivedTokens.Refinement.digest_size keyDigest)
        rw [← keyMeaning] at size
        simpa [vecBytes, byteList] using size
      have fits := complete_write_fits _ _ _ compiled accepted.values echo key meaning object echoSize keySize
      have named := compiled_request_preserves_named_source _ _ _ _ _ (vecBytes echo) (vecBytes key) meaning aligned
      step with translated_construct_write_refines_model as ⟨request, requestMeaning⟩
      simp only [spec_ok]
      intro selected produced same
      have equal := Option.some.inj same
      cases equal
      refine ⟨binding, environment, rows, ?_⟩
      simpa [compiledOf, argsOf, vecBytes, named, echoMeaning, keyMeaning] using requestMeaning

end Auths.Product.RequestCompiler.Refinement
