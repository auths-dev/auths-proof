import Auths.Product.NativeCompilerOriginDomain
import Auths.Product.NativeCompilerConstructorTrace

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

open AuthsNativeRecipe

/-- Complete original parsed components, without an origin-admission bit. -/
def nativeParsedOrigin (parsed : NativeModel.UrlProjection) : RecipeOriginAdmission.Parsed := {
  scheme := schemaSliceBytes parsed.scheme.val
  username := schemaSliceBytes parsed.username.val
  password := parsed.password.map (fun value => schemaSliceBytes value.val)
  host := parsed.host.map (fun value => match value with
    | .domain text => .domain (schemaSliceBytes text.val)
    | .ipv4 address => .ipv4 (address.octets.val.map (·.val))
    | .ipv6 address => .ipv6 (address.octets.val.map (·.val)))
  port := parsed.port.map UScalar.val
  path := schemaSliceBytes parsed.path.val
  query := parsed.query.map (fun value => schemaSliceBytes value.val)
  fragment := parsed.fragment.map (fun value => schemaSliceBytes value.val)
}

def nativeParsedOriginOutcome : Except url.parser.ParseError NativeModel.UrlProjection →
    Except Unit RecipeOriginAdmission.Parsed
  | .error _ => .error ()
  | .ok parsed => .ok (nativeParsedOrigin parsed)

def nativeOriginOutcome : core.result.Result String NativeRecipeError → Except NativeRecipeError (List Nat)
  | .Err error => .error error
  | .Ok host => .ok (textBytes host)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
open RecipeOriginAdmission
open AuthsNativeRecipe

variable [nativeUrl : UrlPrimitives]

set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

/-- Every source success/refusal branch is relative to the named URL parser's
complete result. A separate pinned parser/normalization contract must relate
that result to WHATWG parsing of the original input. No admitted-origin flag,
expected host or accepted helper result is a premise. -/
@[step] theorem native_origin_admission_exact (original : Str) :
    recipe.validate_origin original ⦃ actual => nativeOriginOutcome actual =
      validate NativeRecipeError.UnsafeOrigin (schemaSliceBytes original)
        (nativeParsedOriginOutcome (nativeUrl.parse original)) ⦄ := by
  unfold recipe.validate_origin
  step with native_str_size_exact original as ⟨size, sizeMeaning⟩
  by_cases large : 261 < original.val.length
  · have nativeLarge : size > auths_gateway_kernel.path_compiler.MAX_ORIGIN_BYTES := by
      simp only [auths_gateway_kernel.path_compiler.MAX_ORIGIN_BYTES]
      scalar_tac
    simp [nativeLarge, validate, schemaSliceBytes, Nat.not_le.mpr large, nativeOriginOutcome]
  · have bounded : original.val.length ≤ 261 := by omega
    have nativeBound : ¬size > auths_gateway_kernel.path_compiler.MAX_ORIGIN_BYTES := by
      simp only [auths_gateway_kernel.path_compiler.MAX_ORIGIN_BYTES]
      scalar_tac
    simp only [nativeBound, ↓reduceIte]
    cases parsedResult : nativeUrl.parse original with
    | error reason =>
        simp [url.Url.parse, parsedResult, nativeOriginOutcome, nativeParsedOriginOutcome,
          validate, schemaSliceBytes, bounded, core.result.Result.map_err,
          _root_.core.result.Result.map_err,
          recipe.validate_origin.closure.Insts.CoreOpsFunctionFnOnceTupleParseErrorGatewayRecipeError,
          recipe.validate_origin.closure.Insts.CoreOpsFunctionFnOnceTupleParseErrorGatewayRecipeError.call_once,
          core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
          core.convert.FromSame, core.convert.FromSame.from]
    | ok parsed =>
        simp only [url.Url.parse, parsedResult, core.result.Result.map_err,
          _root_.core.result.Result.map_err, core.result.Result.Insts.CoreOpsTry.branch,
          bind_tc_ok, url.Url.scheme, core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, lift]
        step with native_schema_byte_equality parsed.scheme.val (toStr "https") as ⟨schemeValid, schemeMeaning⟩
        have schemeMeaning : schemeValid = decide (schemaSliceBytes parsed.scheme.val = https) := by
          simpa [https, schemaSliceBytes] using schemeMeaning
        by_cases scheme : schemaSliceBytes parsed.scheme.val = https
        · have schemeTrue : schemeValid = true := by simpa [scheme] using schemeMeaning
          simp only [schemeTrue, Bool.true_eq_true, ↓reduceIte, url.Url.username,
            core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
          step as ⟨usernameEmpty, usernameMeaning⟩
          by_cases username : schemaSliceBytes parsed.username.val = []
          · have usernameTrue : usernameEmpty = true := by
              simpa [schemaSliceBytes, List.length_eq_zero_iff, username] using usernameMeaning
            simp only [usernameTrue, Bool.true_eq_true, ↓reduceIte, url.Url.password, bind_tc_ok]
            cases password : parsed.password with
            | some value =>
                simp [password, core.option.Option.is_some, nativeOriginOutcome, validate,
                  nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin, Attributes,
                  schemaSliceBytes, bounded]
            | none =>
                simp only [password, Option.map_none, core.option.Option.is_some, ↓reduceIte,
                  url.Url.port, bind_tc_ok]
                cases port : parsed.port with
                | some value =>
                    simp [port, core.option.Option.is_some, nativeOriginOutcome, validate,
                      nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin, Attributes,
                      schemaSliceBytes, bounded, password]
                | none =>
                    simp only [port, core.option.Option.is_some, ↓reduceIte, url.Url.path,
                      core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok, lift]
                    step with native_schema_byte_equality parsed.path.val (toStr "/") as ⟨pathValid, pathMeaning⟩
                    have pathMeaning : pathValid = decide (schemaSliceBytes parsed.path.val = [47]) := by
                      simpa [schemaSliceBytes] using pathMeaning
                    by_cases path : schemaSliceBytes parsed.path.val = [47]
                    · have pathTrue : pathValid = true := by simpa [path] using pathMeaning
                      simp only [pathTrue, Bool.true_eq_true, ↓reduceIte, url.Url.query, bind_tc_ok]
                      cases query : parsed.query with
                      | some value =>
                          simp [query, core.option.Option.is_some, nativeOriginOutcome, validate,
                            nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin, Attributes,
                            schemaSliceBytes, bounded, password, port]
                      | none =>
                          simp only [query, Option.map_none, core.option.Option.is_some, ↓reduceIte,
                            url.Url.fragment, bind_tc_ok]
                          cases fragment : parsed.fragment with
                          | some value =>
                              simp [fragment, core.option.Option.is_some, nativeOriginOutcome, validate,
                                nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin, Attributes,
                                schemaSliceBytes, bounded, password, port, query]
                          | none =>
                              have attributes : Attributes (nativeParsedOrigin parsed) := by
                                simp [Attributes, nativeParsedOrigin, scheme, username, password, port, path, query, fragment]
                              simp only [fragment, Option.map_none, core.option.Option.is_some, ↓reduceIte,
                                url.Url.host, bind_tc_ok]
                              cases host : parsed.host with
                              | none =>
                                  simp [host, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
                                    parsedResult, nativeParsedOrigin, schemaSliceBytes, bounded, attributes]
                              | some hostValue =>
                                  cases hostValue with
                                  | ipv4 address =>
                                      simp [host, NativeModel.parsedHost, nativeOriginOutcome, validate,
                                        nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin,
                                        schemaSliceBytes, bounded, attributes]
                                  | ipv6 address =>
                                      simp [host, NativeModel.parsedHost, nativeOriginOutcome, validate,
                                        nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin,
                                        schemaSliceBytes, bounded, attributes]
                                  | domain domain =>
                                      simp only [host, Option.map_some, NativeModel.parsedHost]
                                      step with native_utf8_owned_exact domain as ⟨owned, ownedMeaning, ownedFits⟩
                                      simp only [core.str.Str.as_bytes, _root_.core.str.Str.as_bytes, bind_tc_ok]
                                      step with borrow_text_exact owned ownedFits as ⟨hostBytes, hostMeaning⟩
                                      step with native_origin_frame_exact original hostBytes as ⟨frameValid, frameMeaning⟩
                                      have hostMeaning : schemaSliceBytes hostBytes = schemaSliceBytes domain.val := by
                                        simpa [schemaSliceBytes, ownedMeaning] using hostMeaning
                                      by_cases frame : PathCompiler.OriginMatches (schemaSliceBytes original) (schemaSliceBytes domain.val)
                                      · have frameTrue : frameValid = true := by simpa [hostMeaning, frame] using frameMeaning
                                        simp only [frameTrue, Bool.true_eq_true, ↓reduceIte]
                                        step with native_deref_text_exact owned ownedFits as ⟨view, originalView, viewMeaning⟩
                                        step with native_origin_domain_exact view as ⟨policyValid, policyMeaning⟩
                                        have policyMeaning : policyValid = decide (DomainPolicy (schemaSliceBytes domain.val)) := by
                                          simpa [viewMeaning, ownedMeaning] using policyMeaning
                                        by_cases policy : DomainPolicy (schemaSliceBytes domain.val)
                                        · have policyTrue : policyValid = true := by simpa [policy] using policyMeaning
                                          simp [policyTrue, nativeOriginOutcome, ownedMeaning, validate,
                                            nativeParsedOriginOutcome, parsedResult, nativeParsedOrigin,
                                            schemaSliceBytes, bounded, attributes, host, frame, policy]
                                        · have policyFalse : policyValid = false := by simpa [policy] using policyMeaning
                                          simp [policyFalse, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
                                            parsedResult, nativeParsedOrigin, schemaSliceBytes, bounded,
                                            attributes, host, frame, policy]
                                      · have frameFalse : frameValid = false := by simpa [hostMeaning, frame] using frameMeaning
                                        simp [frameFalse, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
                                          parsedResult, nativeParsedOrigin, schemaSliceBytes, bounded,
                                          attributes, host, frame]
                    · have pathFalse : pathValid = false := by simpa [path] using pathMeaning
                      simp [pathFalse, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
                        parsedResult, nativeParsedOrigin, Attributes, schemaSliceBytes, bounded, path]
          · have usernameFalse : usernameEmpty = false := by
              simpa [schemaSliceBytes, List.length_eq_zero_iff, username] using usernameMeaning
            simp [usernameFalse, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
              parsedResult, nativeParsedOrigin, Attributes, schemaSliceBytes, bounded, username]
        · have schemeFalse : schemeValid = false := by simpa [scheme] using schemeMeaning
          simp [schemeFalse, nativeOriginOutcome, validate, nativeParsedOriginOutcome,
            parsedResult, nativeParsedOrigin, Attributes, schemaSliceBytes, bounded, scheme]

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]

@[step] theorem native_constructor_origin_exact (source : NativeConstructorSource)
    (fits : TextFits source.origin) :
    constructorOrigin source ⦃ actual => nativeOriginOutcome actual =
      validate NativeRecipeError.UnsafeOrigin (textBytes source.origin)
        (nativeParsedOriginOutcome (nativeUrl.parse (nativeTextView source.origin fits))) ⦄ := by
  unfold constructorOrigin
  step with native_deref_view_exact source.origin fits as ⟨original, originalMeaning⟩
  subst original
  apply spec_mono (native_origin_admission_exact (nativeTextView source.origin fits))
  intro actual meaning
  simpa [nativeTextView, schemaSliceBytes, native_text_bytes] using meaning

theorem native_constructor_success_earns_origin (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : recipe.CanonicalRecipeInputs)
    (fits : TextFits source.origin) (checked : NativeConstructorRecord)
    (completed : recipe.validate.validate_source source lock canonical = ok (.Ok checked)) :
    ∃ parsed, nativeParsedOriginOutcome (nativeUrl.parse (nativeTextView source.origin fits)) = .ok parsed ∧
      ParsedOrigin (textBytes source.origin) parsed (textBytes checked.parsed_host) := by
  have trace := native_constructor_success_earns_original_trace source lock canonical checked completed
  have meaning := native_constructor_origin_exact source fits
  rw [trace.originChecked] at meaning
  have accepted : validate NativeRecipeError.UnsafeOrigin (textBytes source.origin)
      (nativeParsedOriginOutcome (nativeUrl.parse (nativeTextView source.origin fits))) =
      .ok (textBytes checked.parsed_host) := by
    have outcome : (.ok (textBytes checked.parsed_host) : Except NativeRecipeError (List Nat)) =
        validate NativeRecipeError.UnsafeOrigin (textBytes source.origin)
          (nativeParsedOriginOutcome (nativeUrl.parse (nativeTextView source.origin fits))) := by
      simpa [spec_ok, nativeOriginOutcome] using meaning
    exact outcome.symm
  exact successful_origin_has_original_components _ _ _ _ accepted

/-- Whole successful compilation earns the original HTTPS/canonical-domain
frame and domain policy. DNS/TLS and the independent URL parser relation remain
explicit external boundaries, and rule/guard admission remains separate. -/
theorem native_compile_success_earns_origin (source : NativeConstructorSource)
    (lock : NativeProfileLock) (canonical : recipe.CanonicalRecipeInputs)
    (fits : TextFits source.origin) (output : recipe.CompiledRecipe)
    (completed : recipe.compile_decoded source lock canonical = ok (.Ok output)) :
    ∃ domain, textBytes source.origin = PathCompiler.httpsPrefix ++ domain ∧
      0 < domain.length ∧ domain.length ≤ 253 ∧ DomainPolicy domain := by
  obtain ⟨checked, admitted, digest, plans, original, namespaceValue⟩ :=
    native_compile_success_keeps_all_stage_results source lock canonical output completed
  obtain ⟨parsed, parserResult, meaning⟩ := native_constructor_success_earns_origin source lock canonical fits checked admitted
  obtain ⟨frame, positive, bound⟩ := parsed_origin_retains_exact_host _ _ _ meaning
  exact ⟨textBytes checked.parsed_host, frame, positive, bound, meaning.2.2.2.2⟩

end Auths.Product.NativeCompiler.Refinement
