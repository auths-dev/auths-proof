import Auths.Product.HeaderCompiler
import Auths.Product.BodyCompilerBounds

namespace Auths.Product.RequestCompiler
open RequestConstruction

inductive SourceBody where
  | json (pieces : List BodyCompiler.NamedJson)
  | form (pieces : List BodyCompiler.NamedForm)
  deriving DecidableEq

structure Source where
  method : Method
  origin : Bytes
  parsedHost : Bytes
  path : List PathCompiler.SourceSegment
  versions : Option HeaderCompiler.Versions
  scope : Option HeaderCompiler.ScopeSource
  idempotency : Bool
  body : SourceBody

inductive CompileError where
  | fields
  | origin
  | method
  | headers (error : HeaderCompiler.CompileError)
  | path (error : ConstructError)
  | body (error : ConstructError)
  deriving DecidableEq

structure Compiled where
  names : List Bytes
  plan : WritePlan

def idempotencyHeader : Bytes := [73,100,101,109,112,111,116,101,110,99,121,45,75,101,121]

def writeMethodAllowed : Method → Bool
  | .post | .put | .patch | .delete => true
  | .get | .head => false

def lowerBody (names : List Bytes) : SourceBody → Except ConstructError BodyPlan
  | .json source => (BodyCompiler.lowerJson names source).map BodyPlan.json
  | .form source => (BodyCompiler.lowerForm names source).map BodyPlan.form

def BodyAdmissible (names : List Bytes) : SourceBody → Prop
  | .json source => BodyCompiler.JsonTemplateAdmissible names source
  | .form source => BodyCompiler.FormTemplateAdmissible names source
instance (names : List Bytes) (source : SourceBody) : Decidable (BodyAdmissible names source) := by
  cases source <;> unfold BodyAdmissible <;> infer_instance

def compile (fields : List FieldProjection.Field) (source : Source) : Except CompileError Compiled :=
  if FieldProjection.LayoutValid fields then
    if PathCompiler.OriginMatches source.origin source.parsedHost then
      if writeMethodAllowed source.method then
        match HeaderCompiler.lowerHeaders (FieldProjection.names fields) source.versions source.scope with
        | .error error => .error (.headers error)
        | .ok headers =>
          match PathCompiler.lowerPath (FieldProjection.names fields) source.path with
          | .error error => .error (.path error)
          | .ok path =>
            match lowerBody (FieldProjection.names fields) source.body with
            | .error error => .error (.body error)
            | .ok body => .ok ⟨FieldProjection.names fields, {
                method := source.method, origin := source.origin, path, headers,
                idempotency := if source.idempotency then some idempotencyHeader else none, body }⟩
      else .error .method
    else .error .origin
  else .error .fields

/-- Independent typed-source admission; neither a compiled result nor a
successful helper is supplied as an input. Native AST/profile/JSON meaning is
outside this byte-source view. -/
def Admissible (fields : List FieldProjection.Field) (source : Source) : Prop :=
  FieldProjection.LayoutValid fields ∧ PathCompiler.OriginMatches source.origin source.parsedHost ∧
    writeMethodAllowed source.method = true ∧
    HeaderCompiler.HeaderAdmissible (FieldProjection.names fields) source.versions source.scope ∧
    PathCompiler.PathAdmissible (FieldProjection.names fields) source.path ∧
    BodyAdmissible (FieldProjection.names fields) source.body
instance (fields : List FieldProjection.Field) (source : Source) : Decidable (Admissible fields source) := by
  unfold Admissible; infer_instance

/-- All assembly equations and component outcomes are conclusions earned from
compilation. In particular the original method/origin/idempotency choice and
the single field-name column cannot be replaced by caller-supplied outcomes. -/
structure CompilationMeaning (fields : List FieldProjection.Field) (source : Source) (result : Compiled) : Prop where
  layout : FieldProjection.LayoutValid fields
  names : result.names = FieldProjection.names fields
  originFrame : PathCompiler.OriginMatches source.origin source.parsedHost
  writeMethod : writeMethodAllowed source.method = true
  method : result.plan.method = source.method
  origin : result.plan.origin = source.origin
  headers : HeaderCompiler.lowerHeaders (FieldProjection.names fields) source.versions source.scope = .ok result.plan.headers
  path : PathCompiler.lowerPath (FieldProjection.names fields) source.path = .ok result.plan.path
  body : lowerBody (FieldProjection.names fields) source.body = .ok result.plan.body
  idempotency : result.plan.idempotency = if source.idempotency then some idempotencyHeader else none

theorem lower_body_complete (names : List Bytes) (source : SourceBody) (admitted : BodyAdmissible names source) :
    ∃ plan, lowerBody names source = .ok plan := by
  cases source with
  | json source =>
    obtain ⟨pieces, run⟩ := BodyCompiler.lower_json_complete names source admitted
    exact ⟨.json pieces, by simp [lowerBody, run]⟩
  | form source =>
    obtain ⟨pieces, run⟩ := BodyCompiler.lower_form_complete names source admitted
    exact ⟨.form pieces, by simp [lowerBody, run]⟩

theorem compile_complete (fields : List FieldProjection.Field) (source : Source) (admitted : Admissible fields source) :
    ∃ compiled, compile fields source = .ok compiled := by
  obtain ⟨layout, origin, method, headersAdmitted, pathAdmitted, bodyAdmitted⟩ := admitted
  obtain ⟨headers, headerRun⟩ := HeaderCompiler.lower_headers_complete _ _ _ headersAdmitted
  obtain ⟨path, pathRun⟩ := PathCompiler.lower_path_complete _ _ pathAdmitted
  obtain ⟨body, bodyRun⟩ := lower_body_complete _ _ bodyAdmitted
  refine ⟨⟨FieldProjection.names fields, {
    method := source.method, origin := source.origin, path, headers,
    idempotency := if source.idempotency then some idempotencyHeader else none, body }⟩, ?_⟩
  simp [compile, layout, origin, method, headerRun, pathRun, bodyRun]

theorem compile_sound (fields : List FieldProjection.Field) (source : Source) (compiled : Compiled)
    (run : compile fields source = .ok compiled) : CompilationMeaning fields source compiled := by
  unfold compile at run
  split at run
  · rename_i layout
    split at run
    · rename_i originFrame
      split at run
      · rename_i method
        cases headerRun : HeaderCompiler.lowerHeaders (FieldProjection.names fields) source.versions source.scope with
        | error error => simp [headerRun] at run
        | ok headers =>
          cases pathRun : PathCompiler.lowerPath (FieldProjection.names fields) source.path with
          | error error => simp [headerRun, pathRun] at run
          | ok path =>
            cases bodyRun : lowerBody (FieldProjection.names fields) source.body with
            | error error => simp [headerRun, pathRun, bodyRun] at run
            | ok body =>
              have same : Compiled.mk (FieldProjection.names fields) {
                  method := source.method, origin := source.origin, path, headers,
                  idempotency := if source.idempotency then some idempotencyHeader else none, body } = compiled := by
                simpa [headerRun, pathRun, bodyRun] using run
              subst compiled
              exact ⟨layout, rfl, originFrame, method, rfl, rfl, headerRun, pathRun, bodyRun, rfl⟩
      · contradiction
    · contradiction
  · contradiction

def namedBody (environment : Bytes → Option Arg) (echo : Bytes) : SourceBody → Except ConstructError Bytes
  | .json source => BodyCompiler.finishNamedBody
      (source.all (BodyCompiler.namedJsonValid environment)) (BodyCompiler.namedJson environment echo source)
  | .form source => BodyCompiler.finishNamedBody
      (source.all (BodyCompiler.namedFormValid environment)) (BodyCompiler.namedForm environment echo source)

/-- Declarative request interpretation uses only source literals and original
names, not compiled indices, a successful writer result or another evaluator's
output. The ordering of typed refusals is URL, body, then headers. -/
def namedRequest (environment : Bytes → Option Arg) (source : Source) (echo key : Bytes) :
    Except ConstructError Request := do
  let url ← PathCompiler.namedUrl source.origin environment source.path
  let body ← namedBody environment echo source.body
  let headers ← HeaderCompiler.namedHeaders environment source.versions source.scope
  let headers := if source.idempotency then headers ++ [⟨idempotencyHeader, key⟩] else headers
  pure ⟨source.method, url, headers, body⟩

theorem lowered_body_preserves_named_rendering (names : List Bytes) (values : List Arg)
    (environment : Bytes → Option Arg) (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : SourceBody) (plan : BodyPlan) (run : lowerBody names source = .ok plan) :
    buildBody plan values echo = namedBody environment echo source := by
  cases source with
  | json source =>
    cases lowered : BodyCompiler.lowerJson names source with
    | error error => simp [lowerBody, lowered] at run
    | ok pieces =>
      have same : BodyPlan.json pieces = plan := by simpa [lowerBody, lowered] using run
      subst plan
      exact BodyCompiler.lowered_json_body_exact _ _ _ _ aligned _ _ lowered
  | form source =>
    cases lowered : BodyCompiler.lowerForm names source with
    | error error => simp [lowerBody, lowered] at run
    | ok pieces =>
      have same : BodyPlan.form pieces = plan := by simpa [lowerBody, lowered] using run
      subst plan
      exact BodyCompiler.lowered_form_body_exact _ _ _ _ aligned _ _ lowered

theorem compiled_request_preserves_named_source (fields : List FieldProjection.Field) (source : Source)
    (compiled : Compiled) (values : List Arg) (environment : Bytes → Option Arg) (echo key : Bytes)
    (meaning : CompilationMeaning fields source compiled)
    (aligned : SchemaIndex.Aligned (FieldProjection.names fields) values environment) :
    constructWrite compiled.plan values echo key = namedRequest environment source echo key := by
  have pathRun := meaning.path
  unfold PathCompiler.lowerPath at pathRun
  split at pathRun
  · have mapping := PathCompiler.lower_list_sound _ _ _ pathRun
    have pathMeaning := PathCompiler.lowered_path_preserves_named_rendering _ _ _ _ _ aligned mapping
    have urlMeaning : buildUrl compiled.plan.origin compiled.plan.path values =
        PathCompiler.namedUrl source.origin environment source.path := by
      simp [buildUrl, PathCompiler.namedUrl, meaning.origin, pathMeaning.1, pathMeaning.2]
    have bodyMeaning := lowered_body_preserves_named_rendering _ _ _ echo aligned _ _ meaning.body
    have headerMeaning := HeaderCompiler.lowered_headers_preserve_named_rendering _ _ _ aligned _ _ _ meaning.headers
    simp only [constructWrite, namedRequest, urlMeaning, bodyMeaning, headerMeaning, meaning.method]
    cases PathCompiler.namedUrl source.origin environment source.path <;> simp
    cases namedBody environment echo source.body <;> simp
    cases HeaderCompiler.namedHeaders environment source.versions source.scope <;>
      simp [writeHeaders, meaning.idempotency]
    cases source.idempotency <;> rfl
  · contradiction

theorem successful_compile_earns_origin_bound (fields : List FieldProjection.Field) (source : Source)
    (compiled : Compiled) (run : compile fields source = .ok compiled) : compiled.plan.origin.length ≤ 261 := by
  have meaning := compile_sound _ _ _ run
  rw [meaning.origin]
  exact PathCompiler.origin_matches_bound _ _ meaning.originFrame

theorem successful_compile_is_write_method (fields : List FieldProjection.Field) (source : Source)
    (compiled : Compiled) (run : compile fields source = .ok compiled) :
    compiled.plan.method ≠ .get ∧ compiled.plan.method ≠ .head := by
  have meaning := compile_sound _ _ _ run
  rw [meaning.method]
  cases source.method <;> simp_all [writeMethodAllowed]

end Auths.Product.RequestCompiler

