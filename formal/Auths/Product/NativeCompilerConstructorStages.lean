import Auths.Product.RecipeConstructorAdmission
import Auths.Product.NativeCompilerConstructorRules
import Auths.Product.NativeCompilerBindingFields
import Auths.Product.NativeCompilerCredentialAdmission
import Auths.Product.NativeCompilerOriginAdmission

open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler

structure ConstructorSourceFits (source : NativeConstructorSource) : Prop where
  schema : TextFits source.schema
  binding : NativeSourceBindingFits source
  namespaceValue : TextFits source.operator_namespace
  credential : NativeSourceCredentialFits source.credential
  origin : TextFits source.origin
  rules : SourceRulesFit source

def constructorErrors : RecipeConstructorAdmission.Errors NativeRecipeError := {
  invalidSource := .InvalidSource
  invalidProfileLock := .InvalidProfileLock
  profileMismatch := .ProfileMismatch
  invalidNamespace := .InvalidNamespace
  invalidCredential := .InvalidCredential
  unsafeOrigin := .UnsafeOrigin
  ruleError := consumptionError
}

def originalConstructorSource (source : NativeConstructorSource) (body : TemplateAst.Body) :
    RecipeConstructorAdmission.Source := {
  schema := textBytes source.schema
  binding := originalSourceBinding source
  namespaceBytes := textBytes source.operator_namespace
  credential := nativeSourceCredentialRequirement source.credential
  origin := textBytes source.origin
  rules := ruleSource source body
}

def originalConstructorLock (lock : NativeProfileLock) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (schema : ProfileSchema.Value) : RecipeConstructorAdmission.Lock :=
  ⟨originalLockMetadata lock, schema, nativeCanonicalOutcome canonical.schema, nativeCanonicalOutcome canonical.source⟩

def constructorValue (checked : NativeConstructorRecord) : RecipeConstructorAdmission.Value :=
  ⟨RecipeConstructorAdmission.fieldPairs (nativeFieldsMeaning checked.field_specs), textBytes checked.«namespace»,
    textBytes checked.parsed_host, nativeCanonicalOutcome checked.canonical_source⟩

def constructorOutcome : core.result.Result NativeConstructorRecord NativeRecipeError →
    Except NativeRecipeError RecipeConstructorAdmission.Value
  | .Err error => .error error
  | .Ok checked => .ok (constructorValue checked)

/-- Complete source/carrier preservation is separate from the semantic view;
an equal projection cannot substitute another original source. These are
native-model value equalities, not an address/lifetime or aliasing proof. -/
def ConstructorFrame (source : NativeConstructorSource) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (actual : core.result.Result NativeConstructorRecord NativeRecipeError) : Prop :=
  ∀ checked, actual = .Ok checked → checked.source = source ∧ checked.canonical_source = canonical.source

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

def constructorParsedOrigin (source : NativeConstructorSource) (fits : ConstructorSourceFits source) :
    Except Unit RecipeOriginAdmission.Parsed :=
  nativeParsedOriginOutcome (nativeUrl.parse (nativeTextView source.origin fits.origin))

/-- Closed transparent source suffixes, retaining actual Try/error branches.
All validator, parser and builder calls are the unchanged native functions. -/
def nativeCtorFromMap (source : NativeConstructorSource) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (specs : NativeVec NativeFieldSpec) (namespaceValue : AuthsNativeRecipe.recipe.OperatorNamespace)
    (fields : NativeRuleMap) : Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let credential ← constructorCredential source
  let credentialFlow ← core.result.Result.Insts.CoreOpsTry.branch credential
  match credentialFlow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
  | .Continue _ =>
      let origin ← constructorOrigin source
      let originFlow ← core.result.Result.Insts.CoreOpsTry.branch origin
      match originFlow with
      | .Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
      | .Continue host =>
          let rules ← AuthsNativeRecipe.recipe.validate.validate_source_rules source fields
          let ruleFlow ← core.result.Result.Insts.CoreOpsTry.branch rules
          match ruleFlow with
          | .Break residual =>
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
          | .Continue _ => ok (.Ok ⟨source, specs, namespaceValue, host, canonical.source⟩)

def nativeCtorWithFields (source : NativeConstructorSource) (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs)
    (specs : NativeVec NativeFieldSpec) : Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let namespaceResult ← constructorNamespace source
  let namespaceFlow ← core.result.Result.Insts.CoreOpsTry.branch namespaceResult
  match namespaceFlow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
  | .Continue namespaceValue =>
      let binding ← AuthsNativeRecipe.recipe.validate_binding_fields (AuthsNativeRecipe.alloc.vec.Vec.deref specs) namespaceValue
      let bindingFlow ← core.result.Result.Insts.CoreOpsTry.branch binding
      match bindingFlow with
      | .Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
      | .Continue _ =>
          let fields ← AuthsNativeRecipe.recipe.profile.rule_fields (AuthsNativeRecipe.alloc.vec.Vec.deref specs)
          let fieldFlow ← core.result.Result.Insts.CoreOpsTry.branch fields
          match fieldFlow with
          | .Break residual =>
              core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
                NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
          | .Continue fields => nativeCtorFromMap source canonical specs namespaceValue fields

def nativeCtorWithProfile (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) :
    Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let fields ← AuthsNativeRecipe.recipe.parse_root_fields lock.command_schema
  let flow ← core.result.Result.Insts.CoreOpsTry.branch fields
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
  | .Continue fields => nativeCtorWithFields source canonical fields

def nativeCtorAfterLock (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) :
    Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let matches ← constructorProfileBinding source lock
  if matches then nativeCtorWithProfile source lock canonical else ok (.Err .ProfileMismatch)

def nativeCtorAfterTag (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) :
    Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let checked ← AuthsNativeRecipe.recipe.validate_lock lock canonical.schema
  let flow ← core.result.Result.Insts.CoreOpsTry.branch checked
  match flow with
  | .Break residual =>
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
        NativeConstructorRecord (core.convert.FromSame NativeRecipeError) residual
  | .Continue _ => nativeCtorAfterLock source lock canonical

def nativeCtorAllStages (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) :
    Result (core.result.Result NativeConstructorRecord NativeRecipeError) := do
  let supported ← constructorSourceTag source
  if supported then nativeCtorAfterTag source lock canonical else ok (.Err .InvalidSource)

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]
variable [nativeUrl : UrlPrimitives]

theorem native_constructor_uses_original_stages (source : NativeConstructorSource) (lock : NativeProfileLock)
    (canonical : AuthsNativeRecipe.recipe.CanonicalRecipeInputs) :
    AuthsNativeRecipe.recipe.validate.validate_source source lock canonical = nativeCtorAllStages source lock canonical := by
  simp [AuthsNativeRecipe.recipe.validate.validate_source, nativeCtorAllStages, nativeCtorAfterTag,
    nativeCtorAfterLock, nativeCtorWithProfile, nativeCtorWithFields, nativeCtorFromMap,
    constructorSourceTag, constructorProfileBinding, constructorNamespace, constructorCredential,
    constructorOrigin, bind_assoc]

end Auths.Product.NativeCompiler.Refinement
