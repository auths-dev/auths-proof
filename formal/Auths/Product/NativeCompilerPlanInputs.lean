import Auths.Product.RecipePlanModel
import Auths.Product.NativeCompilerBodyMeaning
import Auths.Product.NativeCompilerRequestChoices
import Auths.Product.NativeCompilerWrite

open Aeneas Aeneas.Std

namespace Auths.Product.NativeCompiler

abbrev NativeCheckedSource := AuthsNativeRecipe.recipe.validate.ValidatedSource
abbrev NativePlans := AuthsNativeRecipe.recipe.lower.Plans
abbrev NativeCredentialSource := AuthsNativeRecipe.recipe.source.CredentialSource
abbrev NativeGuardSource := AuthsNativeRecipe.recipe.source.GuardSource
abbrev NativeDeniedSource := AuthsNativeRecipe.recipe.source.DeniedReadSource

def planErrors : RecipePlanModel.Errors NativeGatewayError := {
  invalidSource := .InvalidSource
  unsafeTemplate := .UnsafeTemplate
  echoConflict := .EchoConflict
  invalidProfileLock := .InvalidProfileLock
  unsafeOrigin := .UnsafeOrigin
  invalidProviderHeader := .InvalidProviderHeader
  invalidAccountScope := .InvalidAccountScope
}

def planPathSegment : NativePathSource → RecipePlanModel.PathSegment
  | .Fixed value => .fixed (textBytes value)
  | .Field name => .field (textBytes name)
  | .ResponseField pointer maximum => .responseField (textBytes pointer) maximum.val
  | .Echo => .echo

def planPath (path : NativeVec NativePathSource) : List RecipePlanModel.PathSegment := path.val.map planPathSegment

def planEchoSource : NativeEchoSource → RecipePlanModel.EchoSource
  | .JsonPointer pointer => .jsonPointer (textBytes pointer)
  | .FormField name => .formField (textBytes name)

def planIdempotency : AuthsNativeRecipe.recipe.source.IdempotencySource → RecipePlanModel.Idempotency
  | .DerivedHeader maximum => .derivedHeader maximum.val
  | .OperationIdField location maximum => .operationIdField
      ⟨location.json_pointer.map textBytes, location.form_field.map textBytes, location.pointer.map textBytes⟩ maximum.val

def planDeniedRead (read : NativeDeniedSource) : RecipePlanModel.DeniedRead :=
  ⟨textBytes read.method, planPath read.path⟩

def planGuard (guard : NativeGuardSource) : RecipePlanModel.Guard := {
  probe := guard.probe.map (fun source => planPath source.path)
  account := guard.account.map (fun source => planPath source.path)
  denied := guard.denied_reads.map (fun reads => reads.val.map planDeniedRead)
}

def planCredential : NativeCredentialSource → RecipePlanModel.Credential
  | .Bearer guard => .bearer (guard.map planGuard)
  | .HeaderApiKey name guard => .headerApiKey (textBytes name) (guard.map planGuard)

/-- The columns actually consumed by plan lowering, retaining every original
path tag/name/payload and the independently related original body. Unread
source policy fields remain in the native source and must be validated by the
actual admission constructor; this projection does not grant that admission. -/
def planSource (source : NativeRecipeSource) (body : TemplateAst.Body) : RecipePlanModel.Source := {
  method := sourceWriteMethod source.write.method
  origin := textBytes source.origin
  path := planPath source.write.path
  versions := source.provider_headers.map originalHeaders
  scope := source.account_scope.map originalScope
  body
  echo := source.echo.map (fun source => planEchoSource source.write)
  idempotency := source.write.idempotency.map planIdempotency
  observation := source.observation.map (fun source => planPath source.path)
  preEntry := source.pre_entry.map (fun source => planPath source.path)
  relativeCeiling := source.relative_ceiling.map (fun source => planPath source.path)
  credential := planCredential source.credential
}

def nativePlans (plans : NativePlans) : RecipePlanModel.Plans := {
  fields := nativeFieldsMeaning plans.field_schemas
  write := nativeWritePlan plans.write
  observation := plans.observation.map nativeActionRead
  preEntry := plans.pre_entry.map nativeActionRead
  relativeCeiling := plans.relative_ceiling.map nativeActionRead
  probe := plans.probe.map nativeCredentialPlan
  account := plans.account.map nativeCredentialPlan
  denied := plans.denied.val.map nativeCredentialPlan
}

def planReadContext (lowering : NativeLowering) : RecipePlanModel.ReadContext :=
  ⟨loweringNames lowering, bytes lowering.origin, nativeHeaders lowering.headers⟩

/-- Representability of exactly the original method/path bytes inspected by
lowering. This earns neither the GET/HEAD vocabulary nor path admission. -/
def NativeDeniedFits (read : NativeDeniedSource) : Prop :=
  TextFits read.method ∧ ∀ segment ∈ read.path.val, NativePathFits segment

/-- Strings actually copied or borrowed as bytes need native representability.
Other guard policy payloads are not declared admitted by this compiler domain. -/
def GuardPathsFit (guard : NativeGuardSource) : Prop :=
  (∀ probe, guard.probe = some probe → ∀ segment ∈ probe.path.val, NativePathFits segment) ∧
  (∀ account, guard.account = some account → ∀ segment ∈ account.path.val, NativePathFits segment) ∧
  (∀ reads, guard.denied_reads = some reads →
    ∀ read ∈ reads.val, NativeDeniedFits read)

def CredentialPathsFit (credential : NativeCredentialSource) : Prop :=
  ∀ guard, originalGuard credential = some guard → GuardPathsFit guard

structure PlanInputFits (checked : NativeCheckedSource) : Prop where
  origin : TextFits checked.source.origin
  host : checked.parsed_host.toByteArray.size ≤ U32.max
  body : BodyBounds checked.source.write.body
  echo : ∀ echo, checked.source.echo = some echo → NativeEchoFits echo.write
  writePath : ∀ segment ∈ checked.source.write.path.val, NativePathFits segment
  headers : NativeHeaderFits checked.source
  observation : ∀ source, checked.source.observation = some source →
    ∀ segment ∈ source.path.val, NativePathFits segment
  preEntry : ∀ source, checked.source.pre_entry = some source →
    ∀ segment ∈ source.path.val, NativePathFits segment
  relativeCeiling : ∀ source, checked.source.relative_ceiling = some source →
    ∀ segment ∈ source.path.val, NativePathFits segment
  credential : CredentialPathsFit checked.source.credential

theorem plan_path_segment_meaning (source : NativePathSource) :
    RecipePlanModel.pathSegment (planPathSegment source) = originalPathSegment source := by cases source <;> rfl

theorem plan_path_full_lowering (source : NativeVec NativePathSource) :
    (planPath source).map RecipePlanModel.pathSegment = source.val.map originalPathSegment := by
  simp [planPath, List.map_map, Function.comp_def, plan_path_segment_meaning]

theorem plan_response_choice (source : NativePathSource) :
    RecipePlanModel.responseField (planPathSegment source) = originalResponseField source := by cases source <;> rfl

theorem plan_original_echo (source : NativeEchoSource) :
    RecipePlanModel.echo planErrors (planEchoSource source) = originalEcho source := by cases source <;> rfl

theorem plan_original_guard (source : NativeCredentialSource) :
    RecipePlanModel.guard (planCredential source) = (originalGuard source).map planGuard := by cases source <;> rfl

theorem plan_idempotency_choice (source : NativeRecipeSource) (body : TemplateAst.Body) :
    RecipePlanModel.hasIdempotencyHeader (planSource source body) = originalIdempotencyHeader source := by
  cases source.write.idempotency with
  | none => rfl
  | some source => cases source <;> rfl

theorem plan_denied_method (source : NativeDeniedSource) :
    RecipePlanModel.deniedMethod (planDeniedRead source) = originalDeniedMethod source := rfl

end Auths.Product.NativeCompiler
