import Auths.Product.NativeCompilerReadModel
import Auths.Product.RequestCompiler
import Auths.Product.TemplateAst
import Auths.Product.EchoPointer

/-!
Independent complete-plan compilation from original byte syntax. No generated
Rust module is imported. Error codes are fixed values, not callbacks, desired
outcomes or success premises. A source/lock validator must separately earn the
field, parsed-host and source provenance supplied at this compiler boundary.
-/
namespace Auths.Product.RecipePlanModel
open RequestConstruction

structure Errors (E : Type) where
  invalidSource : E
  unsafeTemplate : E
  echoConflict : E
  invalidProfileLock : E
  unsafeOrigin : E
  invalidProviderHeader : E
  invalidAccountScope : E

inductive PathSegment where
  | fixed (value : Bytes)
  | field (name : Bytes)
  | responseField (pointer : Bytes) (maximum : Nat)
  | echo
  deriving DecidableEq

def pathSegment : PathSegment → PathCompiler.SourceSegment
  | .fixed value => .fixed value
  | .field name => .field name
  | .responseField _ _ | .echo => .unsupported

def responseField : PathSegment → Bool
  | .responseField _ _ => true
  | _ => false

inductive EchoSource where
  | jsonPointer (pointer : Bytes)
  | formField (name : Bytes)
  deriving DecidableEq

structure IdempotencyLocation where
  jsonPointer : Option Bytes
  formField : Option Bytes
  pointer : Option Bytes
  deriving DecidableEq

inductive Idempotency where
  | derivedHeader (maximum : Nat)
  | operationIdField (location : IdempotencyLocation) (maximum : Nat)
  deriving DecidableEq

structure DeniedRead where
  method : Bytes
  path : List PathSegment

structure Guard where
  probe : Option (List PathSegment)
  account : Option (List PathSegment)
  denied : Option (List DeniedRead)

inductive Credential where
  | bearer (guard : Option Guard)
  | headerApiKey (name : Bytes) (guard : Option Guard)

def guard : Credential → Option Guard
  | .bearer value | .headerApiKey _ value => value

structure Source where
  method : Method
  origin : Bytes
  path : List PathSegment
  versions : Option HeaderCompiler.Versions
  scope : Option HeaderCompiler.ScopeSource
  body : TemplateAst.Body
  echo : Option EchoSource
  idempotency : Option Idempotency
  observation : Option (List PathSegment)
  preEntry : Option (List PathSegment)
  relativeCeiling : Option (List PathSegment)
  credential : Credential

structure Plans where
  fields : List FieldProjection.Field
  write : WritePlan
  observation : Option ReadPlan
  preEntry : Option ReadPlan
  relativeCeiling : Option ReadPlan
  probe : Option CredentialPlan
  account : Option CredentialPlan
  denied : List CredentialPlan

def echo {E : Type} (errors : Errors E) : EchoSource → Except E TemplateAst.Echo
  | .jsonPointer pointer =>
      ((EchoPointer.decode pointer).map TemplateAst.Echo.json).mapError (fun _ => errors.echoConflict)
  | .formField name => .ok (.form name)

def templateError {E : Type} (errors : Errors E) : TemplateAst.Error → E
  | .shape => errors.unsafeTemplate
  | .echoConflict => errors.echoConflict
  | .resources => errors.invalidSource

def namedBody {E : Type} (errors : Errors E) (body : TemplateAst.Body) (placement : Option EchoSource) :
    Except E TemplateAst.NamedTemplate := do
  let declared ← match placement with
    | none => .ok none
    | some source => (echo errors source).map some
  (TemplateAst.compileBody body declared).mapError (templateError errors)

def writeError {E : Type} (errors : Errors E) : RequestCompiler.CompileError → E
  | .fields => errors.invalidProfileLock
  | .origin => errors.unsafeOrigin
  | .method | .path _ | .body _ => errors.invalidSource
  | .headers .providerHeader => errors.invalidProviderHeader
  | .headers .accountScope => errors.invalidAccountScope

def hasIdempotencyHeader (source : Source) : Bool :=
  match source.idempotency with
  | some (.derivedHeader _) => true
  | none | some (.operationIdField _ _) => false

def writeSource (source : Source) (host : Bytes) (body : TemplateAst.NamedTemplate) : RequestCompiler.Source := {
  method := source.method
  origin := source.origin
  parsedHost := host
  path := source.path.map pathSegment
  versions := source.versions
  scope := source.scope
  idempotency := hasIdempotencyHeader source
  body := TemplateAst.namedBody body
}

structure ReadContext where
  names : List Bytes
  origin : Bytes
  headers : HeaderPlan

def readContext (compiled : RequestCompiler.Compiled) : ReadContext :=
  ⟨compiled.names, compiled.plan.origin, compiled.plan.headers⟩

def actionRead {E : Type} (errors : Errors E) (context : ReadContext) (path : List PathSegment) :
    Except E ReadPlan :=
  NativeCompiler.ReadModel.action errors.invalidSource context.origin context.headers context.names (path.map pathSegment)

def credentialRead {E : Type} (errors : Errors E) (context : ReadContext)
    (method : Method) (path : List PathSegment) : Except E CredentialPlan :=
  NativeCompiler.ReadModel.credential errors.invalidSource method context.origin context.headers.versions (path.map pathSegment)

def optionalAction {E : Type} (errors : Errors E) (context : ReadContext)
    (source : Option (List PathSegment)) : Except E (Option ReadPlan) :=
  match source with
  | none => .ok none
  | some path => (actionRead errors context path).map some

def optionalCredential {E : Type} (errors : Errors E) (context : ReadContext)
    (source : Option (List PathSegment)) : Except E (Option CredentialPlan) :=
  match source with
  | none => .ok none
  | some path => (credentialRead errors context .get path).map some

def deniedMethod (source : DeniedRead) : Method :=
  if source.method = [72, 69, 65, 68] then .head else .get

def deniedReads {E : Type} (errors : Errors E) (context : ReadContext) :
    List DeniedRead → Except E (List CredentialPlan)
  | [] => .ok []
  | read :: rest => do
      let plan ← credentialRead errors context (deniedMethod read) read.path
      let tail ← deniedReads errors context rest
      .ok (plan :: tail)

def remainingPlans {E : Type} (errors : Errors E) (fields : List FieldProjection.Field)
    (source : Source) (compiled : RequestCompiler.Compiled) : Except E Plans := do
  let context := readContext compiled
  let observation ← match source.observation with
    | none => .ok none
    | some path => if path.any responseField then .ok none else (actionRead errors context path).map some
  let preEntry ← optionalAction errors context source.preEntry
  let relativeCeiling ← optionalAction errors context source.relativeCeiling
  let current := guard source.credential
  let probe ← optionalCredential errors context (current.bind Guard.probe)
  let account ← optionalCredential errors context (current.bind Guard.account)
  let denied ← deniedReads errors context ((current.bind Guard.denied).getD [])
  .ok ⟨fields, compiled.plan, observation, preEntry, relativeCeiling, probe, account, denied⟩

def compile {E : Type} (errors : Errors E) (fields : List FieldProjection.Field)
    (host : Bytes) (source : Source) : Except E Plans := do
  let body ← namedBody errors source.body source.echo
  let compiled ← (RequestCompiler.compile fields (writeSource source host body)).mapError (writeError errors)
  remainingPlans errors fields source compiled

end Auths.Product.RecipePlanModel
