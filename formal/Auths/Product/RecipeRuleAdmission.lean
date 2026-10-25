import Auths.Product.RecipeConsumption
import Auths.Product.RecipeCredentialAdmission
import Auths.Product.TemplateAst
import Auths.Product.EchoPointer

/-!
Independent complete decoded-source rule semantics. Every rule reads original
source data and original schema associations. The mutable ledger and JSON node
counter survive refusal at their actual prefix. No native function, expected
plan, caller-supplied validator result or opaque admission callback occurs.
Outer lock/namespace/credential/origin checks have separate original-input
models; this module covers the five ordered source-rule groups after them.
-/
namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeConsumption RecipeAdmissionAtoms
abbrev Bytes := RequestConstruction.Bytes
abbrev Fields := List Rules.Entry

def accepted (state : State) : Outcome := (.ok (), state)
def refused (error : Error) (state : State) : Outcome := (.error error, state)

def andThen (previous : Outcome) (next : State → Outcome) : Outcome :=
  match previous.1 with
  | .error error => (.error error, previous.2)
  | .ok () => next previous.2

inductive Segment where
  | fixed (value : String)
  | field (name : String)
  | responseField (pointer : Bytes) (maximum : Nat)
  | echo
  deriving DecidableEq

def originalSegment : Segment → RecipePlanModel.PathSegment
  | .fixed value => .fixed (textBytes value)
  | .field name => .field (textBytes name)
  | .responseField pointer maximum => .responseField pointer maximum
  | .echo => .echo

def isResponseField : Segment → Bool
  | .responseField _ _ => true
  | _ => false

inductive PathRole where
  | write | observation | preEntry | relativeCeiling
  deriving DecidableEq

def responseMaximum : PathRole → Nat
  | .observation => 2
  | _ => 0

def responseError : PathRole → Error
  | .write | .observation => .responseLocatorConflict
  | .preEntry => .invalidPreEntry
  | .relativeCeiling => .invalidRelativeCeiling

def pathTail (fields : Fields) (role : PathRole) : List Segment → Nat → State → Outcome
  | [], _, state => accepted state
  | .fixed value :: rest, responses, state =>
      if PathCompiler.FixedValid (textBytes value) then pathTail fields role rest responses state
      else refused .unsafePath state
  | .field name :: rest, responses, state =>
      if fieldTest pathSchema fields name && !namespaceOrRecipe name then
        pathTail fields role rest responses (consume state name)
      else refused .unsafePath state
  | .responseField pointer maximum :: rest, responses, state =>
      if responses + 1 ≤ responseMaximum role ∧ ResponsePointer pointer ∧ 1 ≤ maximum ∧ maximum ≤ 255 then
        pathTail fields role rest (responses + 1) state
      else refused (responseError role) state
  | .echo :: _, _, state => refused .echoConflict state

def path (fields : Fields) (role : PathRole) (segments : List Segment) (state : State) : Outcome :=
  if 0 < segments.length ∧ segments.length ≤ 16 then pathTail fields role segments 0 state
  else refused .unsafePath state

def fieldRef (fields : Fields) (name : Bytes) (state : State) : Outcome :=
  match Rules.decodeName name with
  | none => refused .unsafeTemplate state
  | some original =>
      if (schemaFor original fields).isSome && decide (TemplateAst.RenderedField name) then
        accepted (render state original)
      else refused .unsafeTemplate state

abbrev NodeOutcome := Outcome × Nat

def foldNodes {T : Type} (visit : T → Nat → State → NodeOutcome) :
    List T → Nat → State → NodeOutcome
  | [], nodes, state => (accepted state, nodes)
  | item :: rest, nodes, state =>
      let (result, nextNodes) := visit item nodes state
      match result.1 with
      | .error error => ((.error error, result.2), nextNodes)
      | .ok () => foldNodes visit rest nextNodes result.2

/-- Seven levels cover native depths zero through six. At zero fuel the
native charge at depth seven refuses without changing the node counter.
Final correspondence must retain the `fuel + depth = 7` relation. -/
def value : Nat → TemplateAst.Value → Nat → Nat → State → Fields → NodeOutcome
  | 0, _, _, nodes, state, _ => (refused .unsafeTemplate state, nodes)
  | fuel + 1, expression, depth, nodes, state, fields =>
      if nodes < 64 ∧ depth ≤ 6 then
        let charged := nodes + 1
        match expression with
        | .text bytes =>
            (if bytes.length ≤ 1024 then accepted state else refused .unsafeTemplate state, charged)
        | .integer literal =>
            (if literal.natAbs ≤ 9007199254740991 then accepted state else refused .unsafeTemplate state, charged)
        | .boolean _ => (accepted state, charged)
        | .field name => (fieldRef fields name state, charged)
        | .authorEcho => (refused .echoConflict state, charged)
        | .object members =>
            if 0 < members.length ∧ members.length ≤ 32 then
              foldNodes (fun member count current =>
                if OperationIdentity.validToken member.1 64 then
                  value fuel member.2 (depth + 1) count current fields
                else (refused .unsafeTemplate current, count)) members charged state
            else (refused .unsafeTemplate state, charged)
        | .array children =>
            if 0 < children.length ∧ children.length ≤ 16 then
              foldNodes (fun child count current => value fuel child (depth + 1) count current fields)
                children charged state
            else (refused .unsafeTemplate state, charged)
      else (refused .unsafeTemplate state, nodes)

def formJsonShape : TemplateAst.Value → Bool
  | .array items => decide (items.length = 1)
  | _ => true

def formMember (fields : Fields) (member : Bytes × TemplateAst.FormValue)
    (nodes : Nat) (state : State) : NodeOutcome :=
  if member.2 = .authorEcho then (refused .echoConflict state, nodes)
  else if OperationIdentity.validToken member.1 64 then
    match member.2 with
    | .text bytes =>
        (if bytes.length ≤ 1024 then accepted state else refused .unsafeTemplate state, nodes)
    | .field bytes =>
        match Rules.decodeName bytes with
        | none => (refused .unsafeTemplate state, nodes)
        | some name =>
            if fieldTest formSchema fields name then (fieldRef fields bytes state, nodes)
            else (refused .unsafeTemplate state, nodes)
    | .json expression =>
        if formJsonShape expression then value 7 expression 0 nodes state fields
        else (refused .unsafeTemplate state, nodes)
    | .authorEcho => (refused .unsafeTemplate state, nodes)
  else (refused .unsafeTemplate state, nodes)

def bodyWithNodes (fields : Fields) (source : TemplateAst.Body) (state : State) : NodeOutcome :=
  match source with
  | .json expression => value 7 expression 0 0 state fields
  | .form members =>
      if 0 < members.length ∧ members.length ≤ 16 then foldNodes (formMember fields) members 0 state
      else (refused .unsafeTemplate state, 0)

def body (fields : Fields) (source : TemplateAst.Body) (state : State) : Outcome :=
  (bodyWithNodes fields source state).1

structure Observation where
  path : List Segment
  pointer : Bytes
  expectedField : String
  maximum : Nat
  deriving DecidableEq

def observation (fields : Fields) (source : Observation) (state : State) : Outcome :=
  andThen (path fields .observation source.path state) fun next =>
    if ReadBound source.maximum ∧ ResponsePointer source.pointer then
      if (schemaFor source.expectedField fields).isSome && !namespaceOrRecipe source.expectedField then
        accepted (consume next source.expectedField)
      else refused .unsafeTemplate next
    else refused .unsafeTemplate next

structure PreEntry where
  path : List Segment
  pointers : List Bytes
  maximum : Nat
  deriving DecidableEq

def preEntry (fields : Fields) (source : PreEntry) (state : State) : Outcome :=
  andThen (path fields .preEntry source.path state) fun next =>
    if PreEntryPointers source.pointers source.maximum then accepted next else refused .invalidPreEntry next

structure Preconditions where
  readBackSubject : Option String
  verified : List String
  deriving DecidableEq

def preconditions (fields : Fields) (source : Preconditions) (read : Option Observation) (state : State) : Outcome :=
  if source.readBackSubject.isNone && source.verified.isEmpty then refused .invalidSource state
  else if 8 < source.verified.length then refused .preconditionConflict state
  else match source.readBackSubject with
    | none => claimVerified fields state source.verified
    | some subject =>
        match read with
        | none => refused .preconditionWithoutObservation state
        | some observation =>
            if observation.path.any isResponseField then refused .preconditionConflict state
            else andThen (claimUnused state subject (fieldTest textFactSchema fields subject)) fun next =>
              claimVerified fields next source.verified

structure Bind where
  pointer : Bytes
  field : String
  deriving DecidableEq

structure RelativeCeiling where
  argument : String
  basisPoints : Nat
  maximum : Nat
  pointer : Bytes
  subtract : Option Bytes
  binds : Option (List Bind)
  path : List Segment
  deriving DecidableEq

def relativeBindAdmitted (fields : Fields) (argument : String) (source : Bind) : Prop :=
  ResponsePointer source.pointer ∧ fieldTest formSchema fields source.field = true ∧
    source.field ≠ argument ∧ bindingField source.field = false
instance (fields : Fields) (argument : String) (source : Bind) :
    Decidable (relativeBindAdmitted fields argument source) := by unfold relativeBindAdmitted; infer_instance

def RelativeBindsAdmitted (fields : Fields) (argument : String) (binds : List Bind) : Prop :=
  binds.length ≤ 2 ∧ (binds.map Bind.pointer).Nodup ∧ ∀ source ∈ binds, relativeBindAdmitted fields argument source
instance (fields : Fields) (argument : String) (binds : List Bind) :
    Decidable (RelativeBindsAdmitted fields argument binds) := by unfold RelativeBindsAdmitted; infer_instance

def consumeBinds : List Bind → State → State
  | [], state => state
  | source :: rest, state => consumeBinds rest (RecipeConsumption.bind state source.field)

def relativeCeiling (fields : Fields) (source : RelativeCeiling) (state : State) : Outcome :=
  if integerBodyField fields state source.argument && decide
      (1 ≤ source.basisPoints ∧ source.basisPoints ≤ 10000 ∧
        ReadBound source.maximum ∧ ResponsePointer source.pointer) then
    if source.subtract.any (fun pointer => !responsePointer pointer || decide (pointer = source.pointer)) then
      refused .invalidRelativeCeiling state
    else if source.binds.any (fun binds => !decide (RelativeBindsAdmitted fields source.argument binds)) then
      refused .invalidRelativeCeiling state
    else andThen (path fields .relativeCeiling source.path state) fun next =>
      accepted (consumeBinds (source.binds.getD []) next)
  else refused .invalidRelativeCeiling state

def findMember {T : Type} (name : Bytes) : List (Bytes × T) → Option T
  | [] => none
  | (key, item) :: rest => if key = name then some item else findMember name rest

def splitPointer (prefix : Bytes) : Bytes → List Bytes
  | [] => [prefix]
  | byte :: rest =>
      if byte = 47 then prefix :: splitPointer [] rest else splitPointer (prefix ++ [byte]) rest

def selectTemplate : TemplateAst.Value → List Bytes → Option TemplateAst.Value
  | value, [] => some value
  | .object members, token :: rest => (findMember token members).bind (fun selected => selectTemplate selected rest)
  | .array children, token :: rest =>
      (arrayIndex Aeneas.Std.Usize.max token).bind fun index =>
        (children[index]?).bind fun selected => selectTemplate selected rest
  | _, _ :: _ => none

def templateAt (value : TemplateAst.Value) (pointer : Bytes) : Option TemplateAst.Value :=
  if ResponsePointer pointer ∧ 126 ∉ pointer then selectTemplate value (splitPointer [] (pointer.drop 1)) else none

def isOperationId : TemplateAst.Value → Bool
  | .field name => decide (name = FieldProjection.operationName)
  | _ => false

def templateIsOperationId (value : TemplateAst.Value) (pointer : Bytes) : Bool :=
  (templateAt value pointer).any isOperationId

def operationIdLocation (location : RecipePlanModel.IdempotencyLocation) (body : TemplateAst.Body) : Bool :=
  match body with
  | .json value =>
      location.formField.isNone && location.pointer.isNone && location.jsonPointer.any (templateIsOperationId value)
  | .form members =>
      if location.jsonPointer.isSome then false
      else match location.formField.bind (fun name => findMember name members) with
        | some (.field name) => location.pointer.isNone && decide (name = FieldProjection.operationName)
        | some (.json value) => location.pointer.any (templateIsOperationId value)
        | _ => false

def idempotency (source : RecipePlanModel.Idempotency) (body : TemplateAst.Body) : Except Error Unit :=
  let retention := match source with | .derivedHeader value | .operationIdField _ value => value
  if 1 ≤ retention ∧ retention ≤ 2592000 then
    match source with
    | .derivedHeader _ => .ok ()
    | .operationIdField location _ => if operationIdLocation location body then .ok () else .error .invalidIdempotency
  else .error .invalidIdempotency

structure Echo where
  observe : Bytes
  write : RecipePlanModel.EchoSource
  deriving DecidableEq

def jsonEchoTokens : TemplateAst.Value → List Bytes → Except Error Unit
  | .object members, tokens =>
      if members.all (fun member => OperationIdentity.validToken member.1 64) then
        match TemplateMembers.jsonEchoTarget (members.map Prod.fst) tokens with
        | .error _ => .error .echoConflict
        | .ok .insert => .ok ()
        | .ok (.descend _) =>
            match tokens with
            | [] => .error .echoConflict
            | token :: rest =>
                match findMember token members with
                | none => .error .echoConflict
                | some child => jsonEchoTokens child rest
      else .error .echoConflict
  | _, _ => .error .echoConflict
termination_by _ tokens => tokens.length

def echo (source : Echo) (body : TemplateAst.Body) (observation : Observation) : Except Error Unit :=
  if ResponsePointer source.observe then
    if pointersOverlap source.observe observation.pointer then .error .echoConflict
    else match source.write, body with
      | .jsonPointer pointer, .json value =>
          match EchoPointer.decode pointer with
          | .error _ => .error .echoConflict
          | .ok tokens => jsonEchoTokens value tokens
      | .formField name, .form members =>
          if members.all (fun member => OperationIdentity.validToken member.1 64) then
            match TemplateMembers.canonicalMembers (members.map Prod.fst) (some name) .form with
            | .ok _ => .ok ()
            | .error _ => .error .echoConflict
          else .error .echoConflict
      | _, _ => .error .echoConflict
  else .error .unsafeTemplate

structure Scope where
  header : Bytes
  field : String
  deriving DecidableEq

def accountScope (fields : Fields) (source : Scope) (state : State) : Outcome :=
  if source.header = HeaderCompiler.stripeAccountName ∧
      fieldTest pathSchema fields source.field = true ∧
      bindingField source.field = false ∧ source.field ∉ state.all then
    accepted (consume state source.field)
  else refused .invalidAccountScope state

structure Sum where
  argument : String
  partition : Option String
  deriving DecidableEq

structure Bounds where
  sum : Option Sum
  deriving DecidableEq

def bounds (fields : Fields) (source : Bounds) (scope : Option Scope) (state : State) : Outcome :=
  match source.sum with
  | none => refused .invalidBounds state
  | some sum =>
      if integerBodyField fields state sum.argument then
        match sum.partition with
        | none => accepted state
        | some partition =>
            if partition ≠ sum.argument ∧ fieldTest pathSchema fields partition = true ∧ bindingField partition = false then
              if partitionBound state (scope.map Scope.field) partition then accepted state else refused .unboundPartition state
            else refused .invalidBounds state
      else refused .invalidBounds state

structure Source where
  writePath : List Segment
  body : TemplateAst.Body
  idempotency : Option RecipePlanModel.Idempotency
  observation : Option Observation
  echo : Option Echo
  preEntry : Option PreEntry
  relativeCeiling : Option RelativeCeiling
  preconditions : Option Preconditions
  providerHeaders : Option HeaderCompiler.Versions
  guard : Option RecipeCredentialAdmission.Guard
  scope : Option Scope
  bounds : Option Bounds

def paths (source : Source) : RecipeCredentialAdmission.SourcePaths := {
  write := source.writePath.map originalSegment
  observation := source.observation.map (fun read => read.path.map originalSegment)
  preEntry := source.preEntry.map (fun read => read.path.map originalSegment)
  relativeCeiling := source.relativeCeiling.map (fun read => read.path.map originalSegment)
}

def applyPure (verdict : Except Error Unit) (state : State) : Outcome := (verdict, state)

def writeRules (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (path fields .write source.writePath state) fun next =>
    andThen (body fields source.body next) fun next =>
      match source.idempotency with
      | none => accepted next
      | some current => applyPure (idempotency current source.body) next

def responseRules (fields : Fields) (source : Source) (state : State) : Outcome :=
  let observed := match source.observation with
    | none => accepted state
    | some current => observation fields current state
  andThen observed fun next =>
    let echoed := match source.echo with
      | none => accepted next
      | some current =>
          match source.observation with
          | none => refused .echoWithoutObservation next
          | some read => applyPure (echo current source.body read) next
    andThen echoed fun next =>
      match source.preEntry with
      | none => accepted next
      | some current => preEntry fields current next

def factRules (fields : Fields) (source : Source) (state : State) : Outcome :=
  let relative := match source.relativeCeiling with
    | none => accepted state
    | some current => relativeCeiling fields current state
  andThen relative fun next =>
    match source.preconditions with
    | none => accepted next
    | some current => preconditions fields current source.observation next

def headerGuardRules (source : Source) : Except Error Unit := do
  match source.providerHeaders with
  | none => .ok ()
  | some headers => if HeaderCompiler.VersionsValid headers then .ok () else .error .invalidProviderHeader
  match source.guard with
  | none => .ok ()
  | some guard => RecipeCredentialAdmission.validateGuard Error.invalidCredentialGuard guard (paths source)

def boundRules (fields : Fields) (source : Source) (state : State) : Outcome :=
  let scoped := match source.scope with
    | none => accepted state
    | some current => accountScope fields current state
  andThen scoped fun next =>
    match source.bounds with
    | none => accepted next
    | some current => bounds fields current source.scope next

def validateFrom (fields : Fields) (source : Source) (state : State) : Outcome :=
  andThen (writeRules fields source state) fun next =>
    andThen (responseRules fields source next) fun next =>
      andThen (factRules fields source next) fun next =>
        andThen (applyPure (headerGuardRules source) next) fun next =>
          andThen (boundRules fields source next) fun next =>
            if allFieldsConsumed fields next then accepted next else refused .unsafeTemplate next

def validate (fields : Fields) (source : Source) : Outcome := validateFrom fields source empty

end Auths.Product.RecipeRuleAdmission
