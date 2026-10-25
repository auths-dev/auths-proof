import Auths.Product.TemplateMemberSelection
import Auths.Product.BodyCompilerResources
import Auths.Product.RequestBinding
import Auths.Product.RequestCompiler
import Mathlib.Data.Nat.Log

namespace Auths.Product.TemplateAst
open RequestConstruction
open BodyCompiler
open BodyCompiler.Resources

inductive Value where
  | text (bytes : Bytes)
  | integer (value : Int)
  | boolean (value : Bool)
  | field (name : Bytes)
  | object (fields : List (Bytes × Value))
  | array (items : List Value)
  | authorEcho
  deriving DecidableEq

inductive FormValue where
  | text (bytes : Bytes)
  | field (name : Bytes)
  | json (value : Value)
  | authorEcho
  deriving DecidableEq

inductive Body where
  | json (value : Value)
  | form (fields : List (Bytes × FormValue))
  deriving DecidableEq

inductive Echo where
  | json (tokens : List Bytes)
  | form (name : Bytes)
  deriving DecidableEq

inductive NamedTemplate where
  | json (pieces : List NamedJson)
  | form (pieces : List NamedForm)
  deriving DecidableEq

inductive Error where
  | shape | echoConflict | resources
  deriving DecidableEq

def memberError : TemplateMembers.Error → Error
  | .members => .shape
  | .echoConflict => .echoConflict

def chargeNode (nodes depth : Nat) : Except Error Nat :=
  if nodes < 64 ∧ depth ≤ 6 then .ok (nodes + 1) else .error .shape

def RenderedField (name : Bytes) : Prop := OperationIdentity.validToken name 64 = true ∧
  name ≠ FieldProjection.namespaceName ∧ name ≠ FieldProjection.recipeName
instance (name : Bytes) : Decidable (RenderedField name) := by unfold RenderedField; infer_instance

def integerBytes (value : Int) : Bytes :=
  (if value < 0 then [45] else []) ++
    DecimalProjection.emit value.natAbs (10 ^ Nat.log 10 (max 1 value.natAbs))

structure JsonBuild where
  nodes : Nat
  resources : Usage
  pieces : List NamedJson

structure FormBuild where
  nodes : Nat
  resources : Usage
  pieces : List NamedForm

def jsonStart (nodes : Nat) : JsonBuild := ⟨nodes, zero, []⟩
def formStart : FormBuild := ⟨0, zero, []⟩

def pushJson (output : JsonBuild) (piece : NamedJson) : Except Error JsonBuild :=
  if output.pieces.length < 256 then
    match add output.resources (jsonQuantity piece) with
    | none => .error .resources
    | some next => .ok ⟨output.nodes, next, output.pieces ++ [piece]⟩
  else .error .resources

def pushForm (output : FormBuild) (piece : NamedForm) : Except Error FormBuild :=
  if output.pieces.length < 256 then
    match formCharge output.resources piece with
    | none => .error .resources
    | some next => .ok ⟨output.nodes, next, output.pieces ++ [piece]⟩
  else .error .resources

def jsonPrefix (name : Bytes) (comma : Bool) : Bytes :=
  (if comma then [44] else []) ++ jsonString name ++ [58]
def formPrefix (name : Bytes) (separator : Bool) : Bytes :=
  (if separator then [38] else []) ++ formEncode name ++ [61]

def isObject : Value → Bool | .object _ => true | _ => false

/-- A depth-fuel presentation of the same closed source compiler. Public
compilation starts at seven levels; native depth checks earn each recursive
descent. Siblings share the returned node and resource state. -/
def emitJson : Nat → Value → Option (List Bytes) → Nat → JsonBuild → Except Error JsonBuild
  | 0, _, _, _, _ => .error .shape
  | fuel + 1, value, echo, depth, initial => do
    let nodes ← chargeNode initial.nodes depth
    let output := { initial with nodes }
    if echo.isSome && !isObject value then .error .echoConflict else
      match value with
      | .text text =>
        if text.length ≤ 1024 then pushJson output (.raw (jsonString text)) else .error .shape
      | .integer value =>
        if -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 then
          pushJson output (.raw (integerBytes value)) else .error .shape
      | .boolean value =>
        pushJson output (.raw (if value then [116,114,117,101] else [102,97,108,115,101]))
      | .field name =>
        if RenderedField name then pushJson output (.field name) else .error .shape
      | .authorEcho => .error .echoConflict
      | .array items =>
        if 0 < items.length ∧ items.length ≤ 16 then do
          let output ← pushJson output (.raw [91])
          let output ← (items.zipIdx).foldlM (fun output (child, position) => do
            let output ← if 0 < position then pushJson output (.raw [44]) else .ok output
            emitJson fuel child none (depth + 1) output) output
          pushJson output (.raw [93])
        else .error .shape
      | .object fields =>
        if 0 < fields.length ∧ fields.length ≤ 32 then do
          let keys := fields.map Prod.fst
          let target ← match echo with
            | none => .ok none
            | some tokens => ((TemplateMembers.jsonEchoTarget keys tokens).mapError memberError).map some
          let insertion ← match target, echo with
            | some .insert, some tokens => match tokens.head? with
              | none => .error .echoConflict
              | some name => .ok (some name)
            | some .insert, none => .error .echoConflict
            | _, _ => .ok none
          let choices ← (TemplateMembers.canonicalMembers keys insertion .json).mapError memberError
          let output ← pushJson output (.raw [123])
          let output ← (choices.zipIdx).foldlM (fun output (choice, position) => do
            match choice with
            | .source index =>
              match fields[index]? with
              | none => .error .shape
              | some (name, child) => do
                let output ← pushJson output (.raw (jsonPrefix name (decide (0 < position))))
                let nested ← match target, echo with
                  | some (.descend selected), some tokens =>
                    if selected = index then
                      if 0 < tokens.length then .ok (some (tokens.drop 1)) else .error .echoConflict
                    else .ok none
                  | _, _ => .ok none
                emitJson fuel child nested (depth + 1) output
            | .echo => match insertion with
              | none => .error .echoConflict
              | some name => do
                let output ← pushJson output (.raw (jsonPrefix name (decide (0 < position))))
                pushJson output .echo) output
          pushJson output (.raw [125])
        else .error .shape

def FormJsonAllowed : Value → Prop
  | .array items => items.length = 1
  | _ => True
instance (value : Value) : Decidable (FormJsonAllowed value) := by cases value <;> unfold FormJsonAllowed <;> infer_instance

def emitFormValue (value : FormValue) (output : FormBuild) : Except Error FormBuild :=
  match value with
  | .text text => if text.length ≤ 1024 then pushForm output (.raw (formEncode text)) else .error .shape
  | .field name => if RenderedField name then pushForm output (.field name) else .error .shape
  | .authorEcho => .error .echoConflict
  | .json value =>
    if FormJsonAllowed value then do
      let nested ← emitJson 7 value none 0 (jsonStart output.nodes)
      pushForm { output with nodes := nested.nodes } (.json nested.pieces)
    else .error .shape

def compileBody (body : Body) (echo : Option Echo) : Except Error NamedTemplate :=
  match body with
  | .json value => do
    let tokens ← match echo with
      | none => .ok none
      | some (.json tokens) => .ok (some tokens)
      | some (.form _) => .error .echoConflict
    let output ← emitJson 7 value tokens 0 (jsonStart 0)
    .ok (.json output.pieces)
  | .form fields =>
    if 0 < fields.length ∧ fields.length ≤ 16 then do
      let insertion ← match echo with
        | none => .ok none
        | some (.form name) => .ok (some name)
        | some (.json _) => .error .echoConflict
      let choices ← (TemplateMembers.canonicalMembers (fields.map Prod.fst) insertion .form).mapError memberError
      let output ← (choices.zipIdx).foldlM (fun output (choice, position) => do
        match choice with
        | .source index => match fields[index]? with
          | none => .error .shape
          | some (name, value) => do
            let output ← pushForm output (.raw (formPrefix name (decide (0 < position))))
            emitFormValue value output
        | .echo => match insertion with
          | none => .error .echoConflict
          | some name => do
            let output ← pushForm output (.raw (formPrefix name (decide (0 < position))))
            pushForm output .echo) formStart
      .ok (.form output.pieces)
    else .error .shape

def namedBody : NamedTemplate → RequestCompiler.SourceBody
  | .json pieces => .json pieces
  | .form pieces => .form pieces

def JsonInvariant (output : JsonBuild) : Prop :=
  output.nodes ≤ 64 ∧ output.pieces.length ≤ 256 ∧ Bounded output.resources ∧
    output.resources = totals jsonQuantity output.pieces
def FormInvariant (output : FormBuild) : Prop :=
  output.nodes ≤ 64 ∧ output.pieces.length ≤ 256 ∧ Bounded output.resources ∧
    output.resources = totals formQuantity output.pieces ∧ NestedCounts output.pieces

theorem charge_node_earns_domain (nodes depth next : Nat) (run : chargeNode nodes depth = .ok next) :
    nodes < 64 ∧ depth ≤ 6 ∧ next = nodes + 1 ∧ next ≤ 64 := by
  unfold chargeNode at run
  split at run
  · rename_i admitted
    have same : next = nodes + 1 := by simpa using run.symm
    exact ⟨admitted.1, admitted.2, same, by omega⟩
  · contradiction

theorem json_start_invariant (nodes : Nat) (bound : nodes ≤ 64) : JsonInvariant (jsonStart nodes) := by
  simp [JsonInvariant, jsonStart, bound, zero, totals, Bounded]
theorem form_start_invariant : FormInvariant formStart := by
  simp [FormInvariant, formStart, zero, totals, Bounded, NestedCounts]

theorem json_push_preserves_invariant (old next : JsonBuild) (piece : NamedJson)
    (invariant : JsonInvariant old) (run : pushJson old piece = .ok next) : JsonInvariant next ∧
      next.nodes = old.nodes ∧ next.pieces = old.pieces ++ [piece] := by
  unfold pushJson at run
  split at run
  · rename_i room
    cases charged : add old.resources (jsonQuantity piece) with
    | none => simp [charged] at run
    | some resources =>
      have same : next = ⟨old.nodes, resources, old.pieces ++ [piece]⟩ := by simpa [charged] using run.symm
      subst next
      have bound := add_success_earns_bound _ _ _ charged
      have exactSum : resources = plus old.resources (jsonQuantity piece) := by
        unfold add at charged
        split at charged <;> simp_all
      refine ⟨⟨invariant.1, by simp; omega, bound, ?_⟩, rfl, rfl⟩
      rw [exactSum, invariant.2.2.2]
      apply Usage.ext <;> simp [plus, totals, List.map_append, List.sum_append]
  · contradiction

theorem form_push_preserves_invariant (old next : FormBuild) (piece : NamedForm)
    (invariant : FormInvariant old) (run : pushForm old piece = .ok next) : FormInvariant next ∧
      next.nodes = old.nodes ∧ next.pieces = old.pieces ++ [piece] := by
  unfold pushForm at run
  split at run
  · rename_i room
    cases charged : formCharge old.resources piece with
    | none => simp [charged] at run
    | some resources =>
      have same : next = ⟨old.nodes, resources, old.pieces ++ [piece]⟩ := by simpa [charged] using run.symm
      subst next
      have bound := form_charge_success_earns_bound _ _ _ charged
      have nested : NestedCount piece := by
        unfold formCharge at charged
        split at charged
        · assumption
        · simp at charged
      have exactSum : resources = plus old.resources (formQuantity piece) := by
        unfold formCharge add at charged
        split at charged <;> split at charged <;> simp_all
      refine ⟨⟨invariant.1, by simp; omega, bound, ?_, ?_⟩, rfl, rfl⟩
      · rw [exactSum, invariant.2.2.2.1]
        apply Usage.ext <;> simp [plus, totals, List.map_append, List.sum_append]
      · intro value member
        rcases List.mem_append.mp member with earlier | last
        · exact invariant.2.2.2.2 value earlier
        · have same : value = piece := by simpa only [List.mem_singleton] using last
          simpa [same] using nested
  · contradiction

end Auths.Product.TemplateAst
