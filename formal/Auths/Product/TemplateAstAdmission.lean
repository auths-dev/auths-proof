import Auths.Product.TemplateAstResources
import Auths.Product.TemplateAstMeaning

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler BodyCompiler.Resources

/-- Admission accounts for original syntax, never emitted buffers or a
compiler-produced source/argument index. All components are nonnegative. -/
structure Demand where
  nodes : Nat
  pieces : Nat
  literals : Nat
  dynamics : Nat
  deriving DecidableEq

namespace Demand
def zero : Demand := ⟨0, 0, 0, 0⟩
def node : Demand := ⟨1, 0, 0, 0⟩
def plus (first second : Demand) : Demand :=
  ⟨first.nodes + second.nodes, first.pieces + second.pieces,
    first.literals + second.literals, first.dynamics + second.dynamics⟩
def literal (bytes : Bytes) : Demand := ⟨0, 1, bytes.length, 0⟩
def dynamic : Demand := ⟨0, 1, 0, 1⟩
def atom (piece : NamedJson) : Demand := ⟨0, 1, jsonLiteralSize piece, jsonDynamicSize piece⟩
def sum : List Demand → Demand
  | [] => zero
  | first :: rest => plus first (sum rest)
def Bounded (demand : Demand) : Prop := demand.nodes ≤ 64 ∧ demand.pieces ≤ 256 ∧
  demand.literals ≤ 524288 ∧ demand.dynamics ≤ 256
instance (demand : Demand) : Decidable (Bounded demand) := by unfold Bounded; infer_instance
end Demand

/-- Closed literal/reference vocabulary. No authored echo, array, object or
fallback value can obtain this admission witness. -/
inductive LeafAdmission : Value → Prop
  | text (bytes : Bytes) (bounded : bytes.length ≤ 1024) : LeafAdmission (.text bytes)
  | integer (value : Int) (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) : LeafAdmission (.integer value)
  | boolean (value : Bool) : LeafAdmission (.boolean value)
  | field (name : Bytes) (allowed : RenderedField name) : LeafAdmission (.field name)

def leafPiece : Value → NamedJson
  | .text bytes => .raw (jsonString bytes)
  | .integer value => .raw (integerBytes value)
  | .boolean value => .raw (if value then [116,114,117,101] else [102,97,108,115,101])
  | .field name => .field name
  | .authorEcho | .array _ | .object _ => .raw []

def leafDemand (value : Value) : Demand := Demand.plus Demand.node (Demand.atom (leafPiece value))

theorem admitted_integer_literal_length (value : Int)
    (safe : -9007199254740991 ≤ value ∧ value ≤ 9007199254740991) : (integerBytes value).length ≤ 17 := by
  have absolute : value.natAbs ≤ 9007199254740991 := by
    have interval : |value| ≤ (9007199254740991 : Int) := abs_le.mpr safe
    rw [← Int.natCast_natAbs] at interval
    exact_mod_cast interval
  have largest : 10 ^ Nat.log 10 (max 1 value.natAbs) ≤ max 1 value.natAbs :=
    Nat.pow_log_le_self 10 (by omega)
  have digits := DecimalProjection.json_digits_bounded value.natAbs _ absolute largest
  unfold integerBytes
  rw [List.length_append]
  split_ifs <;> simp only [List.length_nil, List.length_singleton] <;> omega

theorem leaf_admission_demand_bounded (value : Value) (admitted : LeafAdmission value) : Demand.Bounded (leafDemand value) := by
  cases admitted with
  | text bytes bounded =>
    have quoted := BodyCompiler.json_string_length bytes
    simp [Demand.Bounded, leafDemand, leafPiece, Demand.plus, Demand.node, Demand.atom, jsonLiteralSize, jsonDynamicSize]
    omega
  | integer value safe =>
    have size := admitted_integer_literal_length value safe
    simp [Demand.Bounded, leafDemand, leafPiece, Demand.plus, Demand.node, Demand.atom, jsonLiteralSize, jsonDynamicSize]
    omega
  | boolean value =>
    cases value <;> decide
  | field name allowed => decide

def arrayDemand (items : List Value) (children : List Demand) : Demand :=
  Demand.plus Demand.node (Demand.plus ⟨0, 2 + (items.length - 1), 2 + (items.length - 1), 0⟩ (Demand.sum children))

def echoDemand (insertion : Option Bytes) : Demand :=
  match insertion with
  | none => Demand.zero
  | some name => Demand.plus (Demand.literal (jsonPrefix name true)) Demand.dynamic

def objectDemand (fields : List (Bytes × Value)) (children : List Demand) (insertion : Option Bytes) : Demand :=
  let members := (fields.zip children).map fun (member, child) =>
    Demand.plus (Demand.literal (jsonPrefix member.1 true)) child
  Demand.plus Demand.node (Demand.plus ⟨0, 2, 2, 0⟩ (Demand.plus (Demand.sum members) (echoDemand insertion)))

/-- Independent original-tree admission. A route names the original parent;
it is not a compiler target/index. Prefix demand includes a separator even
for the first member, a conservative one-byte reserve. -/
inductive JsonAdmission : Nat → Value → Option (List Bytes) → Demand → Prop
  | leaf (depth : Nat) (value : Value) (within : depth ≤ 6) (admitted : LeafAdmission value) :
      JsonAdmission depth value none (leafDemand value)
  | array (depth : Nat) (items : List Value) (children : List Demand)
      (within : depth ≤ 6) (count : 0 < items.length ∧ items.length ≤ 16)
      (admitted : List.Forall₂ (fun child demand => JsonAdmission (depth + 1) child none demand) items children) :
      JsonAdmission depth (.array items) none (arrayDemand items children)
  | object (depth : Nat) (fields : List (Bytes × Value)) (echo : Option (List Bytes))
      (route : NamedEchoRoute) (children : List Demand) (within : depth ≤ 6)
      (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .json)
      (routeMeaning : namedEchoRoute (fields.map Prod.fst) echo = .ok route)
      (admitted : List.Forall₂ (fun member demand => JsonAdmission (depth + 1) member.2
        (namedChildEcho route member.1) demand) fields children) :
      JsonAdmission depth (.object fields) echo (objectDemand fields children route.insertion)

/-- Nested JSON charges its full original literal/dynamic/node demand to the
parent, while occupying one outer form piece. Its own piece count is checked
separately and cannot disappear inside the form envelope. -/
inductive FormValueAdmission : FormValue → Demand → Prop
  | text (bytes : Bytes) (bounded : bytes.length ≤ 1024) :
      FormValueAdmission (.text bytes) (Demand.literal (formEncode bytes))
  | field (name : Bytes) (allowed : RenderedField name) : FormValueAdmission (.field name) Demand.dynamic
  | json (value : Value) (demand : Demand) (shape : FormJsonAllowed value)
      (admitted : JsonAdmission 0 value none demand) (count : demand.pieces ≤ 256) :
      FormValueAdmission (.json value) ⟨demand.nodes, 1, demand.literals, demand.dynamics⟩

def formEchoDemand (insertion : Option Bytes) : Demand :=
  match insertion with
  | none => Demand.zero
  | some name => Demand.plus (Demand.literal (formPrefix name true)) Demand.dynamic

def formDemand (fields : List (Bytes × FormValue)) (children : List Demand) (insertion : Option Bytes) : Demand :=
  let members := (fields.zip children).map fun (member, child) =>
    Demand.plus (Demand.literal (formPrefix member.1 true)) child
  Demand.plus (Demand.sum members) (formEchoDemand insertion)

inductive BodyAdmission : Body → Option Echo → Demand → Prop
  | json (value : Value) (pointer : Option (List Bytes)) (demand : Demand)
      (admitted : JsonAdmission 0 value pointer demand) :
      BodyAdmission (.json value) (pointer.map Echo.json) demand
  | form (fields : List (Bytes × FormValue)) (insertion : Option Bytes) (children : List Demand)
      (keys : TemplateMembers.KeyColumn (fields.map Prod.fst) .form)
      (echo : TemplateMembers.EchoAdmitted (fields.map Prod.fst) insertion .form)
      (admitted : List.Forall₂ (fun member demand => FormValueAdmission member.2 demand) fields children) :
      BodyAdmission (.form fields) (insertion.map Echo.form) (formDemand fields children insertion)

/-- Useful source admission is stated only from original syntax and hard
resource envelopes. No compiler call, expected template or success flag
appears in this predicate. Coverage of every native-valid source is separate. -/
def BodyAdmissible (body : Body) (echo : Option Echo) : Prop :=
  ∃ demand, BodyAdmission body echo demand ∧ Demand.Bounded demand

def JsonRoom (before : JsonBuild) (demand : Demand) : Prop :=
  JsonInvariant before ∧ before.nodes + demand.nodes ≤ 64 ∧
    before.pieces.length + demand.pieces ≤ 256 ∧
    before.resources.literalBytes + demand.literals ≤ 524288 ∧
    before.resources.dynamicPieces + demand.dynamics ≤ 256

theorem json_admission_positive_nodes (depth : Nat) (value : Value) (echo : Option (List Bytes)) (demand : Demand)
    (admitted : JsonAdmission depth value echo demand) : 0 < demand.nodes ∧ depth ≤ 6 := by
  cases admitted with
  | leaf depth value within admitted => simp [leafDemand, Demand.plus, Demand.node, Demand.atom, within]
  | array depth items children within count admitted => simp [arrayDemand, Demand.plus, Demand.node, within]
  | object depth fields echo route children within keys routeMeaning admitted =>
    simp [objectDemand, Demand.plus, Demand.node, within]

theorem json_start_has_admission_room (demand : Demand) (bounded : Demand.Bounded demand) : JsonRoom (jsonStart 0) demand := by
  exact ⟨json_start_invariant 0 (by omega), by simpa [jsonStart] using bounded.1,
    by simpa [jsonStart] using bounded.2.1,
    by simpa [jsonStart, zero] using bounded.2.2.1,
    by simpa [jsonStart, zero] using bounded.2.2.2⟩

theorem json_push_accepts_room (before : JsonBuild) (piece : NamedJson) (valid : JsonInvariant before)
    (pieces : before.pieces.length + 1 ≤ 256) (resources : Bounded (plus before.resources (jsonQuantity piece))) :
    ∃ after, pushJson before piece = .ok after ∧ JsonInvariant after ∧
      after.nodes = before.nodes ∧ after.pieces = before.pieces ++ [piece] := by
  let after : JsonBuild := ⟨before.nodes, plus before.resources (jsonQuantity piece), before.pieces ++ [piece]⟩
  have room : before.pieces.length < 256 := by omega
  have charged : add before.resources (jsonQuantity piece) = some (plus before.resources (jsonQuantity piece)) := by
    simp [add, valid.2.2.1, resources]
  have run : pushJson before piece = .ok after := by simp [pushJson, room, charged, after]
  obtain ⟨preserved, nodes, appended⟩ := json_push_preserves_invariant before after piece valid run
  exact ⟨after, run, preserved, nodes, appended⟩

/-- Every independently admitted leaf compiles from an earned depth/resource
frame. This is the complete induction base for all original AST constructors;
it includes arbitrary text/field bytes and the inclusive safe-integer limits. -/
theorem leaf_json_admission_compiles (value : Value) (admitted : LeafAdmission value) (depth : Nat)
    (within : depth ≤ 6) (before : JsonBuild) (room : JsonRoom before (leafDemand value)) :
    ∃ after, emitJson 7 value none depth before = .ok after ∧ JsonFrame before after ∧
      after.nodes = before.nodes + 1 ∧ after.pieces = before.pieces ++ [leafPiece value] := by
  obtain ⟨valid, nodes, pieces, literals, dynamics⟩ := room
  have nodeBudget : before.nodes + 1 ≤ 64 := by simpa [leafDemand, Demand.plus, Demand.node, Demand.atom] using nodes
  have nodeRoom : before.nodes < 64 := by omega
  have nextBound : before.nodes + 1 ≤ 64 := by omega
  let initial : JsonBuild := { before with nodes := before.nodes + 1 }
  have initialValid : JsonInvariant initial := ⟨nextBound, valid.2⟩
  have pieceRoom : initial.pieces.length + 1 ≤ 256 := by
    simpa [initial, leafDemand, Demand.plus, Demand.node, Demand.atom] using pieces
  have resourceRoom : Bounded (plus initial.resources (jsonQuantity (leafPiece value))) := by
    constructor
    · simpa [initial, plus, jsonQuantity, leafDemand, Demand.plus, Demand.node, Demand.atom] using literals
    · simpa [initial, plus, jsonQuantity, leafDemand, Demand.plus, Demand.node, Demand.atom] using dynamics
  obtain ⟨after, pushed, afterValid, sameNodes, appended⟩ := json_push_accepts_room initial (leafPiece value) initialValid pieceRoom resourceRoom
  have charged : chargeNode before.nodes depth = .ok (before.nodes + 1) := by simp [chargeNode, nodeRoom, within]
  have emitted : emitJson 7 value none depth before = .ok after := by
    cases admitted <;> simpa [emitJson, charged, isObject, leafPiece, initial, *] using pushed
  have frame : JsonFrame before after := ⟨afterValid, by simp [initial] at sameNodes; omega,
    ⟨[leafPiece value], by simpa [initial] using appended.symm⟩⟩
  exact ⟨after, emitted, frame, by simpa [initial] using sameNodes, by simpa [initial] using appended⟩

/-- A useful whole body compiles from independent scalar syntax alone. Its
resource room is derived, rather than supplied as a successful helper flag. -/
theorem admitted_leaf_body_compiles (value : Value) (admitted : LeafAdmission value) :
    ∃ output, compileBody (.json value) none = .ok output := by
  have room := json_start_has_admission_room (leafDemand value) (leaf_admission_demand_bounded value admitted)
  obtain ⟨after, emitted, frame, nodes, pieces⟩ := leaf_json_admission_compiles value admitted 0 (by omega) (jsonStart 0) room
  exact ⟨.json after.pieces, by simp [compileBody, emitted]⟩

end Auths.Product.TemplateAst
