import Auths.Product.TemplateAstTermination
import Auths.Product.TemplateMemberSelection

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler

def arrayItem (child : Value) (depth position : Nat) (initial : JsonBuild) : Except Error JsonBuild := do
  let output ← if 0 < position then pushJson initial (.raw [44]) else .ok initial
  emitJson 7 child none (depth + 1) output

/-- Remaining array work at an original source position. Siblings receive
the state returned by the previous child, including its shared node meter. -/
def arrayFrom (items : List Value) (depth position : Nat) (initial : JsonBuild) : Except Error JsonBuild :=
  ((items.drop position).zipIdx position).foldlM (fun output (child, index) => arrayItem child depth index output) initial

def jsonArray (items : List Value) (depth : Nat) (initial : JsonBuild) : Except Error JsonBuild :=
  if 0 < items.length ∧ items.length ≤ 16 then do
    let output ← pushJson initial (.raw [91])
    let output ← arrayFrom items depth 0 output
    pushJson output (.raw [93])
  else .error .shape

def objectTarget (keys : List Bytes) (echo : Option (List Bytes)) : Except Error (Option TemplateMembers.Target) :=
  match echo with
  | none => .ok none
  | some tokens => ((TemplateMembers.jsonEchoTarget keys tokens).mapError memberError).map some

def objectInsertion (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) : Except Error (Option Bytes) :=
  match target, echo with
  | some .insert, some tokens => match tokens.head? with
    | none => .error .echoConflict
    | some name => .ok (some name)
  | some .insert, none => .error .echoConflict
  | _, _ => .ok none

def objectChildEcho (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (index : Nat) :
    Except Error (Option (List Bytes)) :=
  match target, echo with
  | some (.descend selected), some tokens =>
    if selected = index then
      if 0 < tokens.length then .ok (some (tokens.drop 1)) else .error .echoConflict
    else .ok none
  | _, _ => .ok none

def objectStep (fields : List (Bytes × Value)) (target : Option TemplateMembers.Target)
    (echo : Option (List Bytes)) (insertion : Option Bytes) (depth : Nat)
    (output : JsonBuild) (item : TemplateMembers.Choice × Nat) : Except Error JsonBuild :=
  match item.1 with
  | .source index => match fields[index]? with
    | none => .error .shape
    | some (name, child) => do
      let output ← pushJson output (.raw (jsonPrefix name (decide (0 < item.2))))
      let nested ← objectChildEcho target echo index
      emitJson 7 child nested (depth + 1) output
  | .echo => match insertion with
    | none => .error .echoConflict
    | some name => do
      let output ← pushJson output (.raw (jsonPrefix name (decide (0 < item.2))))
      pushJson output .echo

def objectFrom (fields : List (Bytes × Value)) (order : List TemplateMembers.Choice)
    (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (insertion : Option Bytes)
    (depth position : Nat) (initial : JsonBuild) : Except Error JsonBuild :=
  ((order.drop position).zipIdx position).foldlM (objectStep fields target echo insertion depth) initial

def jsonObject (fields : List (Bytes × Value)) (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild) :
    Except Error JsonBuild :=
  if 0 < fields.length ∧ fields.length ≤ 32 then do
    let keys := fields.map Prod.fst
    let target ← objectTarget keys echo
    let insertion ← objectInsertion target echo
    let order ← (TemplateMembers.canonicalMembers keys insertion .json).mapError memberError
    let output ← pushJson initial (.raw [123])
    let output ← objectFrom fields order target echo insertion depth 0 output
    pushJson output (.raw [125])
  else .error .shape

def formStep (fields : List (Bytes × FormValue)) (insertion : Option Bytes)
    (output : FormBuild) (item : TemplateMembers.Choice × Nat) : Except Error FormBuild :=
  match item.1 with
  | .source index => match fields[index]? with
    | none => .error .shape
    | some (name, value) => do
      let output ← pushForm output (.raw (formPrefix name (decide (0 < item.2))))
      emitFormValue value output
  | .echo => match insertion with
    | none => .error .echoConflict
    | some name => do
      let output ← pushForm output (.raw (formPrefix name (decide (0 < item.2))))
      pushForm output .echo

def formFrom (fields : List (Bytes × FormValue)) (order : List TemplateMembers.Choice)
    (insertion : Option Bytes) (position : Nat) (initial : FormBuild) : Except Error FormBuild :=
  ((order.drop position).zipIdx position).foldlM (formStep fields insertion) initial

def formMembers (fields : List (Bytes × FormValue)) (order : List TemplateMembers.Choice) (insertion : Option Bytes) :
    Except Error FormBuild := formFrom fields order insertion 0 formStart

/-- Dispatch view corresponding to the private Rust traversal functions. It
charges exactly one node before invoking either complete child traversal. -/
def dispatchJson (value : Value) (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild) : Except Error JsonBuild := do
  let nodes ← chargeNode initial.nodes depth
  let output := { initial with nodes }
  if echo.isSome && !isObject value then .error .echoConflict else
    match value with
    | .text bytes => if bytes.length ≤ 1024 then pushJson output (.raw (jsonString bytes)) else .error .shape
    | .integer value => if -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 then
        pushJson output (.raw (integerBytes value)) else .error .shape
    | .boolean value => pushJson output (.raw (if value then [116,114,117,101] else [102,97,108,115,101]))
    | .field name => if RenderedField name then pushJson output (.field name) else .error .shape
    | .authorEcho => .error .echoConflict
    | .array items => jsonArray items depth output
    | .object fields => jsonObject fields echo depth output

theorem emit_json_dispatch_exact (value : Value) (echo : Option (List Bytes)) (depth : Nat) (initial : JsonBuild) :
    emitJson 7 value echo depth initial = dispatchJson value echo depth initial := by
  have children : ∀ child nested output, emitJson 6 child nested (depth + 1) output =
      emitJson 7 child nested (depth + 1) output := by
    intro child nested output
    exact emit_json_child_fuel 6 child nested depth output (by omega)
  unfold dispatchJson
  rw [emitJson]
  simp_rw [children]
  rfl

theorem array_from_step (items : List Value) (depth position : Nat) (initial : JsonBuild)
    (inside : position < items.length) :
    arrayFrom items depth position initial = do
      let output ← arrayItem items[position] depth position initial
      arrayFrom items depth (position + 1) output := by
  unfold arrayFrom
  rw [List.drop_eq_getElem_cons inside, List.zipIdx_cons, List.foldlM_cons]
  rfl

theorem array_from_done (items : List Value) (depth position : Nat) (initial : JsonBuild)
    (finished : items.length ≤ position) : arrayFrom items depth position initial = .ok initial := by
  simp [arrayFrom, List.drop_of_length_le finished]

theorem object_from_step (fields : List (Bytes × Value)) (order : List TemplateMembers.Choice)
    (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (insertion : Option Bytes)
    (depth position : Nat) (initial : JsonBuild) (inside : position < order.length) :
    objectFrom fields order target echo insertion depth position initial = do
      let output ← objectStep fields target echo insertion depth initial (order[position], position)
      objectFrom fields order target echo insertion depth (position + 1) output := by
  unfold objectFrom
  rw [List.drop_eq_getElem_cons inside, List.zipIdx_cons, List.foldlM_cons]
  rfl

theorem object_from_done (fields : List (Bytes × Value)) (order : List TemplateMembers.Choice)
    (target : Option TemplateMembers.Target) (echo : Option (List Bytes)) (insertion : Option Bytes)
    (depth position : Nat) (initial : JsonBuild) (finished : order.length ≤ position) :
    objectFrom fields order target echo insertion depth position initial = .ok initial := by
  simp [objectFrom, List.drop_of_length_le finished]

theorem form_from_step (fields : List (Bytes × FormValue)) (order : List TemplateMembers.Choice)
    (insertion : Option Bytes) (position : Nat) (initial : FormBuild) (inside : position < order.length) :
    formFrom fields order insertion position initial = do
      let output ← formStep fields insertion initial (order[position], position)
      formFrom fields order insertion (position + 1) output := by
  unfold formFrom
  rw [List.drop_eq_getElem_cons inside, List.zipIdx_cons, List.foldlM_cons]
  rfl

theorem form_from_done (fields : List (Bytes × FormValue)) (order : List TemplateMembers.Choice)
    (insertion : Option Bytes) (position : Nat) (initial : FormBuild) (finished : order.length ≤ position) :
    formFrom fields order insertion position initial = .ok initial := by
  simp [formFrom, List.drop_of_length_le finished]

def PrefixDomain (keys : List Bytes) (insertion : Option Bytes) : Prop :=
  (∀ key ∈ keys, key.length ≤ 130) ∧ ∀ name, insertion = some name → name.length ≤ 130

theorem canonical_members_earn_prefix_domain (keys : List Bytes) (insertion : Option Bytes)
    (domain : TemplateMembers.Domain) (order : List TemplateMembers.Choice)
    (run : TemplateMembers.canonicalMembers keys insertion domain = .ok order) : PrefixDomain keys insertion := by
  have admitted := TemplateMembers.canonical_success_earns_admission keys insertion domain order run
  constructor
  · intro key member
    have bound := (TemplateMembers.token_shape_bounds key (admitted.1.2.2.1 key member)).2.1
    omega
  · intro name present
    subst insertion
    have lexical := admitted.2.1
    cases domain with
    | json =>
      have bound := (TemplateMembers.token_shape_bounds name lexical).2.1
      omega
    | form =>
      unfold TemplateMembers.EchoName TemplateMembers.formEchoValid at lexical
      by_cases large : 130 < name.length
      · simp [large] at lexical
      · omega

end Auths.Product.TemplateAst
