import Auths.Product.TemplateAstResources

namespace Auths.Product.TemplateAst
open RequestConstruction BodyCompiler

structure Rendered where
  valid : Bool
  bytes : Bytes
  deriving DecidableEq

def emptyRendered : Rendered := ⟨true, []⟩
def literalRendered (bytes : Bytes) : Rendered := ⟨true, bytes⟩
def appendRendered (first second : Rendered) : Rendered :=
  ⟨first.valid && second.valid, first.bytes ++ second.bytes⟩

def jsonFieldRendered (environment : Bytes → Option Arg) (name : Bytes) : Rendered :=
  match environment name with
  | none => ⟨false, []⟩
  | some value => ⟨true, jsonArgument value⟩

def formFieldRendered (environment : Bytes → Option Arg) (name : Bytes) : Rendered :=
  match environment name with
  | some (.text bytes) | some (.integer bytes) => ⟨true, formEncode bytes⟩
  | none | some (.boolean _) => ⟨false, []⟩

/-- Original key/value association, independent of compiler choices/indices. -/
def lookupSource {α : Type} (name : Bytes) : List (Bytes × α) → Option α
  | [] => none
  | (key, value) :: rest => if key = name then some value else lookupSource name rest

structure NamedEchoRoute where
  insertion : Option Bytes
  descent : Option (Bytes × List Bytes)

/-- Pointer meaning selects an original parent by exact name. It neither
computes nor consumes a compiler-produced source index. -/
def namedEchoRoute (keys : List Bytes) (echo : Option (List Bytes)) : Except Error NamedEchoRoute :=
  match echo with
  | none => .ok ⟨none, none⟩
  | some tokens =>
    if TemplateMembers.PointerDomain tokens then
      match tokens with
      | [] => .error .echoConflict
      | [name] =>
        if name ∉ keys ∧ keys.length < 32 then .ok ⟨some name, none⟩ else .error .echoConflict
      | parent :: next :: rest =>
        if parent ∈ keys then .ok ⟨none, some (parent, next :: rest)⟩ else .error .echoConflict
    else .error .echoConflict

def namedChildEcho (route : NamedEchoRoute) (name : Bytes) : Option (List Bytes) :=
  match route.descent with
  | none => none
  | some (parent, rest) => if parent = name then some rest else none

/-- Direct interpretation of the original AST. It reads action arguments by
original field name and objects by original key/child association. It contains
no compiler argument/source index, emitted template, mutable budget state or
desired-output input. Static refusal and dynamic field validity stay distinct;
the outbound limit is applied once by referenceBody below. -/
def interpretJson : Nat → Value → Option (List Bytes) → (Bytes → Option Arg) → Bytes → Except Error Rendered
  | 0, _, _, _, _ => .error .shape
  | fuel + 1, value, echo, environment, token =>
    if echo.isSome && !isObject value then .error .echoConflict else
      match value with
      | .text bytes =>
        if bytes.length ≤ 1024 then .ok (literalRendered (jsonString bytes)) else .error .shape
      | .integer value =>
        if -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 then
          .ok (literalRendered (integerBytes value)) else .error .shape
      | .boolean value => .ok (literalRendered (if value then [116,114,117,101] else [102,97,108,115,101]))
      | .field name => if RenderedField name then .ok (jsonFieldRendered environment name) else .error .shape
      | .authorEcho => .error .echoConflict
      | .array items =>
        if 0 < items.length ∧ items.length ≤ 16 then do
          let rendered ← (items.zipIdx).foldlM (fun rendered (child, position) => do
            let child ← interpretJson fuel child none environment token
            let separator := literalRendered (if 0 < position then [44] else [])
            .ok (appendRendered rendered (appendRendered separator child))) (literalRendered [91])
          .ok (appendRendered rendered (literalRendered [93]))
        else .error .shape
      | .object fields =>
        let keys := fields.map Prod.fst
        if TemplateMembers.KeyColumn keys .json then do
          let route ← namedEchoRoute keys echo
          let labels := TemplateMembers.namedMerge keys route.insertion false
          let rendered ← (labels.zipIdx).foldlM (fun rendered (name, position) => do
            let child ← if route.insertion = some name then .ok (literalRendered (jsonString token)) else
              match lookupSource name fields with
              | none => .error .shape
              | some child => interpretJson fuel child (namedChildEcho route name) environment token
            let prefix := literalRendered (jsonPrefix name (decide (0 < position)))
            .ok (appendRendered rendered (appendRendered prefix child))) (literalRendered [123])
          .ok (appendRendered rendered (literalRendered [125]))
        else .error .shape

def interpretFormValue (value : FormValue) (environment : Bytes → Option Arg) (token : Bytes) : Except Error Rendered :=
  match value with
  | .text bytes => if bytes.length ≤ 1024 then .ok (literalRendered (formEncode bytes)) else .error .shape
  | .field name => if RenderedField name then .ok (formFieldRendered environment name) else .error .shape
  | .authorEcho => .error .echoConflict
  | .json value =>
    if FormJsonAllowed value then do
      let child ← interpretJson 7 value none environment token
      .ok ⟨child.valid, formEncode child.bytes⟩
    else .error .shape

def interpretBody (body : Body) (echo : Option Echo) (environment : Bytes → Option Arg) (token : Bytes) : Except Error Rendered :=
  match body with
  | .json value => do
    let pointer ← match echo with
      | none => .ok none
      | some (.json pointer) => .ok (some pointer)
      | some (.form _) => .error .echoConflict
    interpretJson 7 value pointer environment token
  | .form fields =>
    if 0 < fields.length ∧ fields.length ≤ 16 then do
      let insertion ← match echo with
        | none => .ok none
        | some (.form name) => .ok (some name)
        | some (.json _) => .error .echoConflict
      let keys := fields.map Prod.fst
      if TemplateMembers.KeyColumn keys .form then
        if TemplateMembers.EchoAdmitted keys insertion .form then do
          let labels := TemplateMembers.namedMerge keys insertion false
          (labels.zipIdx).foldlM (fun rendered (name, position) => do
            let value ← if insertion = some name then .ok (literalRendered (formEncode token)) else
              match lookupSource name fields with
              | none => .error .shape
              | some value => interpretFormValue value environment token
            let prefix := literalRendered (formPrefix name (decide (0 < position)))
            .ok (appendRendered rendered (appendRendered prefix value))) emptyRendered
        else .error .echoConflict
      else .error .shape
    else .error .shape

def referenceBody (body : Body) (echo : Option Echo) (environment : Bytes → Option Arg) (token : Bytes) :
    Except Error (Except ConstructError Bytes) :=
  (interpretBody body echo environment token).map fun rendered => finishNamedBody rendered.valid rendered.bytes

def renderedTemplate (template : NamedTemplate) (environment : Bytes → Option Arg) (token : Bytes) : Rendered :=
  match template with
  | .json pieces => ⟨pieces.all (namedJsonValid environment), namedJson environment token pieces⟩
  | .form pieces => ⟨pieces.all (namedFormValid environment), namedForm environment token pieces⟩

theorem append_rendered_assoc (first second third : Rendered) :
    appendRendered (appendRendered first second) third = appendRendered first (appendRendered second third) := by
  cases first
  cases second
  cases third
  simp [appendRendered, Bool.and_assoc, List.append_assoc]

theorem rendered_json_append (first second : List NamedJson) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.json (first ++ second)) environment token =
      appendRendered (renderedTemplate (.json first) environment token) (renderedTemplate (.json second) environment token) := by
  simp [renderedTemplate, appendRendered, namedJson, List.flatMap_append]

theorem rendered_form_append (first second : List NamedForm) (environment : Bytes → Option Arg) (token : Bytes) :
    renderedTemplate (.form (first ++ second)) environment token =
      appendRendered (renderedTemplate (.form first) environment token) (renderedTemplate (.form second) environment token) := by
  simp [renderedTemplate, appendRendered, namedForm, List.flatMap_append]

theorem lookup_source_member {α : Type} (fields : List (Bytes × α)) (name : Bytes) (value : α)
    (found : lookupSource name fields = some value) : (name, value) ∈ fields := by
  induction fields with
  | nil => simp [lookupSource] at found
  | cons member rest ih =>
    obtain ⟨key, actual⟩ := member
    by_cases equal : key = name
    · have same : actual = value := by simpa [lookupSource, equal] using found
      simp [equal, same]
    · simp only [lookupSource, equal, ↓reduceIte] at found
      exact List.mem_cons_of_mem _ (ih found)

theorem lookup_source_at_unique {α : Type} (fields : List (Bytes × α)) (name : Bytes) (value : α) (index : Nat)
    (unique : (fields.map Prod.fst).Nodup) (atSource : fields[index]? = some (name, value)) :
    lookupSource name fields = some value := by
  induction fields generalizing index with
  | nil => simp at atSource
  | cons member rest ih =>
    obtain ⟨key, actual⟩ := member
    have distinct := List.nodup_cons.mp unique
    cases index with
    | zero =>
      have same : (key, actual) = (name, value) := by simpa using atSource
      cases same
      simp [lookupSource]
    | succ index =>
      have tail : rest[index]? = some (name, value) := by simpa using atSource
      have namePresent : name ∈ rest.map Prod.fst := by
        exact List.mem_map.mpr ⟨(name, value), List.mem_iff_getElem?.mpr ⟨index, tail⟩, rfl⟩
      have notKey : key ≠ name := by intro same; exact distinct.1 (by simpa [same] using namePresent)
      simpa [lookupSource, notKey] using ih index distinct.2 tail

theorem admitted_keys_are_unique (keys : List Bytes) (domain : TemplateMembers.Domain)
    (admitted : TemplateMembers.KeyColumn keys domain) : keys.Nodup := by
  apply List.nodup_iff_pairwise_ne.mpr
  exact admitted.2.2.2.imp (fun _ _ less => ne_of_lt less)

end Auths.Product.TemplateAst
