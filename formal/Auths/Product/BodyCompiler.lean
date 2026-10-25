import Auths.Product.PathCompiler

namespace Auths.Product.BodyCompiler
open RequestConstruction

/-- Names/literals before the compiler introduces any positional index. This
does not assert JSON parsing, canonical object order or echo admissibility. -/
inductive NamedJson where
  | raw (bytes : Bytes)
  | field (name : Bytes)
  | echo
  deriving DecidableEq

inductive NamedForm where
  | raw (bytes : Bytes)
  | field (name : Bytes)
  | json (pieces : List NamedJson)
  | echo
  deriving DecidableEq

def jsonLiteralSize : NamedJson → Nat
  | .raw bytes => bytes.length
  | .field _ | .echo => 0
def jsonDynamicSize : NamedJson → Nat
  | .raw _ => 0
  | .field _ | .echo => 1
def jsonLiterals (source : List NamedJson) : Nat := (source.map jsonLiteralSize).sum
def jsonDynamics (source : List NamedJson) : Nat := (source.map jsonDynamicSize).sum

def formLiteralSize : NamedForm → Nat
  | .raw bytes => bytes.length
  | .json pieces => jsonLiterals pieces
  | .field _ | .echo => 0
def formDynamicSize : NamedForm → Nat
  | .raw _ => 0
  | .json pieces => jsonDynamics pieces
  | .field _ | .echo => 1
def formLiterals (source : List NamedForm) : Nat := (source.map formLiteralSize).sum
def formDynamics (source : List NamedForm) : Nat := (source.map formDynamicSize).sum

/-- Independent aggregate bounds on the original named pieces. Whole-template
lowering checks them before allocating a compiled plan. -/
def JsonResourceDomain (source : List NamedJson) : Prop :=
  jsonLiterals source ≤ 524288 ∧ jsonDynamics source ≤ 256

def NestedCount : NamedForm → Prop
  | .json pieces => pieces.length ≤ 256
  | _ => True
instance (piece : NamedForm) : Decidable (NestedCount piece) := by
  cases piece <;> unfold NestedCount <;> infer_instance

def NestedCounts (source : List NamedForm) : Prop :=
  ∀ piece ∈ source, NestedCount piece

def FormResourceDomain (source : List NamedForm) : Prop :=
  formLiterals source ≤ 524288 ∧ formDynamics source ≤ 256 ∧ NestedCounts source

instance (source : List NamedJson) : Decidable (JsonResourceDomain source) := by
  unfold JsonResourceDomain; infer_instance
instance (source : List NamedForm) : Decidable (NestedCounts source) := by
  unfold NestedCounts; infer_instance
instance (source : List NamedForm) : Decidable (FormResourceDomain source) := by
  unfold FormResourceDomain; infer_instance

def lowerJsonPiece (names : List Bytes) : NamedJson → Except ConstructError JsonPiece
  | .raw bytes => if bytes.length ≤ 524288 then .ok (.raw bytes) else .error .bodySize
  | .field name => (PathCompiler.lowerField names name).map JsonPiece.field
  | .echo => .ok .echo

def lowerJsonList (names : List Bytes) : List NamedJson → Except ConstructError (List JsonPiece)
  | [] => .ok []
  | piece :: rest => do
    let first ← lowerJsonPiece names piece
    let tail ← lowerJsonList names rest
    pure (first :: tail)

def lowerJson (names : List Bytes) (pieces : List NamedJson) : Except ConstructError (List JsonPiece) :=
  if names.length ≤ 32 ∧ pieces.length ≤ 256 then
    if JsonResourceDomain pieces then lowerJsonList names pieces else .error .bodySize
  else .error .argumentMismatch

def lowerFormPiece (names : List Bytes) : NamedForm → Except ConstructError FormPiece
  | .raw bytes => if bytes.length ≤ 524288 then .ok (.raw bytes) else .error .bodySize
  | .field name => (PathCompiler.lowerField names name).map FormPiece.field
  | .json pieces => (lowerJson names pieces).map FormPiece.json
  | .echo => .ok .echo

def lowerFormList (names : List Bytes) : List NamedForm → Except ConstructError (List FormPiece)
  | [] => .ok []
  | piece :: rest => do
    let first ← lowerFormPiece names piece
    let tail ← lowerFormList names rest
    pure (first :: tail)

def lowerForm (names : List Bytes) (pieces : List NamedForm) : Except ConstructError (List FormPiece) :=
  if names.length ≤ 32 ∧ pieces.length ≤ 256 then
    if FormResourceDomain pieces then lowerFormList names pieces else .error .bodySize
  else .error .argumentMismatch

/-- Declarative field association retains the actual approved name. -/
def FieldMeaning (names : List Bytes) (name : Bytes) (index : Nat) : Prop :=
  names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true ∧
    SchemaIndex.position names name = some index

def JsonMeaning (names : List Bytes) : NamedJson → JsonPiece → Prop
  | .raw bytes, .raw actual => bytes.length ≤ 524288 ∧ actual = bytes
  | .field name, .field index => FieldMeaning names name index
  | .echo, .echo => True
  | _, _ => False

def FormMeaning (names : List Bytes) : NamedForm → FormPiece → Prop
  | .raw bytes, .raw actual => bytes.length ≤ 524288 ∧ actual = bytes
  | .field name, .field index => FieldMeaning names name index
  | .json named, .json actual =>
      names.length ≤ 32 ∧ named.length ≤ 256 ∧ List.Forall₂ (JsonMeaning names) named actual
  | .echo, .echo => True
  | _, _ => False

def JsonAdmissible (names : List Bytes) : NamedJson → Prop
  | .raw bytes => bytes.length ≤ 524288
  | .field name => names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true ∧ name ∈ names
  | .echo => True

def JsonTemplateAdmissible (names : List Bytes) (pieces : List NamedJson) : Prop :=
  names.length ≤ 32 ∧ pieces.length ≤ 256 ∧
    (∀ piece ∈ pieces, JsonAdmissible names piece) ∧ JsonResourceDomain pieces

def FormAdmissible (names : List Bytes) : NamedForm → Prop
  | .raw bytes => bytes.length ≤ 524288
  | .field name => names.length ≤ 32 ∧ OperationIdentity.validToken name 64 = true ∧ name ∈ names
  | .json pieces => JsonTemplateAdmissible names pieces
  | .echo => True

def FormTemplateAdmissible (names : List Bytes) (pieces : List NamedForm) : Prop :=
  names.length ≤ 32 ∧ pieces.length ≤ 256 ∧
    (∀ piece ∈ pieces, FormAdmissible names piece) ∧ FormResourceDomain pieces

instance (names : List Bytes) (piece : NamedJson) : Decidable (JsonAdmissible names piece) := by
  cases piece <;> unfold JsonAdmissible <;> infer_instance
instance (names : List Bytes) (pieces : List NamedJson) : Decidable (JsonTemplateAdmissible names pieces) := by
  unfold JsonTemplateAdmissible; infer_instance
instance (names : List Bytes) (piece : NamedForm) : Decidable (FormAdmissible names piece) := by
  cases piece <;> unfold FormAdmissible <;> infer_instance
instance (names : List Bytes) (pieces : List NamedForm) : Decidable (FormTemplateAdmissible names pieces) := by
  unfold FormTemplateAdmissible; infer_instance

theorem lower_field_sound (names : List Bytes) (name : Bytes) (index : Nat)
    (run : PathCompiler.lowerField names name = .ok index) : FieldMeaning names name index := by
  unfold PathCompiler.lowerField at run
  split at run
  · rename_i admitted
    cases found : SchemaIndex.position names name with
    | none => simp [found] at run
    | some actual =>
      have same : actual = index := by simpa [found] using run
      exact ⟨admitted.1, admitted.2, by simpa [same] using found⟩
  · contradiction

theorem lower_json_piece_sound (names : List Bytes) (source : NamedJson) (piece : JsonPiece)
    (run : lowerJsonPiece names source = .ok piece) : JsonMeaning names source piece := by
  cases source with
  | raw bytes =>
    unfold lowerJsonPiece at run
    split at run
    · rename_i bounded
      have same : JsonPiece.raw bytes = piece := by simpa using run
      subst piece
      exact ⟨bounded, rfl⟩
    · contradiction
  | field name =>
    cases found : PathCompiler.lowerField names name with
    | error error => simp [lowerJsonPiece, found] at run
    | ok index =>
      have same : JsonPiece.field index = piece := by simpa [lowerJsonPiece, found] using run
      subst piece
      exact lower_field_sound _ _ _ found
  | echo =>
    have same : JsonPiece.echo = piece := by simpa [lowerJsonPiece] using run
    subst piece
    trivial

theorem lower_json_list_sound (names : List Bytes) (source : List NamedJson) (pieces : List JsonPiece)
    (run : lowerJsonList names source = .ok pieces) : List.Forall₂ (JsonMeaning names) source pieces := by
  induction source generalizing pieces with
  | nil =>
    have same : pieces = [] := by simpa [lowerJsonList] using run.symm
    simp [same]
  | cons head rest ih =>
    cases first : lowerJsonPiece names head with
    | error error => simp [lowerJsonList, first] at run
    | ok piece =>
      cases remaining : lowerJsonList names rest with
      | error error => simp [lowerJsonList, first, remaining] at run
      | ok tail =>
        have same : piece :: tail = pieces := by simpa [lowerJsonList, first, remaining] using run
        subst pieces
        exact List.Forall₂.cons (lower_json_piece_sound _ _ _ first) (ih tail remaining)

theorem lower_json_sound (names : List Bytes) (source : List NamedJson) (pieces : List JsonPiece)
    (run : lowerJson names source = .ok pieces) :
    names.length ≤ 32 ∧ source.length ≤ 256 ∧ List.Forall₂ (JsonMeaning names) source pieces := by
  unfold lowerJson at run
  split at run
  · rename_i bounded
    split at run
    · exact ⟨bounded.1, bounded.2, lower_json_list_sound _ _ _ run⟩
    · contradiction
  · contradiction

theorem lower_json_earns_resources (names : List Bytes) (source : List NamedJson) (pieces : List JsonPiece)
    (run : lowerJson names source = .ok pieces) : JsonResourceDomain source := by
  unfold lowerJson at run
  split at run
  · split at run
    · assumption
    · contradiction
  · contradiction

theorem lower_form_piece_sound (names : List Bytes) (source : NamedForm) (piece : FormPiece)
    (run : lowerFormPiece names source = .ok piece) : FormMeaning names source piece := by
  cases source with
  | raw bytes =>
    unfold lowerFormPiece at run
    split at run
    · rename_i bounded
      have same : FormPiece.raw bytes = piece := by simpa using run
      subst piece
      exact ⟨bounded, rfl⟩
    · contradiction
  | field name =>
    cases found : PathCompiler.lowerField names name with
    | error error => simp [lowerFormPiece, found] at run
    | ok index =>
      have same : FormPiece.field index = piece := by simpa [lowerFormPiece, found] using run
      subst piece
      exact lower_field_sound _ _ _ found
  | json source =>
    cases lowered : lowerJson names source with
    | error error => simp [lowerFormPiece, lowered] at run
    | ok pieces =>
      have same : FormPiece.json pieces = piece := by simpa [lowerFormPiece, lowered] using run
      subst piece
      exact lower_json_sound _ _ _ lowered
  | echo =>
    have same : FormPiece.echo = piece := by simpa [lowerFormPiece] using run
    subst piece
    trivial

theorem lower_form_list_sound (names : List Bytes) (source : List NamedForm) (pieces : List FormPiece)
    (run : lowerFormList names source = .ok pieces) : List.Forall₂ (FormMeaning names) source pieces := by
  induction source generalizing pieces with
  | nil =>
    have same : pieces = [] := by simpa [lowerFormList] using run.symm
    simp [same]
  | cons head rest ih =>
    cases first : lowerFormPiece names head with
    | error error => simp [lowerFormList, first] at run
    | ok piece =>
      cases remaining : lowerFormList names rest with
      | error error => simp [lowerFormList, first, remaining] at run
      | ok tail =>
        have same : piece :: tail = pieces := by simpa [lowerFormList, first, remaining] using run
        subst pieces
        exact List.Forall₂.cons (lower_form_piece_sound _ _ _ first) (ih tail remaining)

theorem lower_form_sound (names : List Bytes) (source : List NamedForm) (pieces : List FormPiece)
    (run : lowerForm names source = .ok pieces) :
    names.length ≤ 32 ∧ source.length ≤ 256 ∧ List.Forall₂ (FormMeaning names) source pieces := by
  unfold lowerForm at run
  split at run
  · rename_i bounded
    split at run
    · exact ⟨bounded.1, bounded.2, lower_form_list_sound _ _ _ run⟩
    · contradiction
  · contradiction

theorem lower_form_earns_resources (names : List Bytes) (source : List NamedForm) (pieces : List FormPiece)
    (run : lowerForm names source = .ok pieces) : FormResourceDomain source := by
  unfold lowerForm at run
  split at run
  · split at run
    · assumption
    · contradiction
  · contradiction

theorem lower_json_piece_complete (names : List Bytes) (source : NamedJson)
    (admitted : JsonAdmissible names source) : ∃ piece, lowerJsonPiece names source = .ok piece := by
  cases source with
  | raw bytes => exact ⟨.raw bytes, by simp [lowerJsonPiece, admitted]⟩
  | field name =>
    cases found : SchemaIndex.position names name with
    | none => exact False.elim ((SchemaIndex.absent_iff names name).mp found admitted.2.2)
    | some index =>
      exact ⟨.field index, by simp [lowerJsonPiece, PathCompiler.lowerField, admitted.1, admitted.2.1, found]⟩
  | echo => exact ⟨.echo, rfl⟩

theorem lower_json_list_complete (names : List Bytes) (source : List NamedJson)
    (admitted : ∀ piece ∈ source, JsonAdmissible names piece) :
    ∃ pieces, lowerJsonList names source = .ok pieces := by
  induction source with
  | nil => exact ⟨[], rfl⟩
  | cons head rest ih =>
    obtain ⟨piece, first⟩ := lower_json_piece_complete names head (admitted _ (by simp))
    obtain ⟨pieces, tail⟩ := ih (fun value member => admitted value (by simp [member]))
    exact ⟨piece :: pieces, by simp [lowerJsonList, first, tail]⟩

theorem lower_json_complete (names : List Bytes) (source : List NamedJson)
    (admitted : JsonTemplateAdmissible names source) : ∃ pieces, lowerJson names source = .ok pieces := by
  obtain ⟨pieces, run⟩ := lower_json_list_complete names source admitted.2.2.1
  exact ⟨pieces, by simp [lowerJson, admitted.1, admitted.2.1, admitted.2.2.2, run]⟩

theorem lower_form_piece_complete (names : List Bytes) (source : NamedForm)
    (admitted : FormAdmissible names source) : ∃ piece, lowerFormPiece names source = .ok piece := by
  cases source with
  | raw bytes => exact ⟨.raw bytes, by simp [lowerFormPiece, admitted]⟩
  | field name =>
    cases found : SchemaIndex.position names name with
    | none => exact False.elim ((SchemaIndex.absent_iff names name).mp found admitted.2.2)
    | some index =>
      exact ⟨.field index, by simp [lowerFormPiece, PathCompiler.lowerField, admitted.1, admitted.2.1, found]⟩
  | json pieces =>
    obtain ⟨actual, run⟩ := lower_json_complete names pieces admitted
    exact ⟨.json actual, by simp [lowerFormPiece, run]⟩
  | echo => exact ⟨.echo, rfl⟩

theorem lower_form_list_complete (names : List Bytes) (source : List NamedForm)
    (admitted : ∀ piece ∈ source, FormAdmissible names piece) :
    ∃ pieces, lowerFormList names source = .ok pieces := by
  induction source with
  | nil => exact ⟨[], rfl⟩
  | cons head rest ih =>
    obtain ⟨piece, first⟩ := lower_form_piece_complete names head (admitted _ (by simp))
    obtain ⟨pieces, tail⟩ := ih (fun value member => admitted value (by simp [member]))
    exact ⟨piece :: pieces, by simp [lowerFormList, first, tail]⟩

theorem lower_form_complete (names : List Bytes) (source : List NamedForm)
    (admitted : FormTemplateAdmissible names source) : ∃ pieces, lowerForm names source = .ok pieces := by
  obtain ⟨pieces, run⟩ := lower_form_list_complete names source admitted.2.2.1
  exact ⟨pieces, by simp [lowerForm, admitted.1, admitted.2.1, admitted.2.2.2, run]⟩

def namedJsonValid (environment : Bytes → Option Arg) : NamedJson → Bool
  | .field name => (environment name).isSome
  | .raw _ | .echo => true

def namedJsonPiece (environment : Bytes → Option Arg) (echo : Bytes) : NamedJson → Bytes
  | .raw bytes => bytes
  | .field name => match environment name with
    | some argument => jsonArgument argument
    | none => []
  | .echo => jsonString echo

def namedJson (environment : Bytes → Option Arg) (echo : Bytes) (source : List NamedJson) : Bytes :=
  source.flatMap (namedJsonPiece environment echo)

def namedFormValid (environment : Bytes → Option Arg) : NamedForm → Bool
  | .field name => match environment name with
    | some (.text _) | some (.integer _) => true
    | _ => false
  | .json pieces => pieces.all (namedJsonValid environment)
  | .raw _ | .echo => true

def namedFormPiece (environment : Bytes → Option Arg) (echo : Bytes) : NamedForm → Bytes
  | .raw bytes => bytes
  | .field name => match environment name with
    | some (.text bytes) | some (.integer bytes) => formEncode bytes
    | _ => []
  | .json pieces => formEncode (namedJson environment echo pieces)
  | .echo => formEncode echo

def namedForm (environment : Bytes → Option Arg) (echo : Bytes) (source : List NamedForm) : Bytes :=
  source.flatMap (namedFormPiece environment echo)

def finishNamedBody (valid : Bool) (bytes : Bytes) : Except ConstructError Bytes :=
  if valid then
    if bytes.length = 0 || maxBodyBytes < bytes.length then .error .bodySize else .ok bytes
  else .error .argumentMismatch

theorem json_piece_named (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : NamedJson) (piece : JsonPiece) (meaning : JsonMeaning names source piece) :
    renderJsonPiece values echo piece = namedJsonPiece environment echo source ∧
      jsonPieceValid values piece = namedJsonValid environment source := by
  cases source with
  | raw bytes =>
    cases piece <;> simp only [JsonMeaning] at meaning
    all_goals try contradiction
    simp [meaning.2, renderJsonPiece, namedJsonPiece, jsonPieceValid, namedJsonValid]
  | field name =>
    cases piece with
    | raw _ => contradiction
    | echo => contradiction
    | field index =>
      have exactName := SchemaIndex.indexed_argument_is_named _ _ _ aligned _ _ meaning.2.2
      have atName := SchemaIndex.position_points_to_name names name index meaning.2.2
      have withinNames : index < names.length := by
        by_contra outside
        have absent : names[index]? = none := List.getElem?_eq_none (by omega)
        simp [absent] at atName
      have inRange : index < values.length := by have lengths := aligned.1; omega
      constructor
      · simp [renderJsonPiece, namedJsonPiece, exactName]
      · simp [jsonPieceValid, namedJsonValid, ← exactName, inRange, List.getElem?_eq_getElem inRange]
  | echo =>
    cases piece <;> simp only [JsonMeaning] at meaning
    all_goals try contradiction
    simp [renderJsonPiece, namedJsonPiece, jsonPieceValid, namedJsonValid]

theorem json_list_named (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : List NamedJson) (pieces : List JsonPiece)
    (meaning : List.Forall₂ (JsonMeaning names) source pieces) :
    renderJson values echo pieces = namedJson environment echo source ∧
      pieces.all (jsonPieceValid values) = source.all (namedJsonValid environment) := by
  induction meaning with
  | nil => simp [renderJson, namedJson]
  | @cons source piece sources pieces first rest ih =>
    have one := json_piece_named names values environment echo aligned source piece first
    simp [renderJson, namedJson, List.flatMap_cons, one.1, one.2, ih.1, ih.2]

theorem form_piece_named (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : NamedForm) (piece : FormPiece) (meaning : FormMeaning names source piece) :
    renderFormPiece values echo piece = namedFormPiece environment echo source ∧
      formPieceValid values piece = namedFormValid environment source := by
  cases source <;> cases piece <;> simp only [FormMeaning] at meaning
  all_goals try contradiction
  · simp [meaning.2, renderFormPiece, namedFormPiece, formPieceValid, namedFormValid]
  · have exactName := SchemaIndex.indexed_argument_is_named _ _ _ aligned _ _ meaning.2.2
    simp [renderFormPiece, namedFormPiece, formPieceValid, namedFormValid, exactName]
  · have exactJson := json_list_named names values environment echo aligned _ _ meaning.2.2
    simp [renderFormPiece, namedFormPiece, formPieceValid, namedFormValid, exactJson.1, exactJson.2]
  · simp [renderFormPiece, namedFormPiece, formPieceValid, namedFormValid]

theorem form_list_named (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : List NamedForm) (pieces : List FormPiece)
    (meaning : List.Forall₂ (FormMeaning names) source pieces) :
    pieces.flatMap (renderFormPiece values echo) = namedForm environment echo source ∧
      pieces.all (formPieceValid values) = source.all (namedFormValid environment) := by
  induction meaning with
  | nil => simp [namedForm]
  | @cons source piece sources pieces first rest ih =>
    have one := form_piece_named names values environment echo aligned source piece first
    simp [namedForm, List.flatMap_cons, one.1, one.2, ih.1, ih.2]

theorem lowered_json_body_exact (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : List NamedJson) (pieces : List JsonPiece) (run : lowerJson names source = .ok pieces) :
    buildBody (.json pieces) values echo =
      finishNamedBody (source.all (namedJsonValid environment)) (namedJson environment echo source) := by
  have exactBody := json_list_named names values environment echo aligned source pieces (lower_json_sound _ _ _ run).2.2
  simp only [buildBody, bodyValid, renderBody, exactBody.1, exactBody.2, finishNamedBody]

theorem lowered_form_body_exact (names : List Bytes) (values : List Arg) (environment : Bytes → Option Arg)
    (echo : Bytes) (aligned : SchemaIndex.Aligned names values environment)
    (source : List NamedForm) (pieces : List FormPiece) (run : lowerForm names source = .ok pieces) :
    buildBody (.form pieces) values echo =
      finishNamedBody (source.all (namedFormValid environment)) (namedForm environment echo source) := by
  have exactBody := form_list_named names values environment echo aligned source pieces (lower_form_sound _ _ _ run).2.2
  simp only [buildBody, bodyValid, renderBody, exactBody.1, exactBody.2, finishNamedBody]

end Auths.Product.BodyCompiler
