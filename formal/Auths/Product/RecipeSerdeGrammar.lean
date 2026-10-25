import Auths.Product.SerdeFieldLayout

/-!
Closed independent typed-shape language of the shipping recipe/lock derives.
This includes serde's map/sequence alternatives and direct/buffered identifier
distinction. It is NOT a decoded-native-value relation, byte parser, diagnostic
priority model, source-admission rule or proof of the actual derive functions.
Full original values and complete field lists are used; no Auths decoder or
admission callback is an argument to these rules.
-/
namespace Auths.Product.RecipeSerdeGrammar
open SerdeFieldLayout

inductive Record where
  | recipe | lock | guard | probe | accountRead | deniedRead | accountScope
  | bounds | sumBound | relativeCeiling | binding | write | idempotencyLocation
  | observation | echo | preEntry | preconditions
  deriving DecidableEq

inductive Enum where
  | credential | idempotency | path | body | form | value | echoPlacement
  deriving DecidableEq

inductive Kind where
  | text | boolean | signed64 | unsigned8 | unsigned16 | unsigned64 | word | json | writeMethod
  | option (inner : Kind)
  | vector (inner : Kind)
  | map (inner : Kind)
  | record (name : Record)
  | internal (name : Enum)
  deriving DecidableEq

abbrev Fields := List (Field Kind)

def required (name : String) (kind : Kind) : Field Kind := ⟨name, kind, .required⟩
def optional (name : String) (kind : Kind) : Field Kind := ⟨name, .option kind, .null⟩

def recordFields : Record → Fields
  | .recipe => [required "schema" .text, required "profile_schema_digest" .text,
      required "service" .text, required "tool" .text, required "operator_namespace" .text,
      required "credential" (.internal .credential), required "origin" .text,
      optional "provider_headers" (.map .text), optional "account_scope" (.record .accountScope),
      optional "bounds" (.record .bounds), optional "relative_ceiling" (.record .relativeCeiling),
      required "write" (.record .write), optional "observation" (.record .observation),
      optional "echo" (.record .echo), optional "pre_entry" (.record .preEntry),
      optional "preconditions" (.record .preconditions)]
  | .lock => [required "schema" .text, required "profile" .text,
      required "version" .unsigned16, required "service" .text, required "tool" .text,
      required "schema_digest" .text, required "command_schema" .json,
      required "generator_format" .unsigned8]
  | .guard => [required "prefixes" (.vector .text), optional "probe" (.record .probe),
      optional "account" (.record .accountRead), optional "denied_reads" (.vector (.record .deniedRead))]
  | .probe => [required "path" (.vector (.internal .path)), required "json_pointer" .text,
      required "equals" .json, required "maximum_response_bytes" .unsigned64]
  | .accountRead => [required "path" (.vector (.internal .path)), required "json_pointer" .text,
      required "maximum_response_bytes" .unsigned64]
  | .deniedRead => [required "method" .text, required "path" (.vector (.internal .path)),
      required "refused_status" (.vector .unsigned64)]
  | .accountScope => [required "header" .text, required "field" .text]
  | .bounds => [optional "sum" (.record .sumBound)]
  | .sumBound => [required "argument" .text, optional "partition" .text]
  | .relativeCeiling => [required "argument" .text, required "basis_points" .unsigned64,
      required "path" (.vector (.internal .path)), required "json_pointer" .text,
      optional "subtract_pointer" .text, optional "bind" (.vector (.record .binding)),
      required "maximum_response_bytes" .unsigned64]
  | .binding => [required "pointer" .text, required "field" .text]
  | .write => [required "method" .writeMethod, required "path" (.vector (.internal .path)),
      required "body" (.internal .body), optional "idempotency" (.internal .idempotency)]
  | .idempotencyLocation => [optional "json_pointer" .text, optional "form_field" .text, optional "pointer" .text]
  | .observation => [required "path" (.vector (.internal .path)), required "json_pointer" .text,
      required "expected_field" .text, required "maximum_response_bytes" .word]
  | .echo => [required "write" (.internal .echoPlacement), required "observe" .text]
  | .preEntry => [required "path" (.vector (.internal .path)), required "pointers" (.vector .text),
      required "maximum_response_bytes" .unsigned64]
  | .preconditions => [optional "read_back_subject" .text, ⟨"verified", .vector .text, .emptyArray⟩]

structure Variant where
  name : String
  /-- None denotes the actual serde unit visitor, including its ignored map
  content. Some [] instead denotes a strict zero-field struct visitor. -/
  fields : Option Fields

def variants : Enum → List Variant
  | .credential => [⟨"bearer", some [optional "guard" (.record .guard)]⟩,
      ⟨"header-api-key", some [required "header" .text, optional "guard" (.record .guard)]⟩]
  | .idempotency => [⟨"derived-header", some [required "retention_seconds" .unsigned64]⟩,
      ⟨"operation-id-field", some [required "location" (.record .idempotencyLocation), required "retention_seconds" .unsigned64]⟩]
  | .path => [⟨"fixed", some [required "value" .text]⟩,
      ⟨"field", some [required "name" .text]⟩,
      ⟨"response-field", some [required "pointer" .text, required "max_bytes" .unsigned64]⟩,
      ⟨"echo", none⟩]
  | .body => [⟨"json", some [required "value" (.internal .value)]⟩,
      ⟨"form", some [required "fields" (.map (.internal .form))]⟩]
  | .form => [⟨"string", some [required "value" .text]⟩,
      ⟨"field", some [required "name" .text]⟩,
      ⟨"json", some [required "value" (.internal .value)]⟩,
      ⟨"echo", none⟩]
  | .value => [⟨"string", some [required "value" .text]⟩,
      ⟨"integer", some [required "value" .signed64]⟩,
      ⟨"boolean", some [required "value" .boolean]⟩,
      ⟨"field", some [required "name" .text]⟩,
      ⟨"object", some [required "fields" (.map (.internal .value))]⟩,
      ⟨"array", some [required "items" (.vector (.internal .value))]⟩,
      ⟨"echo", none⟩]
  | .echoPlacement => [⟨"json-pointer", some [required "pointer" .text]⟩,
      ⟨"form-field", some [required "name" .text]⟩]

def signedValue : FullJsonValue.Number → Option Int
  | .signed value => if -9223372036854775808 ≤ value ∧ value ≤ 9223372036854775807 then some value else none
  | .unsigned value => if value ≤ 9223372036854775807 then some (Int.ofNat value) else none
  | .floating _ => none

def unsignedValue (maximum : Nat) : FullJsonValue.Number → Option Nat
  | .unsigned value => if value ≤ min maximum 18446744073709551615 then some value else none
  | .signed value =>
      if 0 ≤ value ∧ value ≤ Int.ofNat (min maximum 18446744073709551615) then some value.toNat else none
  | .floating _ => none

def writeMethods : List String := ["POST", "PUT", "PATCH", "DELETE"]

theorem unsigned_value_earns_bounds (maximum : Nat) (number : FullJsonValue.Number) (value : Nat)
    (decoded : unsignedValue maximum number = some value) :
    value ≤ maximum ∧ value ≤ 18446744073709551615 := by
  cases number with
  | floating bits => simp [unsignedValue] at decoded
  | unsigned original =>
      by_cases bounded : original ≤ min maximum 18446744073709551615
      · simp [unsignedValue, bounded] at decoded
        subst value
        exact ⟨bounded.trans (Nat.min_le_left _ _), bounded.trans (Nat.min_le_right _ _)⟩
      · simp [unsignedValue, bounded] at decoded
  | signed original =>
      by_cases bounded : 0 ≤ original ∧ original ≤ Int.ofNat (min maximum 18446744073709551615)
      · simp [unsignedValue, bounded] at decoded
        subst value
        have natural : original.toNat ≤ min maximum 18446744073709551615 := by omega
        exact ⟨natural.trans (Nat.min_le_left _ _), natural.trans (Nat.min_le_right _ _)⟩
      · simp [unsignedValue, bounded] at decoded

theorem signed_value_earns_bounds (number : FullJsonValue.Number) (value : Int)
    (decoded : signedValue number = some value) : -9223372036854775808 ≤ value ∧ value ≤ 9223372036854775807 := by
  cases number with
  | floating bits => simp [signedValue] at decoded
  | signed original =>
      by_cases bounded : -9223372036854775808 ≤ original ∧ original ≤ 9223372036854775807
      · simp [signedValue, bounded] at decoded
        subst value
        exact bounded
      · simp [signedValue, bounded] at decoded
  | unsigned original =>
      by_cases bounded : original ≤ 9223372036854775807
      · simp [signedValue, bounded] at decoded
        subst value
        omega
      · simp [signedValue, bounded] at decoded

mutual
  inductive Accepts (wordMaximum : Nat) : Mode → Kind → Json → Prop where
    | text (mode : Mode) (value : String) : Accepts wordMaximum mode .text (.text value)
    | boolean (mode : Mode) (value : Bool) : Accepts wordMaximum mode .boolean (.boolean value)
    | signed (mode : Mode) (number : FullJsonValue.Number) (value : Int)
        (decoded : signedValue number = some value) : Accepts wordMaximum mode .signed64 (.number number)
    | unsigned8 (mode : Mode) (number : FullJsonValue.Number) (value : Nat)
        (decoded : unsignedValue 255 number = some value) : Accepts wordMaximum mode .unsigned8 (.number number)
    | unsigned16 (mode : Mode) (number : FullJsonValue.Number) (value : Nat)
        (decoded : unsignedValue 65535 number = some value) : Accepts wordMaximum mode .unsigned16 (.number number)
    | unsigned (mode : Mode) (number : FullJsonValue.Number) (value : Nat)
        (decoded : unsignedValue 18446744073709551615 number = some value) :
        Accepts wordMaximum mode .unsigned64 (.number number)
    | word (mode : Mode) (number : FullJsonValue.Number) (value : Nat)
        (decoded : unsignedValue wordMaximum number = some value) : Accepts wordMaximum mode .word (.number number)
    | json (mode : Mode) (value : Json) : Accepts wordMaximum mode .json value
    | absent (mode : Mode) (kind : Kind) : Accepts wordMaximum mode (.option kind) .null
    | present {mode : Mode} {kind : Kind} {value : Json} (notNull : value ≠ .null)
        (child : Accepts wordMaximum mode kind value) : Accepts wordMaximum mode (.option kind) value
    | vector {mode : Mode} {kind : Kind} {values : List Json}
        (children : ValuesAccept wordMaximum mode kind values) : Accepts wordMaximum mode (.vector kind) (.array values)
    | map {mode : Mode} {kind : Kind} {members : List (String × Json)}
        (children : MembersAccept wordMaximum mode kind members) : Accepts wordMaximum mode (.map kind) (.object members)
    | record {mode : Mode} {name : Record} {input : Json} {values : List Json}
        (bound : normalize (recordFields name) input = .ok values)
        (children : FieldsAccept wordMaximum mode (recordFields name) values) :
        Accepts wordMaximum mode (.record name) input
    | internal {mode : Mode} {name : Enum} {input content : Json} (variant : Variant)
        (declared : variant ∈ variants name)
        (selected : SerdeFieldLayout.internal mode ((variants name).map Variant.name) input = .ok (variant.name, content))
        (child : VariantAccept wordMaximum variant content) : Accepts wordMaximum mode (.internal name) input
    | writeMethod {mode : Mode} {input : Json} (name : String)
        (selected : externalUnit mode writeMethods input = .ok name) : Accepts wordMaximum mode .writeMethod input

  inductive ValuesAccept (wordMaximum : Nat) : Mode → Kind → List Json → Prop where
    | nil (mode : Mode) (kind : Kind) : ValuesAccept wordMaximum mode kind []
    | cons {mode : Mode} {kind : Kind} {value : Json} {rest : List Json}
        (head : Accepts wordMaximum mode kind value) (tail : ValuesAccept wordMaximum mode kind rest) :
        ValuesAccept wordMaximum mode kind (value :: rest)

  inductive MembersAccept (wordMaximum : Nat) : Mode → Kind → List (String × Json) → Prop where
    | nil (mode : Mode) (kind : Kind) : MembersAccept wordMaximum mode kind []
    | cons {mode : Mode} {kind : Kind} {name : String} {value : Json} {rest : List (String × Json)}
        (head : Accepts wordMaximum mode kind value) (tail : MembersAccept wordMaximum mode kind rest) :
        MembersAccept wordMaximum mode kind ((name, value) :: rest)

  inductive FieldsAccept (wordMaximum : Nat) : Mode → Fields → List Json → Prop where
    | nil (mode : Mode) : FieldsAccept wordMaximum mode [] []
    | cons {mode : Mode} {field : Field Kind} {rest : Fields} {value : Json} {values : List Json}
        (head : Accepts wordMaximum mode field.kind value) (tail : FieldsAccept wordMaximum mode rest values) :
        FieldsAccept wordMaximum mode (field :: rest) (value :: values)

  inductive VariantAccept (wordMaximum : Nat) : Variant → Json → Prop where
    | unit (name : String) (content : Json) (accepted : unitContent content = true) :
        VariantAccept wordMaximum ⟨name, none⟩ content
    | fields (name : String) (fields : Fields) (content : Json) (values : List Json)
        (bound : normalize fields content = .ok values)
        (children : FieldsAccept wordMaximum .buffered fields values) :
        VariantAccept wordMaximum ⟨name, some fields⟩ content
end

/-- Typed shape plus complete duplicate preflight. Byte syntax, physical
limits and the native decoded-value relation remain separate obligations. -/
def SourceShape (wordMaximum : Nat) (input : Json) : Prop :=
  FullJsonValue.checkMembers input = .ok () ∧ Accepts wordMaximum .direct (.record .recipe) input

def LockShape (wordMaximum : Nat) (input : Json) : Prop :=
  FullJsonValue.checkMembers input = .ok () ∧ Accepts wordMaximum .direct (.record .lock) input

theorem record_field_names_distinct (name : Record) : ((recordFields name).map Field.name).Nodup := by
  cases name <;> decide

theorem variant_names_distinct (name : Enum) : ((variants name).map Variant.name).Nodup := by
  cases name <;> decide

theorem typed_record_keeps_every_field {wordMaximum : Nat} {mode : Mode} {name : Record}
    {input : Json} (typed : Accepts wordMaximum mode (.record name) input) :
    ∃ values, normalize (recordFields name) input = .ok values ∧ values.length = (recordFields name).length := by
  cases typed with
  | record bound children => exact ⟨_, bound, normalized_complete_count _ _ _ bound⟩

theorem floating_never_becomes_signed_integer (wordMaximum : Nat) (mode : Mode) (bits : Nat) :
    ¬ Accepts wordMaximum mode .signed64 (.number (.floating bits)) := by
  intro typed
  cases typed with
  | signed _ _ _ decoded => simp [signedValue] at decoded

theorem floating_never_becomes_unsigned_integer (wordMaximum : Nat) (mode : Mode) (bits : Nat) :
    ¬ Accepts wordMaximum mode .unsigned64 (.number (.floating bits)) := by
  intro typed
  cases typed with
  | unsigned _ _ _ decoded => simp [unsignedValue] at decoded

theorem source_shape_refuses_duplicate_members (wordMaximum : Nat) (input : Json)
    (repeated : FullJsonValue.checkMembers input = .error ()) : ¬ SourceShape wordMaximum input := by
  rintro ⟨accepted, _⟩
  rw [repeated] at accepted
  cases accepted

end Auths.Product.RecipeSerdeGrammar
