import Auths.Support.NativePayloadCodec
import Auths.Support.NativeTypeSyntax

/-!
Whole native argument values use the shared reversible field codec, indexed
by the complete actual native type syntax. Field schemas come from actual
instantiated native declarations. They describe logical native values, not
Rust allocation layout or reference/loan permissions. No input/output field,
variant or dictionary argument may disappear to fit an event-port helper.
All scripts await final elaboration.
-/
namespace Auths.Support.NativeRootPayload
open BorrowProjection
abbrev NativeType := NativeTypeSyntax.Expr
abbrev Label := NativePayloadCodec.Label NativeType
abbrev Layout := NativePayloadCodec.Layout NativeType
abbrev Value := @NativePayloadCodec.Value NativeType
abbrev AtomTyping := NativePayloadCodec.AtomTyping NativeType
abbrev SourceAtom := @NativePayloadCodec.SourceAtom NativeType
abbrev Codec := @NativePayloadCodec.Codec NativeType
abbrev encode := @NativePayloadCodec.encode NativeType
abbrev decode := @NativePayloadCodec.decode NativeType
export NativePayloadCodec (decode_encode encode_decode missing_atom_has_no_value)

structure Field where
  name : Option (List Nat)
  type : NativeType
  deriving DecidableEq, Repr

structure Schema where
  type : NativeType
  rows : List (Option Nat × List Field)
  deriving DecidableEq, Repr

def rootType : Layout → Option NativeType
  | .atom type | .named (.nominal type) _ => some type
  | .unit => some (NativeTypeSyntax.tuple [])
  | .empty => some (.node .never [])
  | _ => none

def schemaRows (schemas : List Schema) (type : NativeType) : Option (List (Option Nat × List Field)) :=
  match (schemas.filter fun schema => schema.type == type).map Schema.rows with
  | [] => none
  | first :: rest => if rest.all (· == first) then some first else none

mutual
  def checkLayout : Nat → List NativeType → List Schema → Layout → Bool
    | 0, _, _, _ => false
    | fuel + 1, atoms, schemas, layout =>
        match layout with
        | .atom type => decide (type ∈ atoms) && NativeTypeSyntax.validType (fuel + 1) type
        | .unit | .empty => true
        | .product left right | .sum left right =>
            checkLayout fuel atoms schemas left && checkLayout fuel atoms schemas right
        | .named (.field _ _) body | .named (.variant _) body => checkLayout fuel atoms schemas body
        | .named (.nominal type) body =>
            NativeTypeSyntax.validType (fuel + 1) type &&
            match schemaRows schemas type with
            | none => false
            | some [(none, fields)] => checkFields fuel atoms schemas 0 fields body
            | some rows => checkVariants fuel atoms schemas 0 rows body
  def checkFields : Nat → List NativeType → List Schema → Nat → List Field → Layout → Bool
    | 0, _, _, _, _, _ => false
    | _, _, _, _, [], .unit => true
    | fuel + 1, atoms, schemas, index, field :: fields,
        .product (.named (.field actual name) body) tail =>
          actual == index && name == field.name && rootType body == some field.type &&
          checkLayout fuel atoms schemas body && checkFields fuel atoms schemas (index + 1) fields tail
    | _, _, _, _, _, _ => false
  def checkVariants : Nat → List NativeType → List Schema → Nat → List (Option Nat × List Field) → Layout → Bool
    | 0, _, _, _, _, _ => false
    | _, _, _, _, [], .empty => true
    | fuel + 1, atoms, schemas, index, (some variant, fields) :: rows,
        .sum (.named (.variant actual) body) tail =>
          variant == index && actual == variant && checkFields fuel atoms schemas 0 fields body &&
          checkVariants fuel atoms schemas (index + 1) rows tail
    | _, _, _, _, _, _ => false
end

def check (fuel : Nat) (atoms : List NativeType) (schemas : List Schema)
    (type : NativeType) (layout : Layout) : Bool :=
  rootType layout == some type && checkLayout fuel atoms schemas layout

theorem missing_native_schema_is_refused (fuel : Nat) (atoms : List NativeType)
    (schemas : List Schema) (type : NativeType) (body : Layout)
    (missing : schemaRows schemas type = none) :
    check (fuel + 1) atoms schemas type (.named (.nominal type) body) = false := by
  simp [check, checkLayout, missing]

theorem a_missing_native_field_is_refused (fuel : Nat) (atoms : List NativeType)
    (schemas : List Schema) (index : Nat) (first : Field) (rest : List Field) :
    checkFields (fuel + 1) atoms schemas index (first :: rest) .unit = false := rfl

theorem a_missing_native_variant_is_refused (fuel : Nat) (atoms : List NativeType)
    (schemas : List Schema) (index variant : Nat) (fields : List Field)
    (rest : List (Option Nat × List Field)) :
    checkVariants (fuel + 1) atoms schemas index ((some variant, fields) :: rest) .empty = false := rfl

end Auths.Support.NativeRootPayload
