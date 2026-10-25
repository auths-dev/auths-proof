import Auths.Product.DecimalProjection
import Auths.Product.ArgumentBinding

namespace Auths.Product.ScalarProjection
open RequestConstruction

def StringSchema (minimum maximum : Nat) : Prop := minimum ≤ maximum ∧ maximum ≤ 4096
def StringValue (minimum maximum : Nat) (text : Bytes) : Prop :=
  StringSchema minimum maximum ∧ minimum ≤ text.length ∧ text.length ≤ maximum ∧ 0 ∉ text

def EnumByte (byte : Nat) : Prop :=
  (48 ≤ byte ∧ byte ≤ 57) ∨ (65 ≤ byte ∧ byte ≤ 90) ∨ (97 ≤ byte ∧ byte ≤ 122) ∨
    byte = 95 ∨ byte = 46 ∨ byte = 58 ∨ byte = 45
def EnumVariant (text : Bytes) : Prop :=
  0 < text.length ∧ text.length ≤ 64 ∧ ∀ byte ∈ text, EnumByte byte
def EnumSchema (variants : List Bytes) : Prop :=
  0 < variants.length ∧ variants.length ≤ 32 ∧ variants.Nodup ∧ ∀ text ∈ variants, EnumVariant text
def EnumValue (variants : List Bytes) (text : Bytes) : Prop := EnumSchema variants ∧ text ∈ variants

def IntegerSchema (minimum maximum : Int) : Prop :=
  minimum ≤ maximum ∧ -9007199254740991 ≤ minimum ∧ maximum ≤ 9007199254740991
def IntegerValue (minimum maximum value : Int) : Prop :=
  IntegerSchema minimum maximum ∧ minimum ≤ value ∧ value ≤ maximum

instance (minimum maximum : Nat) : Decidable (StringSchema minimum maximum) := inferInstanceAs (Decidable (_ ∧ _))
instance (minimum maximum : Nat) (text : Bytes) : Decidable (StringValue minimum maximum text) :=
  inferInstanceAs (Decidable (_ ∧ _ ∧ _ ∧ _))
instance (byte : Nat) : Decidable (EnumByte byte) := inferInstanceAs (Decidable (_ ∨ _ ∨ _ ∨ _ ∨ _ ∨ _ ∨ _))
instance (text : Bytes) : Decidable (EnumVariant text) := by unfold EnumVariant; infer_instance
instance (variants : List Bytes) : Decidable (EnumSchema variants) := by unfold EnumSchema; infer_instance
instance (variants : List Bytes) (text : Bytes) : Decidable (EnumValue variants text) := by unfold EnumValue; infer_instance
instance (minimum maximum : Int) : Decidable (IntegerSchema minimum maximum) := inferInstanceAs (Decidable (_ ∧ _ ∧ _))
instance (minimum maximum value : Int) : Decidable (IntegerValue minimum maximum value) := inferInstanceAs (Decidable (_ ∧ _ ∧ _))

inductive Schema where
  | text (minimum maximum : Nat)
  | enumeration (variants : List Bytes)
  | integer (minimum maximum : Int)
  | boolean
  deriving DecidableEq

inductive Scalar where
  | text (bytes : Bytes)
  | integer (value : Int)
  | boolean (value : Bool)
  | unsupported

def Accepts : Schema → Scalar → Prop
  | .text minimum maximum, .text bytes => StringValue minimum maximum bytes
  | .enumeration variants, .text bytes => EnumValue variants bytes
  | .integer minimum maximum, .integer value => IntegerValue minimum maximum value
  | .boolean, .boolean _ => True
  | _, _ => False

instance (schema : Schema) (input : Scalar) : Decidable (Accepts schema input) := by
  cases schema <;> cases input <;> unfold Accepts <;> infer_instance

/-- Complete semantic scalar projection; a signed integer is specified by
its base-ten meaning rather than an assumed formatter result. -/
def Projects : Schema → Scalar → Arg → Prop
  | .text minimum maximum, .text bytes, .text actual =>
    StringValue minimum maximum bytes ∧ actual = bytes
  | .enumeration variants, .text bytes, .text actual => EnumValue variants bytes ∧ actual = bytes
  | .integer minimum maximum, .integer value, .integer bytes =>
    IntegerValue minimum maximum value ∧ DecimalProjection.SignedDecimal bytes value
  | .boolean, .boolean value, .boolean actual => actual = value
  | _, _, _ => False

def FormScalarSchema : Schema → Prop
  | .text _ _ | .enumeration _ | .integer _ _ => True
  | .boolean => False
instance (schema : Schema) : Decidable (FormScalarSchema schema) := by cases schema <;> unfold FormScalarSchema <;> infer_instance

def FormArgument : Arg → Prop
  | .text _ | .integer _ => True
  | .boolean _ => False

theorem projected_form_argument (schema : Schema) (input : Scalar) (output : Arg)
    (allowed : FormScalarSchema schema) (projected : Projects schema input output) : FormArgument output := by
  cases schema <;> cases input <;> cases output <;> simp_all [FormScalarSchema, Projects, FormArgument]

def PayloadLength : Arg → Nat
  | .text bytes | .integer bytes => bytes.length
  | .boolean _ => 0

theorem accepted_string_bound (minimum maximum : Nat) (bytes : Bytes)
    (valid : StringValue minimum maximum bytes) : bytes.length ≤ 4096 := by
  exact valid.2.2.1.trans valid.1.2

theorem accepted_enum_bound (variants : List Bytes) (bytes : Bytes)
    (valid : EnumValue variants bytes) : bytes.length ≤ 64 :=
  (valid.1.2.2.2 bytes valid.2).2.1

theorem accepted_integer_bound (minimum maximum value : Int)
    (valid : IntegerValue minimum maximum value) :
    -9007199254740991 ≤ value ∧ value ≤ 9007199254740991 := by
  exact ⟨valid.1.2.1.trans valid.2.1, valid.2.2.trans valid.1.2.2⟩

end Auths.Product.ScalarProjection
