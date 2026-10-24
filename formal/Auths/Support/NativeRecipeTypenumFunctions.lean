import qualification.aeneas.generated.native_recipe.Types
import Auths.Support.NativeRecipeCryptoTypes

/-!
Concrete typenum 1.20.1 data/constant interfaces from the actual constructor
ABI. Numeric extension uses the source's fixed-width shift and bitwise OR;
both methods and associated constants preserve bit-first evaluation order.
Private comparisons delegate to the original more-significant-bit callback
and retain or replace SoFar exactly as the pinned implementation does.
These are unverified ordinary models, not cryptographic or Auths decisions.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe.NativeModel

def appendUnsignedBit {ty : UScalarTy} (upper : UScalar ty) (bit : Std.U8) : UScalar ty :=
  { bv := (upper.bv <<< 1) ||| BitVec.ofNat ty.numBits bit.val }

def appendSignedBit {ty : IScalarTy} (upper : IScalar ty) (bit : Std.U8) : IScalar ty :=
  { bv := (upper.bv <<< 1) ||| BitVec.ofNat ty.numBits bit.val }

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe

-- Pinned typenum's private marker is an uninhabited enum, used only as a
-- generic method parameter; no value of it is manufactured.
abbrev typenum.private.Internal := Empty

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_isize
  : Result Std.Isize := ok 0#isize

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_i64
  : Result Std.I64 := ok 0#i64

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_i32
  : Result Std.I32 := ok 0#i32

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_i16
  : Result Std.I16 := ok 0#i16

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_i8
  : Result Std.I8 := ok 0#i8

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_usize
  : Result Std.Usize := ok 0#usize

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_u64
  : Result Std.U64 := ok 0#u64

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_u32
  : Result Std.U32 := ok 0#u32

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_u16
  : Result Std.U16 := ok 0#u16

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.to_u8
  : Result Std.U8 := ok 0#u8

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.ISIZE
  : Result Std.Isize := ok 0#isize

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.I64
  : Result Std.I64 := ok 0#i64

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.I32
  : Result Std.I32 := ok 0#i32

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.I16
  : Result Std.I16 := ok 0#i16

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.I8 : Result Std.I8 := ok 0#i8

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.USIZE
  : Result Std.Usize := ok 0#usize

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.U64
  : Result Std.U64 := ok 0#u64

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.U32
  : Result Std.U32 := ok 0#u32

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.U16
  : Result Std.U16 := ok 0#u16

def typenum.uint.UTerm.Insts.TypenumMarker_traitsUnsigned.U8 : Result Std.U8 := ok 0#u8

def typenum.uint.UTerm.Insts.CoreDefaultDefault.default
  : Result typenum.uint.UTerm := ok ()

def typenum.uint.UTerm.Insts.CoreCloneClone.clone
  (value : typenum.uint.UTerm) : Result typenum.uint.UTerm := ok value

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_isize
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.Isize := do
  let low ← bit.to_u8
  let high ← upper.to_isize
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_i64
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.I64 := do
  let low ← bit.to_u8
  let high ← upper.to_i64
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_i32
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.I32 := do
  let low ← bit.to_u8
  let high ← upper.to_i32
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_i16
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.I16 := do
  let low ← bit.to_u8
  let high ← upper.to_i16
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_i8
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.I8 := do
  let low ← bit.to_u8
  let high ← upper.to_i8
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_usize
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.Usize := do
  let low ← bit.to_u8
  let high ← upper.to_usize
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_u64
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.U64 := do
  let low ← bit.to_u8
  let high ← upper.to_u64
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_u32
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.U32 := do
  let low ← bit.to_u8
  let high ← upper.to_u32
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_u16
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.U16 := do
  let low ← bit.to_u8
  let high ← upper.to_u16
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.to_u8
  {U : Type} {B : Type} (upper :
  typenum.marker_traits.Unsigned U) (bit :
  typenum.marker_traits.Bit B) :
  Result Std.U8 := do
  let low ← bit.to_u8
  let high ← upper.to_u8
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.ISIZE {U : Type} {B
  : Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.Isize := do
  let low ← bit.U8
  let high ← upper.ISIZE
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.I64 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.I64 := do
  let low ← bit.U8
  let high ← upper.I64
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.I32 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.I32 := do
  let low ← bit.U8
  let high ← upper.I32
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.I16 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.I16 := do
  let low ← bit.U8
  let high ← upper.I16
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.I8 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.I8 := do
  let low ← bit.U8
  let high ← upper.I8
  ok (NativeModel.appendSignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.USIZE {U : Type} {B
  : Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.Usize := do
  let low ← bit.U8
  let high ← upper.USIZE
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.U64 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.U64 := do
  let low ← bit.U8
  let high ← upper.U64
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.U32 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.U32 := do
  let low ← bit.U8
  let high ← upper.U32
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.U16 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.U16 := do
  let low ← bit.U8
  let high ← upper.U16
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.TypenumMarker_traitsUnsigned.U8 {U : Type} {B :
  Type} (upper : typenum.marker_traits.Unsigned U)
  (bit : typenum.marker_traits.Bit B) : Result Std.U8 := do
  let low ← bit.U8
  let high ← upper.U8
  ok (NativeModel.appendUnsignedBit high low)

def typenum.uint.UInt.Insts.CoreDefaultDefault.default
  {U : Type} {B : Type} (highDefault : core.default.Default U)
  (lowDefault : core.default.Default B) :
  Result (typenum.uint.UInt U B) := do
  let high ← highDefault.default
  let low ← lowDefault.default
  ok ⟨high, low⟩

def typenum.uint.UInt.Insts.CoreCloneClone.clone
  {U : Type} {B : Type} (highClone : core.clone.Clone U)
  (lowClone : core.clone.Clone B) (value : typenum.uint.UInt U B) : Result (typenum.uint.UInt U B) := do
  let high ← highClone.clone value.msb
  let low ← lowClone.clone value.lsb
  ok ⟨high, low⟩

def typenum.bit.B0.Insts.TypenumMarker_traitsBit.to_bool : Result Bool := ok false

def typenum.bit.B0.Insts.TypenumMarker_traitsBit.to_u8 : Result Std.U8 := ok 0#u8

def typenum.bit.B0.Insts.TypenumMarker_traitsBit.new : Result typenum.bit.B0 := ok ()

def typenum.bit.B0.Insts.TypenumMarker_traitsBit.BOOL : Result Bool := ok false

def typenum.bit.B0.Insts.TypenumMarker_traitsBit.U8 : Result Std.U8 := ok 0#u8

def typenum.bit.B0.Insts.CoreDefaultDefault.default : Result typenum.bit.B0 := ok ()

def typenum.bit.B0.Insts.CoreCloneClone.clone
  (value : typenum.bit.B0) : Result typenum.bit.B0 := ok value

def typenum.bit.B1.Insts.TypenumMarker_traitsBit.to_bool : Result Bool := ok true

def typenum.bit.B1.Insts.TypenumMarker_traitsBit.to_u8 : Result Std.U8 := ok 1#u8

def typenum.bit.B1.Insts.TypenumMarker_traitsBit.new : Result typenum.bit.B1 := ok ()

def typenum.bit.B1.Insts.TypenumMarker_traitsBit.BOOL : Result Bool := ok true

def typenum.bit.B1.Insts.TypenumMarker_traitsBit.U8 : Result Std.U8 := ok 1#u8

def typenum.bit.B1.Insts.CoreDefaultDefault.default : Result typenum.bit.B1 := ok ()

def typenum.bit.B1.Insts.CoreCloneClone.clone
  (value : typenum.bit.B1) : Result typenum.bit.B1 := ok value

def
  typenum.uint.UTerm.Insts.TypenumPrivatePrivateCmpUIntSoFarLess.private_cmp
  {U : Type} {B : Type} {SoFar : Type} (marker_traitsUnsignedInst :
  typenum.marker_traits.Unsigned U) (marker_traitsBitInst :
  typenum.marker_traits.Bit B) (marker_traitsOrdInst :
  typenum.marker_traits.Ord SoFar) (_left : typenum.uint.UTerm) (_right : typenum.uint.UInt U B) (_soFar : SoFar) : Result typenum.Less := ok ()

def
  typenum.uint.UIntUlB1.Insts.TypenumPrivatePrivateCmpUIntUrB0SoFarClause3_Output.private_cmp
  {Ul : Type} {Ur : Type} {SoFar : Type} {Clause3_Output : Type}
  (marker_traitsUnsignedInst : typenum.marker_traits.Unsigned Ul)
  (marker_traitsUnsignedInst1 : typenum.marker_traits.Unsigned Ur)
  (marker_traitsOrdInst : typenum.marker_traits.Ord SoFar)
  (parentComparison : typenum.private.PrivateCmp
  Ul Ur typenum.Greater Clause3_Output) (left : typenum.uint.UInt Ul typenum.bit.B1) (right : typenum.uint.UInt Ur typenum.bit.B0) (soFar : SoFar) : Result Clause3_Output := parentComparison.private_cmp left.msb right.msb ()

def
  typenum.uint.UIntUlB0.Insts.TypenumPrivatePrivateCmpUIntUrB0SoFarClause3_Output.private_cmp
  {Ul : Type} {Ur : Type} {SoFar : Type} {Clause3_Output : Type}
  (marker_traitsUnsignedInst : typenum.marker_traits.Unsigned Ul)
  (marker_traitsUnsignedInst1 : typenum.marker_traits.Unsigned Ur)
  (marker_traitsOrdInst : typenum.marker_traits.Ord SoFar)
  (parentComparison : typenum.private.PrivateCmp Ul Ur SoFar
  Clause3_Output) (left : typenum.uint.UInt Ul typenum.bit.B0) (right : typenum.uint.UInt Ur typenum.bit.B0) (soFar : SoFar) : Result Clause3_Output := parentComparison.private_cmp left.msb right.msb soFar

def
  typenum.uint.UIntUlB0.Insts.TypenumType_operatorsCmpUIntUrB0Clause2_Output.compare
  {Ul : Type} {Ur : Type} {IM : Type} {Clause2_Output : Type}
  (marker_traitsUnsignedInst : typenum.marker_traits.Unsigned Ul)
  (marker_traitsUnsignedInst1 : typenum.marker_traits.Unsigned Ur)
  (parentComparison : typenum.private.PrivateCmp Ul
  Ur typenum.Equal Clause2_Output) (privateInternalMarkerInst :
  typenum.private.InternalMarker IM) (left : typenum.uint.UInt Ul typenum.bit.B0) (right : typenum.uint.UInt Ur typenum.bit.B0) : Result Clause2_Output := parentComparison.private_cmp left.msb right.msb ()

def typenum.type_operators.IsLess.Blanket.is_less
  {A : Type} {B : Type} {Clause0_Output : Type} {Clause1_Output : Type}
  (comparison : typenum.type_operators.Cmp A B Clause0_Output)
  (decision : typenum.private.IsLessPrivate A B Clause0_Output
  Clause1_Output) (left : A) (right : B) : Result Clause1_Output := do
  let result ← comparison.compare (IM := typenum.private.Internal) ⟨⟩ left right
  decision.is_less_private left right result

def typenum.private.IsLessPrivateABLessB1.Blanket.is_less_private
  {A : Type} {B : Type} (_left : A) (_right : B) (_comparison : typenum.Less) : Result typenum.bit.B1 := ok ()

def typenum.Equal.Insts.TypenumMarker_traitsOrd.to_ordering : Result Ordering := ok .eq

def typenum.Greater.Insts.TypenumMarker_traitsOrd.to_ordering
  : Result Ordering := ok .gt

def
  typenum.private.IsLessOrEqualPrivateABEqualB1.Blanket.is_less_or_equal_private
  {A : Type} {B : Type} (_left : A) (_right : B) (_comparison : typenum.Equal) : Result typenum.bit.B1 := ok ()

def typenum.type_operators.IsLessOrEqual.Blanket.is_less_or_equal
  {A : Type} {B : Type} {Clause0_Output : Type} {Clause1_Output : Type}
  (comparison : typenum.type_operators.Cmp A B Clause0_Output)
  (decision : typenum.private.IsLessOrEqualPrivate A B
  Clause0_Output Clause1_Output) (left : A) (right : B) : Result Clause1_Output := do
  let result ← comparison.compare (IM := typenum.private.Internal) ⟨⟩ left right
  decision.is_less_or_equal_private left right result

def
  typenum.uint.UIntUlB1.Insts.TypenumPrivatePrivateCmpUIntUrB1SoFarClause3_Output.private_cmp
  {Ul : Type} {Ur : Type} {SoFar : Type} {Clause3_Output : Type}
  (marker_traitsUnsignedInst : typenum.marker_traits.Unsigned Ul)
  (marker_traitsUnsignedInst1 : typenum.marker_traits.Unsigned Ur)
  (marker_traitsOrdInst : typenum.marker_traits.Ord SoFar)
  (parentComparison : typenum.private.PrivateCmp Ul Ur SoFar
  Clause3_Output) (left : typenum.uint.UInt Ul typenum.bit.B1) (right : typenum.uint.UInt Ur typenum.bit.B1) (soFar : SoFar) : Result Clause3_Output := parentComparison.private_cmp left.msb right.msb soFar

def
  typenum.uint.UTerm.Insts.TypenumPrivatePrivateCmpUTermSoFarSoFar.private_cmp
  {SoFar : Type} (marker_traitsOrdInst : typenum.marker_traits.Ord SoFar) (_left _right : typenum.uint.UTerm) (soFar : SoFar) : Result SoFar := ok soFar

end AuthsNativeRecipe
