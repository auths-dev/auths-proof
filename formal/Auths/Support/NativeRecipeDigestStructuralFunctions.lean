import qualification.aeneas.generated.native_recipe.Types
import Auths.Support.NativeRecipeCryptoTypes

/-!
Ordinary structural operations from the pinned generic-array/digest/sha2 ABI.
The source declarations and type-argument order come from the actual constructor
extraction. No compression, padding, or cryptographic security is asserted here.
These bodies require final elaboration and foreign-model qualification.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe.NativeModel

abbrev Storage1 (T : Type) := generic_array.GenericArrayImplOdd T (Array T 0#usize)

def readStorage1 {T : Type} (input : Storage1 T) : List T :=
  input.parent1.val ++ input.parent2.val ++ [input.data]

theorem readStorage1_length {T : Type} (input : Storage1 T) :
    (readStorage1 input).length = 1 := by
  simp [readStorage1, input.parent1.property, input.parent2.property]

def readStorageEven {T U : Type} (read : U → List T)
    (input : generic_array.GenericArrayImplEven T U) : List T :=
  read input.parent1 ++ read input.parent2

theorem readStorageEven_length {T U : Type} (read : U → List T) (size : Nat)
    (length : ∀ value, (read value).length = size)
    (input : generic_array.GenericArrayImplEven T U) :
    (readStorageEven read input).length = size + size := by
  simp [readStorageEven, length]

abbrev Storage2 (T : Type) := generic_array.GenericArrayImplEven T (Storage1 T)

def readStorage2 {T : Type} (input : Storage2 T) : List T :=
  readStorageEven readStorage1 input

theorem readStorage2_length {T : Type} (input : Storage2 T) :
    (readStorage2 input).length = 2 := by
  exact readStorageEven_length readStorage1 1 readStorage1_length input

abbrev Storage4 (T : Type) := generic_array.GenericArrayImplEven T (Storage2 T)

def readStorage4 {T : Type} (input : Storage4 T) : List T :=
  readStorageEven readStorage2 input

theorem readStorage4_length {T : Type} (input : Storage4 T) :
    (readStorage4 input).length = 4 := by
  exact readStorageEven_length readStorage2 2 readStorage2_length input

abbrev Storage8 (T : Type) := generic_array.GenericArrayImplEven T (Storage4 T)

def readStorage8 {T : Type} (input : Storage8 T) : List T :=
  readStorageEven readStorage4 input

theorem readStorage8_length {T : Type} (input : Storage8 T) :
    (readStorage8 input).length = 8 := by
  exact readStorageEven_length readStorage4 4 readStorage4_length input

abbrev Storage16 (T : Type) := generic_array.GenericArrayImplEven T (Storage8 T)

def readStorage16 {T : Type} (input : Storage16 T) : List T :=
  readStorageEven readStorage8 input

theorem readStorage16_length {T : Type} (input : Storage16 T) :
    (readStorage16 input).length = 16 := by
  exact readStorageEven_length readStorage8 8 readStorage8_length input

abbrev Storage32 (T : Type) := generic_array.GenericArrayImplEven T (Storage16 T)

def readStorage32 {T : Type} (input : Storage32 T) : List T :=
  readStorageEven readStorage16 input

theorem readStorage32_length {T : Type} (input : Storage32 T) :
    (readStorage32 input).length = 32 := by
  exact readStorageEven_length readStorage16 16 readStorage16_length input

-- Initial states are copied from sha2 0.10.9 src/consts.rs, H256_224/256.
def sha224InitialState : Array Std.U32 8#usize :=
  ⟨[0xc1059ed8#u32, 0x367cd507#u32, 0x3070dd17#u32, 0xf70e5939#u32,
    0xffc00b31#u32, 0x68581511#u32, 0x64f98fa7#u32, 0xbefa4fa4#u32], by decide⟩

def sha256InitialState : Array Std.U32 8#usize :=
  ⟨[0x6a09e667#u32, 0xbb67ae85#u32, 0x3c6ef372#u32, 0xa54ff53a#u32,
    0x510e527f#u32, 0x9b05688c#u32, 0x1f83d9ab#u32, 0x5be0cd19#u32], by decide⟩

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe

def block_buffer.Eager.Insts.CoreDefaultDefault.default
  : Result block_buffer.Eager :=
  ok ()

def block_buffer.Eager.Insts.Block_bufferSealedSealed.invariant
  : Std.Usize → Std.Usize → Result Bool :=
  fun position size => ok (decide (position.val < size.val))

def digest.core_api.ct_variable.CtVariableCoreWrapper.Insts.DigestCore_apiUpdateCore.update_blocks
  {T : Type} {OutSize : Type} {O : Type} {Clause0_Clause0_Clause0_BlockSize :
  Type} {Clause0_Clause0_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause1_OutputSize : Type} {Clause0_Clause1_Clause0_ArrayType :
  Type} {Clause0_Clause2_BufferKind : Type} {Clause0_Clause2_Clause0_BlockSize
  : Type} {Clause0_Clause2_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause3_Output : Type} {Clause1_ArrayType : Type} {Clause2_Output :
  Type} {Clause4_Output : Type} (VariableOutputCoreInst :
  digest.core_api.VariableOutputCore T Clause0_Clause0_Clause0_BlockSize
  Clause0_Clause0_Clause0_Clause0_ArrayType Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType Clause0_Clause2_BufferKind
  Clause0_Clause2_Clause0_BlockSize Clause0_Clause2_Clause0_Clause0_ArrayType
  Clause0_Clause3_Output)
  (generic_arrayArrayLengthOutSizeU8Clause1_ArrayTypeInst :
  generic_array.ArrayLength OutSize Std.U8 Clause1_ArrayType)
  (typenumtype_operatorsIsLessOrEqualInst :
  typenum.type_operators.IsLessOrEqual OutSize Clause0_Clause1_OutputSize
  Clause2_Output) (typenummarker_traitsNonZeroInst :
  typenum.marker_traits.NonZero Clause2_Output)
  (typenumtype_operatorsIsLessClause0_Clause0_Clause0_BlockSizeUIntUIntUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0B0B0Clause4_OutputInst
  : typenum.type_operators.IsLess Clause0_Clause0_Clause0_BlockSize
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) Clause4_Output)
  (typenummarker_traitsNonZeroInst1 : typenum.marker_traits.NonZero
  Clause4_Output) :
  digest.core_api.ct_variable.CtVariableCoreWrapper T OutSize O
    Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause0_Clause1_OutputSize Clause0_Clause1_Clause0_ArrayType
    Clause0_Clause2_BufferKind Clause0_Clause2_Clause0_BlockSize
    Clause0_Clause2_Clause0_Clause0_ArrayType Clause0_Clause3_Output
    Clause1_ArrayType Clause2_Output Clause4_Output → Slice
    (generic_array.GenericArray Std.U8 Clause0_Clause0_Clause0_BlockSize
    Clause0_Clause0_Clause0_Clause0_ArrayType) → Result
    (digest.core_api.ct_variable.CtVariableCoreWrapper T OutSize O
    Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause0_Clause1_OutputSize Clause0_Clause1_Clause0_ArrayType
    Clause0_Clause2_BufferKind Clause0_Clause2_Clause0_BlockSize
    Clause0_Clause2_Clause0_Clause0_ArrayType Clause0_Clause3_Output
    Clause1_ArrayType Clause2_Output Clause4_Output) :=
  fun input blocks => do
  let inner ← VariableOutputCoreInst.UpdateCoreInst.update_blocks input.inner blocks
  ok { input with inner := inner }

def digest.core_api.ct_variable.CtVariableCoreWrapper.Insts.CoreDefaultDefault.default
  {T : Type} {OutSize : Type} (O : Type) {Clause0_Clause0_Clause0_BlockSize :
  Type} {Clause0_Clause0_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause1_OutputSize : Type} {Clause0_Clause1_Clause0_ArrayType :
  Type} {Clause0_Clause2_BufferKind : Type} {Clause0_Clause2_Clause0_BlockSize
  : Type} {Clause0_Clause2_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause3_Output : Type} {Clause1_ArrayType : Type} {Clause2_Output :
  Type} {Clause4_Output : Type} (VariableOutputCoreInst :
  digest.core_api.VariableOutputCore T Clause0_Clause0_Clause0_BlockSize
  Clause0_Clause0_Clause0_Clause0_ArrayType Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType Clause0_Clause2_BufferKind
  Clause0_Clause2_Clause0_BlockSize Clause0_Clause2_Clause0_Clause0_ArrayType
  Clause0_Clause3_Output)
  (generic_arrayArrayLengthOutSizeU8Clause1_ArrayTypeInst :
  generic_array.ArrayLength OutSize Std.U8 Clause1_ArrayType)
  (typenumtype_operatorsIsLessOrEqualInst :
  typenum.type_operators.IsLessOrEqual OutSize Clause0_Clause1_OutputSize
  Clause2_Output) (typenummarker_traitsNonZeroInst :
  typenum.marker_traits.NonZero Clause2_Output)
  (typenumtype_operatorsIsLessClause0_Clause0_Clause0_BlockSizeUIntUIntUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0B0B0Clause4_OutputInst
  : typenum.type_operators.IsLess Clause0_Clause0_Clause0_BlockSize
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) Clause4_Output)
  (typenummarker_traitsNonZeroInst1 : typenum.marker_traits.NonZero
  Clause4_Output) :
  Result (digest.core_api.ct_variable.CtVariableCoreWrapper T OutSize O
    Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause0_Clause1_OutputSize Clause0_Clause1_Clause0_ArrayType
    Clause0_Clause2_BufferKind Clause0_Clause2_Clause0_BlockSize
    Clause0_Clause2_Clause0_Clause0_ArrayType Clause0_Clause3_Output
    Clause1_ArrayType Clause2_Output Clause4_Output) :=
  do
  let size ← generic_arrayArrayLengthOutSizeU8Clause1_ArrayTypeInst.typenummarker_traitsUnsignedInst.USIZE
  let initialized ← VariableOutputCoreInst.new size
  match initialized with
  | .Err _ => fail .panic
  | .Ok inner => ok ⟨inner⟩

def ArrayT32.Insts.CoreConvertFromGenericArrayTUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0GenericArrayImplEvenTGenericArrayImplEvenTGenericArrayImplEvenTGenericArrayImplEvenTGenericArrayImplEvenTGenericArrayImplOddTArrayT0.from
  {T : Type} :
  generic_array.GenericArray T (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    (generic_array.GenericArrayImplEven T (generic_array.GenericArrayImplEven T
    (generic_array.GenericArrayImplEven T (generic_array.GenericArrayImplEven T
    (generic_array.GenericArrayImplEven T (generic_array.GenericArrayImplOdd T
    (Array T 0#usize))))))) → Result (Array T 32#usize) :=
  fun input =>
  ok ⟨NativeModel.readStorage32 input.data, NativeModel.readStorage32_length input.data⟩

def sha2.core_api.Sha256VarCore.Insts.DigestCore_apiVariableOutputCoreUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80UIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80EagerUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80B1.new
  :
  Std.Usize → Result (core.result.Result sha2.core_api.Sha256VarCore
    digest.InvalidOutputSize) :=
  fun outputSize =>
  if outputSize.val = 28 then
    ok (.Ok ⟨NativeModel.sha224InitialState, 0#u64⟩)
  else if outputSize.val = 32 then
    ok (.Ok ⟨NativeModel.sha256InitialState, 0#u64⟩)
  else ok (.Err ())

def sha2.core_api.Sha256VarCore.Insts.DigestCore_apiVariableOutputCoreUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80UIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80EagerUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80B1.TRUNC_SIDE
  : Result digest.core_api.TruncSide :=
  ok .Left

end AuthsNativeRecipe
