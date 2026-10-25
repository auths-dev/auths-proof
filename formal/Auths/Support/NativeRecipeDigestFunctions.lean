import Auths.Support.NativeRecipeCryptoPrimitives

/-!
Remaining crypto-library interfaces from the actual constructor ABI. Ordinary
buffering, digest dispatch, padding and output movement are explicit. Only the
foreign generic-array memory view and vetted SHA-256 compression are explicit
primitive parameters; neither supplies an Auths decision or canonical bytes.
All bodies and foreign contracts still need final elaboration and review.
-/
open Aeneas Aeneas.Std Result
open Auths.Product.NativeCompiler

namespace AuthsNativeRecipe.NativeModel

def compressOne [primitive : NativeSha256Compression]
    (state : Array Std.U32 8#usize) (bytes : List Std.U8) :
    Result (Array Std.U32 8#usize) :=
  if size : bytes.length = (64#usize).val then
    primitive.compress state ⟨[⟨bytes, size⟩], by simp; scalar_tac⟩
  else fail .panic

/-- The two-block padding branch leaves the first padded block in the original
buffer; the length-suffix block is a separate temporary in the pinned source. -/
def sha256Padding [primitive : NativeSha256Compression]
    (state : Array Std.U32 8#usize) (stored : List Std.U8) (position : Nat)
    (bitLength : Std.U64) : Result (Array Std.U32 8#usize × List Std.U8) := do
  if stored.length ≠ 64 ∨ position ≥ 64 then fail .undef
  else do
    let first := stored.take position ++ [128#u8] ++ List.replicate (63 - position) 0#u8
    let suffix := bigEndianBytes 8 bitLength.val
    if 63 - position < 8 then
      let state ← compressOne state first
      let second := List.replicate 56 0#u8 ++ suffix
      let state ← compressOne state second
      ok (state, first)
    else do
      let complete := first.take 56 ++ suffix
      let state ← compressOne state complete
      ok (state, complete)

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe

def block_buffer.Eager.Insts.Block_bufferSealedSealed.split_blocks
  [primitive : NativeArrayLayouts]
  {N : Type} {Clause0_ArrayType : Type}
  (generic_arrayArrayLengthNU8Clause0_ArrayTypeInst : generic_array.ArrayLength
  N Std.U8 Clause0_ArrayType) :
  Slice Std.U8 → Result ((Slice (generic_array.GenericArray Std.U8 N
    Clause0_ArrayType)) × (Slice Std.U8)) :=
  fun input => do
  let size ← generic_arrayArrayLengthNU8Clause0_ArrayTypeInst.typenummarker_traitsUnsignedInst.USIZE
  if size.val = 0 then fail .panic
  else do
    let count := input.val.length / size.val
    let full ← NativeModel.packBlocks generic_arrayArrayLengthNU8Clause0_ArrayTypeInst size.val count input.val
    let blocks ← NativeModel.sliceOfList full
    let leftover ← NativeModel.sliceOfList (input.val.drop (count * size.val))
    ok (blocks, leftover)

def digest.core_api.ct_variable.CtVariableCoreWrapper.Insts.DigestCore_apiFixedOutputCore.finalize_fixed_core
  [primitive : NativeArrayLayouts]
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
    Clause1_ArrayType Clause2_Output Clause4_Output →
    block_buffer.BlockBuffer Clause0_Clause0_Clause0_BlockSize
    Clause0_Clause2_BufferKind Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause4_Output → generic_array.GenericArray Std.U8 OutSize
    Clause1_ArrayType → Result
    ((digest.core_api.ct_variable.CtVariableCoreWrapper T OutSize O
    Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause0_Clause1_OutputSize Clause0_Clause1_Clause0_ArrayType
    Clause0_Clause2_BufferKind Clause0_Clause2_Clause0_BlockSize
    Clause0_Clause2_Clause0_Clause0_ArrayType Clause0_Clause3_Output
    Clause1_ArrayType Clause2_Output Clause4_Output) ×
    (block_buffer.BlockBuffer Clause0_Clause0_Clause0_BlockSize
    Clause0_Clause2_BufferKind Clause0_Clause0_Clause0_Clause0_ArrayType
    Clause4_Output) × (generic_array.GenericArray Std.U8 OutSize
    Clause1_ArrayType)) :=
  fun input buffer output => do
  let fullLayout := VariableOutputCoreInst.crypto_commonOutputSizeUserInst.generic_arrayArrayLengthSelf_OutputSizeU8Self_Clause0_ArrayTypeInst
  let full ← NativeModel.zeroArray fullLayout
  let adapted : block_buffer.BlockBuffer Clause0_Clause0_Clause0_BlockSize
      Clause0_Clause2_BufferKind Clause0_Clause0_Clause0_Clause0_ArrayType Clause0_Clause3_Output :=
    ⟨buffer.buffer, buffer.pos⟩
  let (inner, changedBuffer, full) ← VariableOutputCoreInst.finalize_variable_core input.inner adapted full
  let size ← generic_arrayArrayLengthOutSizeU8Clause1_ArrayTypeInst.typenummarker_traitsUnsignedInst.USIZE
  let fullSize ← fullLayout.typenummarker_traitsUnsignedInst.USIZE
  if size.val > fullSize.val then fail .panic
  else do
    let side ← VariableOutputCoreInst.TRUNC_SIDE
    let bytes := (primitive.unpack fullLayout full).val
    let selected := match side with
      | .Left => bytes.take size.val
      | .Right => bytes.drop (fullSize.val - size.val)
    let output ← NativeModel.packChecked generic_arrayArrayLengthOutSizeU8Clause1_ArrayTypeInst selected
    ok ({ input with inner := inner }, ⟨changedBuffer.buffer, changedBuffer.pos⟩, output)

def digest.core_api.wrapper.CoreWrapper.Insts.CoreDefaultDefault.default
  [primitive : NativeArrayLayouts]
  {T : Type} {Clause1_BufferKind : Type} {Clause1_Clause0_BlockSize : Type}
  {Clause1_Clause0_Clause0_ArrayType : Type} {Clause2_Output : Type}
  (coredefaultDefaultInst : core.default.Default T) (BufferKindUserInst :
  digest.core_api.BufferKindUser T Clause1_BufferKind Clause1_Clause0_BlockSize
  Clause1_Clause0_Clause0_ArrayType)
  (typenumtype_operatorsIsLessClause1_Clause0_BlockSizeUIntUIntUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0B0B0Clause2_OutputInst
  : typenum.type_operators.IsLess Clause1_Clause0_BlockSize (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) Clause2_Output)
  (typenummarker_traitsNonZeroInst : typenum.marker_traits.NonZero
  Clause2_Output) (coredefaultDefaultInst1 : core.default.Default
  Clause1_Clause0_BlockSize) (coredefaultDefaultInst2 : core.default.Default
  Clause1_BufferKind) :
  Result (digest.core_api.wrapper.CoreWrapper T Clause1_BufferKind
    Clause1_Clause0_BlockSize Clause1_Clause0_Clause0_ArrayType Clause2_Output) :=
  do
  let core ← coredefaultDefaultInst.default
  let layout := BufferKindUserInst.crypto_commonBlockSizeUserInst.generic_arrayArrayLengthSelf_BlockSizeU8Self_Clause0_ArrayTypeInst
  let size ← layout.typenummarker_traitsUnsignedInst.USIZE
  if size.val = 0 then fail .panic
  else do
    let buffer ← NativeModel.zeroArray layout
    ok ⟨core, ⟨buffer, 0#u8⟩⟩

def digest.core_api.wrapper.CoreWrapper.Insts.DigestUpdate.update
  [primitive : NativeArrayLayouts]
  {T : Type} {Clause0_BufferKind : Type} {Clause0_Clause0_BlockSize : Type}
  {Clause0_Clause0_Clause0_ArrayType : Type} {Clause1_Clause0_BlockSize : Type}
  {Clause1_Clause0_Clause0_ArrayType : Type} {Clause2_Output : Type}
  (BufferKindUserInst : digest.core_api.BufferKindUser T Clause0_BufferKind
  Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_ArrayType) (UpdateCoreInst
  : digest.core_api.UpdateCore T Clause1_Clause0_BlockSize
  Clause1_Clause0_Clause0_ArrayType)
  (typenumtype_operatorsIsLessClause0_Clause0_BlockSizeUIntUIntUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0B0B0Clause2_OutputInst
  : typenum.type_operators.IsLess Clause0_Clause0_BlockSize (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) Clause2_Output)
  (typenummarker_traitsNonZeroInst : typenum.marker_traits.NonZero
  Clause2_Output) :
  digest.core_api.wrapper.CoreWrapper T Clause0_BufferKind
    Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_ArrayType Clause2_Output
    → Slice Std.U8 → Result (digest.core_api.wrapper.CoreWrapper T
    Clause0_BufferKind Clause0_Clause0_BlockSize
    Clause0_Clause0_Clause0_ArrayType Clause2_Output) :=
  fun input bytes => do
  let layout := BufferKindUserInst.crypto_commonBlockSizeUserInst.generic_arrayArrayLengthSelf_BlockSizeU8Self_Clause0_ArrayTypeInst
  let updateLayout := UpdateCoreInst.crypto_commonBlockSizeUserInst.generic_arrayArrayLengthSelf_BlockSizeU8Self_Clause0_ArrayTypeInst
  let (core, buffer) ← NativeModel.updateBuffered layout updateLayout
    BufferKindUserInst.block_bufferBufferKindInst UpdateCoreInst.update_blocks input.core input.buffer bytes
  ok ⟨core, buffer⟩

def digest.core_api.wrapper.CoreWrapper.Insts.DigestFixedOutput.finalize_into
  [primitive : NativeArrayLayouts]
  {T : Type} {Clause0_Clause0_Clause0_BlockSize : Type}
  {Clause0_Clause0_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause1_BufferKind : Type} {Clause0_Clause1_Clause0_BlockSize :
  Type} {Clause0_Clause1_Clause0_Clause0_ArrayType : Type}
  {Clause0_Clause2_OutputSize : Type} {Clause0_Clause2_Clause0_ArrayType :
  Type} {Clause0_Clause3_Output : Type} {Clause1_Output : Type}
  (FixedOutputCoreInst : digest.core_api.FixedOutputCore T
  Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType
  Clause0_Clause1_BufferKind Clause0_Clause1_Clause0_BlockSize
  Clause0_Clause1_Clause0_Clause0_ArrayType Clause0_Clause2_OutputSize
  Clause0_Clause2_Clause0_ArrayType Clause0_Clause3_Output)
  (typenumtype_operatorsIsLessClause0_Clause0_Clause0_BlockSizeUIntUIntUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0B0B0Clause1_OutputInst
  : typenum.type_operators.IsLess Clause0_Clause0_Clause0_BlockSize
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
  (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
  typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) Clause1_Output)
  (typenummarker_traitsNonZeroInst : typenum.marker_traits.NonZero
  Clause1_Output) :
  digest.core_api.wrapper.CoreWrapper T Clause0_Clause1_BufferKind
    Clause0_Clause1_Clause0_BlockSize Clause0_Clause1_Clause0_Clause0_ArrayType
    Clause1_Output → generic_array.GenericArray Std.U8
    Clause0_Clause2_OutputSize Clause0_Clause2_Clause0_ArrayType → Result
    (generic_array.GenericArray Std.U8 Clause0_Clause2_OutputSize
    Clause0_Clause2_Clause0_ArrayType) :=
  fun input output => do
  let sourceLayout := FixedOutputCoreInst.BufferKindUserInst.crypto_commonBlockSizeUserInst.generic_arrayArrayLengthSelf_BlockSizeU8Self_Clause0_ArrayTypeInst
  let targetLayout := FixedOutputCoreInst.UpdateCoreInst.crypto_commonBlockSizeUserInst.generic_arrayArrayLengthSelf_BlockSizeU8Self_Clause0_ArrayTypeInst
  let buffer ← NativeModel.reshapeBuffer (P := Clause0_Clause3_Output) sourceLayout targetLayout input.buffer
  let (_, _, output) ← FixedOutputCoreInst.finalize_fixed_core input.core buffer output
  ok output

def digest.digest.Digest.Blanket.digest
  [primitive : NativeArrayLayouts]
  {D : Type} {T1 : Type} {Clause0_Clause1_OutputSize : Type}
  {Clause0_Clause1_Clause0_ArrayType : Type} (FixedOutputInst :
  digest.FixedOutput D Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType) (coredefaultDefaultInst :
  core.default.Default D) (UpdateInst : digest.Update D) (HashMarkerInst :
  digest.digest.HashMarker D) (coreconvertAsRefT1SliceU8Inst :
  core.convert.AsRef T1 (Slice Std.U8)) :
  T1 → Result (generic_array.GenericArray Std.U8 Clause0_Clause1_OutputSize
    Clause0_Clause1_Clause0_ArrayType) :=
  fun input => do
  let hasher ← coredefaultDefaultInst.default
  let bytes ← coreconvertAsRefT1SliceU8Inst.as_ref input
  let hasher ← UpdateInst.update hasher bytes
  let layout := FixedOutputInst.crypto_commonOutputSizeUserInst.generic_arrayArrayLengthSelf_OutputSizeU8Self_Clause0_ArrayTypeInst
  let output ← NativeModel.zeroArray layout
  FixedOutputInst.finalize_into hasher output

def digest.digest.Digest.Blanket.new
  {D : Type} {Clause0_Clause1_OutputSize : Type}
  {Clause0_Clause1_Clause0_ArrayType : Type} (FixedOutputInst :
  digest.FixedOutput D Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType) (coredefaultDefaultInst :
  core.default.Default D) (UpdateInst : digest.Update D) (HashMarkerInst :
  digest.digest.HashMarker D) :
  Result D :=
  coredefaultDefaultInst.default

def digest.digest.Digest.Blanket.update
  {D : Type} {T1 : Type} {Clause0_Clause1_OutputSize : Type}
  {Clause0_Clause1_Clause0_ArrayType : Type} (FixedOutputInst :
  digest.FixedOutput D Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType) (coredefaultDefaultInst :
  core.default.Default D) (UpdateInst : digest.Update D) (HashMarkerInst :
  digest.digest.HashMarker D) (coreconvertAsRefT1SliceU8Inst :
  core.convert.AsRef T1 (Slice Std.U8)) :
  D → T1 → Result D :=
  fun hasher input => do
  let bytes ← coreconvertAsRefT1SliceU8Inst.as_ref input
  UpdateInst.update hasher bytes

def digest.digest.Digest.Blanket.finalize
  [primitive : NativeArrayLayouts]
  {D : Type} {Clause0_Clause1_OutputSize : Type}
  {Clause0_Clause1_Clause0_ArrayType : Type} (FixedOutputInst :
  digest.FixedOutput D Clause0_Clause1_OutputSize
  Clause0_Clause1_Clause0_ArrayType) (coredefaultDefaultInst :
  core.default.Default D) (UpdateInst : digest.Update D) (HashMarkerInst :
  digest.digest.HashMarker D) :
  D → Result (generic_array.GenericArray Std.U8 Clause0_Clause1_OutputSize
    Clause0_Clause1_Clause0_ArrayType) :=
  fun hasher => do
  let layout := FixedOutputInst.crypto_commonOutputSizeUserInst.generic_arrayArrayLengthSelf_OutputSizeU8Self_Clause0_ArrayTypeInst
  let output ← NativeModel.zeroArray layout
  FixedOutputInst.finalize_into hasher output

def sha2.core_api.Sha256VarCore.Insts.DigestCore_apiUpdateCoreUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80.update_blocks
  [primitive : NativeSha256Compression]
  :
  sha2.core_api.Sha256VarCore → Slice (generic_array.GenericArray Std.U8
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt typenum.uint.UTerm
    typenum.bit.B1) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplOdd Std.U8 (Array Std.U8 0#usize)))))))))
    → Result sha2.core_api.Sha256VarCore :=
  fun input blocks => do
  let count ← UScalar.add input.block_len (NativeModel.u64OfNat blocks.val.length)
  let actual : Slice (Array Std.U8 64#usize) :=
    ⟨blocks.val.map (fun block =>
      ⟨NativeModel.readStorage64 block.data, NativeModel.readStorage64_length block.data⟩),
      by simpa using blocks.property⟩
  let state ← primitive.compress input.state actual
  ok ⟨state, count⟩

def sha2.core_api.Sha256VarCore.Insts.DigestCore_apiVariableOutputCoreUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80UIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80EagerUIntUIntUIntUIntUIntUIntUIntUTermB1B0B0B0B0B0B0GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplEvenU8GenericArrayImplOddU8ArrayU80B1.finalize_variable_core
  [primitive : NativeSha256Compression]
  :
  sha2.core_api.Sha256VarCore → block_buffer.BlockBuffer (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) block_buffer.Eager
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplOdd Std.U8 (Array Std.U8 0#usize))))))))
    typenum.bit.B1 → generic_array.GenericArray Std.U8 (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplOdd Std.U8 (Array Std.U8 0#usize))))))) →
    Result (sha2.core_api.Sha256VarCore × (block_buffer.BlockBuffer
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt typenum.uint.UTerm
    typenum.bit.B1) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) block_buffer.Eager
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplOdd Std.U8 (Array Std.U8 0#usize))))))))
    typenum.bit.B1) × (generic_array.GenericArray Std.U8 (typenum.uint.UInt
    (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt (typenum.uint.UInt
    (typenum.uint.UInt typenum.uint.UTerm typenum.bit.B1) typenum.bit.B0)
    typenum.bit.B0) typenum.bit.B0) typenum.bit.B0) typenum.bit.B0)
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplEven Std.U8
    (generic_array.GenericArrayImplOdd Std.U8 (Array Std.U8 0#usize))))))))) :=
  fun input buffer output => do
  if buffer.pos.val ≥ 64 then fail .undef
  else do
    let blocksLength ← UScalar.mul 64#u64 input.block_len
    let byteLength ← UScalar.add (NativeModel.u64OfNat buffer.pos.val) blocksLength
    let bitLength ← UScalar.mul 8#u64 byteLength
    let stored := NativeModel.readStorage64 buffer.buffer.data
    let (state, retained) ← NativeModel.sha256Padding input.state stored buffer.pos.val bitLength
    let encoded := state.val.flatMap (fun word => NativeModel.bigEndianBytes 4 word.val)
    if bufferSize : retained.length = (64#usize).val then
      if outputSize : encoded.length = (32#usize).val then
        ok ({ input with state := state },
          ⟨⟨NativeModel.writeStorage64 ⟨retained, bufferSize⟩⟩, 0#u8⟩,
          ⟨NativeModel.writeStorage32 ⟨encoded, outputSize⟩⟩)
      else fail .panic
    else fail .panic

end AuthsNativeRecipe
