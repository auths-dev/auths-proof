import Auths.Support.NativeRecipeDigestStructuralFunctions

/-!
Explicit foreign leaves for the pinned crypto ABI. Array layouts describe only
memory representation; SHA compression describes only the vetted block primitive.
No instance, Auths admission predicate, lock-match result, canonicalization or
compiler decision is supplied. The per-layout laws below must be discharged or
retained as named foreign-memory contracts for each actual selected instance.
-/
open Aeneas Aeneas.Std Result

namespace AuthsNativeRecipe.NativeModel

abbrev Storage64 (T : Type) := generic_array.GenericArrayImplEven T (Storage32 T)

def readStorage64 {T : Type} (input : Storage64 T) : List T :=
  readStorageEven readStorage32 input

theorem readStorage64_length {T : Type} (input : Storage64 T) :
    (readStorage64 input).length = 64 := by
  exact readStorageEven_length readStorage32 32 readStorage32_length input

def splitFixed {T : Type} {whole half : Std.Usize}
    (size : whole.val = half.val + half.val) (input : Array T whole) :
    Array T half × Array T half :=
  (⟨input.val.take half.val, by
      simp only [List.length_take, input.property]
      omega⟩,
   ⟨input.val.drop half.val, by
      simp only [List.length_drop, input.property]
      omega⟩)

def writeStorage1 {T : Type} (input : Array T 1#usize) : Storage1 T :=
  ⟨⟨[], by rfl⟩, ⟨[], by rfl⟩, input.val[0]'(by have := input.property; scalar_tac)⟩

def writeStorage2 {T : Type} (input : Array T 2#usize) : Storage2 T :=
  let halves := splitFixed (half := 1#usize) (by decide) input
  ⟨writeStorage1 halves.1, writeStorage1 halves.2⟩

def writeStorage4 {T : Type} (input : Array T 4#usize) : Storage4 T :=
  let halves := splitFixed (half := 2#usize) (by decide) input
  ⟨writeStorage2 halves.1, writeStorage2 halves.2⟩

def writeStorage8 {T : Type} (input : Array T 8#usize) : Storage8 T :=
  let halves := splitFixed (half := 4#usize) (by decide) input
  ⟨writeStorage4 halves.1, writeStorage4 halves.2⟩

def writeStorage16 {T : Type} (input : Array T 16#usize) : Storage16 T :=
  let halves := splitFixed (half := 8#usize) (by decide) input
  ⟨writeStorage8 halves.1, writeStorage8 halves.2⟩

def writeStorage32 {T : Type} (input : Array T 32#usize) : Storage32 T :=
  let halves := splitFixed (half := 16#usize) (by decide) input
  ⟨writeStorage16 halves.1, writeStorage16 halves.2⟩

def writeStorage64 {T : Type} (input : Array T 64#usize) : Storage64 T :=
  let halves := splitFixed (half := 32#usize) (by decide) input
  ⟨writeStorage32 halves.1, writeStorage32 halves.2⟩

def sliceOfList {T : Type} (values : List T) : Result (Slice T) :=
  if bound : values.length ≤ Std.Usize.max then ok ⟨values, bound⟩
  else fail .panic

def usizeOfNat (value : Nat) : Result Std.Usize :=
  if bound : value ≤ Std.Usize.max then
    ok (UScalar.ofNatCore value (by scalar_tac))
  else fail .panic

def byteOfNat (value : Nat) : Std.U8 := { bv := BitVec.ofNat 8 value }

def u64OfNat (value : Nat) : Std.U64 := { bv := BitVec.ofNat 64 value }

def bigEndianBytes (count value : Nat) : List Std.U8 :=
  (List.range count).map fun index => byteOfNat (value / 2 ^ (8 * (count - 1 - index)))

def overwrite (original : List Std.U8) (offset : Nat) (replacement : List Std.U8) :
    Result (List Std.U8) :=
  if offset ≤ original.length ∧ replacement.length ≤ original.length - offset then
    ok (original.take offset ++ replacement ++ original.drop (offset + replacement.length))
  else fail .panic

end AuthsNativeRecipe.NativeModel

namespace Auths.Product.NativeCompiler

/-- Generic-array's unsafe slice/storage view, kept separate from all Auths and
hash semantics. `pack` reconstructs the same complete storage, not a digest. -/
class NativeArrayLayouts where
  unpack : {N A : Type} → AuthsNativeRecipe.generic_array.ArrayLength N Std.U8 A →
    AuthsNativeRecipe.generic_array.GenericArray Std.U8 N A → Slice Std.U8
  pack : {N A : Type} → AuthsNativeRecipe.generic_array.ArrayLength N Std.U8 A →
    List Std.U8 → Result (AuthsNativeRecipe.generic_array.GenericArray Std.U8 N A)

/-- Exact laws for one selected pinned ArrayLength instance. No law quantifies
over fabricated Rust trait dictionaries or grants source/lock admission. -/
structure NativeArrayLayoutContract (primitive : NativeArrayLayouts)
    {N A : Type} (layout : AuthsNativeRecipe.generic_array.ArrayLength N Std.U8 A)
    (size : Std.Usize) : Prop where
  usizeConstant : layout.typenummarker_traitsUnsignedInst.USIZE = ok size
  usizeMethod : layout.typenummarker_traitsUnsignedInst.to_usize = ok size
  unpackLength : ∀ array, (primitive.unpack layout array).val.length = size.val
  packUnpack : ∀ array, primitive.pack layout (primitive.unpack layout array).val = ok array
  packComplete : ∀ bytes, bytes.length = size.val →
    ∃ array, primitive.pack layout bytes = ok array ∧ (primitive.unpack layout array).val = bytes
  rejectWrongLength : ∀ bytes, bytes.length ≠ size.val → primitive.pack layout bytes = fail .panic

/-- Vetted SHA-256 block compression only. Initialization, counter arithmetic,
padding, output encoding and all Auths message construction remain explicit. -/
class NativeSha256Compression where
  compress : Array Std.U32 8#usize → Slice (Array Std.U8 64#usize) →
    Result (Array Std.U32 8#usize)

/-- The independently named block function is a crypto premise, not a source
validation premise. Collision resistance is a separate security assumption. -/
structure NativeSha256CompressionContract (primitive : NativeSha256Compression)
    (compressionMeaning : Array Std.U32 8#usize → List (Array Std.U8 64#usize) →
      Array Std.U32 8#usize) : Prop where
  compressExact : ∀ state blocks, primitive.compress state blocks = ok (compressionMeaning state blocks.val)

end Auths.Product.NativeCompiler

namespace AuthsNativeRecipe.NativeModel

open Auths.Product.NativeCompiler

def packChecked [primitive : NativeArrayLayouts] {N A : Type}
    (layout : generic_array.ArrayLength N Std.U8 A) (bytes : List Std.U8) :
    Result (generic_array.GenericArray Std.U8 N A) := do
  let size ← layout.typenummarker_traitsUnsignedInst.USIZE
  if bytes.length = size.val then primitive.pack layout bytes else fail .panic

def zeroArray [primitive : NativeArrayLayouts] {N A : Type}
    (layout : generic_array.ArrayLength N Std.U8 A) :
    Result (generic_array.GenericArray Std.U8 N A) := do
  let size ← layout.typenummarker_traitsUnsignedInst.USIZE
  packChecked layout (List.replicate size.val 0#u8)

def packBlocks [primitive : NativeArrayLayouts] {N A : Type}
    (layout : generic_array.ArrayLength N Std.U8 A) (size : Nat) :
    Nat → List Std.U8 → Result (List (generic_array.GenericArray Std.U8 N A))
  | 0, _ => ok []
  | count + 1, bytes => do
    let block ← packChecked layout (bytes.take size)
    let rest ← packBlocks layout size count (bytes.drop size)
    ok (block :: rest)

def reshapeBuffer [primitive : NativeArrayLayouts] {N A M B Kind O P : Type}
    (source : generic_array.ArrayLength N Std.U8 A)
    (target : generic_array.ArrayLength M Std.U8 B)
    (buffer : block_buffer.BlockBuffer N Kind A O) :
    Result (block_buffer.BlockBuffer M Kind B P) := do
  let block ← packChecked target (primitive.unpack source buffer.buffer).val
  ok ⟨block, buffer.pos⟩

/-- Reblock in complete byte order when Charon gives distinct type parameters
to equal Rust associated types. The actual-instance layout laws must establish
that both witnesses have the same size and memory order. -/
def reshapeBlocks [primitive : NativeArrayLayouts] {N A M B : Type}
    (source : generic_array.ArrayLength N Std.U8 A)
    (target : generic_array.ArrayLength M Std.U8 B)
    (blocks : Slice (generic_array.GenericArray Std.U8 N A)) :
    Result (Slice (generic_array.GenericArray Std.U8 M B)) := do
  let converted ← blocks.val.mapM fun block => packChecked target (primitive.unpack source block).val
  sliceOfList converted

/-- The block-buffer source's two compression points and final retained buffer.
The unused tail of the buffer is preserved too; it is not replaced by zeros. -/
def updateBuffered [primitive : NativeArrayLayouts]
    {T Kind N A M B O : Type}
    (layout : generic_array.ArrayLength N Std.U8 A)
    (updateLayout : generic_array.ArrayLength M Std.U8 B)
    (kind : block_buffer.BufferKind Kind)
    (update : T → Slice (generic_array.GenericArray Std.U8 M B) → Result T)
    (core : T) (buffer : block_buffer.BlockBuffer N Kind A O) (input : Slice Std.U8) :
    Result (T × block_buffer.BlockBuffer N Kind A O) := do
  let size ← layout.typenummarker_traitsUnsignedInst.USIZE
  let position ← usizeOfNat buffer.pos.val
  let valid ← kind.sealedSealedInst.invariant position size
  if !valid then fail .undef
  else if position.val > size.val then fail .panic
  else do
    let remaining ← usizeOfNat (size.val - position.val)
    let inputSize ← usizeOfNat input.val.length
    let fits ← kind.sealedSealedInst.invariant inputSize remaining
    let stored := (primitive.unpack layout buffer.buffer).val
    if fits then
      let updated ← overwrite stored position.val input.val
      let newPosition ← usizeOfNat (position.val + inputSize.val)
      let valid ← kind.sealedSealedInst.invariant newPosition size
      if !valid then fail .panic
      else do
        let block ← packChecked layout updated
        ok (core, ⟨block, byteOfNat newPosition.val⟩)
    else do
      let (core, retained, pending) ←
        if position.val = 0 then ok (core, stored, input.val)
        else if remaining.val > input.val.length then fail .panic
        else do
          let full ← overwrite stored position.val (input.val.take remaining.val)
          let block ← packChecked updateLayout full
          let one ← sliceOfList [block]
          let core ← update core one
          ok (core, full, input.val.drop remaining.val)
      let pendingSlice ← sliceOfList pending
      let (blocks, leftover) ← kind.sealedSealedInst.split_blocks layout pendingSlice
      let core ←
        if blocks.val.isEmpty then ok core
        else do
          let converted ← reshapeBlocks layout updateLayout blocks
          update core converted
      let finalBytes ← overwrite retained 0 leftover.val
      let finalSize ← usizeOfNat leftover.val.length
      let valid ← kind.sealedSealedInst.invariant finalSize size
      if !valid then fail .panic
      else do
        let finalBuffer ← packChecked layout finalBytes
        ok (core, ⟨finalBuffer, byteOfNat finalSize.val⟩)

end AuthsNativeRecipe.NativeModel

namespace AuthsNativeRecipe.NativeModel

open Auths.Product.NativeCompiler

/-- The checked adapter adds no data transformation to a lawful memory pack. -/
theorem packCheckedMeaning [primitive : NativeArrayLayouts] {N A : Type}
    (layout : generic_array.ArrayLength N Std.U8 A) (size : Std.Usize)
    (law : NativeArrayLayoutContract primitive layout size)
    (bytes : List Std.U8) (length : bytes.length = size.val) :
    ∃ array, packChecked layout bytes = ok array ∧
      (primitive.unpack layout array).val = bytes := by
  obtain ⟨array, packed, meaning⟩ := law.packComplete bytes length
  refine ⟨array, ?_, meaning⟩
  simp [packChecked, law.usizeConstant, length, packed]

theorem zeroArrayMeaning [primitive : NativeArrayLayouts] {N A : Type}
    (layout : generic_array.ArrayLength N Std.U8 A) (size : Std.Usize)
    (law : NativeArrayLayoutContract primitive layout size) :
    ∃ array, zeroArray layout = ok array ∧
      (primitive.unpack layout array).val = List.replicate size.val 0#u8 := by
  obtain ⟨array, packed, meaning⟩ :=
    packCheckedMeaning layout size law (List.replicate size.val 0#u8) (by simp)
  refine ⟨array, ?_, meaning⟩
  simp [zeroArray, law.usizeConstant, packed]

/-- Equal-size associated-type witnesses preserve every original buffer byte
and the cursor. This is a representation claim, with no compiler admission. -/
theorem reshapeBufferMeaning [primitive : NativeArrayLayouts]
    {N A M B Kind O P : Type}
    (source : generic_array.ArrayLength N Std.U8 A)
    (target : generic_array.ArrayLength M Std.U8 B) (size : Std.Usize)
    (sourceLaw : NativeArrayLayoutContract primitive source size)
    (targetLaw : NativeArrayLayoutContract primitive target size)
    (buffer : block_buffer.BlockBuffer N Kind A O) :
    ∃ changed : block_buffer.BlockBuffer M Kind B P,
      reshapeBuffer source target buffer = ok changed ∧
      (primitive.unpack target changed.buffer).val =
        (primitive.unpack source buffer.buffer).val ∧
      changed.pos = buffer.pos := by
  obtain ⟨array, packed, meaning⟩ := packCheckedMeaning target size targetLaw
    (primitive.unpack source buffer.buffer).val (sourceLaw.unpackLength buffer.buffer)
  refine ⟨⟨array, buffer.pos⟩, ?_, meaning, rfl⟩
  simp [reshapeBuffer, packed]

end AuthsNativeRecipe.NativeModel
