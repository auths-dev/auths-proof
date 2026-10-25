import Auths.Support.NativeRecipeTypes

/-!
Positive data carriers copied from the pinned foreign library layouts:
generic-array 0.14.7, block-buffer 0.10.4, digest 0.10.7, typenum 1.20.1 and
sha2 0.10.9. Phantom type parameters keep their exact extracted arity but add
no runtime data. These structures retain array storage, buffer position, core
state and block count; they assert no hashing equation or Auths validity.
The function contracts and final representation review remain separate.
-/
open Aeneas Aeneas.Std

namespace AuthsNativeRecipe.generic_array

structure GenericArrayImplEven (T U : Type) where
  parent1 : U
  parent2 : U

structure GenericArrayImplOdd (T U : Type) where
  parent1 : U
  parent2 : U
  data : T

structure GenericArray (T U Clause0_ArrayType : Type) where
  data : Clause0_ArrayType

end AuthsNativeRecipe.generic_array

namespace AuthsNativeRecipe.typenum.uint

structure UInt (U B : Type) where
  msb : U
  lsb : B

end AuthsNativeRecipe.typenum.uint

namespace AuthsNativeRecipe.block_buffer

structure BlockBuffer (BlockSize Kind Clause0_ArrayType Clause1_Output : Type) where
  buffer : generic_array.GenericArray Std.U8 BlockSize Clause0_ArrayType
  pos : Std.U8

end AuthsNativeRecipe.block_buffer

namespace AuthsNativeRecipe.digest.core_api.ct_variable

structure CtVariableCoreWrapper (T OutSize O : Type)
    (Clause0_Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_Clause0_ArrayType : Type)
    (Clause0_Clause1_OutputSize Clause0_Clause1_Clause0_ArrayType : Type)
    (Clause0_Clause2_BufferKind Clause0_Clause2_Clause0_BlockSize Clause0_Clause2_Clause0_Clause0_ArrayType : Type)
    (Clause0_Clause3_Output Clause1_ArrayType Clause2_Output Clause4_Output : Type) where
  inner : T

end AuthsNativeRecipe.digest.core_api.ct_variable

namespace AuthsNativeRecipe.digest.core_api.wrapper

structure CoreWrapper (T Clause0_BufferKind Clause0_Clause0_BlockSize Clause0_Clause0_Clause0_ArrayType Clause1_Output : Type) where
  core : T
  buffer : block_buffer.BlockBuffer Clause0_Clause0_BlockSize Clause0_BufferKind Clause0_Clause0_Clause0_ArrayType Clause1_Output

end AuthsNativeRecipe.digest.core_api.wrapper

namespace AuthsNativeRecipe.sha2.core_api

structure Sha256VarCore where
  state : Array Std.U32 8#usize
  block_len : Std.U64

end AuthsNativeRecipe.sha2.core_api
