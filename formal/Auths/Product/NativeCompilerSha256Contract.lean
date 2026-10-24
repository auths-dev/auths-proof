import Auths.Product.NativeCompilerSha256Api

/-!
Named vetted-library API contract for the actual selected SHA-256 instances.
This is an explicit theorem argument, not a global axiom or implementation.
It supplies no Auths validation, lock-match, canonicalization or namespace fact.
The state relation concerns complete absorbed byte prefixes only. Final source
and SDK evidence must retain the selected foreign API/memory contracts.
-/
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]

/-- SHA-256's 64-bit bit-length framing. The caller must independently earn
its much smaller public source/lock limits and physical resource bounds. -/
def sha256InputLimit : Nat := 2305843009213693951

structure NativeSha256LibraryContract (hash : List Nat → List Nat) where
  stateMeaning : NativeSha256State → List Nat → Prop
  initializes : nativeSha256Start ⦃ state => stateMeaning state [] ⦄
  absorbs : ∀ state prefix input, stateMeaning state prefix →
    prefix.length + input.val.length ≤ sha256InputLimit →
    nativeSha256Update state input ⦃ updated =>
      stateMeaning updated (prefix ++ input.val.map (·.val)) ⦄
  finalizes : ∀ state prefix, stateMeaning state prefix → prefix.length ≤ sha256InputLimit →
    nativeSha256Finish state ⦃ output => nativeSha256OutputBytes output = hash prefix ⦄

def nativeSha256TwoParts (first second : Slice Std.U8) : Result NativeSha256Output := do
  let initial ← nativeSha256Start
  let afterFirst ← nativeSha256Update initial first
  let afterSecond ← nativeSha256UpdateSecond afterFirst second
  nativeSha256Finish afterSecond

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement

variable [nativeArrays : NativeArrayLayouts]
variable [nativeSha256 : NativeSha256Compression]

set_option maxHeartbeats 8000000
set_option maxRecDepth 4096

/-- The two source update positions use the same closed selected library
instances, rather than caller-supplied dispatch or an algorithm tag. -/
theorem native_sha256_update_instance_agrees (state : NativeSha256State) (input : Slice Std.U8) :
    nativeSha256UpdateSecond state input = nativeSha256Update state input := by rfl

/-- Exact library dispatch composition. The source instances and real foreign
models reduce to the same Default/AsRef/Update/FixedOutput sequence. -/
theorem native_sha256_once_is_selected_sequence (input : Slice Std.U8) :
    nativeSha256Once input = (do
      let initial ← nativeSha256Start
      let updated ← nativeSha256Update initial input
      nativeSha256Finish updated) := by rfl

@[step] theorem native_sha256_once_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (input : Slice Std.U8)
    (bound : input.val.length ≤ sha256InputLimit) :
    nativeSha256Once input ⦃ output => nativeSha256OutputBytes output = hash (input.val.map (·.val)) ⦄ := by
  rw [native_sha256_once_is_selected_sequence]
  step with library.initializes as ⟨initial, initialMeaning⟩
  step with library.absorbs initial [] input initialMeaning (by simpa using bound)
    as ⟨updated, updatedMeaning⟩
  apply library.finalizes updated (input.val.map (·.val))
    (by simpa only [List.nil_append] using updatedMeaning)
    (by simpa only [List.length_map] using bound)

@[step] theorem native_sha256_two_parts_exact (hash : List Nat → List Nat)
    (library : NativeSha256LibraryContract hash) (first second : Slice Std.U8)
    (bound : first.val.length + second.val.length ≤ sha256InputLimit) :
    nativeSha256TwoParts first second ⦃ output =>
      nativeSha256OutputBytes output = hash (first.val.map (·.val) ++ second.val.map (·.val)) ⦄ := by
  unfold nativeSha256TwoParts
  step with library.initializes as ⟨initial, initialMeaning⟩
  step with library.absorbs initial [] first initialMeaning (by simp; omega)
    as ⟨afterFirst, firstMeaning⟩
  have firstMeaning : library.stateMeaning afterFirst (first.val.map (·.val)) := by
    simpa only [List.nil_append] using firstMeaning
  rw [native_sha256_update_instance_agrees]
  step with library.absorbs afterFirst (first.val.map (·.val)) second firstMeaning
    (by simpa only [List.length_map] using bound) as ⟨afterSecond, secondMeaning⟩
  exact library.finalizes afterSecond _ secondMeaning
    (by simpa only [List.length_append, List.length_map] using bound)

theorem native_sha256_into_array_definition (output : NativeSha256Output) :
    nativeSha256IntoArray output = ok
      ⟨AuthsNativeRecipe.NativeModel.readStorage32 output.data,
        AuthsNativeRecipe.NativeModel.readStorage32_length output.data⟩ := by rfl

@[step] theorem native_sha256_into_array_exact (output : NativeSha256Output) :
    nativeSha256IntoArray output ⦃ array => array.val.map (·.val) = nativeSha256OutputBytes output ⦄ := by
  simp [native_sha256_into_array_definition, nativeSha256OutputBytes, spec_ok]

theorem native_sha256_output_size (output : NativeSha256Output) :
    (nativeSha256OutputBytes output).length = 32 := by
  simp [nativeSha256OutputBytes, AuthsNativeRecipe.NativeModel.readStorage32_length]

end Auths.Product.NativeCompiler.Refinement
