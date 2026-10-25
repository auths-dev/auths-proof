import Auths.Product.HeaderCompiler
import Auths.Product.PathCompilerLeaves

open Aeneas Aeneas.Std Result ControlFlow
open Aeneas.Std.WP
open auths_gateway_kernel
open Auths.Product.RequestConstruction
open Auths.Product.Refinement.Gateway
open Auths.Product.SchemaIndex.Refinement

namespace Auths.Product.HeaderCompiler.Refinement
set_option maxHeartbeats 4000000
set_option maxRecDepth 4096

def namedHeaderOf (source : header_compiler.NamedHeader) : Bytes × Bytes :=
  (sliceBytes source.name, sliceBytes source.value)
def versionsView (source : Slice header_compiler.NamedHeader) : Versions := source.val.map namedHeaderOf
def scopeSourceOf (source : header_compiler.NamedScope) : ScopeSource :=
  ⟨sliceBytes source.name, sliceBytes source.field⟩

@[step] theorem header_index_exact (name : Slice Std.U8) :
    header_compiler.header_index name ⦃ actual =>
      actual.map UScalar.val = headerIndex (sliceBytes name) ⦄ := by
  unfold header_compiler.header_index header_compiler.STRIPE_VERSION_BYTES
    header_compiler.GITHUB_VERSION_BYTES header_compiler.STRIPE_ACCOUNT_BYTES
  step with field_name_equal_spec as ⟨stripe, stripeMeaning⟩
  cases stripe
  · step with field_name_equal_spec as ⟨github, githubMeaning⟩
    cases github
    · step with field_name_equal_spec as ⟨account, accountMeaning⟩
      cases account <;> simp_all [headerIndex, stripeVersionName, githubVersionName,
        stripeAccountName, sliceBytes, byteList, byteList_inj]
    · simp_all [headerIndex, stripeVersionName, githubVersionName, sliceBytes, byteList, byteList_inj]
  · simp_all [headerIndex, stripeVersionName, sliceBytes, byteList, byteList_inj]

@[step] theorem version_byte_exact (byte : Std.U8) :
    header_compiler.version_byte_valid byte ⦃ actual => actual = decide (VersionByte byte.val) ⦄ := by
  unfold header_compiler.version_byte_valid
  step with is_alphanumeric_spec as ⟨alpha, alphaMeaning⟩
  simp [VersionByte, ← alphaMeaning, UScalar.eq_equiv]

@[step] theorem date_byte_exact (position : Usize) (byte : Std.U8) :
    header_compiler.date_byte_valid position byte ⦃ actual => actual = decide (DateByte position.val byte.val) ⦄ := by
  unfold header_compiler.date_byte_valid DateByte Digit
  simp only [UScalar.eq_equiv, UScalar.lt_equiv, UScalar.le_equiv, UScalar.ofNatCore_val_eq]
  split_ifs <;> simp_all

@[step] theorem stripe_scan_exact (value : Slice Std.U8) :
    header_compiler.stripe_version_valid_loop value 0#usize ⦃ actual =>
      actual = decide (∀ byte ∈ sliceBytes value, VersionByte byte) ⦄ := by
  unfold header_compiler.stripe_version_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => value.val.length - index.val)
    (inv := fun index => index.val ≤ value.val.length ∧
      ∀ byte ∈ value.val.take index.val, VersionByte byte.val)
  · intro index invariant
    unfold header_compiler.stripe_version_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < value.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      step with version_byte_exact as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : ¬VersionByte byte.val := by simpa using meaning.symm
        have member : byte.val ∈ sliceBytes value := List.mem_map.mpr
          ⟨byte, List.mem_iff_getElem?.mpr ⟨index.val, by simpa [byteAt] using List.getElem?_eq_getElem inside⟩, rfl⟩
        have refused : ¬∀ current ∈ sliceBytes value, VersionByte current := fun all => invalid (all _ member)
        simp [refused]
      · have admitted : VersionByte byte.val := by simpa using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        rw [nextValue, List.take_succ_eq_append_getElem inside]
        intro current member
        rcases List.mem_append.mp member with earlier | current
        · exact invariant.2 _ earlier
        · simpa [List.mem_singleton, current, byteAt] using admitted
    · simp only [spec_ok]
      have atEnd : value.val.length ≤ index.val := by simpa using within
      have every : ∀ byte ∈ sliceBytes value, VersionByte byte := by
        intro byte member
        obtain ⟨native, member, same⟩ := List.mem_map.mp member
        simpa [same] using invariant.2 native (by simpa [List.take_of_length_le atEnd] using member)
      simp [every]
  · exact ⟨by simp, by simp⟩

private def DatesThrough (value : Slice Std.U8) (count : Nat) : Prop :=
  ∀ index < count, DateByte index ((sliceBytes value)[index]?.getD 0)

@[step] theorem date_scan_exact (value : Slice Std.U8) :
    header_compiler.iso_date_valid_loop value 0#usize ⦃ actual =>
      actual = decide (∀ index ∈ List.range value.val.length,
        DateByte index ((sliceBytes value)[index]?.getD 0)) ⦄ := by
  unfold header_compiler.iso_date_valid_loop
  apply loop.spec_decr_nat
    (measure := fun index => value.val.length - index.val)
    (inv := fun index => index.val ≤ value.val.length ∧ DatesThrough value index.val)
  · intro index invariant
    unfold header_compiler.iso_date_valid_loop.body
    dsimp only
    split <;> rename_i within
    · have inside : index.val < value.val.length := by simpa using within
      step as ⟨byte, byteAt⟩
      have atByte : ((sliceBytes value)[index.val]?.getD 0) = byte.val := by
        simp [sliceBytes, byteList, List.getElem?_eq_getElem inside, byteAt]
      step with date_byte_exact as ⟨allowed, meaning⟩
      cases allowed
      · have invalid : ¬DateByte index.val byte.val := by simpa using meaning.symm
        have refused : ¬∀ current ∈ List.range value.val.length,
            DateByte current ((sliceBytes value)[current]?.getD 0) := by
          intro every
          exact invalid (by simpa [atByte] using every index.val (List.mem_range.mpr inside))
        simp [refused]
      · have admitted : DateByte index.val byte.val := by simpa using meaning.symm
        simp only [Bool.not_true, Bool.false_eq_true, ↓reduceIte]
        step as ⟨next, nextValue⟩
        refine ⟨by omega, ?_, by omega⟩
        intro current before
        by_cases earlier : current < index.val
        · exact invariant.2 current earlier
        · have same : current = index.val := by omega
          simpa [same, atByte] using admitted
    · simp only [spec_ok]
      have atEnd : value.val.length ≤ index.val := by simpa using within
      have every : ∀ current ∈ List.range value.val.length,
          DateByte current ((sliceBytes value)[current]?.getD 0) := by
        intro current member
        exact invariant.2 current (by have inside := List.mem_range.mp member; omega)
      simp [every]
  · exact ⟨by simp, by simp [DatesThrough]⟩

@[step] theorem stripe_version_exact (value : Slice Std.U8) :
    header_compiler.stripe_version_valid value ⦃ actual =>
      actual = decide (StripeVersionValid (sliceBytes value)) ⦄ := by
  unfold header_compiler.stripe_version_valid
  by_cases short : value.val.length < 10
  · have native : value.len < 10#usize := by scalar_tac
    have invalid : ¬StripeVersionValid (sliceBytes value) := by
      intro valid
      have size := valid.1
      simp only [sliceBytes, byteList, List.length_map] at size
      omega
    simp [native, invalid]
  · have notShort : ¬value.len < 10#usize := by scalar_tac
    by_cases long : 64 < value.val.length
    · have native : value.len > 64#usize := by scalar_tac
      have invalid : ¬StripeVersionValid (sliceBytes value) := by
        intro valid
        have size := valid.2.1
        simp only [sliceBytes, byteList, List.length_map] at size
        omega
      simp [notShort, native, invalid]
    · have notLong : ¬value.len > 64#usize := by scalar_tac
      have count : 10 ≤ value.val.length ∧ value.val.length ≤ 64 := by omega
      simp only [notShort, notLong, Bool.false_or, ↓reduceIte]
      step as ⟨first, firstAt⟩
      have firstMeaning : (sliceBytes value).headD 0 = first.val := by
        cases bytes : value.val with
        | nil => simp [bytes] at count
        | cons head rest => simpa [sliceBytes, byteList, bytes] using congrArg UScalar.val firstAt.symm
      by_cases digit : Digit first.val
      · have notLow : ¬first < 48#u8 := by unfold Digit at digit; scalar_tac
        have notHigh : ¬first > 57#u8 := by unfold Digit at digit; scalar_tac
        simp only [notLow, notHigh, Bool.false_or, ↓reduceIte]
        step with stripe_scan_exact as ⟨actual, meaning⟩
        simpa [StripeVersionValid, sliceBytes, byteList, count.1, count.2, firstMeaning, digit] using meaning
      · have invalid : ¬StripeVersionValid (sliceBytes value) := by
          intro valid
          exact digit (by simpa [firstMeaning] using valid.2.2.1)
        have outside : first < 48#u8 ∨ first > 57#u8 := by unfold Digit at digit; scalar_tac
        rcases outside with low | high
        · simp [low, invalid]
        · simp [high, invalid]

@[step] theorem iso_date_exact (value : Slice Std.U8) :
    header_compiler.iso_date_valid value ⦃ actual =>
      actual = decide (IsoDateValid (sliceBytes value)) ⦄ := by
  unfold header_compiler.iso_date_valid
  by_cases sized : value.val.length = 10
  · have native : value.len = 10#usize := by scalar_tac
    simp only [native, ne_eq, not_true_eq_false, ↓reduceIte]
    step with date_scan_exact as ⟨actual, meaning⟩
    simpa [IsoDateValid, sliceBytes, byteList, sized] using meaning
  · have native : value.len ≠ 10#usize := by scalar_tac
    simp [native, IsoDateValid, sliceBytes, byteList, sized]

end Auths.Product.HeaderCompiler.Refinement

