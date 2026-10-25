import Auths.Verifier.StatusSearchLoop
open Aeneas Aeneas.Std Result
open Aeneas.Std.WP
open AuthsStatusSelection
namespace Auths.StatusSelection.Search

theorem usize_conversion (value : Nat) (fits : value ≤ Usize.max) :
    ∃ converted : Std.Usize, UScalar.tryMk .Usize value = ok converted := by
  have maximum : Usize.max < 2 ^ UScalarTy.Usize.numBits := by
    simp only [Usize.max, Usize.numBits]
    exact Nat.sub_lt (Nat.two_pow_pos _) (by decide)
  have within : value < 2 ^ UScalarTy.Usize.numBits := Nat.lt_of_le_of_lt fits maximum
  simp only [UScalar.tryMk, UScalar.tryMkOpt, UScalar.check_bounds, within, decide_true, ↓reduceDIte,
    Result.ofOption]
  exact ⟨_, rfl⟩

theorem found_full (values : List String) (target : String) :
    Found values target 0 values.length ↔ target ∈ values := by
  simp only [Found, Nat.zero_add, Nat.zero_le, true_and, List.mem_iff_getElem?]
  constructor
  · rintro ⟨index, _, value⟩; exact ⟨index, value⟩
  · rintro ⟨index, value⟩
    obtain ⟨within, _⟩ := List.getElem?_eq_some_iff.mp value
    exact ⟨index, within, value⟩

theorem scope_contains (values : AuthsStatusSelection.auths_model.StatusScopeAnchors)
    (target : String) (ordered : Ordered values.val) :
    AuthsStatusSelection.auths_model.StatusScopeAnchors.contains values target = ok (values.val.contains target) := by
  unfold AuthsStatusSelection.auths_model.StatusScopeAnchors.contains
  simp only [alloc.vec.Vec.deref]
  unfold AuthsStatusSelection.core.slice.Slice.binary_search
  by_cases empty : values.val = []
  · simp [empty, core.result.Result.is_ok]
  · have positive : 0 < values.val.length := List.length_pos_iff.mpr empty
    obtain ⟨result, equation, meaning, bound⟩ := search_loop values.val target (values.val.length + 1) 0 values.val.length
      ordered positive (by omega) (by omega)
    have notEmpty : values.val.isEmpty = false := by simpa using empty
    simp only [notEmpty, Bool.false_eq_true, ↓reduceIte, equation, bind_tc_ok]
    have fits : index result ≤ Usize.max := Nat.le_trans (by simpa using bound) values.property
    obtain ⟨converted, conversion⟩ := usize_conversion (index result) fits
    have correct : hit result = values.val.contains target := by
      apply Bool.eq_iff_iff.mpr
      exact meaning.trans ((found_full values.val target).trans List.contains_iff_mem.symm)
    cases result <;>
      simp only [index] at conversion <;>
      simp only [conversion, bind_tc_ok, core.result.Result.is_ok, ← correct, hit]

end Auths.StatusSelection.Search
