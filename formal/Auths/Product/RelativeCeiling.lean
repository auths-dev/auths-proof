/-!
# The relative ceiling

A recipe may bound the verified argument by a declared ratio of one integer
basis the gateway reads from the provider after the lease. The basis is the
value read, or the value minus a second value when a subtrahend is declared;
a negative difference is unavailable, never zero. The check compares
`argument × 10 000` with `basis × basis points` exactly, over natural numbers,
so the ceiling rounds toward zero and the boundary is inclusive.

The model works over `Nat`; the refinement theorems of the translated leaves
map `u64` and `u16` to their values, where the leaf's `u128` products never
overflow.
-/

namespace Auths.Product.RelativeCeiling

/-- The number of basis points in one whole. -/
def basisPointsPerWhole : Nat := 10000

/-- The basis: `value`, or `value - subtrahend` when the subtrahend is at
most the value, and unavailable otherwise. -/
def relativeBasis (value : Nat) : Option Nat → Option Nat
  | none => some value
  | some second => if second ≤ value then some (value - second) else none

/-- Whether `argument` is within `basisPoints` ten-thousandths of `basis`. -/
def admits (argument basis basisPoints : Nat) : Bool :=
  decide (argument * basisPointsPerWhole ≤ basis * basisPoints)

/-- The leaf admits exactly the arguments at most the floor of
`basis × basisPoints / 10 000`. This holds for every basis point, so in
particular for every declared value in 1–10 000. -/
theorem relative_ceiling_exact (argument basis basisPoints : Nat) :
    admits argument basis basisPoints = true ↔
      argument ≤ basis * basisPoints / basisPointsPerWhole := by
  simp [admits, basisPointsPerWhole, Nat.le_div_iff_mul_le]

/-- An admitted argument, scaled by 10 000, is at most the basis times the
basis points: the argument never exceeds the declared ratio of the basis. -/
theorem relative_ceiling_never_exceeds_ratio (argument basis basisPoints : Nat)
    (admitted : admits argument basis basisPoints = true) :
    argument * basisPointsPerWhole ≤ basis * basisPoints := by
  simpa [admits] using admitted

/-- A larger basis, more basis points, or a smaller argument never admits
less; a zero basis or zero basis points admit only a zero argument. -/
theorem relative_ceiling_monotone :
    (∀ argument argument' basis basis' basisPoints basisPoints' : Nat,
        argument' ≤ argument → basis ≤ basis' → basisPoints ≤ basisPoints' →
          admits argument basis basisPoints = true →
            admits argument' basis' basisPoints' = true) ∧
      (∀ argument basisPoints : Nat,
        admits argument 0 basisPoints = true ↔ argument = 0) ∧
      (∀ argument basis : Nat,
        admits argument basis 0 = true ↔ argument = 0) := by
  refine ⟨?_, ?_, ?_⟩
  · intro argument argument' basis basis' basisPoints basisPoints' smaller larger more admitted
    simp only [admits, decide_eq_true_eq] at admitted ⊢
    calc argument' * basisPointsPerWhole
        ≤ argument * basisPointsPerWhole := Nat.mul_le_mul_right _ smaller
      _ ≤ basis * basisPoints := admitted
      _ ≤ basis' * basisPoints' := Nat.mul_le_mul larger more
  · intro argument basisPoints
    simp only [admits, basisPointsPerWhole, Nat.zero_mul, decide_eq_true_eq]
    omega
  · intro argument basis
    simp only [admits, basisPointsPerWhole, Nat.mul_zero, decide_eq_true_eq]
    omega

/-- The basis is never a truncated difference: without a subtrahend it is
the value; with one, it is present exactly when the subtrahend is at most the
value, and then it adds back to the value; it is never larger than the
value. -/
theorem relative_basis_never_negative (value : Nat) :
    relativeBasis value none = some value ∧
      (∀ second basis : Nat,
        relativeBasis value (some second) = some basis ↔
          second ≤ value ∧ basis + second = value) ∧
      (∀ second : Nat, relativeBasis value (some second) = none ↔ value < second) ∧
      (∀ subtrahend basis, relativeBasis value subtrahend = some basis → basis ≤ value) := by
  refine ⟨rfl, ?_, ?_, ?_⟩
  · intro second basis
    by_cases within : second ≤ value
    · simp only [relativeBasis, within, if_true, Option.some.injEq, true_and]
      omega
    · simp only [relativeBasis, within, if_false, reduceCtorEq, false_iff, not_and]
      intro _
      omega
  · intro second
    by_cases within : second ≤ value
    · simp only [relativeBasis, within, if_true, reduceCtorEq, false_iff]
      omega
    · simp only [relativeBasis, within, if_false, true_iff]
      omega
  · intro subtrahend basis present
    cases subtrahend with
    | none => cases present; exact Nat.le_refl _
    | some second =>
        by_cases within : second ≤ value
        · simp only [relativeBasis, within, if_true, Option.some.injEq] at present
          omega
        · simp [relativeBasis, within] at present

end Auths.Product.RelativeCeiling
