import Aeneas

open Aeneas Aeneas.Std Result

namespace Auths.Product.NativeCompiler.Outcome

/-- A successful observation earns the preceding monadic result. It does not
assume successful validation or any property of the returned value. -/
theorem successful_bind {A B : Type} (first : Result A)
    (next : A → Result B) (output : B)
    (completed : (do let value ← first; next value) = ok output) :
    ∃ value, first = ok value ∧ next value = ok output := by
  cases first with
  | ok value => exact ⟨value, rfl, by simpa using completed⟩
  | fail error => simp at completed
  | div => simp at completed

/-- The exact standard Result/Try/FromSame pattern emitted for Rust `?`.
No application helper is abstracted into an assumed successful callback. -/
theorem successful_try {A B E : Type}
    (first : Result (core.result.Result A E))
    (next : A → Result (core.result.Result B E)) (output : B)
    (completed : (do
      let result ← first
      let flow ← core.result.Result.Insts.CoreOpsTry.branch result
      match flow with
      | .Continue value => next value
      | .Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            B (core.convert.FromSame E) residual) = ok (.Ok output)) :
    ∃ value, first = ok (.Ok value) ∧ next value = ok (.Ok output) := by
  obtain ⟨result, firstStep, afterFirst⟩ := successful_bind first _ (.Ok output) completed
  cases result with
  | Err error =>
      simp [core.result.Result.Insts.CoreOpsTry.branch,
        core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
        core.convert.FromSame, core.convert.FromSame.from] at afterFirst
  | Ok value =>
      exact ⟨value, firstStep, by simpa [core.result.Result.Insts.CoreOpsTry.branch] using afterFirst⟩

end Auths.Product.NativeCompiler.Outcome
