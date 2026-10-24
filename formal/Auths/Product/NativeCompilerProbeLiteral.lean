import Auths.Product.NativeCompilerBodyAdmissionState
import Auths.Product.NativeCompilerRuleSource

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

/-- The literal validator borrows only a top-level String. Unsupported arrays
and objects refuse without traversing their contents. This is representation,
not admission or an expected literal-kind/result flag. -/
def ProbeLiteralFits : Json → Prop
  | .String text => TextFits text
  | _ => True

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 16000000
set_option maxRecDepth 4096

/-- Complete actual JSON literal dispatch, including signed absolute value,
unsigned fallback and the selected checked safe-integer constant. Integral
looking floating-point representations remain unsupported, as in Rust. -/
@[step] theorem native_probe_literal_exact (source : Json) (fits : ProbeLiteralFits source) :
    AuthsNativeRecipe.recipe.validate.probe_literal_valid source ⦃ actual =>
      actual = decide (RecipeCredentialAdmission.ProbeLiteralAdmitted (ruleProbeLiteral source)) ⦄ := by
  unfold AuthsNativeRecipe.recipe.validate.probe_literal_valid
  cases source with
  | Null => rfl
  | Bool value => rfl
  | String text =>
      step with native_text_size_exact text fits as ⟨size, sizeMeaning⟩
      simp [RecipeCredentialAdmission.ProbeLiteralAdmitted, ruleProbeLiteral,
        AuthsNativeRecipe.recipe.validate.MAX_PROBE_TEXT_BYTES, UScalar.le_equiv, sizeMeaning]
  | Array values => rfl
  | Object members => rfl
  | Number number =>
      cases number with
      | Float bits =>
          simp [AuthsNativeRecipe.serde_json.number.Number.as_i64, AuthsNativeRecipe.serde_json.number.Number.as_u64,
            AuthsNativeRecipe.core.option.Option.map, AuthsNativeRecipe.core.option.Option.or_else,
            AuthsNativeRecipe.core.option.Option.is_some_and,
            AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure.Insts.CoreOpsFunctionFnOnceTupleOptionU64,
            AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure.Insts.CoreOpsFunctionFnOnceTupleOptionU64.call_once,
            RecipeCredentialAdmission.ProbeLiteralAdmitted, ruleProbeLiteral]
      | NegInt value =>
          simp only [AuthsNativeRecipe.serde_json.number.Number.as_i64,
            AuthsNativeRecipe.core.option.Option.map, BuiltinFnOnce, bind_tc_ok]
          step with native_body_unsigned_abs_exact value as ⟨magnitude, magnitudeMeaning⟩
          simp only [AuthsNativeRecipe.core.option.Option.or_else, AuthsNativeRecipe.core.option.Option.is_some_and,
            AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool,
            AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool.call_once,
            bind_tc_ok]
          step with native_safe_integer_constant_exact as ⟨maximum, maximumMeaning⟩
          simp [RecipeCredentialAdmission.ProbeLiteralAdmitted, ruleProbeLiteral,
            UScalar.le_equiv, magnitudeMeaning, maximumMeaning]
      | PosInt value =>
          unfold AuthsNativeRecipe.serde_json.number.Number.as_i64
          by_cases signed : value.val ≤ 9223372036854775807
          · simp only [if_pos signed, AuthsNativeRecipe.core.option.Option.map, BuiltinFnOnce, bind_tc_ok]
            step with native_body_unsigned_abs_exact as ⟨magnitude, magnitudeMeaning⟩
            simp only [AuthsNativeRecipe.core.option.Option.or_else, AuthsNativeRecipe.core.option.Option.is_some_and,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool.call_once,
              bind_tc_ok]
            step with native_safe_integer_constant_exact as ⟨maximum, maximumMeaning⟩
            simp [RecipeCredentialAdmission.ProbeLiteralAdmitted, ruleProbeLiteral,
              UScalar.le_equiv, magnitudeMeaning, maximumMeaning]
          · simp only [if_neg signed, AuthsNativeRecipe.core.option.Option.map,
              AuthsNativeRecipe.core.option.Option.or_else,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure.Insts.CoreOpsFunctionFnOnceTupleOptionU64,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure.Insts.CoreOpsFunctionFnOnceTupleOptionU64.call_once,
              AuthsNativeRecipe.serde_json.number.Number.as_u64,
              AuthsNativeRecipe.core.option.Option.is_some_and,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool,
              AuthsNativeRecipe.recipe.validate.probe_literal_valid.closure_1.Insts.CoreOpsFunctionFnOnceTupleU64Bool.call_once,
              bind_tc_ok]
            step with native_safe_integer_constant_exact as ⟨maximum, maximumMeaning⟩
            have unsafe : ¬value.val ≤ 9007199254740991 := by omega
            simp [RecipeCredentialAdmission.ProbeLiteralAdmitted, ruleProbeLiteral,
              UScalar.le_equiv, maximumMeaning, unsafe]

end Auths.Product.NativeCompiler.Refinement
