import Auths.Product.NativeCompilerConstruction

open Aeneas Aeneas.Std Result
open Aeneas.Std.WP

namespace Auths.Product.NativeCompiler

abbrev NativeHeader := AuthsNativeRecipe.auths_gateway_kernel.construct.Header
abbrev NativeScopePlan := AuthsNativeRecipe.auths_gateway_kernel.construct.AccountScopePlan
abbrev NativeHeaderPlan := AuthsNativeRecipe.auths_gateway_kernel.construct.HeaderPlan
abbrev NativeCredentialPlan := AuthsNativeRecipe.auths_gateway_kernel.construct.CredentialReadPlan

end Auths.Product.NativeCompiler

namespace Auths.Product.NativeCompiler.Refinement
open Auths.Product.NativeCompiler.StdModel
set_option maxHeartbeats 4000000

@[step] theorem native_header_clone_exact (input : NativeHeader) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact core.clone.CloneU8 input.name (by intro byte _; rfl)
    as ⟨name, nameMeaning⟩
  step with native_vector_clone_exact core.clone.CloneU8 input.value (by intro byte _; rfl)
    as ⟨value, valueMeaning⟩
  cases input
  simp_all

theorem native_header_clone_result (input : NativeHeader) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_header_clone_exact input)
  simpa only [same] using run

@[step] theorem native_scope_plan_clone_exact (input : NativeScopePlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.AccountScopePlan.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.AccountScopePlan.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact core.clone.CloneU8 input.name (by intro byte _; rfl)
    as ⟨name, same⟩
  cases input
  simp_all [AuthsNativeRecipe.auths_gateway_kernel.construct.ScopeGrammar.Insts.CoreCloneClone.clone,
    core.clone.impls.CloneUsize.clone]

theorem native_scope_plan_clone_result (input : NativeScopePlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.AccountScopePlan.Insts.CoreCloneClone.clone input = ok input := by
  obtain ⟨actual, run, same⟩ := spec_imp_exists (native_scope_plan_clone_exact input)
  simpa only [same] using run

@[step] theorem native_header_plan_clone_exact (input : NativeHeaderPlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.HeaderPlan.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.HeaderPlan.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact
    AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone input.versions
    (by intro header _; exact native_header_clone_result header) as ⟨versions, versionsMeaning⟩
  step with native_option_clone_exact
    AuthsNativeRecipe.auths_gateway_kernel.construct.AccountScopePlan.Insts.CoreCloneClone input.account_scope
    (by intro scope _; exact native_scope_plan_clone_result scope) as ⟨scope, scopeMeaning⟩
  cases input
  simp_all

@[step] theorem native_credential_plan_clone_exact (input : NativeCredentialPlan) :
    AuthsNativeRecipe.auths_gateway_kernel.construct.CredentialReadPlan.Insts.CoreCloneClone.clone input
      ⦃ actual => actual = input ⦄ := by
  unfold AuthsNativeRecipe.auths_gateway_kernel.construct.CredentialReadPlan.Insts.CoreCloneClone.clone
    AuthsNativeRecipe.auths_gateway_kernel.construct.RequestMethod.Insts.CoreCloneClone.clone
  step with native_vector_clone_exact core.clone.CloneU8 input.origin (by intro byte _; rfl)
    as ⟨origin, originMeaning⟩
  step with native_vector_clone_exact
    (AuthsNativeRecipe.core.clone.CloneallocvecVec core.clone.CloneU8) input.path
    (by intro segment _; exact native_vector_clone_result core.clone.CloneU8 segment (by intro byte _; rfl))
    as ⟨path, pathMeaning⟩
  step with native_vector_clone_exact
    AuthsNativeRecipe.auths_gateway_kernel.construct.Header.Insts.CoreCloneClone input.versions
    (by intro header _; exact native_header_clone_result header) as ⟨versions, versionsMeaning⟩
  cases input
  simp_all

end Auths.Product.NativeCompiler.Refinement
