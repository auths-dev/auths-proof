(* Source substitution regressions for the scoped-substitution overlay.
   These require the exact overlaid Charon library; run at final validation. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let empty = TypesUtils.empty_generic_args
let bound depth id = RVar (Bound (depth, RegionId.of_int id))
let free id = RVar (Free (RegionId.of_int id))
let parameter : region_param = { index = RegionId.of_int 0; name = Some "'local";
  variance = Covariant; mutability = LtShared }
let function_type regions = TFnDef { binder_regions = [parameter]; binder_value = {
  kind = FunId (FRegular (FunDeclId.of_int 12)); generics = { empty with regions } } }
let predicate ty : trait_decl_ref = { id = TraitDeclId.of_int 5;
  generics = { empty with types = [ty] } }

let () =
  let original = function_type [bound 0 0; bound 1 4; free 7] in
  let moved = Substitute.ty_substitute Substitute.move_under_binder_subst original in
  require "moving a function type must preserve its own binder and shift only captures"
    (moved = function_type [bound 0 0; bound 2 4; free 7]);
  require "identity substitution must preserve complete nested binders"
    (Substitute.ty_substitute Substitute.empty_subst original = original);
  let wrapped = Substitute.trait_decl_ref_to_poly_trait_decl_ref (predicate original) in
  require "an empty outer predicate binder still must preserve a function's local lifetime"
    (wrapped = { binder_regions = []; binder_value = predicate moved });
  let substitution = { Substitute.empty_subst with ty_subst = (function
    | Free id when TypeVarId.to_int id = 0 -> original
    | variable -> TVar variable) } in
  let outer = { binder_regions = [parameter];
    binder_value = predicate (TVar (Free (TypeVarId.of_int 0))) } in
  let substituted = Substitute.st_substitute_visitor#visit_region_binder
    Substitute.st_substitute_visitor#visit_trait_decl_ref substitution outer in
  require "inserting a type beneath another binder must not shift its locally bound variables"
    (substituted = { outer with binder_value = predicate moved });
  let local_type = TVar (Bound (0, TypeVarId.of_int 0)) in
  let dyn_parameters = { TypesUtils.empty_generic_params with types = [
    { index = TypeVarId.of_int 0; name = "_dyn"; variance = VaUnknown }] } in
  let dyn = TDynTrait { binder = { binder_params = dyn_parameters; binder_value = local_type } } in
  require "an existential dyn Self must remain locally bound during movement"
    (Substitute.ty_substitute Substitute.move_under_binder_subst dyn = dyn);
  let dyn_substitution = { substitution with ty_subst = (function
    | Free id when TypeVarId.to_int id = 0 -> dyn
    | variable -> TVar variable) } in
  let dyn_result = Substitute.st_substitute_visitor#visit_region_binder
    Substitute.st_substitute_visitor#visit_trait_decl_ref dyn_substitution outer in
  require "inserting a dyn trait type must not move its existential Self out of scope"
    (dyn_result.binder_value = predicate dyn);
  let negative = Substitute.shift_subst Substitute.empty_subst in
  require "the negative-index placeholder must be restored for local regions"
    (negative.r_subst (Bound (0, RegionId.of_int 0)) = bound 0 0);
  require "the negative-index placeholder must be restored for local types"
    (negative.ty_subst (Bound (0, TypeVarId.of_int 0)) = local_type);
  require "the negative-index placeholder must be restored for local consts"
    (negative.cg_subst (Bound (0, ConstGenericVarId.of_int 0)) = CVar (Bound (0, ConstGenericVarId.of_int 0)));
  require "the negative-index placeholder must be restored for local dictionaries"
    (negative.tr_subst (Bound (0, TraitClauseId.of_int 0)) = Clause (Bound (0, TraitClauseId.of_int 0)))
