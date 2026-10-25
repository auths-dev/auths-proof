(* Source-vtable lifetime-view regressions. Authored only: final execution and
   native source/ABI/loan qualification are separate required work. *)
open Charon
open Types
open Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let rid = RegionId.of_int
let bound depth id = RVar (Bound (depth, rid id))
let parameter id : region_param = { index = rid id; name = None;
  variance = Covariant; mutability = LtShared }
let self_id = TypeVarId.of_int 0
let owner : dyn_predicate = { binder = {
  binder_params = { TypesUtils.empty_generic_params with
    types = [{ index = self_id; name = "_dyn"; variance = VaUnknown }];
    trait_clauses = [{ clause_id = TraitClauseId.of_int 0; span = None; origin = OriginDyn;
      trait = { binder_regions = []; binder_value = {
        id = TraitDeclId.of_int 4; generics = { empty with types = [TVar (Bound (1, self_id))] } } } }];
    types_outlive = [{ binder_regions = []; binder_value = TVar (Bound (1, self_id)), RErased }] };
  binder_value = TVar (Bound (0, self_id)) } }
let borrow region = TRef (region, TDynTrait owner, RShared)
let signature inputs : fun_sig = { is_unsafe = false; abi = AbiRust; is_variadic = false;
  inputs; output = TLiteral TBool }
let original = { binder_regions = [parameter 7]; binder_value = signature [borrow (bound 0 7)] }

let () =
  let field = Vtable_shape.parameterize owner original in
  require "a vtable lifetime view must reconstruct the complete original signature"
    (Vtable_shape.forget_object_parameter field = original && Vtable_shape.replay_function owner field);
  require "a sparse existing parameter ID cannot be reused for the object annotation"
    (field.object_parameter.index = rid 8);
  require "parameterizing an object annotation must preserve every existing function binder"
    (field.parameterized.binder_regions = original.binder_regions @ [field.object_parameter]);
  require "the original receiver borrow and new object region must stay distinct"
    (match field.parameterized.binder_value.inputs with
     | [TRef (region, TDynTrait actual, RShared)] ->
         region = bound 0 7 &&
         (match actual.binder.binder_params.types_outlive with
          | [{ binder_regions = []; binder_value = _, target }] -> target = bound 2 8
          | _ -> false)
     | _ -> false);
  let scope = new Region_scope.check [] in
  scope#visit_ty [] (TFnPtr field.parameterized);
  let nested = { original with binder_value = signature [
    TFnPtr { binder_regions = [parameter 0]; binder_value = signature [borrow (bound 0 0)] }] } in
  let nested = Vtable_shape.parameterize owner nested in
  require "an object parameter used under another function binder must retain its capture depth"
    (Vtable_shape.forget_object_parameter nested = nested.original);
  scope#visit_ty [] (TFnPtr nested.parameterized);
  require "changing an ABI flag must invalidate the original source witness"
    (not (Vtable_shape.replay_function owner { field with parameterized = {
      field.parameterized with binder_value = { field.parameterized.binder_value with is_unsafe = true } } }));
  require "the new object parameter cannot silently replace an existing parameter"
    (not (Vtable_shape.replay_function owner { field with object_parameter = parameter 7 }));
  require "a source object marker cannot be replaced by a static guess"
    (refuses (fun () -> ignore (Vtable_shape.parameterize {
      binder = { owner.binder with binder_params = {
        owner.binder.binder_params with types_outlive = [
          { binder_regions = []; binder_value = TVar (Bound (1, self_id)), RStatic }] } } } original)));
  let erased_borrow = Vtable_shape.parameterize owner
    { original with binder_value = signature [borrow RErased] } in
  require "round-trip erasure cannot license an unrelated erased receiver borrow"
    (refuses (fun () -> scope#visit_ty [] (TFnPtr erased_borrow.parameterized)));
  require "a function field without the actual source owner cannot obtain this witness"
    (refuses (fun () -> ignore (Vtable_shape.parameterize owner
      { original with binder_value = signature [TLiteral TBool] })))
