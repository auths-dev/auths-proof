(* Exact stored-field signature regressions. Authored/unbuilt/unrun until the
   final validation batch. No native cast or loan qualification follows. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let rid = RegionId.of_int
let bound depth id = RVar (Bound (depth, rid id))
let free id = RVar (Free (rid id))
let body id = RBody (rid id)
let boolean = TLiteral Charon.Values.TBool
let parameter index : region_param = { index = rid index; name = None;
  variance = Invariant; mutability = LtShared }
let self_id = TypeVarId.of_int 0
let owner target : dyn_predicate = { binder = {
  binder_params = { TypesUtils.empty_generic_params with
    types = [{ index = self_id; name = "_dyn"; variance = VaUnknown }];
    trait_clauses = [{ clause_id = TraitClauseId.of_int 0; span = None; origin = OriginDyn;
      trait = { binder_regions = []; binder_value = {
        id = TraitDeclId.of_int 4; generics = { empty with types = [TVar (Bound (1, self_id))] } } } }];
    types_outlive = [{ binder_regions = []; binder_value = TVar (Bound (1, self_id)), target }] };
  binder_value = TVar (Bound (0, self_id)) } }
let source_owner = owner RErased
let borrow target = TRef (bound 0 7, TDynTrait (owner target), RShared)
let signature inputs : fun_sig region_binder = { binder_regions = [parameter 7]; binder_value = {
  is_unsafe = false; abi = AbiRust; is_variadic = false; inputs; output = boolean } }
let original = signature [borrow RErased]
let family = Vtable_shape.parameterize source_owner original
let create ?(parameters = TypesUtils.empty_generic_params) ?(arguments = empty)
    ?(free_parameters = []) ?(body_regions = 8) family actual =
  Vtable_field.create ~parameters ~arguments ~free_parameters ~body_regions ~owner:source_owner family actual

let () =
  let actual = signature [borrow (body 4)] in
  let witness = create family actual in
  require "the object annotation must come from the exact actual stored source signature"
    (witness.object_argument = body 4 && witness.reconstructed = actual && Vtable_field.replay witness);
  require "a source body annotation cannot be inferred outside its actual body binder"
    (refuses (fun () -> ignore (create ~body_regions:4 family actual)));
  require "an erased actual object annotation cannot become a static or fresh default"
    (refuses (fun () -> ignore (create family original)));
  require "the source receiver borrow cannot be changed while only the object annotation varies"
    (refuses (fun () -> ignore (create ~free_parameters:[parameter 3] family
      (signature [TRef (free 3, TDynTrait (owner (body 4)), RShared)]))));
  require "an unsafe flag change cannot hide behind region erasure"
    (refuses (fun () -> ignore (create family { actual with binder_value = {
      actual.binder_value with is_unsafe = true } })));
  require "a calling convention change cannot hide behind region erasure"
    (refuses (fun () -> ignore (create family { actual with binder_value = {
      actual.binder_value with abi = AbiC } })));
  require "removing an original function binder cannot be licensed by the object parameter"
    (refuses (fun () -> ignore (create family { actual with binder_regions = [] })));
  require "a different result type is a complete signature mismatch"
    (refuses (fun () -> ignore (create family { actual with binder_value = {
      actual.binder_value with output = TLiteral (Charon.Values.TUInt Charon.Values.U64) } })));
  let repeated = Vtable_shape.parameterize source_owner (signature [borrow RErased; borrow RErased]) in
  require "one object parameter cannot mean different source regions in two positions"
    (refuses (fun () -> ignore (create repeated (signature [borrow (body 4); borrow (body 5)]))));
  let own = create family (signature [borrow (bound 2 7)]) in
  require "an actual annotation tied to the existing field borrow stays in that exact binder"
    (own.object_argument = bound 0 7 && Vtable_field.replay own);
  require "a hidden annotation cannot capture the local empty outlives binder"
    (refuses (fun () -> ignore (create family (signature [borrow (bound 0 7)])))) ;
  require "an undeclared outer field parameter cannot supply object provenance"
    (refuses (fun () -> ignore (create family (signature [borrow (bound 2 9)]))));
  let generic_original = signature [borrow RErased; TRef (free 99, boolean, RShared)] in
  let generic_family = Vtable_shape.parameterize source_owner generic_original in
  let parameters = { TypesUtils.empty_generic_params with regions = [parameter 99] } in
  let arguments = { empty with regions = [free 3] } in
  let generic_actual = signature [borrow (body 4); TRef (free 3, boolean, RShared)] in
  let generic = create ~parameters ~arguments ~free_parameters:[parameter 3] generic_family generic_actual in
  require "captured source template arguments must be substituted before comparing the complete field"
    (generic.reconstructed = generic_actual && Vtable_field.replay generic);
  require "a known captured source argument cannot be replaced by another in-scope region"
    (refuses (fun () -> ignore (create ~parameters ~arguments ~free_parameters:[parameter 3; parameter 4]
      generic_family (signature [borrow (body 4); TRef (free 4, boolean, RShared)]))));
  require "a mutated object witness cannot replay the actual stored signature"
    (not (Vtable_field.replay { witness with object_argument = RStatic }))
