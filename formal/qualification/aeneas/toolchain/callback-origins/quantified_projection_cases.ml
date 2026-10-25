(* Authored regressions for universal-output binder reconstruction; unrun until
   the final verification batch. No source qualification follows from these. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let rid = RegionId.of_int
let free id = RVar (Free (rid id))
let bound depth id = RVar (Bound (depth, rid id))
let parameter index : region_param = { index = rid index; name = None;
  variance = Invariant; mutability = LtShared }
let shared region = TRef (region, TLiteral TBool, RShared)

let () =
  let parameters = [parameter 0] in
  let fresh = [free 90] in
  let original = Callable_instance.tuple [shared (bound 0 0); shared (free 3); shared RStatic;
    shared (RBody (rid 2)); shared (bound 1 7)] in
  let binder = { binder_regions = parameters; binder_value = original } in
  let opened = Callable_instance.open_binder Substitute.st_substitute_visitor#visit_ty fresh binder in
  require "closing a universal output must reconstruct every original label and capture depth"
    (Quantified_projection.close_type parameters fresh opened = binder);
  require "universal output reconstruction cannot invent a missing binder argument" (refuses (fun () ->
    ignore (Quantified_projection.close_type parameters [] opened)));
  let inner = TFnPtr { binder_regions = [parameter 0]; binder_value = {
    is_unsafe = false; abi = AbiRust; is_variadic = false;
    inputs = [shared (bound 0 0); shared (bound 1 0); shared (bound 2 7)];
    output = shared (bound 1 0) } } in
  let binder = { binder_regions = parameters; binder_value = inner } in
  let opened = Callable_instance.open_binder Substitute.st_substitute_visitor#visit_ty fresh binder in
  require "inner bound lifetimes must stay local while outer output captures are restored"
    (Quantified_projection.close_type parameters fresh opened = binder);
  Quantified_projection.require_invariant fresh (fun visitor ty -> visitor#visit_ty () ty)
    (shared (free 3));
  require "varying source prerequisites require an explicit proof" (refuses (fun () ->
    Quantified_projection.require_invariant fresh (fun visitor ty -> visitor#visit_ty () ty)
      (shared (free 90))));
  require "body regions cannot be captured as universal output parameters" (refuses (fun () ->
    ignore (Region_equations.add_quantified_type Region_equations.empty_predicates
      { binder_regions = parameters; binder_value = shared (RBody (rid 2)) }
      { binder_regions = parameters; binder_value = shared (bound 0 0) })))
