(* Scope regressions are authored only; run with the final validation batch. *)
open Charon.Types
open Charon.Values

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let parameter id : region_param = { index = RegionId.of_int id; name = None;
  variance = Invariant; mutability = LtShared }
let free id = RVar (Free (RegionId.of_int id))
let bound depth id = RVar (Bound (depth, RegionId.of_int id))
let check = new Region_scope.check ~body_regions:3 [parameter 7]
let borrow region = TRef (region, TLiteral TBool, RShared)
let binder parameters ty = TFnPtr { binder_regions = parameters; binder_value = {
  is_unsafe = false; abi = AbiRust; is_variadic = false; inputs = [ty]; output = TLiteral TBool } }

let () =
  List.iter (check#visit_region []) [RStatic; free 7; RBody (RegionId.of_int 2)];
  require "an undeclared free region cannot be treated as a specialization parameter"
    (refuses (fun () -> check#visit_region [] (free 0)));
  require "the exclusive original body-region bound must hold"
    (refuses (fun () -> check#visit_region [] (RBody (RegionId.of_int 3))));
  require "erased normalized regions cannot establish provenance"
    (refuses (fun () -> check#visit_region [] RErased));
  require "an outer bound variable cannot escape into a source declaration"
    (refuses (fun () -> check#visit_region [] (bound 0 0)));
  check#visit_ty [] (binder [parameter 2] (borrow (bound 0 2)));
  check#visit_ty [] (binder [parameter 2] (binder [] (borrow (bound 1 2))));
  require "empty binders still affect captured de Bruijn depth"
    (refuses (fun () -> check#visit_ty [] (binder [parameter 2] (binder [] (borrow (bound 0 2))))));
  require "the correct binder depth cannot license a different local parameter"
    (refuses (fun () -> check#visit_ty [] (binder [parameter 2] (borrow (bound 0 1)))));
  let global = new Region_scope.check [parameter 7] in
  require "global/type declarations cannot capture an existential function-body lifetime"
    (refuses (fun () -> global#visit_region [] (RBody (RegionId.of_int 0))));
  require "duplicate source parameter IDs cannot shadow one another"
    (refuses (fun () -> ignore (new Region_scope.check [parameter 7; parameter 7])))
