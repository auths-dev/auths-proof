(* Original function-pointer binder regressions; authored/unbuilt/unrun until
   the final validation batch. No native invocation/loan proof follows. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let rid = RegionId.of_int
let free id = RVar (Free (rid id))
let bound depth id = RVar (Bound (depth, rid id))
let body id = RBody (rid id)
let boolean = TLiteral Charon.Values.TBool
let parameter id : region_param = { index = rid id; name = None;
  variance = Invariant; mutability = LtShared }
let borrow region = TRef (region, boolean, RShared)
let signature inputs output : fun_sig = { is_unsafe = false; abi = AbiRust;
  is_variadic = false; inputs; output }

let () =
  let original = { binder_regions = [parameter 7]; binder_value =
    signature [borrow (bound 0 7); borrow (free 3)] (borrow (bound 0 7)) } in
  let actual = signature [borrow (body 4); borrow (free 3)] (borrow (body 4)) in
  let witness = Signature_instance.create original actual in
  require "the original own binder must reconstruct the complete actual signature"
    (witness.arguments = [body 4] && witness.reconstructed = actual && Signature_instance.replay witness);
  List.iter (fun changed ->
    require "full ABI/result/fixed-region mutations cannot be explained by own lifetime instantiation"
      (refuses (fun () -> ignore (Signature_instance.create original changed))))
    [{ actual with is_unsafe = true }; { actual with is_variadic = true }; { actual with abi = AbiC };
     { actual with output = boolean }; { actual with inputs = [borrow (body 4); borrow (free 2)] };
     { actual with output = borrow (body 5) }];
  require "an erased actual argument cannot determine a lifetime"
    (refuses (fun () -> ignore (Signature_instance.create original
      (signature [borrow RErased; borrow (free 3)] (borrow RErased)))));
  require "an unused own lifetime cannot default to static"
    (refuses (fun () -> ignore (Signature_instance.create
      { original with binder_regions = original.binder_regions @ [parameter 9] } actual)));
  let nested ty = TFnPtr { binder_regions = [parameter 0];
    binder_value = signature [borrow (bound 0 0); ty] boolean } in
  let nested_source = { binder_regions = [parameter 7]; binder_value = signature
    [nested (borrow (bound 1 7))] boolean } in
  let nested_actual = signature [nested (borrow (body 4))] boolean in
  require "a function's own argument must pass beneath the complete unchanged inner binder"
    (Signature_instance.replay (Signature_instance.create nested_source nested_actual));
  require "the outer binder cannot capture the inner callback's local lifetime"
    (refuses (fun () -> ignore (Signature_instance.create nested_source
      (signature [nested (borrow (bound 0 0))] boolean))));
  require "a mutated reconstructed signature cannot replay"
    (not (Signature_instance.replay { witness with reconstructed = { actual with is_unsafe = true } }));
  require "literal static input can instantiate an own binder without promoting another source region"
    (let actual = signature [borrow RStatic; borrow (free 3)] (borrow RStatic) in
      (Signature_instance.create original actual).arguments = [RStatic])
