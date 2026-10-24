(* Source/capture substitution regressions. Authored/unbuilt/unrun until the
   final batch. These do not qualify a native instance or its source bridge. *)
open Charon
open Types

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let parameter index : region_param = { index = RegionId.of_int index; name = None;
  variance = Invariant; mutability = LtShared }
let parameters ids = { TypesUtils.empty_generic_params with regions = List.map parameter ids }
let free index = RVar (Free (RegionId.of_int index))

let () =
  let captured = parameters [4] in
  let actual = { TypesUtils.empty_generic_args with regions = [free 5] } in
  let caller = parameters [0; 1; 2; 3; 4] and shim = parameters [4; 1; 2; 3] in
  let caller_arguments = Vtable_instance.capture_arguments ~captured ~actual ~enclosing:caller in
  let shim_arguments = Vtable_instance.capture_arguments ~captured ~actual ~enclosing:shim in
  require "captured source substitution preserves every unrelated caller lifetime"
    (caller_arguments.regions = [free 0; free 1; free 2; free 3; free 5]);
  require "the callee's own lifetime binder remains independent of the caller's same numeric IDs"
    (shim_arguments.regions = [free 5; free 1; free 2; free 3]);
  let substitution = Substitute.make_subst_from_generics caller caller_arguments Self in
  let boolean = TLiteral Charon.Values.TBool in
  let value = TRef (free 1, TRef (free 4, boolean, RShared), RShared) in
  require "substitution must replace only the capture inside the complete original source signature"
    (Substitute.ty_substitute substitution value = TRef (free 1, TRef (free 5, boolean, RShared), RShared));
  require "a missing captured parameter cannot be silently ignored"
    (refuses (fun () -> ignore (Vtable_instance.capture_arguments ~captured ~actual ~enclosing:(parameters [0; 1]))));
  require "an extra caller type parameter needs its own explicit substitution"
    (refuses (fun () -> ignore (Vtable_instance.capture_arguments ~captured ~actual ~enclosing:{ caller with
      types = [{ index = TypeVarId.of_int 0; name = "T"; variance = Invariant }] }))));
  require "duplicate enclosing lifetimes cannot alias a capture"
    (refuses (fun () -> ignore (Vtable_instance.capture_arguments ~captured ~actual ~enclosing:(parameters [4; 4]))))
