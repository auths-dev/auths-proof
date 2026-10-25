(* Own-method binder and full pointer-routing regressions. Authored/unbuilt/
   unrun until the final batch; no ABI or source loan qualification follows. *)
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
let source : fun_decl_ref binder = {
  binder_params = { TypesUtils.empty_generic_params with regions = [parameter 7] };
  binder_value = { id = FunDeclId.of_int 12;
    generics = { empty with regions = [bound 0 7; free 3]; types = [boolean] } } }
let actual : fn_ptr = { kind = FunId (FRegular source.binder_value.id);
  generics = { empty with regions = [body 8; free 3]; types = [boolean] } }

let () =
  let witness = Method_instance.create source actual in
  require "only the method's own sparse bound parameter may be instantiated"
    (witness.own_arguments = [body 8] && witness.reconstructed = actual && witness.source = source);
  require "a complete source method pointer route must independently replay"
    (Method_instance.replay witness);
  require "a supplied static own argument is an instantiation, not a static guess"
    ((Method_instance.create source { actual with generics = {
      actual.generics with regions = [RStatic; free 3] } }).own_arguments = [RStatic]);
  require "the same method shape cannot select a different source function"
    (refuses (fun () -> ignore (Method_instance.create source {
      actual with kind = FunId (FRegular (FunDeclId.of_int 13)) })));
  require "a fixed captured lifetime cannot change to fit the shim"
    (refuses (fun () -> ignore (Method_instance.create source { actual with generics = {
      actual.generics with regions = [body 8; RStatic] } })));
  require "an erased actual method argument cannot supply provenance"
    (refuses (fun () -> ignore (Method_instance.create source { actual with generics = {
      actual.generics with regions = [RErased; free 3] } })));
  require "type arguments are part of the complete routing equality"
    (refuses (fun () -> ignore (Method_instance.create source { actual with generics = {
      actual.generics with types = [TLiteral (Charon.Values.TUInt Charon.Values.U64)] } })));
  let repeated = { source with binder_value = { source.binder_value with generics = {
    source.binder_value.generics with regions = [bound 0 7; bound 0 7] } } } in
  require "one own method lifetime cannot route to two unrelated actual regions"
    (refuses (fun () -> ignore (Method_instance.create repeated { actual with generics = {
      actual.generics with regions = [body 8; body 9] } })));
  let unused = { source with binder_value = { source.binder_value with generics = {
    source.binder_value.generics with regions = [free 3] } } } in
  require "unused own parameters cannot be invented from defaults"
    (refuses (fun () -> ignore (Method_instance.create unused { actual with generics = {
      actual.generics with regions = [free 3] } })));
  require "a mutated own-argument witness cannot replay"
    (not (Method_instance.replay { witness with own_arguments = [] }));
  let nested region = TFnPtr { binder_regions = [parameter 9]; binder_value = {
    is_unsafe = false; abi = AbiRust; is_variadic = false;
    inputs = [TRef (bound 0 9, boolean, RShared)]; output = TRef (region, boolean, RShared) } } in
  let nested_source = { source with binder_value = { source.binder_value with generics = {
    source.binder_value.generics with types = [nested (bound 1 7)] } } } in
  let nested_actual = { actual with generics = { actual.generics with types = [nested (body 8)] } } in
  require "inner function binders stay local while own-method captures instantiate"
    ((Method_instance.create nested_source nested_actual).reconstructed = nested_actual)
