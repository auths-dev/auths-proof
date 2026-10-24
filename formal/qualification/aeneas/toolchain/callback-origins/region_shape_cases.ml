(* Authored regression executable. Deferred with all final checks. *)
open Charon.Types
open Charon.Values

let require message condition = if not condition then failwith message
let rid = RegionId.of_int
let bool_ty = TLiteral TBool
let shared region = TRef (region, bool_ty, RShared)
let args types = { Charon.TypesUtils.empty_generic_args with types }
let bound id = { index = rid id; name = None; variance = Invariant; mutability = LtUnknown }

let () =
  let original = args [shared RStatic] in
  let static = Region_shape.factor original in
  require "static lifetimes must remain static" (static.pattern = original && static.parameters = []);
  let aliases = Region_shape.factor (args [shared (RBody (rid 7)); shared (RBody (rid 7))]) in
  require "equal source lifetimes must share one parameter" (List.length aliases.parameters = 1);
  let distinct = Region_shape.factor (args [shared (RBody (rid 7)); shared (RBody (rid 8))]) in
  require "distinct source lifetimes must remain distinct" (List.length distinct.parameters = 2);
  let alpha = Region_shape.factor (args [shared (RBody (rid 70)); shared (RBody (rid 80))]) in
  require "caller region identifiers must not create new type specializations" (alpha.pattern = distinct.pattern);
  let kinds = Region_shape.factor (args [shared (RBody (rid 1)); TRef (RBody (rid 1), bool_ty, RMut)]) in
  require "reference mutability must remain significant"
    (kinds.pattern.types = [shared (RVar (Free (rid 0))); TRef (RVar (Free (rid 0)), bool_ty, RMut)]);
  let higher_ranked = TFnPtr { binder_regions = [bound 0]; binder_value = {
    is_unsafe = false; abi = AbiRust; is_variadic = false;
    inputs = [shared (RVar (Bound (0, rid 0))); shared (RVar (Bound (1, rid 3)))];
    output = shared (RVar (Free (rid 5))) } } in
  let source = args [shared (RVar (Bound (0, rid 3))); higher_ranked] in
  let factored = Region_shape.factor source in
  require "higher-ranked locals must not become specialization parameters" (List.length factored.parameters = 2);
  require "captured outer lifetimes must round-trip beneath a binder" (Region_shape.instantiate factored = source);
  let empty = Region_shape.factor Charon.TypesUtils.empty_generic_args in
  require "empty generic arguments must remain empty" (empty.parameters = [] && empty.arguments = []);
  let refused = try ignore (Region_shape.factor (args [shared RErased])); false
    with Invalid_argument _ -> true in
  require "erased input lifetimes must be refused" refused
