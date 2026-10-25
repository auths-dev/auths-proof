(* Authored source-instantiation and statement-ABI regressions. Run only in the
   final validation batch; these synthetic inputs are not source qualification. *)
open Charon
open Types
open Expressions
open LlbcAst

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let body id = RBody (RegionId.of_int id)
let free id = RVar (Free (RegionId.of_int id))
let bound id = RVar (Bound (0, RegionId.of_int id))
let boolean = TLiteral TBool
let reference region = TRef (region, boolean, RShared)
let parameter index : region_param = { index = RegionId.of_int index; name = None;
  variance = Invariant; mutability = LtShared }
let definition = { binder_regions = [parameter 0]; binder_value = {
  kind = FunId (FRegular (FunDeclId.of_int 17)); generics = { empty with regions = [bound 0] } } }
let source inputs output : fun_sig region_binder = { binder_regions = definition.binder_regions;
  binder_value = { is_unsafe = false; abi = AbiRust; is_variadic = false; inputs; output } }
let instantiate signature args = Callable_instance.instantiate definition signature (Callable_instance.tuple args)
let value ty = Constant { kind = COpaque "synthetic callable ABI fixture"; ty }

let () =
  let signature = source [reference (bound 0)] (reference (bound 0)) in
  let plan = instantiate signature [reference (body 3)] in
  require "own call lifetime must instantiate the actual function pointer"
    (plan.target.generics.regions = [body 3]);
  require "the output must come from the actual instantiated source signature"
    (plan.output = reference (body 3));
  require "the complete supplied tuple must remain recorded"
    (plan.actual_tuple = Callable_instance.tuple [reference (body 3)]);
  require "explicit static call lifetimes are valid instantiations of an own quantifier"
    ((instantiate signature [reference RStatic]).output = reference RStatic);
  require "erased actual lifetime evidence must be refused" (refuses (fun () ->
    ignore (instantiate signature [reference RErased])));
  require "an unopened caller quantifier cannot be captured" (refuses (fun () ->
    ignore (instantiate signature [reference (bound 0)])));
  require "a non-region input mismatch must be refused" (refuses (fun () ->
    ignore (instantiate signature [boolean])));
  require "unused own lifetimes cannot be guessed" (refuses (fun () ->
    ignore (instantiate (source [boolean] boolean) [boolean])));
  let repeated = instantiate (source [reference (bound 0); reference (bound 0)] boolean)
    [reference (body 3); reference (body 4)] in
  require "a repeated call lifetime mismatch remains an explicit full tuple obligation"
    (repeated.input_tuple <> repeated.actual_tuple);
  let certificate = Region_equations.add_type Region_equations.empty_predicates
    repeated.input_tuple repeated.actual_tuple in
  require "body alias obligations must retain full replay evidence"
    (Region_equations.replay_predicates certificate);
  let fixed = instantiate (source [reference (bound 0); reference (free 2)] boolean)
    [reference (body 3); reference (free 9)] in
  require "fixed captured regions must remain unchanged in source inputs"
    (fixed.input_tuple = Callable_instance.tuple [reference (body 3); reference (free 2)]);
  require "rigid captured region disagreement must refuse body replay" (refuses (fun () ->
    ignore (Region_equations.add_type Region_equations.empty_predicates fixed.input_tuple fixed.actual_tuple)));
  let pointer kind regions : fn_ptr = { kind = TraitMethod ({
    kind = BuiltinOrAuto (kind, [], AssocTypeId.Map.empty);
    trait_decl_ref = { binder_regions = []; binder_value = {
      id = TraitDeclId.of_int 4; generics = { empty with types = [TFnDef definition; plan.actual_tuple] } } } },
    TraitMethodId.of_int 0); generics = { empty with regions } } in
  let once = pointer BuiltinFnOnce [] in
  let call : call = { func = FnOpRegular once;
    args = [value (TFnDef definition); value plan.actual_tuple];
    dest = { kind = PlaceLocal (LocalId.of_int 0); ty = plan.output } } in
  let equal requirements = List.for_all (fun (left, right) -> left = right) requirements in
  require "the receiver, complete tuple and output must all match the actual statement"
    (equal (Callable_instance.call_requirements once plan call));
  require "flat arguments cannot replace the callable tuple ABI" (refuses (fun () ->
    ignore (Callable_instance.call_requirements once plan { call with args = [value (reference (body 3))] })));
  require "wrong receiver types must remain a failed full equality"
    (not (equal (Callable_instance.call_requirements once plan
      { call with args = [value boolean; value plan.actual_tuple] })));
  require "wrong destination types must remain a failed full equality"
    (not (equal (Callable_instance.call_requirements once plan
      { call with dest = { call.dest with ty = boolean } })));
  List.iter (fun (kind, mutability) ->
    let pointer = pointer kind [body 8] in
    let call = { call with func = FnOpRegular pointer;
      args = [value (TRef (body 8, TFnDef definition, mutability)); value plan.actual_tuple] } in
    require "borrowed callable receivers must preserve the method's exact region and mutability"
      (equal (Callable_instance.call_requirements pointer plan call)))
    [BuiltinFnMut, RMut; BuiltinFn, RShared]
