(* A concrete Rust function item has a source definition and universally bound
   call lifetimes. This constructs its instantiation from the complete argument
   tuple. It never changes captured/type/const/dictionary arguments and never
   pretends the Fn* receiver/tuple ABI is the direct function's ABI. That adapter
   remains an explicit pending compiler/primitive obligation. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  definition : fn_ptr region_binder;
  target : fn_ptr;
  source_signature : fun_sig;
  late_arguments : region list;
  input_tuple : ty;
  actual_tuple : ty;
  output : ty;
}

let tuple types = TAdt { id = TTuple; generics = { TypesUtils.empty_generic_args with types } }

let source_substitution crate (pointer : fn_ptr) =
  match pointer.kind with
  | FunId (FRegular id) ->
      let declaration = match FunDeclId.Map.find_opt id crate.fun_decls with
        | Some declaration -> declaration
        | None -> invalid_arg "a callable function item's source definition is absent" in
      (match declaration.src with TraitDeclItem _ ->
        invalid_arg "a callable default method requires its actual source Self environment" | _ -> ());
      let arguments = pointer.generics in
      List.iter (fun (expected, actual) -> if expected <> actual then
        invalid_arg "a callable item has the wrong source generic argument arity") [
        List.length declaration.generics.regions, List.length arguments.regions;
        List.length declaration.generics.types, List.length arguments.types;
        List.length declaration.generics.const_generics, List.length arguments.const_generics;
        List.length declaration.generics.trait_clauses, List.length arguments.trait_refs ];
      let preliminary = Substitute.make_subst_from_generics declaration.generics arguments Self in
      let tr_self = match declaration.src with
        | TraitImplItem (owner, _, _, _) -> TraitImpl
            (Substitute.st_substitute_visitor#visit_trait_impl_ref preliminary owner)
        | _ -> Self in
      declaration, { preliminary with tr_self }
  | _ -> invalid_arg "a callable item requires a concrete regular source function"

let signature crate (definition : fn_ptr region_binder) =
      let declaration, substitution = source_substitution crate definition.binder_value in
      let signature = Substitute.st_substitute_visitor#visit_fun_sig
        substitution declaration.signature in
      if signature.is_unsafe || signature.is_variadic then
        invalid_arg "a callable adapter requires a safe non-variadic source signature";
      { binder_regions = definition.binder_regions; binder_value = signature }

let requirements crate witness =
  let declaration, substitution = source_substitution crate witness.target in
  Substitute.predicates_substitute substitution declaration.generics

let open_binder visit regions binder =
  Substitute.apply_args_to_binder { TypesUtils.empty_generic_args with regions } visit
    { binder_params = { TypesUtils.empty_generic_params with regions = binder.binder_regions };
      binder_value = binder.binder_value }

let instantiate definition source_signature actual_tuple =
  if source_signature.binder_regions <> definition.binder_regions then
    invalid_arg "callable source signature and item lifetime binders disagree";
  let all_regions = ref (Region_equations.type_occurrences actual_tuple) in
  let scan = object
    inherit [_] iter_ty
    method! visit_region _ region = all_regions := region :: !all_regions
  end in
  scan#visit_region_binder scan#visit_fn_ptr () definition;
  scan#visit_region_binder scan#visit_fun_sig () source_signature;
  let largest = List.fold_left (fun largest -> function
    | RVar (Free id) -> max largest (RegionId.to_int id) | _ -> largest) (-1) !all_regions in
  if largest >= max_int - List.length definition.binder_regions - 1 then
    invalid_arg "callable matching parameters exceed the construction identifier space";
  let markers = List.mapi (fun index _ -> RVar (Free (RegionId.of_int (largest + index + 1)))) definition.binder_regions in
  let pattern_signature = open_binder Substitute.st_substitute_visitor#visit_fun_sig markers source_signature in
  let pattern_tuple = tuple pattern_signature.inputs in
  if Region_equations.type_shape pattern_tuple <> Region_equations.type_shape actual_tuple then
    invalid_arg "callable source inputs differ from the complete supplied tuple structure";
  let actual_regions = Region_equations.type_occurrences actual_tuple in
  if List.mem RErased actual_regions then invalid_arg "callable arguments need complete source lifetime labels";
  let pattern_regions = Region_equations.type_occurrences pattern_tuple in
  if List.length pattern_regions <> List.length actual_regions then
    invalid_arg "callable tuple region traversal arities disagree";
  let inferred = ref [] in
  List.iter2 (fun pattern actual ->
    if List.mem pattern markers then (
      (match actual with RBody _ | RVar (Free _) | RStatic -> () | _ ->
        invalid_arg "callable inference must not capture an unopened caller quantifier");
      if not (List.mem_assoc pattern !inferred) then inferred := (pattern, actual) :: !inferred
    )) pattern_regions actual_regions;
  let late_arguments = List.map (fun marker -> match List.assoc_opt marker !inferred with
    | Some argument -> argument
    | None -> invalid_arg "a callable lifetime is not determined by its source argument tuple") markers in
  let target = open_binder Substitute.st_substitute_visitor#visit_fn_ptr late_arguments definition in
  let instantiated = open_binder Substitute.st_substitute_visitor#visit_fun_sig late_arguments source_signature in
  let input_tuple = tuple instantiated.inputs in
  (* This complete equality is retained for the caller's common body replay.
     In particular repeated/fixed argument labels are not silently merged. *)
  if Region_equations.type_shape input_tuple <> Region_equations.type_shape actual_tuple then
    invalid_arg "callable instantiation changed non-region input structure";
  { definition; target; source_signature = source_signature.binder_value;
    late_arguments; input_tuple; actual_tuple; output = instantiated.output }

let derive crate definition actual_tuple =
  instantiate definition (signature crate definition) actual_tuple

let replay crate witness =
  try derive crate witness.definition witness.actual_tuple = witness
  with Invalid_argument _ | Not_found -> false

let create crate definition actual_tuple =
  let witness = derive crate definition actual_tuple in
  if not (replay crate witness) then invalid_arg "callable source instantiation did not replay";
  witness

let operand_type = function
  | Copy place | Move place -> place.ty
  | Constant value -> value.ty

(* A callable dictionary describes an ABI; it does not establish that the
   actual statement supplied that ABI. Keep all three full type equalities in
   the common caller certificate, including the receiver and destination. *)
let call_requirements (pointer : fn_ptr) witness (call : call) =
  let receiver = match pointer.kind, pointer.generics.regions with
    | TraitMethod ({ kind = BuiltinOrAuto (BuiltinFnOnce, _, _); _ }, _), [] ->
        TFnDef witness.definition
    | TraitMethod ({ kind = BuiltinOrAuto (BuiltinFnMut, _, _); _ }, _), [region] ->
        TRef (region, TFnDef witness.definition, RMut)
    | TraitMethod ({ kind = BuiltinOrAuto (BuiltinFn, _, _); _ }, _), [region] ->
        TRef (region, TFnDef witness.definition, RShared)
    | _ -> invalid_arg "a callable statement has an unsupported receiver ABI" in
  match call.args with
  | [actual_receiver; actual_tuple] ->
      [receiver, operand_type actual_receiver;
       witness.actual_tuple, operand_type actual_tuple;
       witness.output, call.dest.ty]
  | _ -> invalid_arg "a callable statement must supply its receiver and one complete tuple"

let report crate witness =
  let open Diagnostic in
  let text value = `String value in
  `Assoc [
    "source_definition", text (Diagnostic.show_fn_ptr witness.definition.binder_value);
    "source_lifetime_binder", `List (List.map (fun parameter ->
      text (show_region_param parameter)) witness.definition.binder_regions);
    "source_signature", text (show_fun_sig witness.source_signature);
    "instantiated_source_target", text (Diagnostic.show_fn_ptr witness.target);
    "late_arguments", `List (List.map (fun region -> text (show_region region)) witness.late_arguments);
    "source_input_tuple", text (show_ty witness.input_tuple);
    "supplied_argument_tuple", text (show_ty witness.actual_tuple);
    "source_output", text (show_ty witness.output);
    "source_instantiation_replays", `Bool (replay crate witness);
    "receiver_tuple_adapter_contract_required", `Bool true;
    "adapter_semantics_discharged", `Bool false ]
