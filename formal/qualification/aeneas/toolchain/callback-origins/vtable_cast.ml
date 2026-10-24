(* Source signature correspondence for generated vtable function-item casts.
   Captured owner arguments are rigid. Only compiler-generated fresh body
   placeholders for the declared own method/drop lifetimes are re-exposed in
   the original field binder. Original operands/types remain recorded. No
   runtime pointer, native call, loan or drop equivalence follows by itself. *)
open Charon
open Types
open LlbcAst

type t = {
  definition : fun_decl;
  owner_parameters : generic_params;
  owner_arguments : generic_args;
  field : Vtable_field.t;
  source_pointer : fn_ptr;
  source_from_type : ty;
  source_into_type : ty;
  own_source_parameters : region_param list;
  original_late_placeholders : region list;
  reexposed_item : fn_ptr region_binder;
  reconstructed_source_from : ty;
  source_signature : fun_sig region_binder;
  source_requirements : generic_params;
}

let split count values =
  let rec take count prefix rest =
    if count = 0 then List.rev prefix, rest else match rest with
      | first :: rest -> take (count - 1) (first :: prefix) rest
      | [] -> invalid_arg "a generated vtable shim has an incomplete captured argument prefix" in
  if count < 0 then invalid_arg "a generated vtable shim has a negative captured prefix";
  take count [] values

let derive ~(definition : fun_decl) ~(owner_parameters : generic_params)
    ~(owner_arguments : generic_args) ~(field : Vtable_field.t)
    ~(source_pointer : fn_ptr) ~from_type ~into_type =
  if not (Vtable_field.replay field) then invalid_arg "a vtable source cast needs its exact stored field witness";
  (match definition.src, source_pointer.kind with
   | VTableMethodShimItem, FunId (FRegular id) when id = definition.def_id -> ()
   | _ -> invalid_arg "a vtable source cast must retain its exact generated regular shim definition");
  if definition.is_global_initializer <> None then invalid_arg "a vtable method shim cannot be an initializer";
  Static_targets.require_argument_arity definition.generics source_pointer.generics;
  Static_targets.require_argument_arity owner_parameters owner_arguments;
  let captured_count = List.length owner_parameters.regions in
  let captured_parameters, own_source_parameters = split captured_count definition.generics.regions in
  if captured_parameters <> owner_parameters.regions ||
     definition.generics.types <> owner_parameters.types ||
     definition.generics.const_generics <> owner_parameters.const_generics ||
     definition.generics.trait_clauses <> owner_parameters.trait_clauses then
    invalid_arg "a generated vtable shim changed its complete captured owner parameter environment";
  let captured_arguments, original_late_placeholders = split captured_count source_pointer.generics.regions in
  if captured_arguments <> owner_arguments.regions ||
     source_pointer.generics.types <> owner_arguments.types ||
     source_pointer.generics.const_generics <> owner_arguments.const_generics ||
     source_pointer.generics.trait_refs <> owner_arguments.trait_refs then
    invalid_arg "a generated vtable shim changed a captured owner argument";
  if List.length own_source_parameters <> List.length field.original.binder_regions ||
     List.length original_late_placeholders <> List.length own_source_parameters then
    invalid_arg "the generated shim's declared own lifetimes disagree with the original source field binder";
  List.iter2 (fun (source : region_param) (bound : region_param) ->
    if source.variance <> bound.variance || source.mutability <> bound.mutability then
      invalid_arg "a generated shim lifetime changed its original field variance or borrow classification")
    own_source_parameters field.original.binder_regions;
  let late_ids = List.map (function
    | RBody id when RegionId.to_int id >= 0 && RegionId.to_int id < field.body_regions -> id
    | _ -> invalid_arg "declared vtable own lifetimes need their actual fresh source body placeholders")
    original_late_placeholders in
  if List.length (List.sort_uniq RegionId.compare_id late_ids) <> List.length late_ids then
    invalid_arg "distinct generated own lifetimes cannot share a source erasure placeholder";
  let captured_pointer = { source_pointer with generics = {
    source_pointer.generics with regions = captured_arguments } } in
  List.iter (function
    | RBody id when List.mem id late_ids ->
        invalid_arg "a vtable own lifetime placeholder aliases a captured argument"
    | _ -> ()) (Method_instance.regions captured_pointer);
  let stored_scope = object
    inherit [_] iter_ty
    method! visit_region _ = function
      | RBody id when List.mem id late_ids ->
          invalid_arg "a vtable own lifetime placeholder aliases the stored field's source lifetime"
      | _ -> ()
  end in
  stored_scope#visit_ty () (TFnPtr field.actual);
  let under = Substitute.st_substitute_visitor#visit_fn_ptr
    Substitute.move_under_binder_subst source_pointer in
  let original_item = { binder_regions = field.original.binder_regions; binder_value = under } in
  if from_type <> TFnDef original_item || into_type <> TFnPtr field.actual then
    invalid_arg "the source vtable cast operand/destination differs from the complete original typed expression";
  let captured_under, _ = split captured_count under.generics.regions in
  let own_bound_arguments = List.map (fun (parameter : region_param) ->
    RVar (Bound (0, parameter.index))) field.original.binder_regions in
  let reexposed_pointer = { under with generics = { under.generics with
    regions = captured_under @ own_bound_arguments } } in
  let reexposed_item = { original_item with binder_value = reexposed_pointer } in
  let restored_pointer = { reexposed_pointer with generics = { reexposed_pointer.generics with
    regions = captured_under @ original_late_placeholders } } in
  let reconstructed_source_from = TFnDef { original_item with binder_value = restored_pointer } in
  if reconstructed_source_from <> from_type then
    invalid_arg "the re-exposed function item did not reconstruct the complete original source operand type";
  let preliminary = Substitute.make_subst_from_generics definition.generics reexposed_pointer.generics Self in
  let source_signature = { binder_regions = field.original.binder_regions;
    binder_value = Substitute.st_substitute_visitor#visit_fun_sig preliminary definition.signature } in
  if source_signature <> field.original then
    invalid_arg "the generated shim source signature does not reconstruct the complete instantiated original field ABI";
  let source_requirements = Substitute.predicates_substitute preliminary definition.generics in
  { definition; owner_parameters; owner_arguments; field; source_pointer;
    source_from_type = from_type; source_into_type = into_type; own_source_parameters;
    original_late_placeholders; reexposed_item; reconstructed_source_from; source_signature; source_requirements }

let replay witness =
  try derive ~definition:witness.definition ~owner_parameters:witness.owner_parameters
    ~owner_arguments:witness.owner_arguments ~field:witness.field ~source_pointer:witness.source_pointer
    ~from_type:witness.source_from_type ~into_type:witness.source_into_type = witness
  with Invalid_argument _ -> false

let create ~definition ~owner_parameters ~owner_arguments ~field ~source_pointer ~from_type ~into_type =
  let witness = derive ~definition ~owner_parameters ~owner_arguments ~field ~source_pointer ~from_type ~into_type in
  if not (replay witness) then invalid_arg "the complete source vtable cast signature witness did not replay";
  witness

let report witness =
  let open Diagnostic in
  `Assoc ["source_function_id", `Int (FunDeclId.to_int witness.definition.def_id);
    "source_function_pointer", `String (show_fn_ptr witness.source_pointer);
    "source_cast_from", `String (show_ty witness.source_from_type);
    "source_cast_into", `String (show_ty witness.source_into_type);
    "captured_source_owner_parameters", `String (show_generic_params witness.owner_parameters);
    "captured_source_owner_arguments", `String (show_generic_args witness.owner_arguments);
    "declared_own_source_parameters", `List (List.map (fun value -> `String (show_region_param value)) witness.own_source_parameters);
    "original_source_own_placeholders", `List (List.map (fun value -> `String (show_region value)) witness.original_late_placeholders);
    "reexposed_function_item_descriptor", `String (show_ty (TFnDef witness.reexposed_item));
    "reconstructed_original_source_operand", `String (show_ty witness.reconstructed_source_from);
    "source_signature_in_original_field_binder", `String (show_ty (TFnPtr witness.source_signature));
    "retained_source_where_requirements", `String (show_generic_params witness.source_requirements);
    "complete_source_cast_signature_replays", `Bool (replay witness);
    "native_cast_value_loan_ownership_and_execution_adequacy_discharged", `Bool false]
