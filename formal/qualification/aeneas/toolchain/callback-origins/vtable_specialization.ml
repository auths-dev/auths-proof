(* Two isolated source adapter candidates for one real vtable template: a
   concrete caller and its concrete shim. These are actual typed AST bodies,
   not function results or an adopted transformed program. Captured owner
   lifetimes are fresh in the caller; shim own lifetimes retain their separate
   callee scope. Runtime template selection, source/loan simulation and closed
   native instances must be proved before these units could be emitted. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  dispatch : Vtable_dispatch.t;
  branch : Vtable_dispatch.branch;
  captured_region_renaming : (region_param * region_param) list;
  captured_parameters : generic_params;
  captured_arguments : generic_args;
  self_type : ty;
  original_object_region : region;
  object_obligations : region list;
  native_call_pointer : fn_ptr;
  native_call_signature : fun_sig;
  native_call_requirements : generic_params;
  caller_candidate : fun_decl;
  shim_candidate : fun_decl;
}

let fresh_name original suffix = original @ [PeIdent (suffix, Disambiguator.of_int 0)]

let fresh_capture_regions ~(caller : generic_params) ~(shim : generic_params) ~(captured : generic_params) =
  if caller.types <> [] || caller.const_generics <> [] || caller.trait_clauses <> [] then
    invalid_arg "a dispatch with captured caller type/const/dictionary parameters needs complete cross-context renaming";
  List.iter Region_scope.require_parameters [caller.regions; shim.regions; captured.regions];
  let prefix, _ = Vtable_cast.split (List.length captured.regions) shim.regions in
  if prefix <> captured.regions then invalid_arg "the captured source lifetimes are not the actual complete shim prefix";
  let largest = List.fold_left (fun current (parameter : region_param) ->
    Stdlib.max current (RegionId.to_int parameter.index)) (-1) (caller.regions @ shim.regions) in
  if largest >= Int.max_int - List.length captured.regions - 1 then
    invalid_arg "fresh captured lifetime parameters exceed the construction identifier space";
  List.mapi (fun index (parameter : region_param) ->
    parameter, { parameter with index = RegionId.of_int (largest + index + 1) }) captured.regions

let rename_captured_region (renaming : (region_param * region_param) list) = function
  | RVar (Free id) as original ->
      (match List.find_opt (fun ((source : region_param), _) -> source.index = id) renaming with
       | Some (_, target) -> RVar (Free target.index)
       | None -> original)
  | original -> original

let derive crate ~(dispatch : Vtable_dispatch.t) ~(branch : Vtable_dispatch.branch)
    ~caller_id ~shim_id =
  if not (Vtable_dispatch.replay crate dispatch) || not (List.mem branch dispatch.available_source_branches) then
    invalid_arg "vtable specialization requires the complete actual source dispatch and one original template branch";
  if caller_id = shim_id || FunDeclId.to_int caller_id < 0 || FunDeclId.to_int shim_id < 0 ||
     FunDeclId.Map.mem caller_id crate.fun_decls || FunDeclId.Map.mem shim_id crate.fun_decls then
    invalid_arg "vtable candidate functions need distinct fresh declaration IDs";
  let caller = dispatch.caller in
  let source_vtable = branch.source_vtable in
  let implementation = source_vtable.implementation in
  if source_vtable.global.generics <> implementation.generics then
    invalid_arg "source vtable/implementation parameter environments differ before specialization";
  let binding = match branch.source_slot.function_binding with Some binding -> binding
    | None -> invalid_arg "the source branch has no original shim binding" in
  if not (Vtable_receiver.replay binding.receiver_lowering) then
    invalid_arg "the actual concrete receiver shim candidate did not replay";
  let captured_region_renaming = fresh_capture_regions ~caller:caller.generics
    ~shim:binding.definition.generics ~captured:implementation.generics in
  let rename = object inherit [_] map_statement
    method! visit_region _ region = rename_captured_region captured_region_renaming region
  end in
  let rename_parameters (parameters : generic_params) =
    let result = rename#visit_generic_params () parameters in
    { result with regions = List.map (fun (parameter : region_param) ->
      match List.find_opt (fun ((source : region_param), _) -> source.index = parameter.index) captured_region_renaming with
      | Some (_, target) -> target | None -> parameter) parameters.regions } in
  let captured_parameters = rename_parameters implementation.generics in
  let captured_arguments = rename#visit_generic_args () source_vtable.owner.generics in
  Static_targets.require_argument_arity captured_parameters captured_arguments;
  let self_type = rename#visit_ty () binding.receiver_lowering.self_type in
  let source_body = match caller.body with StructuredBody body -> body
    | _ -> invalid_arg "the actual dispatch caller has no structured source body" in
  let original_object_region = match caller.signature.inputs with
    | TRef (_, TDynTrait predicate, _) :: _ ->
        Vtable_shape.object_annotation dispatch.lookup.shape.source_predicate predicate
    | _ -> invalid_arg "the actual dispatch caller does not expose its original borrowed dynamic receiver" in
  if original_object_region = RErased then
    invalid_arg "the original dynamic caller object bound has no source lifetime provenance";
  let object_obligations = ref [] in
  let direct_arguments = { captured_arguments with regions = captured_arguments.regions @ branch.own_call_arguments } in
  let native_call_pointer : fn_ptr = { kind = FunId (FRegular shim_id); generics = direct_arguments } in
  let mapper = object (self)
    inherit [_] map_statement as super
    method! visit_ty env = function
      | TDynTrait predicate ->
          let object_region = Vtable_shape.object_annotation dispatch.lookup.shape.source_predicate predicate in
          if object_region = RErased then invalid_arg "a concrete caller cannot discard an unknown source object bound";
          object_obligations := object_region :: !object_obligations;
          self_type
      | TFnPtr _ | TFnDef _ ->
          invalid_arg "a concrete dispatch unit still contains an unlowered source function-pointer value"
      | ty -> super#visit_ty env ty
    method! visit_place env place =
      (match place.kind with PlaceProjection (_, PtrMetadata) ->
        invalid_arg "source metadata outside the bound receiver lookup/reborrow needs explicit lowering"
       | _ -> ());
      super#visit_place env place
    method! visit_statement env (statement : statement) =
      if statement.statement_id = dispatch.source_statement.statement_id then (
        if statement <> dispatch.source_statement then invalid_arg "the source dynamic call changed before candidate lowering";
        { statement with kind = Call ({
          func = FnOpRegular native_call_pointer;
          args = List.map (self#visit_operand env) dispatch.source_call.args;
          dest = self#visit_place env dispatch.source_call.dest }, self#visit_block env dispatch.on_unwind) }
      ) else match List.find_opt (fun (entry : Vtable_dispatch.reborrow) ->
          entry.statement.statement_id = statement.statement_id) dispatch.reborrows with
        | Some entry ->
            if statement <> entry.statement then invalid_arg "the source paired reborrow changed before candidate lowering";
            (match statement.kind with
             | Assign (destination, RvRef (source, kind, metadata)) when metadata = entry.metadata ->
                 { statement with kind = Assign (self#visit_place env destination,
                   RvRef (self#visit_place env source, kind,
                     Constant { kind = CAdt (None, []); ty = Vtable_shape.unit })) }
             | _ -> invalid_arg "the bound source reborrow is no longer an original reference construction")
        | None ->
            (match statement.kind with Call ({ func = FnOpDynamic _; _ }, _) ->
              invalid_arg "an additional dynamic call needs its own typed source specialization"
             | _ -> ());
            super#visit_statement env statement
  end in
  let caller_signature = mapper#visit_fun_sig () caller.signature in
  let inherited_caller = mapper#visit_generic_params () caller.generics in
  let caller_generics : generic_params = {
    regions = inherited_caller.regions @ captured_parameters.regions;
    types = captured_parameters.types;
    const_generics = captured_parameters.const_generics;
    trait_clauses = captured_parameters.trait_clauses;
    regions_outlive = inherited_caller.regions_outlive @ captured_parameters.regions_outlive;
    types_outlive = inherited_caller.types_outlive @ captured_parameters.types_outlive @ [
      { binder_regions = []; binder_value = self_type, original_object_region }];
    trait_type_constraints = inherited_caller.trait_type_constraints @ captured_parameters.trait_type_constraints } in
  let caller_body = { source_body with
    locals = { source_body.locals with locals = List.map (mapper#visit_local ()) source_body.locals.locals };
    body = mapper#visit_block () source_body.body } in
  let shim_source = binding.receiver_lowering in
  let shim_signature = rename#visit_fun_sig () shim_source.concrete_signature in
  let shim_generics = rename_parameters binding.definition.generics in
  let shim_body = { shim_source.concrete_body with
    locals = { shim_source.concrete_body.locals with locals =
      List.map (rename#visit_local ()) shim_source.concrete_body.locals.locals };
    body = rename#visit_block () shim_source.concrete_body.body } in
  Static_targets.require_argument_arity shim_generics direct_arguments;
  let caller_candidate = { caller with def_id = caller_id; src = TopLevelItem;
    item_meta = { caller.item_meta with name = fresh_name caller.item_meta.name
      ("__auths_concrete_vtable_" ^ string_of_int (GlobalDeclId.to_int source_vtable.global.def_id)) };
    signature = caller_signature; generics = caller_generics; body = StructuredBody caller_body } in
  let shim_candidate = { binding.definition with def_id = shim_id; src = TopLevelItem;
    item_meta = { binding.definition.item_meta with name = fresh_name binding.definition.item_meta.name "__auths_concrete_receiver" };
    signature = shim_signature; generics = shim_generics; body = StructuredBody shim_body } in
  let native_substitution = Substitute.make_subst_from_generics shim_generics direct_arguments Self in
  let native_call_signature = Substitute.st_substitute_visitor#visit_fun_sig native_substitution shim_signature in
  let native_call_requirements = Substitute.predicates_substitute native_substitution shim_generics in
  let actual_calls = ref [] in
  let collect = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = dispatch.source_statement.statement_id then (
        match statement.kind with
        | Call (({ func = FnOpRegular pointer; _ } as call), _) when pointer = native_call_pointer ->
            actual_calls := call :: !actual_calls
        | _ -> invalid_arg "the concrete caller does not retain its exact new shim call");
      super#visit_statement env statement
  end in
  collect#visit_block () caller_body.body;
  (match !actual_calls with
   | [call] when List.map Vtable_dispatch.operand_type call.args = native_call_signature.inputs &&
       call.dest.ty = native_call_signature.output -> ()
   | _ -> invalid_arg "the concrete caller/shim candidates disagree in their complete instantiated call ABI");
  let check (declaration : fun_decl) (body : expr_body) =
    let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions declaration.generics.regions in
    scope#visit_generic_params [] declaration.generics;
    scope#visit_fun_sig [] declaration.signature;
    List.iter (scope#visit_local []) body.locals.locals;
    scope#visit_block [] body.body in
  check caller_candidate caller_body;
  check shim_candidate shim_body;
  (new Region_scope.statement_check ~body_regions:caller_body.bound_body_regions caller_generics.regions)
    #visit_generic_params [] native_call_requirements;
  { dispatch; branch; captured_region_renaming; captured_parameters; captured_arguments; self_type;
    original_object_region; object_obligations = List.rev !object_obligations; native_call_pointer;
    native_call_signature; native_call_requirements;
    caller_candidate; shim_candidate }

let replay crate witness =
  try derive crate ~dispatch:witness.dispatch ~branch:witness.branch
    ~caller_id:witness.caller_candidate.def_id ~shim_id:witness.shim_candidate.def_id = witness
  with Invalid_argument _ -> false

let create crate ~dispatch ~branch ~caller_id ~shim_id =
  let witness = derive crate ~dispatch ~branch ~caller_id ~shim_id in
  if not (replay crate witness) then invalid_arg "the complete paired source caller/shim candidates did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let declaration (value : fun_decl) = `Assoc ["candidate_id", `Int (FunDeclId.to_int value.def_id);
    "parameters", `String (show_generic_params value.generics);
    "signature", `String (show_fun_sig value.signature);
    "locals", (match value.body with StructuredBody body ->
      `List (List.map (fun value -> `String (show_local value)) body.locals.locals) | _ -> `Null);
    "body", (match value.body with StructuredBody body -> `String (show_block body.body) | _ -> `Null)] in
  `Assoc ["source_caller_id", `Int (FunDeclId.to_int witness.dispatch.caller.def_id);
    "source_vtable_global", `Int (GlobalDeclId.to_int witness.branch.source_vtable.global.def_id);
    "captured_region_renaming", `List (List.map (fun ((before : region_param), (after : region_param)) ->
      `Assoc ["source", `Int (RegionId.to_int before.index); "fresh", `Int (RegionId.to_int after.index)]) witness.captured_region_renaming);
    "captured_parameters", `String (show_generic_params witness.captured_parameters);
    "captured_arguments", `String (show_generic_args witness.captured_arguments);
    "concrete_self", `String (show_ty witness.self_type);
    "native_candidate_call", `String (show_fn_ptr witness.native_call_pointer);
    "instantiated_candidate_call_signature", `String (show_fun_sig witness.native_call_signature);
    "candidate_call_where_requirements", `String (show_generic_params witness.native_call_requirements);
    "caller_candidate", declaration witness.caller_candidate;
    "shim_candidate", declaration witness.shim_candidate;
    "retained_object_liveness_obligations", `List (List.map (fun region -> `String (show_region region)) witness.object_obligations);
    "required_concrete_self_has_unit_reference_metadata", `String (show_ty witness.self_type);
    "source_metadata_layout_adequacy_proved", `Bool false;
    "complete_source_candidate_replays", `Bool (replay crate witness);
    "closed_native_capture_instances_and_exhaustive_selection_proved", `Bool false;
    "source_type_loan_value_drop_and_unwind_simulation_proved", `Bool false;
    "program_emitted", `Bool false; "qualified", `Bool false]
