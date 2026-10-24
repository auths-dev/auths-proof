(* Actual source closure captures and universally quantified source method
   families. Own lifetimes come from their original method binder, not guessed
   native arguments. No callback result or carrier effect is supplied. *)
open Charon
open Types
open Expressions
open LlbcAst

type member = {
  role : closure_kind;
  owner : trait_impl_ref;
  source_method : fun_decl_ref binder;
  own_parameters : region_param list;
  routing : Method_instance.t;
  resolution : Static_targets.resolved;
  signature : fun_sig;
}
type t = {
  caller : Source_closure.node;
  statement : statement;
  reference : type_decl_ref;
  source_type : type_decl;
  type_resolution : Type_view.resolution;
  source_info : closure_info;
  actual_info : closure_info;
  field_types : ty list;
  source_operands : operand list;
  box_fields : int list;
  constraints : Region_equations.predicates;
  members : member list;
}

let rec carries_box crate depth seen ty =
  if depth > 32 then invalid_arg "source closure capture nesting exceeds its explicit construction limit";
  match ty with
  | TRef (_, box, _) when Option.is_some (Capture_return.predicate box) -> true
  | TRef (_, nested, _) -> carries_box crate (depth + 1) seen nested
  | TAdt ({ id = TAdtId id; _ } as reference) when not (List.mem reference seen) ->
      (match TypeDeclId.Map.find_opt id crate.type_decls with
       | Some ({ src = ClosureItem _; kind = Struct fields; _ } as source) ->
           let substitution = Type_view.source_substitution source reference.generics None in
           List.exists (fun (field : field) -> carries_box crate (depth + 1) (reference :: seen)
             (Substitute.ty_substitute substitution field.field_ty)) fields
       | _ -> false)
  | _ -> false

let is_box_capture crate reference = carries_box crate 0 [] (TAdt reference)

let instantiate_info substitution (source_info : closure_info) =
  let substitute_impl reference = Substitute.st_substitute_visitor#visit_region_binder
    Substitute.st_substitute_visitor#visit_trait_impl_ref substitution reference in
  { source_info with fn_once_impl = substitute_impl source_info.fn_once_impl;
    fn_mut_impl = Option.map substitute_impl source_info.fn_mut_impl;
    fn_impl = Option.map substitute_impl source_info.fn_impl;
    signature = Substitute.st_substitute_visitor#visit_region_binder
      Substitute.st_substitute_visitor#visit_fun_sig substitution source_info.signature }

let derive crate ~(caller : Source_closure.node) statement_id =
  Source_call.actual_view crate caller;
  let frame = Source_call.frame caller in
  let statement = Prepared_injection.unique_statement frame.body statement_id in
  let destination, reference, source_operands = match statement.kind with
    | Assign (destination, Aggregate (AggregatedAdt (({ id = TAdtId _; _ } as reference), None, None), operands)) ->
        destination, reference, operands
    | _ -> invalid_arg "source closure capture requires its original nominal aggregate and operand order" in
  let type_resolution = Type_view.resolve crate reference in
  if type_resolution.reference <> reference || type_resolution.obligations <> [] then
    invalid_arg "the actual closure type does not replay its strict source predicates";
  let source_type = type_resolution.declaration in
  let source_info, source_fields = match source_type.src, source_type.kind with ClosureItem info, Struct fields -> info, fields
    | _ -> invalid_arg "a source closure capture cannot substitute another nominal struct" in
  let substitution = Type_view.source_substitution source_type reference.generics type_resolution.self_evidence in
  let normalizer = new Static_targets.normalize crate in
  let field_types = List.map (fun (field : field) ->
    normalizer#visit_ty 0 (Substitute.ty_substitute substitution field.field_ty)) source_fields in
  normalizer#check_requirements;
  if normalizer#obligations <> [] then invalid_arg "an actual closure field retains unresolved source predicates";
  if List.length field_types <> List.length source_operands then invalid_arg "the actual closure aggregate changed its complete field arity";
  let constraints = Region_equations.add_type frame.region_certificate (TAdt reference) destination.ty in
  let constraints = List.fold_left (fun constraints (field, source) ->
    Region_equations.add_type constraints field (Vtable_dispatch.operand_type source)) constraints (List.combine field_types source_operands) in
  if not (Region_equations.replay_predicates constraints) then invalid_arg "the complete actual closure/field/operand typing premises did not replay";
  let box_fields = List.mapi (fun index field -> index, field) field_types |> List.filter_map (fun (index, field) ->
    if carries_box crate 0 [] field then Some index else None) in
  if box_fields = [] then invalid_arg "the actual closure has no source captured Box reference";
  let actual_info = instantiate_info substitution source_info in
  let scope = new Region_scope.statement_check ~body_regions:frame.source_body.bound_body_regions caller.view.arguments.parameters in
  List.iter (scope#visit_ty []) field_types;
  scope#visit_region_binder scope#visit_fun_sig [] actual_info.signature;
  let roots = [FnOnce, actual_info.fn_once_impl] @
    (match actual_info.fn_mut_impl with Some reference -> [FnMut, reference] | None -> []) @
    (match actual_info.fn_impl with Some reference -> [Fn, reference] | None -> []) in
  (match actual_info.kind, actual_info.fn_mut_impl, actual_info.fn_impl with
   | FnOnce, _, _ | FnMut, Some _, _ | Fn, Some _, Some _ -> ()
   | _ -> invalid_arg "the actual closure kind lost its required original callable implementation");
  let expected_closure_type = TAdt reference in
  let members = List.concat_map (fun (role, owner_reference) ->
    scope#visit_region_binder scope#visit_trait_impl_ref [] owner_reference;
    if owner_reference.binder_regions <> [] then invalid_arg "a higher-ranked closure owner needs its explicit source caller instantiation";
    let owner = Substitute.extract_from_binder Substitute.st_substitute_visitor#visit_trait_impl_ref owner_reference in
    let implementation = match TraitImplId.Map.find_opt owner.id crate.trait_impls with Some source -> source
      | None -> invalid_arg "the actual closure callable implementation is absent" in
    let owner_substitution = Substitute.make_subst_from_generics implementation.generics owner.generics (TraitImpl owner) in
    let predicate = Substitute.trait_decl_ref_substitute owner_substitution implementation.impl_trait in
    (match predicate.generics.types with actual :: _ when actual = expected_closure_type -> ()
     | _ -> invalid_arg "the actual closure callable implementation changed its complete captured Self type");
    if TraitMethodId.Map.is_empty implementation.methods then invalid_arg "the actual closure callable implementation has no source method";
    List.map (fun (_, original_method) ->
      let source_method = Substitute.apply_args_to_item_binder (TraitImpl owner) owner.generics
        (Substitute.st_substitute_visitor#visit_binder Substitute.st_substitute_visitor#visit_fun_decl_ref)
        { item_binder_params = implementation.generics; item_binder_value = original_method } in
      if source_method.binder_params.types <> [] || source_method.binder_params.const_generics <> [] || source_method.binder_params.trait_clauses <> [] then
        invalid_arg "a closure method requires explicit source own type/const/dictionary instantiation";
      let occupied = caller.view.arguments.parameters @ source_method.binder_params.regions in
      let largest = List.fold_left (fun current (parameter : region_param) -> Stdlib.max current (RegionId.to_int parameter.index)) (-1) occupied in
      if largest >= Int.max_int - List.length source_method.binder_params.regions - 1 then invalid_arg "source closure own lifetimes exceed construction identifier space";
      let own_parameters = List.mapi (fun index (parameter : region_param) ->
        { parameter with index = RegionId.of_int (largest + index + 1) }) source_method.binder_params.regions in
      let pointer = Method_instance.open_source (List.map (fun (parameter : region_param) -> RVar (Free parameter.index)) own_parameters) source_method in
      let routing = Method_instance.create source_method pointer in
      let resolution = Static_targets.resolve crate pointer in
      if resolution.obligations <> [] then invalid_arg "an actual closure source method retains unresolved declared predicates";
      let definition, method_substitution = Callable_instance.source_substitution crate resolution.pointer in
      (match definition.body with StructuredBody _ -> ()
       | _ -> invalid_arg "an actual captured callback requires its original source body, not a supplied result");
      let signature_normalizer = new Static_targets.normalize crate in
      let signature = signature_normalizer#visit_fun_sig 0
        (Substitute.st_substitute_visitor#visit_fun_sig method_substitution definition.signature) in
      signature_normalizer#check_requirements;
      if signature_normalizer#obligations <> [] then invalid_arg "the actual closure method signature retains unresolved source predicates";
      let parameters = caller.view.arguments.parameters @ own_parameters in
      let method_scope = new Region_scope.statement_check ~body_regions:frame.source_body.bound_body_regions parameters in
      method_scope#visit_fn_ptr [] resolution.pointer; method_scope#visit_fun_sig [] signature;
      let closed = new Closed_arguments.statement_check ~body_regions:frame.source_body.bound_body_regions parameters in
      closed#visit_fn_ptr [] resolution.pointer;
      closed#visit_fun_sig [] signature;
      { role; owner; source_method; own_parameters; routing; resolution; signature }
    ) (TraitMethodId.Map.bindings implementation.methods)
  ) roots in
  { caller; statement; reference; source_type; type_resolution; source_info; actual_info; field_types; source_operands;
    box_fields; constraints; members }

let replay crate witness = try derive crate ~caller:witness.caller witness.statement.statement_id = witness
  with Invalid_argument _ | Not_found -> false

let create crate ~(caller : Source_closure.node) statement_id =
  if Function_frame.prepare crate caller.view <> Source_call.frame caller then
    invalid_arg "closure capture requires its actual complete prepared source frame";
  let witness = derive crate ~caller statement_id in
  if not (replay crate witness) then invalid_arg "the complete actual source closure capture/method family did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["caller_node", `Int witness.caller.index; "source_statement", `Int (StatementId.to_int witness.statement.statement_id);
    "actual_source_closure_type", `String (show_type_decl_ref witness.reference);
    "captured_box_fields", `List (List.map (fun index -> `Int index) witness.box_fields);
    "actual_field_types", `List (List.map (fun ty -> `String (show_ty ty)) witness.field_types);
    "actual_source_operands", `List (List.map (fun source -> `String (show_operand source)) witness.source_operands);
    "complete_original_source_type_premises", region_certificate_json witness.constraints;
    "actual_source_method_families", `List (List.map (fun member -> `Assoc [
      "role", `String (show_closure_kind member.role); "routing", Method_instance.report member.routing;
      "actual_source_pointer", `String (show_fn_ptr member.resolution.pointer);
      "actual_source_signature", `String (show_fun_sig member.signature);
      "own_parameters_are_universal_source_binders", `Bool true;
      "native_callback_call_context_bound", `Bool false]) witness.members);
    "complete_actual_closure_capture_replays", `Bool (replay crate witness);
    "closure_capture_loan_iterator_call_and_native_carrier_effect_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
