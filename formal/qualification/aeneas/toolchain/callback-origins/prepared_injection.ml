(* Concrete-to-dynamic construction at an actual prepared source instance.
   The source cast, exact static/dictionary pair and full lifetime capture
   environment identify a producer case. Native unsize/loan/ownership
   simulation and propagation of that paired value still have to be proved. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  original : Vtable_injection.t;
  view : Instance_view.t;
  frame : Function_frame.t;
  statement : statement;
  destination : place;
  operand : operand;
  from_type : ty;
  into_type : ty;
  dictionary : trait_ref;
  metadata : constant_expr;
  global_reference : global_decl_ref;
  global : Global_view.t;
  capture_environment : region list;
  implementation : trait_impl_ref;
  concrete_self : ty;
  carrier : Vtable_injection.carrier;
  object_region : region;
  inherited_requirements : generic_params;
  constraints : Region_equations.predicates;
}

let unique_statement block id =
  let found = ref [] in
  let collect = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = id then found := statement :: !found;
      super#visit_statement env statement
  end in collect#visit_block () block;
  match !found with [statement] -> statement
    | _ -> invalid_arg "a prepared injection requires one exact original source statement ID"

let derive crate ~(view : Instance_view.t) ~(frame : Function_frame.t) statement_id =
  if view.original_id <> frame.original_function_id then
    invalid_arg "a prepared injection changed its original source function";
  let caller = match FunDeclId.Map.find_opt view.original_id crate.fun_decls with Some caller -> caller
    | None -> invalid_arg "the original source injection caller is absent" in
  let original_body = match caller.body with StructuredBody body -> body
    | _ -> invalid_arg "a prepared injection requires its actual structured source body" in
  let original = Vtable_injection.create crate ~caller (unique_statement original_body.body statement_id) in
  let statement = unique_statement frame.body statement_id in
  let destination, from_type, into_type, dictionary, metadata, operand = match statement.kind with
    | Assign (destination, UnaryOp (Cast (CastUnsize (from_type, into_type, MetaVTable (dictionary, metadata))), operand)) ->
        destination, from_type, into_type, dictionary, metadata, operand
    | _ -> invalid_arg "a prepared source injection changed its original value-to-vtable cast" in
  let scope = new Region_scope.statement_check ~body_regions:frame.source_body.bound_body_regions view.arguments.parameters in
  scope#visit_statement [] statement;
  let closed = new Closed_arguments.statement_check ~body_regions:frame.source_body.bound_body_regions view.arguments.parameters in
  closed#visit_statement [] statement;
  let global_reference, value_type = match metadata.kind, metadata.ty with
    | CRef ({ kind = CGlobal reference; ty }, None), TRef (RStatic, outer, RShared) when ty = outer -> reference, ty
    | _ -> invalid_arg "a prepared injection lost its actual static shared vtable reference" in
  if global_reference.id <> original.global_reference.id then
    invalid_arg "a prepared injection substituted another original vtable static";
  let resolution = Static_targets.resolve_global crate global_reference in
  if resolution.global_obligations <> [] || resolution.global_reference <> global_reference then
    invalid_arg "the actual prepared vtable capture does not replay strict source normalization";
  let global = Global_view.create crate resolution in
  Closed_arguments.require ~parameters:global.arguments.parameters global.call_arguments;
  let capture_environment = global.arguments.arguments in
  if Region_shape.instantiate global.arguments <> global_reference.generics then
    invalid_arg "a prepared injection changed its full actual lifetime capture environment";
  let actual_global_substitution = Substitute.make_subst_from_generics global.declaration.generics global_reference.generics Self in
  if Substitute.ty_substitute actual_global_substitution global.declaration.ty <> value_type then
    invalid_arg "a prepared injection's actual metadata has another complete source vtable type";
  let static_owner = Substitute.st_substitute_visitor#visit_trait_impl_ref actual_global_substitution original.source_vtable.owner in
  let implementation = match dictionary.kind with TraitImpl owner when owner.id = static_owner.id -> owner
    | _ -> invalid_arg "the prepared dictionary and static metadata select different source implementations" in
  let declaration = original.source_vtable.implementation in
  Static_targets.require_argument_arity declaration.generics implementation.generics;
  let substitution = Substitute.make_subst_from_generics declaration.generics implementation.generics dictionary.kind in
  let predicate = Substitute.trait_decl_ref_substitute substitution declaration.impl_trait in
  let concrete_self = match predicate.generics.types with self :: _ -> self
    | _ -> invalid_arg "the prepared source implementation has no actual Self type" in
  let carrier, object_region, source_self = Vtable_injection.classify_carrier
    ~owner:original.source_vtable.shape.source_predicate ~from_type ~into_type operand in
  let constraints = Region_equations.add_arguments Region_equations.empty_predicates implementation.generics static_owner.generics in
  let constraints = Region_equations.add_predicate constraints { binder_regions = []; binder_value = predicate } dictionary.trait_decl_ref in
  let constraints = Region_equations.add_type constraints concrete_self source_self in
  let constraints = Region_equations.add_type constraints into_type destination.ty in
  if not (Region_equations.replay_predicates constraints) then
    invalid_arg "the complete prepared source injection does not reconstruct its actual value/dictionary/static";
  let inherited_requirements = Substitute.predicates_substitute substitution declaration.generics in
  scope#visit_generic_params [] inherited_requirements;
  { original; view; frame; statement; destination; operand; from_type; into_type; dictionary; metadata;
    global_reference; global; capture_environment; implementation; concrete_self; carrier; object_region;
    inherited_requirements; constraints }

let replay crate witness = try derive crate ~view:witness.view ~frame:witness.frame witness.statement.statement_id = witness
  with Invalid_argument _ -> false

let create crate ~view ~frame statement_id =
  if Function_frame.prepare crate view <> frame then
    invalid_arg "a prepared injection requires its complete actual source frame replay";
  let witness = derive crate ~view ~frame statement_id in
  if not (replay crate witness) then invalid_arg "the complete prepared source injection/capture did not replay";
  witness

let same_capture (left : Global_view.t) (right : Global_view.t) =
  left.declaration = right.declaration && left.call_arguments = right.call_arguments &&
  left.arguments.parameters = right.arguments.parameters && left.self_evidence = right.self_evidence &&
  left.ty = right.ty && left.value = right.value && left.inherited_requirements = right.inherited_requirements

let open_capture ~parameters ~(source_global : Global_view.t) witness =
  if not (same_capture source_global witness.global) then
    invalid_arg "a producer cannot select a case from a different actual source capture";
  Region_scope.require_parameters parameters;
  if List.length parameters <> List.length witness.capture_environment then
    invalid_arg "a source producer must open the complete exact captured lifetime environment";
  let bindings = List.combine (List.map (fun (parameter : region_param) -> parameter.index) parameters) witness.capture_environment in
  let rename = object inherit [_] Region_shape.binder_map
    method! visit_region depth = function
      | RVar (Free id) -> (match List.assoc_opt id bindings with Some region -> Region_shape.under depth region
          | None -> invalid_arg "an opened capture contains an unrelated free lifetime parameter")
      | region -> region
  end in
  rename

let virtual_self ~candidate witness =
  let opening = open_capture ~parameters:candidate.Virtual_shim.capture_parameters ~source_global:candidate.source_global witness in
  if not (Region_equations.replay_predicates witness.constraints) then
    invalid_arg "a virtual capture opening requires its complete original source equations";
  let source_regions = Function_frame.region_mapper witness.constraints.solution in
  let actual = source_regions#visit_ty () (opening#visit_ty 0 candidate.concrete_self) in
  if actual <> source_regions#visit_ty () witness.concrete_self then
    invalid_arg "a produced virtual case changed its complete concrete Self value type";
  actual

let instance_self ~(candidate : Vtable_instance.t) witness =
  let opening = open_capture ~parameters:candidate.capture_parameters ~source_global:candidate.source_global witness in
  let declaration = candidate.family.branch.source_vtable.implementation in
  let substitution = Substitute.make_subst_from_generics declaration.generics candidate.owner_arguments Self in
  let predicate = Substitute.trait_decl_ref_substitute substitution declaration.impl_trait in
  let captured = match predicate.generics.types with self :: _ -> self
    | _ -> invalid_arg "a concrete capture candidate has no actual source Self" in
  if not (Region_equations.replay_predicates witness.constraints) then
    invalid_arg "a method capture opening requires its complete original source equations";
  let source_regions = Function_frame.region_mapper witness.constraints.solution in
  let actual = source_regions#visit_ty () (opening#visit_ty 0 captured) in
  if actual <> source_regions#visit_ty () witness.concrete_self then
    invalid_arg "a produced method case changed its complete concrete Self value type";
  actual

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_function", `Int (FunDeclId.to_int witness.view.original_id);
    "source_statement", `Int (StatementId.to_int witness.statement.statement_id);
    "source_global", `Int (GlobalDeclId.to_int witness.global_reference.id);
    "source_implementation", `Int (TraitImplId.to_int witness.implementation.id);
    "original_concrete_operand", `String (show_operand witness.operand);
    "source_destination", `String (show_place witness.destination);
    "source_from_type", `String (show_ty witness.from_type); "source_into_type", `String (show_ty witness.into_type);
    "actual_dictionary", `String (show_trait_ref witness.dictionary);
    "actual_static_metadata", `String (show_constant_expr witness.metadata);
    "closed_capture_pattern", `String (show_generic_args witness.global.call_arguments);
    "actual_capture_environment", `List (List.map (fun region -> `String (show_region region)) witness.capture_environment);
    "concrete_self", `String (show_ty witness.concrete_self);
    "source_type_constraints", region_certificate_json witness.constraints;
    "case_opening_uses_only_recorded_original_source_equations", `Bool true;
    "source_where_requirements", `String (show_generic_params witness.inherited_requirements);
    "source_carrier", `String (match witness.carrier with Vtable_injection.OwnedBox _ -> "owned_box_move" | Borrowed _ -> "borrowed");
    "original_object_region", `String (show_region witness.object_region);
    "complete_actual_source_producer_replays", `Bool (replay crate witness);
    "native_unsize_loan_ownership_and_paired_value_propagation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
