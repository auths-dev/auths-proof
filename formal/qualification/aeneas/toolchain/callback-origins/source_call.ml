(* Exact actual source call/edge instantiation. The complete caller and callee
   views, signatures, operands, result and source typing premises are retained.
   This constructs a source interface, never a runtime result or simulation. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  caller : Source_closure.node;
  callee : Source_closure.node;
  source_statement : statement;
  call : call;
  unwind : block;
  edge : Source_closure.edge;
  arguments : Region_shape.factorization;
  instantiated_signature : fun_sig;
  requirements : (ty * ty) list;
  constraints : Region_equations.predicates;
  normalized_arguments : region list;
}

let frame (node : Source_closure.node) = match node.frame with Some frame -> frame
  | None -> invalid_arg "a captured source return call requires its actual prepared caller and callee frames"

let actual_view crate (node : Source_closure.node) =
  match FunDeclId.Map.find_opt node.declaration.def_id crate.fun_decls with
  | Some declaration when declaration = node.declaration && Instance_view.replay declaration node.view -> ()
  | _ -> invalid_arg "a source return call changed its complete original declaration/argument/Self view"

let instantiate_signature ~(parameters : region_param list) ~arguments signature =
  if List.length parameters <> List.length arguments then
    invalid_arg "a source return call lost a declared callee lifetime argument";
  let source_scope = new Region_scope.check parameters in
  source_scope#visit_fun_sig [] signature;
  let bindings = List.combine (List.map (fun (parameter : region_param) -> parameter.index) parameters) arguments in
  let mapper = object inherit [_] Region_shape.binder_map
    method! visit_region depth = function
      | RVar (Free id) -> (match List.assoc_opt id bindings with Some region -> Region_shape.under depth region
          | None -> invalid_arg "the actual callee interface contains an unbound source lifetime")
      | RBody _ | RErased -> invalid_arg "a public source call signature cannot export a private or erased callee lifetime"
      | region -> region
  end in mapper#visit_fun_sig 0 signature

(* A normalized default-method function pointer does not necessarily contain
   its source Self dictionary. Recover that dictionary only from this exact
   original call site, replayed under its caller certificate, then match the
   entire recorded source binding. Never infer it from another call/type. *)
let site_resolution crate ~(caller : Source_closure.node) statement_id =
  actual_view crate caller;
  let caller_frame = frame caller in
  let actual = Prepared_injection.unique_statement caller_frame.body statement_id in
  let pointer = match actual.kind with Call ({ func = FnOpRegular pointer; _ }, _) -> pointer
    | _ -> invalid_arg "an actual source call site requires its normalized regular pointer" in
  let raw_body = match caller.view.locals_and_body with Some (_, body) -> body
    | None -> invalid_arg "the original source call body is absent" in
  let original = Prepared_injection.unique_statement raw_body statement_id in
  let original_pointer = match original.kind with Call ({ func = FnOpRegular pointer; _ }, _) -> pointer
    | _ -> invalid_arg "the actual normalized call lost its original source pointer" in
  let regions = Function_frame.region_mapper caller_frame.region_certificate.solution in
  let replayed_pointer = regions#visit_fn_ptr () original_pointer in
  let resolution = Static_targets.resolve crate replayed_pointer in
  if resolution.pointer <> pointer || resolution.obligations <> [] then
    invalid_arg "the actual call pointer did not reconstruct from its complete original call-site/Self source";
  let bindings = List.filter (fun (binding : Function_frame.call_binding) ->
    binding.original = replayed_pointer && binding.direct = pointer && binding.self_evidence = resolution.self_evidence) caller_frame.bindings in
  let binding = match bindings with first :: rest when List.for_all ((=) first) rest -> first
    | _ -> invalid_arg "the actual source call site has no unique complete original frame binding" in
  resolution, binding

let derive crate ~(caller : Source_closure.node) ~(callee : Source_closure.node) statement_id =
  actual_view crate caller; actual_view crate callee;
  let caller_frame = frame caller and callee_frame = frame callee in
  let source_statement = Prepared_injection.unique_statement caller_frame.body statement_id in
  let call, unwind, pointer = match source_statement.kind with
    | Call (({ func = FnOpRegular pointer; _ } as call), unwind) -> call, unwind, pointer
    | _ -> invalid_arg "a captured return must attach to its actual regular source call statement" in
  let resolved, source_binding = site_resolution crate ~caller statement_id in
  (match pointer.kind with FunId (FRegular id) when id = callee.declaration.def_id -> ()
   | _ -> invalid_arg "the source result and return summary identify different actual functions");
  let edges = List.filter (fun (edge : Source_closure.edge) -> edge.binding = source_binding &&
    edge.target = Source_closure.Instance callee.index) caller.callees in
  let edge = match edges with first :: rest when List.for_all ((=) first) rest -> first
    | _ -> invalid_arg "the actual result call has no unique complete source dependency edge" in
  let arguments, _, _ = Instance_view.factor_context pointer.generics resolved.self_evidence in
  if arguments.pattern <> callee.view.arguments.pattern || arguments.parameters <> callee.view.arguments.parameters then
    invalid_arg "the source return edge changed the complete factored callee argument/Self context";
  let instantiated_signature = instantiate_signature ~parameters:callee.view.arguments.parameters
    ~arguments:arguments.arguments callee_frame.signature in
  let caller_scope = new Region_scope.statement_check ~body_regions:caller_frame.source_body.bound_body_regions caller.view.arguments.parameters in
  caller_scope#visit_statement [] source_statement;
  caller_scope#visit_fun_sig [] instantiated_signature;
  let inputs = List.map Vtable_dispatch.operand_type call.args in
  if List.length inputs <> List.length instantiated_signature.inputs then
    invalid_arg "the actual source result call changed its complete argument arity";
  let requirements = List.combine instantiated_signature.inputs inputs @ [instantiated_signature.output, call.dest.ty] in
  let constraints = List.fold_left (fun constraints (expected, actual) ->
    Region_equations.add_type constraints expected actual) caller_frame.region_certificate requirements in
  if not (Region_equations.replay_predicates constraints) then
    invalid_arg "the complete actual source call input/result typing premises did not replay";
  let normalized_arguments = List.map (Region_equations.resolve constraints.solution) arguments.arguments in
  { caller; callee; source_statement; call; unwind; edge; arguments; instantiated_signature; requirements;
    constraints; normalized_arguments }

let replay crate witness = try derive crate ~caller:witness.caller ~callee:witness.callee
  witness.source_statement.statement_id = witness with Invalid_argument _ | Not_found -> false

let create crate ~(caller : Source_closure.node) ~(callee : Source_closure.node) statement_id =
  if Function_frame.prepare crate caller.view <> frame caller ||
     Function_frame.prepare crate callee.view <> frame callee then
    invalid_arg "source call binding requires complete actual prepared source frames";
  let witness = derive crate ~caller ~callee statement_id in
  if not (replay crate witness) then invalid_arg "the complete actual source call/edge/ABI did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let regions = Function_frame.region_mapper witness.constraints.solution in
  `Assoc ["caller_node", `Int witness.caller.index; "callee_node", `Int witness.callee.index;
    "caller_function", `Int (FunDeclId.to_int witness.caller.declaration.def_id);
    "callee_function", `Int (FunDeclId.to_int witness.callee.declaration.def_id);
    "source_statement", `Int (StatementId.to_int witness.source_statement.statement_id);
    "source_call", `String (show_call witness.call);
    "actual_original_source_pointer", `String (show_fn_ptr witness.edge.binding.original);
    "actual_original_self_dictionary", (match witness.edge.binding.self_evidence with Some evidence -> `String (show_trait_ref evidence) | None -> `Null);
    "source_result_place", `String (show_place witness.call.dest);
    "complete_actual_callee_signature", `String (show_fun_sig witness.instantiated_signature);
    "callee_original_opaque_signature_refinement_required", (match (frame witness.callee).return_signature with
      | Some candidate -> Return_signature.report crate candidate | None -> `Null);
    "actual_callee_region_arguments", `List (List.map (fun region -> `String (show_region region)) witness.arguments.arguments);
    "callee_arguments_after_caller_source_premises", `List (List.map (fun region -> `String (show_region region)) witness.normalized_arguments);
    "caller_original_source_type_premises", region_certificate_json witness.constraints;
    "full_argument_result_equalities", `List (List.map (fun (expected, actual) -> `Assoc [
      "expected", `String (show_ty expected); "actual", `String (show_ty actual);
      "raw_equal", `Bool (expected = actual);
      "equal_under_original_source_premises", `Bool (regions#visit_ty () expected = regions#visit_ty () actual)]) witness.requirements);
    "complete_actual_source_call_replays", `Bool (replay crate witness);
    "source_call_replaced_or_result_supplied", `Bool false;
    "native_call_activation_loan_ownership_and_unwind_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
