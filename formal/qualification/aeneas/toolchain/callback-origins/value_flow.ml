(* Connect actual source access/definition trees to actual capture fields and
   callee parameter positions. These edges do not assert a unique caller,
   runtime activation identity or preservation through aliases/iterations.
   Those remain semantic obligations, not type-based value equalities. *)
open Charon
open LlbcAst

type destination =
  | CapturedField of Closure_capture.t * int
  | CalleeParameter of Source_call.t * int
type edge = { origin : Value_origin.t; destination : destination }
type t = { context : Value_origin.context; edges : edge list; failures : (int * statement_id * string) list }

let build crate ~captures ~closure_returns ~box_returns ~reference_accesses ~box_receivers
    ~(effects : Carrier_effect.graph) ~arguments ~receivers =
  let context : Value_origin.context = { captures; closure_returns; box_returns; reference_accesses; box_receivers } in
  let edges = ref [] and failures = ref [] in
  let add node statement operand destination =
    try let origin = Value_origin.create crate ~context ~node statement operand in
      edges := { origin; destination } :: !edges
    with Invalid_argument message -> failures := (node.Source_closure.index, statement, message) :: !failures
      | Source_path.Not_dominating -> failures := (node.Source_closure.index, statement,
          "the actual source value point has no conditional lexical predecessor path") :: !failures in
  List.iter (fun (capture : Closure_capture.t) ->
    List.iteri (fun index operand ->
      add capture.caller capture.statement.statement_id operand (CapturedField (capture, index))) capture.source_operands) captures;
  let seen = Hashtbl.create 32 in
  let call_argument (binding : Source_call.t) index =
    let key = binding.caller.index, binding.source_statement.statement_id, index in
    if not (Hashtbl.mem seen key) then (
      Hashtbl.add seen key ();
      if not (Source_call.replay crate binding) then invalid_arg "an actual source value-flow call lost its complete binding";
      if index < 0 || index >= List.length binding.call.args then invalid_arg "an actual value-flow callee parameter is absent";
      add binding.caller binding.source_statement.statement_id (List.nth binding.call.args index) (CalleeParameter (binding, index))) in
  List.iter (fun (footprint : Carrier_effect.t) -> List.iter (fun (call : Carrier_effect.call_effect) ->
    match call.binding with Some binding -> List.iter (call_argument binding) call.tracked_arguments | None -> ()) footprint.calls) effects.nodes;
  List.iter (fun (argument : Closure_argument.t) -> call_argument argument.binding argument.argument_index) arguments;
  List.iter (fun (receiver : Box_receiver_call.t) ->
    call_argument receiver.consumer (Charon.Expressions.LocalId.to_int receiver.receiver.receiver_origin.argument - 1)) receivers;
  (* Every actual returned closure field needs its actual source input, including
     an ordinary counter reference. This does not invent mappings for other
     ordinary call results or remove their native effect/model obligations. *)
  List.iter (fun (returned : Closure_return_call.t) ->
    List.iteri (fun index _ -> call_argument returned.binding index) returned.binding.call.args) closure_returns;
  { context; edges = List.rev !edges; failures = List.rev !failures }

let replay_edge crate ~context edge =
  Value_origin.replay crate ~context edge.origin &&
    match edge.destination with
    | CapturedField (capture, index) ->
        Closure_capture.replay crate capture && capture.caller = edge.origin.node && capture.statement = edge.origin.target &&
        index >= 0 && index < List.length capture.source_operands && List.nth capture.source_operands index = edge.origin.operand
    | CalleeParameter (binding, index) ->
        Source_call.replay crate binding && binding.caller = edge.origin.node && binding.source_statement = edge.origin.target &&
        index >= 0 && index < List.length binding.call.args && List.nth binding.call.args index = edge.origin.operand

let report crate graph = `Assoc [
  "actual_source_value_edges", `List (List.map (fun edge -> `Assoc [
    "actual_definition_and_access", Value_origin.report crate ~context:graph.context edge.origin;
    "actual_destination", (match edge.destination with
      | CapturedField (capture, index) -> `Assoc ["kind", `String "actual_source_capture_field";
          "source_node", `Int capture.caller.index; "source_statement", `Int (StatementId.to_int capture.statement.statement_id);
          "actual_field_index", `Int index]
      | CalleeParameter (binding, index) -> `Assoc ["kind", `String "actual_source_call_parameter";
          "caller", `Int binding.caller.index; "callee", `Int binding.callee.index;
          "source_statement", `Int (StatementId.to_int binding.source_statement.statement_id);
          "zero_based_parameter_index", `Int index;
          "fresh_native_call_activation_and_parameter_value_transport_proved", `Bool false]);
    "complete_source_edge_replays", `Bool (replay_edge crate ~context:graph.context edge)]) graph.edges);
  "failures", `List (List.map (fun (node, statement, message) -> `Assoc ["source_node", `Int node;
    "source_statement", `Int (StatementId.to_int statement); "error", `String message]) graph.failures);
  "native_origin_composition_loop_alias_and_activation_simulation_proved", `Bool false;
  "qualified", `Bool false; "program_emitted", `Bool false]
