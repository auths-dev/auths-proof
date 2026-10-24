(* Complete source-body footprint for the actual iterator/callback carrier
   subgraph. This rejects direct carrier replacement/escape and retains every
   call, destructor, branch, loop, abort and unwind. It does not infer that an
   opaque callee or an unrelated ordinary call preserves a native alias. Native
   activation/loan/alias simulation and the semantic loop invariant remain
   required before this syntax footprint can license carrier preservation. *)
open Charon
open Types
open Expressions
open LlbcAst

type call_effect = {
  statement : statement;
  source_call : call;
  tracked_arguments : int list;
  tracked_result : bool;
  callee : int option;
  binding : Source_call.t option;
  unresolved : string option;
  payload_forwarding : Box_carrier.t option;
  returned_closure : Closure_return_call.t option;
}
type t = {
  node : Source_closure.node;
  statements : statement_id list;
  calls : call_effect list;
  drops : (statement * Function_frame.drop_binding * bool) list;
  switches : statement list;
  loops : statement list;
  exits : statement list;
  projected_data_writes : statement list;
  source_box_accesses : Virtual_receiver.box_access list;
  source_reference_accesses : statement list;
  retags : statement list;
}
type graph = { roots : int list; nodes : t list; failures : (int * string) list }

let carries crate ty = Closure_capture.carries_box crate 0 [] ty || Option.is_some (Capture_return.predicate ty)

let local_destination (destination : place) = match destination.kind with PlaceLocal _ -> true | _ -> false

let derive crate ~(source : Source_closure.t) ~(node : Source_closure.node)
    ~(receivers : Virtual_receiver.t list) ~(accessors : Closure_receiver.t list)
    ~(returned_closures : Closure_return_call.t list) =
  Source_call.actual_view crate node;
  let frame = Source_call.frame node in
  if not (List.mem node source.nodes) || Function_frame.prepare crate node.view <> frame then
    invalid_arg "a carrier footprint needs its complete actual prepared source node and frame";
  let receivers = List.filter (fun (receiver : Virtual_receiver.t) -> receiver.view = node.view && receiver.frame = frame) receivers in
  let box_accesses = List.concat_map (fun (receiver : Virtual_receiver.t) -> receiver.box_accesses) receivers in
  let reference_accesses = List.filter_map (fun (accessor : Closure_receiver.t) ->
    if accessor.consumer.caller = node then Some accessor.address_load else None) accessors in
  let statements = ref StatementId.Set.empty and ordered = ref [] in
  let calls = ref [] and drops = ref [] and switches = ref [] and loops = ref [] and exits = ref [] and writes = ref [] and retags = ref [] in
  let relevant ty = carries crate ty in
  let operand_relevant operand = relevant (Vtable_dispatch.operand_type operand) in
  let require_move = function
    | Move { kind = PlaceLocal _; _ } -> ()
    | _ -> invalid_arg "a carrier footprint cannot copy or project an exclusive captured value into another owner" in
  let is_source_address_load statement = List.mem statement reference_accesses ||
    List.exists (fun (access : Virtual_receiver.box_access) -> access.statement = statement) box_accesses in
  let has_source rvalue =
    let found = ref false in
    let scan = object inherit [_] iter_statement
      method! visit_place _ place = if relevant place.ty then found := true
      method! visit_operand _ operand = if operand_relevant operand then found := true
    end in scan#visit_rvalue () rvalue; !found in
  let callee_for statement_id (pointer : fn_ptr) = match pointer.kind with
    | FunId (FRegular id) ->
        let resolution, _ = Source_call.site_resolution crate ~caller:node statement_id in
        let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
        List.find_opt (fun (callee : Source_closure.node) ->
          callee.declaration.def_id = id && callee.view.arguments.pattern = arguments.pattern) source.nodes
    | _ -> None in
  let collect = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if StatementId.Set.mem statement.statement_id !statements then
        invalid_arg "the actual carrier footprint has ambiguous source statement identities";
      statements := StatementId.Set.add statement.statement_id !statements;
      ordered := statement.statement_id :: !ordered;
      (match statement.kind with
       | Assign (destination, rvalue) ->
           (match rvalue with Use (_, YesRetag) -> retags := statement :: !retags | _ -> ());
           if relevant destination.ty && not (local_destination destination) then
             invalid_arg "a source callback writes through a captured carrier/reference field";
           if Option.is_some (Capture_return.predicate destination.ty) && not (is_source_address_load statement) then
             invalid_arg "a source callback replaces or creates a Box owner without its explicit injection/ownership interface";
           if relevant destination.ty || has_source rvalue then (
             match rvalue with
             | Use (Move source, NoRetag) -> if relevant source.ty then require_move (Move source)
             | Use (Move source, YesRetag) -> if relevant source.ty then require_move (Move source)
             | Use (Copy { ty = TRef (_, _, RShared); _ }, NoRetag) -> ()
             | Use (Copy _, NoRetag) when is_source_address_load statement -> ()
             | RvRef (_, (BMut | BTwoPhaseMut | BShared), _) -> ()
             | Aggregate (AggregatedAdt (reference, None, None), operands)
                 when Closure_capture.is_box_capture crate reference ->
                 ignore (Closure_capture.create crate ~caller:node statement.statement_id);
                 List.iter (fun operand -> if operand_relevant operand then require_move operand) operands
             | _ -> invalid_arg "an actual carrier rvalue needs an explicit address/value/escape rule");
           if not (local_destination destination) then writes := statement :: !writes
       | Call (call, _) ->
           if relevant call.dest.ty && not (local_destination call.dest) then
             invalid_arg "a source callback call result overwrites a captured carrier/reference field";
           let tracked_arguments = List.mapi (fun index operand -> index, operand) call.args |> List.filter_map (fun (index, operand) ->
             if operand_relevant operand then (require_move operand; Some index) else None) in
           let tracked_result = relevant call.dest.ty in
           let returned_closure = match List.filter (fun (returned : Closure_return_call.t) ->
             returned.binding.caller = node && returned.binding.source_statement = statement) returned_closures with
             | [] -> None
             | [returned] -> if not (Closure_return_call.replay crate returned) then
                   invalid_arg "the actual carrier-bearing return lost its complete source closure/capture binding";
                 Some returned
             | _ -> invalid_arg "the actual carrier-bearing return has ambiguous source closure provenance" in
           let payload_forwarding = match List.filter (fun (receiver : Virtual_receiver.t) -> receiver.source_statement = statement) receivers with
             | [receiver] -> Some (Box_carrier.create receiver)
             | [] -> None
             | _ -> invalid_arg "the actual carrier payload forwarding site has ambiguous receiver provenance" in
           let callee, binding, unresolved = match call.func with
             | FnOpRegular pointer ->
                 (match callee_for statement.statement_id pointer with
                  | Some callee when Option.is_some callee.frame ->
                      let binding = if tracked_arguments <> [] || tracked_result then
                        Some (Source_call.create crate ~caller:node ~callee statement.statement_id) else None in
                      let unresolved = if tracked_result && Option.is_none returned_closure then
                          Some "the actual carrier-bearing result needs its complete original source return/value mapping"
                        else if tracked_arguments = [] && not tracked_result then
                          Some "the ordinary call still needs its exact source/primitive effect and native alias-disjointness contract"
                        else None in
                      Some callee.index, binding, unresolved
                  | Some callee -> Some callee.index, None, Some "the actual source callee is an ordinary leaf; its effect contract remains required"
                  | None when Option.is_some payload_forwarding -> None, None, Some "actual payload forwarding still needs native loan/alias and primitive effect simulation"
                  | None -> None, None, Some "the actual callee has no prepared regular source body; no preservation summary is supplied")
             | _ -> invalid_arg "an actual carrier footprint cannot guess a dynamic call target" in
           calls := { statement; source_call = call; tracked_arguments; tracked_result;
             callee; binding; unresolved; payload_forwarding; returned_closure } :: !calls
       | Drop (place, pointer, _, _) ->
           if Option.is_some (Capture_return.predicate place.ty) then
             invalid_arg "a callback footprint destroys its actual Box owner";
           let binding = match List.filter (fun (binding : Function_frame.drop_binding) ->
             binding.drop_statement_id = statement.statement_id && binding.normalized_drop = pointer) frame.drop_bindings with
             | [binding] -> binding
             | _ -> invalid_arg "an actual carrier cleanup lost its complete original destructor binding" in
           drops := (statement, binding, relevant place.ty) :: !drops
       | Switch _ -> switches := statement :: !switches
       | Loop _ -> loops := statement :: !loops
       | Return | Abort _ | UnwindResume | Break _ | Continue _ -> exits := statement :: !exits
       | StorageDead id ->
           let declared = match List.find_opt (fun (local : local) -> local.index = id) frame.locals with Some local -> local
             | None -> invalid_arg "an actual carrier footprint references undeclared storage" in
           let source_alias = List.exists (fun (access : Virtual_receiver.box_access) ->
             access.destination.kind = PlaceLocal id) box_accesses in
           if Option.is_some (Capture_return.predicate declared.local_ty) && not source_alias then
             invalid_arg "a callback footprint discards a Box owner without its actual move/destructor interface"
       | Assert _ | StorageLive _ | PlaceMention _ | Nop -> ()
       | SetDiscriminant _ | CopyNonOverlapping _ | InlineAsm _ | Error _ ->
           invalid_arg "an actual callback carrier footprint contains an unsupported memory/control effect");
      super#visit_statement env statement
  end in collect#visit_block () frame.body;
  { node; statements = List.rev !ordered; calls = List.rev !calls; drops = List.rev !drops;
    switches = List.rev !switches; loops = List.rev !loops; exits = List.rev !exits;
    projected_data_writes = List.rev !writes; source_box_accesses = box_accesses; source_reference_accesses = reference_accesses;
    retags = List.rev !retags }

let replay crate ~source ~receivers ~accessors ~returned_closures witness =
  try derive crate ~source ~node:witness.node ~receivers ~accessors ~returned_closures = witness
  with Invalid_argument _ | Not_found -> false

let build crate ~(source : Source_closure.t) ~roots ~receivers ~accessors ~returned_closures =
  let roots = List.sort_uniq Int.compare roots in
  let pending = Queue.create () in List.iter (fun index -> Queue.add index pending) roots;
  let seen = Hashtbl.create 32 in
  let nodes = ref [] and failures = ref [] in
  while not (Queue.is_empty pending) do
    let index = Queue.take pending in
    if not (Hashtbl.mem seen index) then (
      Hashtbl.add seen index ();
      if Hashtbl.length seen > 50000 then invalid_arg "carrier source dependency closure exceeds its explicit construction limit";
      try
        let node = match List.find_opt (fun (node : Source_closure.node) -> node.index = index) source.nodes with Some node -> node
          | None -> invalid_arg "an actual carrier source dependency node is missing" in
        let footprint = derive crate ~source ~node ~receivers ~accessors ~returned_closures in
        List.iter (fun call -> if call.tracked_arguments <> [] || call.tracked_result then
          match call.callee, call.binding with Some index, Some _ -> Queue.add index pending | _ -> ()) footprint.calls;
        nodes := footprint :: !nodes
      with Invalid_argument message -> failures := (index, message) :: !failures)
  done;
  { roots; nodes = List.rev !nodes; failures = List.rev !failures }

let report crate (graph : graph) =
  let open Diagnostic in
  `Assoc ["actual_source_roots", `List (List.map (fun index -> `Int index) graph.roots);
    "actual_source_body_footprints", `List (List.map (fun (footprint : t) -> `Assoc [
      "source_node", `Int footprint.node.index;
      "complete_original_statements", `List (List.map (fun id -> `Int (StatementId.to_int id)) footprint.statements);
      "calls", `List (List.map (fun call -> `Assoc [
        "source_statement", `Int (StatementId.to_int call.statement.statement_id);
        "actual_source_call", `String (show_call call.source_call);
        "tracked_argument_indices", `List (List.map (fun index -> `Int index) call.tracked_arguments);
        "tracked_result", `Bool call.tracked_result;
        "actual_callee_node", (match call.callee with Some index -> `Int index | None -> `Null);
        "complete_actual_call_binding", (match call.binding with Some binding -> Source_call.report crate binding | None -> `Null);
        "unresolved_effect_contract", (match call.unresolved with Some reason -> `String reason | None -> `Null);
        "actual_returned_closure_value", (match call.returned_closure with Some returned -> Closure_return_call.report crate returned | None -> `Null);
        "actual_payload_forwarding", (match call.payload_forwarding with Some footprint -> Box_carrier.report footprint | None -> `Null)]) footprint.calls);
      "retained_destructors", `List (List.map (fun (statement, (binding : Function_frame.drop_binding), tracked) -> `Assoc [
        "statement", `Int (StatementId.to_int statement.statement_id); "tracked_carrier", `Bool tracked;
        "actual_normalized_pointer", `String (show_fn_ptr binding.normalized_drop);
        "actual_original_pointer", `String (show_fn_ptr binding.original_drop);
        "native_destructor_effect_and_unwind_simulation_proved", `Bool false]) footprint.drops);
      "original_switches", `List (List.map (fun statement -> `Int (StatementId.to_int statement.statement_id)) footprint.switches);
      "original_loops_requiring_inductive_carrier_invariants", `List (List.map (fun statement -> `Int (StatementId.to_int statement.statement_id)) footprint.loops);
      "original_exits", `List (List.map (fun statement -> `Int (StatementId.to_int statement.statement_id)) footprint.exits);
      "original_retags_requiring_native_loan_simulation", `List (List.map (fun statement -> `Int (StatementId.to_int statement.statement_id)) footprint.retags);
      "projected_data_writes_requiring_native_disjointness", `List (List.map (fun statement -> `Int (StatementId.to_int statement.statement_id)) footprint.projected_data_writes);
      "native_direct_carrier_and_alias_simulation_proved", `Bool false]) graph.nodes);
    "failures", `List (List.map (fun (node, error) -> `Assoc ["source_node", `Int node; "error", `String error]) graph.failures);
    "semantic_carrier_preservation_and_loop_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
