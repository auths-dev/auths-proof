(* Attach concrete adapter candidates to actual prepared source-global views.
   Public roots are unchanged. Every real implementation-method dependency is
   retained for the ordinary source closure; missing nodes remain explicit.
   No candidate or fixed-point completion qualifies a transformed program. *)
open Charon
open Types
open LlbcAst

type instance = {
  source_global_index : int;
  source_dispatch_nodes : int list;
  candidate : Vtable_instance.t;
  source_methods : (Vtable_instance.method_call * int option) list;
}
type injection = {
  source_node : int;
  source_global_index : int;
  producer : Prepared_injection.t;
  method_cases : fun_decl_id list;
  virtual_cases : fun_decl_id list;
}
type t = {
  instances : instance list;
  virtual_instances : (int * statement_id * int * Virtual_shim.t * (Vtable_instance.method_call * int option) list) list;
  virtual_receivers : (int * statement_id * Virtual_receiver.t) list;
  injections : injection list;
  capture_returns : (int * Capture_return.t) list;
  return_calls : Capture_callsite.t list;
  box_receiver_calls : Box_receiver_call.t list;
  closure_captures : (int * Closure_capture.t * (Closure_capture.member * int option) list) list;
  closure_invocations : Closure_invocation.t list;
  closure_receivers : Closure_receiver.t list;
  closure_arguments : Closure_argument.t list;
  closure_returns : Closure_return.t list;
  closure_return_calls : Closure_return_call.t list;
  carrier_effects : Carrier_effect.graph;
  value_flow : Value_flow.t;
  failures : (string * string) list;
  unmatched_globals : int list;
  method_dependencies : Static_targets.resolved list;
}

let dependency_key (resolution : Static_targets.resolved) =
  match resolution.pointer.kind with
  | FunId (FRegular id) ->
      let factor, _, _ = Instance_view.factor_context resolution.pointer.generics resolution.self_evidence in
      id, factor.pattern
  | _ -> invalid_arg "an adapter source dependency must identify an actual regular function"

let build crate (graph : Source_closure.t) =
  let next = ref (match FunDeclId.Map.max_binding_opt crate.fun_decls with Some (id, _) -> FunDeclId.to_int id | None -> -1) in
  let fresh () = if !next >= Int.max_int then invalid_arg "adapter candidate declaration IDs exceed construction space";
    incr next; FunDeclId.of_int !next in
  let functions = List.fold_left (fun known (node : Source_closure.node) ->
    Source_closure.Key.add (node.declaration.def_id, node.view.arguments.pattern) node.index known)
    Source_closure.Key.empty graph.nodes in
  let dispatches = ref [] and failures = ref [] in
  FunDeclId.Map.iter (fun id (declaration : fun_decl) -> match declaration.body with
    | StructuredBody body ->
        let collect = object inherit [_] iter_statement as super
          method! visit_statement env (statement : statement) =
            (match statement.kind with
             | Call ({ func = FnOpDynamic _; _ }, _) ->
                 (try dispatches := Vtable_dispatch.create crate ~caller:declaration statement :: !dispatches
                  with Invalid_argument message -> failures :=
                    ("dispatch:" ^ string_of_int (FunDeclId.to_int id), message) :: !failures)
             | _ -> ());
            super#visit_statement env statement
        end in collect#visit_block () body.body
    | _ -> ()) crate.fun_decls;
  let matched = ref [] and instances = ref [] and methods = ref Source_closure.Key.empty in
  List.iter (fun (dispatch : Vtable_dispatch.t) ->
    let source_dispatch_nodes = List.filter_map (fun (node : Source_closure.node) ->
      if node.declaration.def_id = dispatch.caller.def_id then Some node.index else None) graph.nodes in
    List.iter (fun (branch : Vtable_dispatch.branch) ->
      let caller_id = fresh () in let shim_id = fresh () in
      try
        let family = Vtable_specialization.create crate ~dispatch ~branch ~caller_id ~shim_id in
        List.iter (fun (global : Source_closure.global_node) ->
          if global.view.declaration.def_id = branch.source_vtable.global.def_id then (
            matched := global.global_index :: !matched;
            try
              let caller_id = fresh () in let shim_id = fresh () in
              let candidate = Vtable_instance.create crate ~family ~source_global:global.view ~caller_id ~shim_id in
              let source_methods = List.map (fun (call : Vtable_instance.method_call) ->
                let key = dependency_key call.resolution in
                methods := Source_closure.Key.add key call.resolution !methods;
                call, Source_closure.Key.find_opt key functions) candidate.source_method_calls in
              instances := { source_global_index = global.global_index; source_dispatch_nodes; candidate; source_methods } :: !instances
            with Invalid_argument message -> failures :=
              ("global:" ^ string_of_int global.global_index, message) :: !failures
          )) graph.global_nodes
      with Invalid_argument message -> failures :=
        ("family:" ^ string_of_int (GlobalDeclId.to_int branch.source_vtable.global.def_id), message) :: !failures
    ) dispatch.available_source_branches
  ) (List.rev !dispatches);
  let virtual_instances = ref [] and virtual_receivers = ref [] in
  List.iter (fun (node : Source_closure.node) -> match node.frame with
    | None -> ()
    | Some frame -> List.iter (fun (call : Function_frame.dynamic_call) ->
        (try let receiver = Virtual_receiver.create crate ~view:node.view ~frame ~call in
          virtual_receivers := (node.index, call.dynamic_statement_id, receiver) :: !virtual_receivers
         with Invalid_argument message -> failures :=
           ("virtual_receiver:" ^ string_of_int node.index, message) :: !failures);
        List.iter (fun (global : Source_closure.global_node) ->
          if global.view.ty = TAdt call.dynamic_plan.vtable_reference then (
            matched := global.global_index :: !matched;
            try
              let candidate = Virtual_shim.create crate ~interface:call.dynamic_plan ~source_global:global.view
                ~caller_parameters:node.view.arguments.parameters ~caller_body_regions:frame.source_body.bound_body_regions ~id:(fresh ()) in
              let source_methods = List.map (fun (method_ : Vtable_instance.method_call) ->
                let key = dependency_key method_.resolution in
                methods := Source_closure.Key.add key method_.resolution !methods;
                method_, Source_closure.Key.find_opt key functions) candidate.actual_source_methods in
              virtual_instances := (node.index, call.dynamic_statement_id, global.global_index, candidate, source_methods) :: !virtual_instances
            with Invalid_argument message -> failures :=
              ("virtual:" ^ string_of_int node.index ^ "/global:" ^ string_of_int global.global_index, message) :: !failures
          )) graph.global_nodes
      ) frame.dynamic_calls) graph.nodes;
  let unmatched_globals = List.filter_map (fun (node : Source_closure.global_node) ->
    match node.view.declaration.src with VTableInstanceItem _ when not (List.mem node.global_index !matched) -> Some node.global_index
    | _ -> None) graph.global_nodes in
  let injections = ref [] in
  List.iter (fun (node : Source_closure.node) -> match node.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Assign (_, Charon.Expressions.UnaryOp (Cast (CastUnsize (_, _, MetaVTable _)), _)) ->
             (try
               let producer = Prepared_injection.create crate ~view:node.view ~frame statement.statement_id in
               let source_global_index = match List.filter (fun (global : Source_closure.global_node) ->
                 Prepared_injection.same_capture global.view producer.global) graph.global_nodes with
                 | [global] -> global.global_index
                 | _ -> invalid_arg "an actual source producer has no unique complete prepared-global capture" in
               let method_cases = List.filter_map (fun (instance : instance) ->
                 if instance.source_global_index = source_global_index then (
                   ignore (Prepared_injection.instance_self ~candidate:instance.candidate producer);
                   Some instance.candidate.shim_candidate.def_id) else None) !instances in
               let virtual_cases = List.filter_map (fun (_, _, global, candidate, _) ->
                 if global = source_global_index then (
                   ignore (Prepared_injection.virtual_self ~candidate producer); Some candidate.declaration.def_id) else None) !virtual_instances in
               if method_cases = [] && virtual_cases = [] then invalid_arg "an actual source producer has no concrete method-capture interface";
               injections := { source_node = node.index; source_global_index; producer; method_cases; virtual_cases } :: !injections
              with Invalid_argument message -> failures :=
                ("producer:" ^ string_of_int node.index ^ "/statement:" ^ string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ());
        super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let capture_returns = List.filter_map (fun (node : Source_closure.node) -> match node.frame with None -> None
    | Some frame ->
        let producers = List.filter_map (fun (injection : injection) ->
          if injection.source_node = node.index && (match injection.producer.carrier with Vtable_injection.OwnedBox _ -> true | _ -> false)
          then Some injection.producer else None) !injections in
        if producers = [] || Option.is_none (Capture_return.predicate frame.signature.output) then None
        else try Some (node.index, Capture_return.create crate ~view:node.view ~frame ~producers)
        with Invalid_argument message -> failures := ("capture_return:" ^ string_of_int node.index, message) :: !failures; None) graph.nodes in
  let closure_captures = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Assign (_, Charon.Expressions.Aggregate (AggregatedAdt (reference, None, None), _)) ->
             (try if Closure_capture.is_box_capture crate reference then (
               let capture = Closure_capture.create crate ~caller statement.statement_id in
               List.iter (fun (member : Closure_capture.member) ->
                 methods := Source_closure.Key.add (dependency_key member.resolution) member.resolution !methods) capture.members;
               let source_methods = List.map (fun (member : Closure_capture.member) ->
                 member, Source_closure.Key.find_opt (dependency_key member.resolution) functions) capture.members in
               closure_captures := (caller.index, capture, source_methods) :: !closure_captures)
              with Invalid_argument message -> failures := ("closure_capture:" ^ string_of_int caller.index ^ "/statement:" ^
                string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ()); super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let closure_returns = List.filter_map (fun (_, (capture : Closure_capture.t), _) ->
    match (Source_call.frame capture.caller).signature.output with
    | TAdt reference when reference.id = capture.reference.id ->
        (try Some (Closure_return.create crate ~capture)
         with Invalid_argument message -> failures := ("closure_return:" ^ string_of_int capture.caller.index, message) :: !failures; None)
    | _ -> None) !closure_captures in
  let closure_return_calls = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Call (({ func = FnOpRegular ({ kind = FunId (FRegular id); _ } as pointer); _ } as call), _)
             when (match call.dest.ty with TAdt reference -> Closure_capture.is_box_capture crate reference | _ -> false) &&
               List.exists (fun (returns : Closure_return.t) -> returns.capture.caller.declaration.def_id = id) closure_returns ->
             (try
               let resolution = Static_targets.resolve crate pointer in
               let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
               let index = match Source_closure.Key.find_opt (id, arguments.pattern) functions with Some index -> index
                 | None -> invalid_arg "the actual returned-closure call has no complete prepared source dependency instance" in
               let returns = match List.find_opt (fun (returns : Closure_return.t) -> returns.capture.caller.index = index) closure_returns with
                 | Some returns -> returns | None -> invalid_arg "the exact actual closure-returning callee has no original aggregate/return routes" in
               let binding = Source_call.create crate ~caller ~callee:returns.capture.caller statement.statement_id in
               closure_return_calls := Closure_return_call.create crate ~binding ~returns :: !closure_return_calls
              with Invalid_argument message -> failures := ("closure_return_call:" ^ string_of_int caller.index ^ "/statement:" ^
                string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ()); super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let closure_arguments = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let captures = List.filter_map (fun (node, capture, _) -> if node = caller.index then Some capture else None) !closure_captures in
    if captures <> [] then (
      let collect = object inherit [_] iter_statement as super
        method! visit_statement env statement =
          (match statement.kind with
           | Call (({ func = FnOpRegular ({ kind = FunId (FRegular id); _ } as pointer); _ } as call), _) ->
               List.iter (fun (capture : Closure_capture.t) -> List.iteri (fun argument_index source ->
                 let same_nominal = match Vtable_dispatch.operand_type source with
                   | TAdt reference -> reference.id = capture.reference.id | _ -> false in
                 if same_nominal then (
                   try
                     let resolution = Static_targets.resolve crate pointer in
                     let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
                     let index = match Source_closure.Key.find_opt (id, arguments.pattern) functions with Some index -> index
                       | None -> invalid_arg "the actual captured-value argument has no exact prepared callee instance" in
                     let callee = match List.find_opt (fun (node : Source_closure.node) -> node.index = index) graph.nodes with Some node -> node
                       | None -> invalid_arg "the actual captured-value argument callee is absent" in
                     let binding = Source_call.create crate ~caller ~callee statement.statement_id in
                     closure_arguments := Closure_argument.create crate ~capture ~binding argument_index :: !closure_arguments
                   with Closure_argument.Unrelated -> ()
                     | Invalid_argument message -> failures := ("closure_argument:" ^ string_of_int caller.index ^ "/statement:" ^
                         string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
               ) call.args) captures
           | _ -> ()); super#visit_statement env statement
      end in collect#visit_block () frame.body)) graph.nodes;
  let closure_invocations = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Call (({ func = FnOpRegular ({ kind = FunId (FRegular id); _ } as pointer); _ } as call), _)
             when Closure_invocation.candidate crate call ->
             (try
               let resolution = Static_targets.resolve crate pointer in
               let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
               let index = match Source_closure.Key.find_opt (id, arguments.pattern) functions with Some index -> index
                 | None -> invalid_arg "the actual captured closure invocation has no exact prepared source dependency instance" in
               let callee = match List.find_opt (fun (node : Source_closure.node) -> node.index = index) graph.nodes with Some node -> node
                 | None -> invalid_arg "the actual captured closure invocation source node is absent" in
               let binding = Source_call.create crate ~caller ~callee statement.statement_id in
               closure_invocations := Closure_invocation.create crate ~binding :: !closure_invocations
              with Invalid_argument message -> failures := ("closure_invocation:" ^ string_of_int caller.index ^ "/statement:" ^
                string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ()); super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let return_calls = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Call ({ func = FnOpRegular ({ kind = FunId (FRegular id); _ } as pointer); _ }, _)
             when List.exists (fun (_, (returns : Capture_return.t)) -> returns.view.original_id = id) capture_returns ->
             (try
               let resolution = Static_targets.resolve crate pointer in
               let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
               let index = match Source_closure.Key.find_opt (id, arguments.pattern) functions with Some index -> index
                 | None -> invalid_arg "the actual Box-returning call has no exact prepared source dependency instance" in
               let callee = match List.find_opt (fun (node : Source_closure.node) -> node.index = index) graph.nodes with Some node -> node
                 | None -> invalid_arg "the actual Box-returning callee source node is absent" in
               let returns = match List.assoc_opt index capture_returns with Some returns -> returns
                 | None -> invalid_arg "the actual source callee instance has no complete Box return provenance" in
               return_calls := Capture_callsite.create crate ~caller ~callee ~returns statement.statement_id :: !return_calls
              with Invalid_argument message -> failures := ("return_call:" ^ string_of_int caller.index ^ "/statement:" ^
                string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ()); super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let box_receiver_calls = ref [] and closure_receivers = ref [] in
  List.iter (fun (caller : Source_closure.node) -> match caller.frame with None -> () | Some frame ->
    let collect = object inherit [_] iter_statement as super
      method! visit_statement env statement =
        (match statement.kind with
         | Call ({ func = FnOpRegular ({ kind = FunId (FRegular id); _ } as pointer); _ }, _)
             when List.exists (fun (_, _, (receiver : Virtual_receiver.t)) -> receiver.view.original_id = id) !virtual_receivers ->
             (try
               let resolution = Static_targets.resolve crate pointer in
               let arguments, _, _ = Instance_view.factor_context pointer.generics resolution.self_evidence in
               let index = match Source_closure.Key.find_opt (id, arguments.pattern) functions with Some index -> index
                 | None -> invalid_arg "the actual Box receiver call has no exact prepared source dependency instance" in
               let callee = match List.find_opt (fun (node : Source_closure.node) -> node.index = index) graph.nodes with Some node -> node
                 | None -> invalid_arg "the actual Box receiver callee is absent" in
               let consumer = Source_call.create crate ~caller ~callee statement.statement_id in
               let receivers = List.filter_map (fun (node, _, receiver) -> if node = index then Some receiver else None) !virtual_receivers in
               if receivers = [] then invalid_arg "the actual Box receiver callee has no source virtual receiver provenance";
               let candidates = List.filter (fun (producer : Capture_callsite.t) -> producer.binding.caller.index = caller.index) !return_calls in
               let matched = ref false and pending = ref false in
               List.iter (fun receiver -> List.iter (fun producer ->
                 try let route = Box_receiver_call.create crate ~producer ~consumer ~receiver in
                   matched := true; box_receiver_calls := route :: !box_receiver_calls
                 with Box_receiver_call.Unrelated -> ()
                   | Invalid_argument message -> pending := true; failures :=
                       ("box_receiver_candidate:" ^ string_of_int caller.index ^ "/statement:" ^ string_of_int (StatementId.to_int statement.statement_id), message) :: !failures
               ) candidates) receivers;
               if not !matched && not !pending then (
                 let captured = match frame.signature.inputs with
                   | TRef (_, TAdt reference, RMut) :: _ -> Closure_capture.is_box_capture crate reference
                   | _ -> false in
                 if not captured then invalid_arg "the actual source Box receiver has no dominating paired return route";
                 List.iter (fun receiver -> closure_receivers := Closure_receiver.create crate ~consumer ~receiver :: !closure_receivers) receivers)
              with Invalid_argument message -> failures := ("box_receiver_call:" ^ string_of_int caller.index ^ "/statement:" ^
                string_of_int (StatementId.to_int statement.statement_id), message) :: !failures)
         | _ -> ()); super#visit_statement env statement
    end in collect#visit_block () frame.body) graph.nodes;
  let carrier_roots = List.concat_map (fun (invocation : Closure_invocation.t) ->
      [invocation.binding.caller.index; invocation.binding.callee.index]) !closure_invocations @
    List.map (fun (argument : Closure_argument.t) -> argument.binding.callee.index) !closure_arguments @
    List.filter_map (fun (node, (capture : Closure_capture.t), _) ->
      if List.exists (Carrier_effect.carries crate) (Source_call.frame capture.caller).signature.inputs
      then Some node else None) !closure_captures in
  let carrier_effects = Carrier_effect.build crate ~source:graph ~roots:carrier_roots
    ~receivers:(List.map (fun (_, _, receiver) -> receiver) !virtual_receivers) ~accessors:!closure_receivers
    ~returned_closures:!closure_return_calls in
  let value_flow = Value_flow.build crate ~captures:(List.map (fun (_, capture, _) -> capture) !closure_captures)
    ~closure_returns:!closure_return_calls ~box_returns:!return_calls ~reference_accesses:!closure_receivers
    ~box_receivers:(List.map (fun (_, _, receiver) -> receiver) !virtual_receivers) ~effects:carrier_effects
    ~arguments:!closure_arguments ~receivers:!box_receiver_calls in
  { instances = List.rev !instances; virtual_instances = List.rev !virtual_instances;
    virtual_receivers = List.rev !virtual_receivers;
    injections = List.rev !injections;
    capture_returns;
    return_calls = List.rev !return_calls;
    box_receiver_calls = List.rev !box_receiver_calls;
    closure_captures = List.rev !closure_captures;
    closure_invocations = List.rev !closure_invocations;
    closure_receivers = List.rev !closure_receivers;
    closure_arguments = List.rev !closure_arguments;
    closure_returns;
    closure_return_calls = List.rev !closure_return_calls;
    carrier_effects;
    value_flow;
    failures = List.rev !failures; unmatched_globals;
    method_dependencies = List.map snd (Source_closure.Key.bindings !methods) }

let report crate graph =
  let open Diagnostic in
  `Assoc ["scope", `String "actual prepared-global capture views and source method dependencies; no qualified native program";
    "instances", `List (List.map (fun (instance : instance) -> `Assoc [
      "source_global_index", `Int instance.source_global_index;
      "source_dispatch_nodes", `List (List.map (fun id -> `Int id) instance.source_dispatch_nodes);
      "ordinary_interface_binding_required", `Bool (instance.source_dispatch_nodes = []);
      "candidate", Vtable_instance.report crate instance.candidate;
      "actual_source_method_nodes", `List (List.map (fun ((call : Vtable_instance.method_call), node) -> `Assoc [
        "source_pointer", `String (show_fn_ptr call.resolution.pointer);
        "source_node", (match node with Some index -> `Int index | None -> `Null)]) instance.source_methods)]) graph.instances);
    "virtual_capture_candidates", `List (List.map (fun (node, statement, global, candidate, methods) -> `Assoc [
      "source_node", `Int node; "source_statement", `Int (StatementId.to_int statement);
      "source_global_index", `Int global; "candidate", Virtual_shim.report crate candidate;
      "actual_source_method_nodes", `List (List.map (fun ((call : Vtable_instance.method_call), node) -> `Assoc [
        "source_pointer", `String (show_fn_ptr call.resolution.pointer);
        "source_node", (match node with Some index -> `Int index | None -> `Null)]) methods)]) graph.virtual_instances);
    "virtual_receiver_provenance", `List (List.map (fun (node, statement, receiver) -> `Assoc [
      "source_node", `Int node; "source_statement", `Int (StatementId.to_int statement);
      "source_receiver", Virtual_receiver.report receiver]) graph.virtual_receivers);
    "actual_source_producers", `List (List.map (fun (injection : injection) -> `Assoc [
      "source_node", `Int injection.source_node; "source_global_index", `Int injection.source_global_index;
      "producer", Prepared_injection.report crate injection.producer;
      "concrete_method_cases", `List (List.map (fun id -> `Int (FunDeclId.to_int id)) injection.method_cases);
      "virtual_method_cases", `List (List.map (fun id -> `Int (FunDeclId.to_int id)) injection.virtual_cases);
      "native_injection_and_interprocedural_paired_value_propagation_proved", `Bool false]) graph.injections);
    "normal_box_return_provenance", `List (List.map (fun (node, routes) -> `Assoc [
      "source_node", `Int node; "source_return_routes", Capture_return.report crate routes]) graph.capture_returns);
    "actual_source_return_calls", `List (List.map (Capture_callsite.report crate) graph.return_calls);
    "actual_source_box_receiver_calls", `List (List.map (Box_receiver_call.report crate) graph.box_receiver_calls);
    "actual_source_closure_captures", `List (List.map (fun (node, capture, methods) -> `Assoc [
      "source_node", `Int node; "closure_capture", Closure_capture.report crate capture;
      "actual_source_method_nodes", `List (List.map (fun ((member : Closure_capture.member), node) -> `Assoc [
        "source_pointer", `String (show_fn_ptr member.resolution.pointer);
        "source_node", (match node with Some index -> `Int index | None -> `Null)]) methods)]) graph.closure_captures);
    "actual_source_closure_invocations", `List (List.map (Closure_invocation.report crate) graph.closure_invocations);
    "actual_source_captured_field_receivers", `List (List.map (Closure_receiver.report crate) graph.closure_receivers);
    "actual_source_closure_arguments", `List (List.map (Closure_argument.report crate) graph.closure_arguments);
    "actual_source_closure_returns", `List (List.map (Closure_return.report crate) graph.closure_returns);
    "actual_source_closure_return_calls", `List (List.map (Closure_return_call.report crate) graph.closure_return_calls);
    "actual_source_callback_carrier_effects", Carrier_effect.report crate graph.carrier_effects;
    "actual_source_carrier_value_flow", Value_flow.report crate graph.value_flow;
    "unmatched_vtable_globals", `List (List.map (fun id -> `Int id) graph.unmatched_globals);
    "failures", `List (List.map (fun (owner, message) -> `Assoc ["owner", `String owner; "error", `String message]) graph.failures);
    "actual_method_dependency_count", `Int (List.length graph.method_dependencies);
    "source_ordinary_interface_and_runtime_selection_bound", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]

let close_source_dependencies crate public_roots =
  let rec close iteration known =
    if iteration >= 64 then invalid_arg "native adapter dependency closure exceeds its explicit construction iteration bound";
    let additional_roots = List.map snd (Source_closure.Key.bindings known) in
    let graph = Source_closure.build ~additional_roots crate public_roots in
    let adapters = build crate graph in
    let present = List.fold_left (fun known (node : Source_closure.node) ->
      Source_closure.Key.add (node.declaration.def_id, node.view.arguments.pattern) () known) Source_closure.Key.empty graph.nodes in
    let missing = List.filter (fun dependency -> not (Source_closure.Key.mem (dependency_key dependency) present)) adapters.method_dependencies in
    let expanded = List.fold_left (fun result dependency ->
      Source_closure.Key.add (dependency_key dependency) dependency result) known missing in
    Printf.printf "Vtable source adapters: instances=%d virtual=%d failures=%d unmatched=%d methods=%d missing=%d; dependency pass %d\n%!"
      (List.length adapters.instances) (List.length adapters.virtual_instances) (List.length adapters.failures) (List.length adapters.unmatched_globals)
      (List.length adapters.method_dependencies) (List.length missing) (iteration + 1);
    if Source_closure.Key.cardinal expanded = Source_closure.Key.cardinal known then graph, adapters, iteration + 1
    else close (iteration + 1) expanded in
  close 0 Source_closure.Key.empty
