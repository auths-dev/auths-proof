(* Track the very Box returned by an actual source call into an actual source
   receiver call. This is source value provenance, not a native loan/alias or
   execution proof. Unknown effects touching the tracked carrier refuse. *)
open Charon
open Types
open Expressions
open LlbcAst

exception Unrelated
type kind = Owned | Borrowed of ref_kind
type value = { ty : ty; kind : kind; steps : statement list }
type t = {
  producer : Capture_callsite.t;
  consumer : Source_call.t;
  receiver : Virtual_receiver.t;
  owner_place : place;
  passed_receiver : operand;
  prefix : Source_path.step list;
  receiver_steps : statement list;
  intervening_calls : (Source_call.t * Box_carrier.t) list;
  deferred_switches : statement list;
  constraints : Region_equations.predicates;
}

let derive crate ~(producer : Capture_callsite.t) ~(consumer : Source_call.t) ~(receiver : Virtual_receiver.t) =
  if not (Capture_callsite.replay crate producer) || not (Source_call.replay crate consumer) ||
     not (Virtual_receiver.replay receiver) then invalid_arg "a Box receiver route needs its exact source producer/call/receiver interfaces";
  if producer.binding.caller <> consumer.caller then raise Unrelated;
  let frame = Source_call.frame consumer.caller in
  if receiver.view <> consumer.callee.view || receiver.frame <> Source_call.frame consumer.callee then
    invalid_arg "the Box receiver route and actual callee identify different source instances";
  let owner_place = producer.binding.call.dest in
  let owner_id = match owner_place.kind with PlaceLocal id when Option.is_some (Capture_return.predicate owner_place.ty) -> id
    | _ -> invalid_arg "the actual returned Box must retain its source local ownership place" in
  let prefix = try Source_path.between frame.body producer.binding.source_statement.statement_id consumer.source_statement.statement_id
    with Source_path.Not_dominating -> raise Unrelated in
  let constraints = ref (List.fold_left Region_equations.add_premise producer.binding.constraints
    (List.rev consumer.constraints.originals)) in
  let equal left right = constraints := Region_equations.add_type !constraints left right in
  let locals = List.fold_left (fun known (local : local) ->
    if LocalId.Map.mem local.index known then invalid_arg "source Box route local declarations are ambiguous";
    LocalId.Map.add local.index local known) LocalId.Map.empty frame.locals in
  let declared id = match LocalId.Map.find_opt id locals with Some local -> local
    | None -> invalid_arg "a source Box route references an undeclared local" in
  equal owner_place.ty (declared owner_id).local_ty;
  let cells = ref (LocalId.Map.singleton owner_id { ty = owner_place.ty; kind = Owned; steps = [] }) in
  let read (place : place) = match place.kind with
    | PlaceLocal id -> (match LocalId.Map.find_opt id !cells with Some value -> equal value.ty place.ty; Some value | None -> None)
    | _ ->
        let tracked = ref false in
        let scan = object inherit [_] iter_statement as super
          method! visit_place env place =
            (match place.kind with PlaceLocal id when LocalId.Map.mem id !cells -> tracked := true | _ -> ());
            super#visit_place env place
        end in scan#visit_place () place;
        if !tracked then invalid_arg "a projected source Box route needs explicit carrier/alias semantics";
        None in
  let operand = function
    | Constant _ -> None
    | Copy place ->
        (match read place with Some { kind = (Owned | Borrowed RMut); _ } ->
          invalid_arg "a source receiver route cannot copy an owned Box or exclusive borrow"
         | value -> value)
    | Move place ->
        let value = read place in
        (match place.kind with PlaceLocal id -> cells := LocalId.Map.remove id !cells
         | _ when value <> None -> invalid_arg "a projected owned source move needs its exact ownership rule" | _ -> ()); value in
  let store (destination : place) value = match destination.kind with
    | PlaceLocal id ->
        if LocalId.Map.mem id !cells then invalid_arg "a source Box route cannot overwrite an active owner or borrow";
        equal destination.ty (declared id).local_ty;
        Option.iter (fun value -> equal value.ty destination.ty; cells := LocalId.Map.add id { value with ty = destination.ty } !cells) value
    | _ ->
        if Option.is_some value then invalid_arg "a source Box route cannot escape into an unmodeled projected destination";
        ignore (read destination) in
  let no_tracked value = if Option.is_some value then invalid_arg "an intervening source effect needs a checked carrier-preserving interface" in
  let intervening_calls = ref [] and deferred_switches = ref [] in
  let ensure_owner () =
    if LocalId.Map.fold (fun _ value count -> match value.kind with Owned -> count + 1 | _ -> count) !cells 0 <> 1 then
      invalid_arg "a source receiver route must retain exactly one actual returned Box owner" in
  let receiver_argument = LocalId.to_int receiver.receiver_origin.argument - 1 in
  let execute (statement : statement) = match statement.kind with
    | StorageLive id ->
        ignore (declared id);
        if LocalId.Map.mem id !cells then invalid_arg "StorageLive cannot silently replace a tracked source Box allocation"
    | StorageDead id ->
        (match LocalId.Map.find_opt id !cells with Some { kind = Owned; _ } ->
          invalid_arg "a source Box owner cannot disappear without its actual destructor/move"
         | _ -> cells := LocalId.Map.remove id !cells)
    | Assign (destination, Use (source, _)) ->
        let value = operand source in
        let value = Option.map (fun value -> { value with steps = value.steps @ [statement] }) value in
        store destination value
    | Assign (destination, RvRef (source, kind, metadata)) ->
        let value = match source.kind with
          | PlaceLocal _ -> read source
          | PlaceProjection (parent, Deref) ->
              (match read parent with
               | Some ({ kind = Borrowed _; ty = TRef (_, pointee, _); _ } as value) -> equal pointee source.ty; Some value
               | Some _ -> invalid_arg "a source Box reborrow lost its actual reference carrier"
               | None -> None)
          | _ -> read source in
        let value = Option.map (fun value ->
          if Option.is_none (Capture_return.predicate source.ty) then invalid_arg "a source carrier borrow changed its complete dynamic Box type";
          let pointee, mutability = match destination.ty with TRef (_, pointee, mutability) -> pointee, mutability
            | _ -> invalid_arg "a source Box borrow needs its original reference destination" in
          equal source.ty pointee;
          (match kind, mutability, value.kind with
           | BShared, RShared, _ -> ()
           | (BMut | BTwoPhaseMut), RMut, (Owned | Borrowed RMut) -> ()
           | _ -> invalid_arg "a source receiver borrow cannot acquire stronger mutability than its carrier");
          (match metadata with Constant { kind = CAdt (None, []); ty } when ty = Vtable_shape.unit -> ()
           | _ -> invalid_arg "a reference to the sized Box carrier must retain its exact original unit metadata");
          { ty = destination.ty; kind = Borrowed mutability; steps = value.steps @ [statement] }) value in
        store destination value
    | Assign (destination, rvalue) ->
        let scan = object inherit [_] iter_statement as super
          method! visit_operand _ source = no_tracked (operand source)
          method! visit_place env place = no_tracked (read place); super#visit_place env place
        end in scan#visit_rvalue () rvalue; store destination None
    | Call (call, _) ->
        let values = List.map operand call.args in
        if List.exists Option.is_some values then (
          ensure_owner ();
          if receiver_argument < 0 || receiver_argument >= List.length values then
            invalid_arg "an intervening carrier call lost its source receiver argument";
          (match List.nth values receiver_argument with Some { kind = Borrowed RMut; _ } -> ()
           | _ -> invalid_arg "an intervening receiver call cannot take ownership or amplify its original borrow");
          List.iteri (fun index value -> if index <> receiver_argument then no_tracked value) values;
          let binding = Source_call.derive crate ~caller:consumer.caller ~callee:consumer.callee statement.statement_id in
          let footprint = Box_carrier.create receiver in
          constraints := List.fold_left Region_equations.add_premise !constraints (List.rev binding.constraints.originals);
          intervening_calls := (binding, footprint) :: !intervening_calls
        );
        store call.dest None
    | Switch _ ->
        let scan = object inherit [_] iter_statement as super
          method! visit_statement env statement =
            (match statement.kind with
             | StorageLive id | StorageDead id -> no_tracked (LocalId.Map.find_opt id !cells)
             | _ -> ()); super#visit_statement env statement
          method! visit_place env place = no_tracked (read place); super#visit_place env place
        end in scan#visit_statement () statement;
        deferred_switches := statement :: !deferred_switches
    | Nop -> ()
    | _ -> invalid_arg "the source Box receiver route needs explicit control-flow/drop/alias effects" in
  List.iter (function
    | Source_path.Execute statement ->
        (try execute statement with Invalid_argument message -> invalid_arg (
          "source statement " ^ string_of_int (StatementId.to_int statement.statement_id) ^ ": " ^ message))
    | Source_path.Branch choice ->
        (match choice.selector with Source_path.Value source -> no_tracked (operand source)
         | Source_path.Discriminant source -> no_tracked (read source))) prefix;
  ensure_owner ();
  let argument = LocalId.to_int receiver.receiver_origin.argument - 1 in
  if argument < 0 || argument >= List.length consumer.call.args then
    invalid_arg "the source virtual receiver argument is absent from the actual caller ABI";
  let passed_receiver = List.nth consumer.call.args argument in
  let value = match operand passed_receiver with Some value -> value | None -> raise Unrelated in
  (match value.kind, Vtable_dispatch.operand_type passed_receiver with
   | Borrowed mutability, TRef (_, box, actual) when mutability = actual && Option.is_some (Capture_return.predicate box) -> ()
   | _ -> invalid_arg "the actual Box receiver argument lost its source borrowed owning carrier");
  if receiver.receiver_origin.dereferences <> 2 || receiver.receiver_origin.reborrows = [] then
    invalid_arg "the concrete Box callee needs its exact reference/Box dereference and dynamic reborrow route";
  List.iter (fun (case : Capture_callsite.case) ->
    if case.returned.paired.producer.original.source_vtable.shape.source_predicate <>
       receiver.call.dynamic_plan.vtable_shape.source_predicate then
      invalid_arg "a returned source Box and its actual virtual receiver use different complete trait predicates") producer.cases;
  if not (Region_equations.replay_predicates !constraints) then invalid_arg "the complete original caller Box route typing premises did not replay";
  { producer; consumer; receiver; owner_place; passed_receiver; prefix;
    receiver_steps = value.steps; intervening_calls = List.rev !intervening_calls;
    deferred_switches = List.rev !deferred_switches; constraints = !constraints }

let replay crate witness = try derive crate ~producer:witness.producer ~consumer:witness.consumer ~receiver:witness.receiver = witness
  with Invalid_argument _ | Unrelated -> false

let create crate ~producer ~consumer ~receiver =
  let witness = derive crate ~producer ~consumer ~receiver in
  if not (replay crate witness) then invalid_arg "the complete actual returned Box/receiver path did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["caller_node", `Int witness.consumer.caller.index;
    "producer_call_statement", `Int (StatementId.to_int witness.producer.binding.source_statement.statement_id);
    "receiver_call", Source_call.report crate witness.consumer;
    "original_returned_owner", `String (show_place witness.owner_place);
    "actual_passed_receiver", `String (show_operand witness.passed_receiver);
    "actual_carrier_step_statements", `List (List.map (fun (statement : statement) -> `Int (StatementId.to_int statement.statement_id)) witness.receiver_steps);
    "original_conditional_source_path", Source_path.report witness.prefix;
    "intervening_actual_receiver_calls", `List (List.map (fun (binding, footprint) -> `Assoc [
      "actual_source_call", Source_call.report crate binding; "actual_wrapper_footprint", Box_carrier.report footprint]) witness.intervening_calls);
    "other_original_switches_without_tracked_carrier_access", `Int (List.length witness.deferred_switches);
    "original_caller_type_premises", region_certificate_json witness.constraints;
    "source_virtual_receiver_origin", Virtual_receiver.origin_json witness.receiver.receiver_origin;
    "normal_source_capture_case_count", `Int (List.length witness.producer.cases);
    "complete_actual_source_box_receiver_route_replays", `Bool (replay crate witness);
    "runtime_case_capture_opening_loan_ownership_and_source_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
