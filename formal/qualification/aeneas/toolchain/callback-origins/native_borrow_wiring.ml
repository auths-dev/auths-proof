(* Level-aware ports are extracted from the original native trees, never the
   flattened scope observations. Payload routing performs no value operation.
   Layout, projected-value/region and heap/loan adequacy remain required. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol

type edge = Root of int | Field of int | Child | GivenBack | Consumed of int
  | BorrowReprojection of int | LoanReprojection of int | Argument of int * int
  | ContinuationInput | ContinuationOutput
type leaf = { value : V.symbolic_value; given_back : bool; path : edge list }
type port = {
  value : V.symbolic_value; payload_type : ty; given_back : bool;
  abstraction : V.abs_id; group : region_group_id; input : bool; level : int;
  abstract_path : edge list; continuation_path : edge list;
}
type event = { abstraction : V.abs_id; group : region_group_id; input : bool; level : int; ports : port list }
type internal = { producer_event : int; consumer_event : int; producer : port; consumer : port }
type branch = { target : region_group_id; events : event list; inputs : port list; outputs : port list;
  routes : int list; internal : internal list }
type t = { branches : branch list }

let ports (abs : V.abs) selected =
  let make current path given_back value = if current = selected then [{ value; given_back; path }] else [] in
  let regular current path (value : V.tvalue) = match value.value with
    | V.VSymbolic value -> make current path false value
    | _ -> invalid_arg "native backward consumed payload needs explicit value/layout lowering; it is not a symbolic port" in
  let require_inactive current = if current = selected then
    invalid_arg "an active native owned projector at the selected ending level needs explicit value semantics" in
  let record variant = if variant <> None then
    invalid_arg "native backward enum field layout requires explicit variant-preserving lowering" in
  let rec abstract current path (value : V.tavalue) = match value.value with
    | V.AIgnored _ -> []
    | V.AAdt aggregate -> record aggregate.variant_id;
        List.concat (List.mapi (fun index field -> abstract current (path @ [Field index]) field) aggregate.fields)
    | V.ALoan loan ->
        (match loan with
         | V.AMutLoan (pm, _, child) -> B.marker pm; require_inactive current; abstract current (path @ [Child]) child
         | V.AIgnoredMutLoan (_, child) -> abstract current (path @ [Child]) child
         | V.AEndedMutLoan ended ->
             regular current path ended.given_back_meta @ abstract current (path @ [Child]) ended.child @
               abstract (current + 1) (path @ [GivenBack]) ended.given_back
         | V.AEndedIgnoredMutLoan ended ->
             abstract current (path @ [Child]) ended.child @ abstract (current + 1) (path @ [GivenBack]) ended.given_back
         | _ -> invalid_arg "native backward shared-loan port semantics are not implemented")
    | V.ABorrow borrow ->
        (match borrow with
         | V.AMutBorrow (pm, _, child) -> B.marker pm; require_inactive current; abstract current (path @ [Child]) child
         | V.AIgnoredMutBorrow (_, child) -> abstract current (path @ [Child]) child
         | V.AEndedMutBorrow (meta, child) ->
             let nested = abstract current (path @ [Child]) child in
             if current = selected && nested <> [] then
               invalid_arg "a native whole-borrow port and selected child ports need explicit nested reconstruction";
             make current path true meta.given_back @ nested
         | V.AEndedIgnoredMutBorrow ended ->
             (* No owned header port: a parent already produced the metadata
                value. Match the native level visitor exactly for its child
                and given-back loan subtree. *)
             abstract current (path @ [Child]) ended.child @
               abstract (current + 1) (path @ [GivenBack]) ended.given_back
         | _ -> invalid_arg "native backward shared-borrow port semantics are not implemented")
    | V.ASymbolic (pm, projector) -> B.marker pm; aproj current path value.ty projector
  and aproj current path sort = function
    | V.AEmpty -> []
    | V.AProjLoans node -> require_inactive current;
        apairs current path (fun n -> Consumed n) node.consumed @ apairs current path (fun n -> BorrowReprojection n) node.borrows
    | V.AProjBorrows node -> require_inactive current; apairs current path (fun n -> LoanReprojection n) node.loans
    | V.AEndedProjLoans node ->
        let consumed = if node.consumed = [] then
          make current path false { V.sv_id = node.proj; sv_ty = sort }
          else List.concat (List.mapi (fun index ((value : V.mconsumed_symb), _) ->
            make current (path @ [Consumed index]) false { V.sv_id = value.sv_id; sv_ty = value.proj_ty }) node.consumed) in
        consumed @ apairs current path (fun n -> Consumed n) node.consumed @ apairs current path (fun n -> BorrowReprojection n) node.borrows
    | V.AEndedProjBorrows node -> make current path true node.mvalues.given_back @
        apairs current path (fun n -> LoanReprojection n) node.loans
  and apairs current path edge pairs = List.concat (List.mapi (fun index ((value : V.mconsumed_symb), child) ->
    aproj (current + 1) (path @ [edge index]) value.proj_ty child) pairs)
  and continuation current path (value : V.tevalue) = match value.value with
    | V.EIgnored _ -> []
    | V.EAdt aggregate -> record aggregate.variant_id;
        List.concat (List.mapi (fun index field -> continuation current (path @ [Field index]) field) aggregate.fields)
    | V.EMutBorrowInput child -> continuation current (path @ [Child]) child
    | V.EValue (_, value) -> regular current path value
    | V.EApp ((V.EInputAbs _ | V.EOutputAbs _), args) ->
        List.concat (List.mapi (fun group fields -> List.concat (List.mapi (fun index field ->
          continuation current (path @ [Argument (group, index)]) field) fields)) args)
    | V.ELoan loan ->
        (match loan with
         | V.EMutLoan (pm, _, child) -> B.marker pm; require_inactive current; continuation current (path @ [Child]) child
         | V.EIgnoredMutLoan (_, child) -> continuation current (path @ [Child]) child
         | V.EEndedMutLoan ended -> regular current path ended.given_back_meta @
             continuation current (path @ [Child]) ended.child @ continuation (current + 1) (path @ [GivenBack]) ended.given_back
         | V.EEndedIgnoredMutLoan ended -> continuation current (path @ [Child]) ended.child @
             continuation (current + 1) (path @ [GivenBack]) ended.given_back)
    | V.EBorrow borrow ->
        (match borrow with
         | V.EMutBorrow (pm, _, child) -> B.marker pm; require_inactive current; continuation current (path @ [Child]) child
         | V.EIgnoredMutBorrow (_, child) -> continuation current (path @ [Child]) child
         | V.EEndedMutBorrow (meta, child) ->
             let nested = continuation current (path @ [Child]) child in
             if current = selected && nested <> [] then
               invalid_arg "a native whole-borrow continuation port and selected children need explicit reconstruction";
             make current path true meta.given_back @ nested
         | V.EEndedIgnoredMutBorrow ended ->
             continuation current (path @ [Child]) ended.child @
               continuation (current + 1) (path @ [GivenBack]) ended.given_back)
    | V.ESymbolic (pm, projector) -> B.marker pm; eproj current path value.ty projector
    | _ -> invalid_arg "native backward port extraction cannot omit a binder, effect, join or function application"
  and eproj current path sort = function
    | V.EEmpty -> []
    | V.EProjLoans node -> require_inactive current;
        epairs current path (fun n -> Consumed n) node.consumed @ epairs current path (fun n -> BorrowReprojection n) node.borrows
    | V.EProjBorrows node -> require_inactive current; epairs current path (fun n -> LoanReprojection n) node.loans
    | V.EEndedProjLoans node ->
        let consumed = if node.consumed = [] then
          make current path false { V.sv_id = node.proj; sv_ty = sort }
          else List.concat (List.mapi (fun index ((value : V.mconsumed_symb), _) ->
            make current (path @ [Consumed index]) false { V.sv_id = value.sv_id; sv_ty = value.proj_ty }) node.consumed) in
        consumed @ epairs current path (fun n -> Consumed n) node.consumed @ epairs current path (fun n -> BorrowReprojection n) node.borrows
    | V.EEndedProjBorrows node -> make current path true node.mvalues.given_back @
        epairs current path (fun n -> LoanReprojection n) node.loans
  and epairs current path edge pairs = List.concat (List.mapi (fun index ((value : V.mconsumed_symb), child) ->
    eproj (current + 1) (path @ [edge index]) value.proj_ty child) pairs) in
  let left = List.concat (List.mapi (fun index value -> abstract 0 [Root index] value) abs.avalues) in
  let cont = match abs.cont with Some cont -> cont | None -> invalid_arg "native port extraction requires the actual continuation" in
  let right = Option.fold ~none:[] ~some:(continuation 0 [ContinuationInput]) cont.input @
    Option.fold ~none:[] ~some:(continuation 0 [ContinuationOutput]) cont.output in
  if List.map (fun (leaf : leaf) -> leaf.value, leaf.given_back) left <>
      List.map (fun (leaf : leaf) -> leaf.value, leaf.given_back) right then
    invalid_arg "level-aware native abstraction and continuation ports disagree on complete types, identities, direction or order";
  List.combine left right

let external_input (port : port) = port.given_back && (if port.level = 0 then not port.input else port.input)
let external_output (port : port) = not port.given_back && (if port.level = 0 then port.input else not port.input)
let internal_port port = not (external_input port || external_output port)

let internal_links target events =
  let ports = List.concat (List.mapi (fun index (event : event) ->
    if event.group = target then List.filter_map (fun port -> if internal_port port then Some (index, port) else None) event.ports
    else []) events) in
  let sources = List.filter (fun (_, port) -> port.given_back) ports in
  let sinks = List.filter (fun (_, port) -> not port.given_back) ports in
  let same_key left right = left.value.sv_id = right.value.sv_id && left.level = right.level in
  let unique values = List.iter (fun (_, value) ->
    if List.length (List.filter (fun (_, other) -> same_key value other) values) <> 1 then
      invalid_arg "an internal native channel repeats its producer or consumer at one level") values in
  unique sources; unique sinks;
  if List.length sources <> List.length sinks then invalid_arg "an internal native channel lost its actual producer or consumer";
  List.map (fun (producer_event, producer) ->
    let consumer_event, consumer = match List.filter (fun (_, value) -> same_key producer value) sinks with
      | [entry] -> entry | _ -> invalid_arg "an internal native value has no unique actual consuming port" in
    if producer_event >= consumer_event || producer.group <> target || consumer.group <> target ||
        producer.payload_type <> consumer.payload_type then
      invalid_arg "an internal native channel changed its source order, region group or complete normalized payload type";
    { producer_event; consumer_event; producer; consumer }) sources

let validate (branch : branch) =
  if internal_links branch.target branch.events <> branch.internal then
    invalid_arg "native wiring lost an actual internal producer/consumer pair";
  let owned = List.concat_map (fun (event : event) ->
    if event.group = branch.target then event.ports else []) branch.events in
  let accounted = branch.inputs @ branch.outputs @ List.concat_map (fun link ->
    [link.producer; link.consumer]) branch.internal in
  if List.length owned <> List.length accounted || List.exists (fun port ->
      List.length (List.filter ((=) port) owned) <> 1 ||
      List.length (List.filter ((=) port) accounted) <> 1) (owned @ accounted) then
    invalid_arg "native wiring must account for every actual owned port exactly once";
  List.iter (fun (event : event) -> List.iter (fun (port : port) ->
    if port.abstraction <> event.abstraction || port.group <> event.group ||
        port.input <> event.input || port.level <> event.level ||
        port.payload_type <> Region_equations.type_shape port.value.sv_ty then
      invalid_arg "native wiring port changed its actual event or normalized type") event.ports) branch.events;
  let unique label ports =
    let names = List.map (fun (port : port) -> port.value.sv_id, port.level) ports in
    if List.length names <> List.length (List.sort_uniq compare names) then
      invalid_arg ("native backward " ^ label ^ " ports repeat a symbolic identity at one level") in
  unique "input" branch.inputs; unique "output" branch.outputs;
  if branch.inputs = [] || List.length branch.inputs <> List.length branch.outputs ||
      List.length branch.outputs <> List.length branch.routes ||
      List.length branch.routes <> List.length (List.sort_uniq compare branch.routes) then
    invalid_arg "a move-only native constructor must route every boundary channel bijectively";
  List.iter (fun (port : port) -> if port.group <> branch.target || not (external_input port) ||
    port.payload_type <> Region_equations.type_shape port.value.sv_ty then
      invalid_arg "native backward input has a wrong target, direction, level or normalized type") branch.inputs;
  List.iter2 (fun (output : port) index ->
    if output.group <> branch.target || not (external_output output) ||
        output.payload_type <> Region_equations.type_shape output.value.sv_ty then
      invalid_arg "native backward output has a wrong target, direction, level or normalized type";
    let input = match List.nth_opt branch.inputs index with Some value -> value
      | None -> invalid_arg "native backward payload route is out of bounds" in
    if input.value.sv_id <> output.value.sv_id || input.level <> output.level || input.payload_type <> output.payload_type then
      invalid_arg "native backward route cannot change symbolic identity, selected level or complete normalized payload type"
  ) branch.outputs branch.routes

let derive component projection inputs expression forward protocol =
  if not (B.replay component projection inputs expression forward protocol) then
    invalid_arg "native backward wiring requires the complete actual ordered scope witness";
  let rec delimiter = function
    | S.Meta (_, next) | S.Expansion (_, _, S.ExpandNoBranch (_, next)) -> delimiter next
    | S.Expansion (_, _, S.ExpandAdt [None, _, next]) -> delimiter next
    | S.ForwardEnd (_, _, _, backward) -> backward
    | _ -> invalid_arg "native wiring cannot drop an intervening symbolic effect" in
  let branches = RegionGroupId.Map.bindings (delimiter expression) |> List.map (fun (target, expression) ->
    let rec events = function
      | S.Meta (_, next) -> events next
      | S.Return (_, None) -> []
      | S.EndAbs (_, abs, level, next) ->
          let input, group = match abs.kind with V.SynthInput group -> true, group | V.SynthRet group -> false, group
            | _ -> invalid_arg "native wiring requires an actual synthesis input/output abstraction" in
          if level < 0 then invalid_arg "a native backward port level cannot be negative";
          let ports = ports abs level |> List.map (fun ((left : leaf), (right : leaf)) ->
            { value = left.value; payload_type = Region_equations.type_shape left.value.sv_ty;
              given_back = left.given_back; abstraction = abs.abs_id; input; group; level;
              abstract_path = left.path; continuation_path = right.path }) in
          { abstraction = abs.abs_id; input; group; level; ports } :: events next
      | _ -> invalid_arg "every native backward effect and terminal return must have an explicit port translation" in
    let events = events expression in
    let own = List.filter (fun (event : event) -> event.group = target) events in
    let all = List.concat_map (fun (event : event) -> event.ports) own in
    let internal = internal_links target events in
    (* Native backward arguments/results put higher sub-abstraction levels first.
       Stable sorting retains actual field/parameter order within each level. *)
    let sort = List.stable_sort (fun (left : port) right -> Int.compare right.level left.level) in
    let inputs = sort (List.filter external_input all) and outputs = sort (List.filter external_output all) in
    let routes = List.map (fun (output : port) ->
      match List.mapi (fun index input -> index, input) inputs |> List.filter (fun (_, input) ->
        input.value.sv_id = output.value.sv_id && input.level = output.level) with
      | [index, _] -> index
      | _ -> invalid_arg "native backward output has no unique actual input payload channel") outputs in
    let branch = { target; events; inputs; outputs; routes; internal } in validate branch; branch) in
  { branches }

let replay component projection inputs expression forward protocol witness =
  try derive component projection inputs expression forward protocol = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol =
  let witness = derive component projection inputs expression forward protocol in
  if not (replay component projection inputs expression forward protocol witness) then
    invalid_arg "the complete actual native level-aware port wiring did not replay";
  witness

let nat = B.nat
let list = B.list
let sid = B.sid
let gid = B.gid
let aid = B.aid
let bool = B.bool
let ty = P.reflect
let edge = function
  | Root n -> ".root " ^ nat n | Field n -> ".field " ^ nat n | Child -> ".child" | GivenBack -> ".givenBack"
  | Consumed n -> ".consumed " ^ nat n | BorrowReprojection n -> ".borrowReprojection " ^ nat n
  | LoanReprojection n -> ".loanReprojection " ^ nat n | Argument (group, index) -> ".argument " ^ nat group ^ " " ^ nat index
  | ContinuationInput -> ".continuationInput" | ContinuationOutput -> ".continuationOutput"
let lean_port (port : port) = "{ identity := " ^ sid port.value.sv_id ^ ", nativeType := " ^ ty port.value.sv_ty ^
  ", payloadType := " ^ ty port.payload_type ^ ", abstraction := " ^ aid port.abstraction ^ ", group := " ^ gid port.group ^
  ", inputAbstraction := " ^ bool port.input ^ ", level := " ^ nat port.level ^ ", givenBack := " ^ bool port.given_back ^
  ", abstractPath := " ^ list edge port.abstract_path ^ ", continuationPath := " ^ list edge port.continuation_path ^ " }"
let lean_event (event : event) = "{ abstraction := " ^ aid event.abstraction ^ ", group := " ^ gid event.group ^
  ", inputAbstraction := " ^ bool event.input ^ ", level := " ^ nat event.level ^
  ", ports := " ^ list lean_port event.ports ^ " }"
let lean_internal link = "{ producerEvent := " ^ nat link.producer_event ^
  ", consumerEvent := " ^ nat link.consumer_event ^ ", producer := " ^ lean_port link.producer ^
  ", consumer := " ^ lean_port link.consumer ^ " }"
let type_fuel witness =
  1 + List.fold_left (fun n branch -> List.fold_left (fun n (port : port) ->
    max n (B.expression_depth (Return_region_certificate.reflect_type ~holes:[] port.value.sv_ty))) n
    (List.concat_map (fun (event : event) -> event.ports) branch.events)) 0 witness.branches

let report component projection inputs expression forward protocol witness =
  if not (replay component projection inputs expression forward protocol witness) then
    invalid_arg "native wiring report requires the complete actual-source witness";
  `Assoc ["schema", `String "actual-native-level-aware-backward-wiring/v2";
    "actual_native_port_wiring_replays", `Bool true; "type_fuel", `Int (type_fuel witness);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "events", `List (List.map (fun event -> `Assoc ["abstraction", `Int (V.AbsId.to_int event.abstraction);
        "input", `Bool event.input; "group", `Int (RegionGroupId.to_int event.group); "level", `Int event.level;
        "level_selected_ports", `List (List.map (fun port -> `String (lean_port port)) event.ports)]) branch.events);
      "external_inputs", `List (List.map (fun port -> `String (lean_port port)) branch.inputs);
      "external_outputs", `List (List.map (fun port -> `String (lean_port port)) branch.outputs);
      "internal_channels", `List (List.map (fun link -> `Assoc [
        "producer_event", `Int link.producer_event; "consumer_event", `Int link.consumer_event;
        "producer", `String (lean_port link.producer); "consumer", `String (lean_port link.consumer)]) branch.internal);
      "routes", `List (List.map (fun index -> `Int index) branch.routes)]) witness.branches);
    "all_actual_owned_ports_accounted_once", `Bool true;
    "internal_value_execution_implemented", `Bool false;
    "payload_routing_only_no_new_payload_operation", `Bool true;
    "native_projected_value_layout_region_adapter_proved", `Bool false;
    "foreign_parent_default_values_lowered", `Bool false;
    "complete_native_backward_abi_lowered", `Bool false;
    "native_heap_loan_layout_refinement_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeBorrowWiring";
  line "/- Actual native level-aware boundary payload routing; unelaborated/unqualified.";
  line "   Projected-value/region/layout adapters, parent defaults and heap/loan adequacy remain required. -/";
  line "namespace Auths.Qualification.NativeBorrowWiring";
  line "open Auths.Support.SourceClosureRegions Auths.Support.NativeBorrowWiring";
  line "universe u";
  List.iter (fun branch ->
    let name = "branch" ^ gid branch.target in
    line ("def " ^ name ^ " : Program := {");
    line ("  target := " ^ gid branch.target);
    line ("  events := " ^ list lean_event branch.events);
    line ("  inputs := " ^ list lean_port branch.inputs);
    line ("  outputs := " ^ list lean_port branch.outputs);
    line ("  routes := " ^ list nat branch.routes);
    line ("  internal := " ^ list lean_internal branch.internal);
    line ("  typeFuel := " ^ nat (type_fuel witness) ^ " }");
    line ("theorem " ^ name ^ "_preserves_actual_port_identities_and_sorts : check " ^ name ^ " = true := by"); line "  rfl";
    let slot index = List.fold_left (fun inside _ -> ".there (" ^ inside ^ ")") ".here" (List.init index Fun.id) in
    let route = List.fold_right (fun index tail -> ".cons (" ^ slot index ^ ") (" ^ tail ^ ")") branch.routes ".nil" in
    line ("def " ^ name ^ "Route : Route (" ^ name ^ ".inputs.map Port.payloadType) (" ^ name ^ ".outputs.map Port.payloadType) :=");
    line ("  " ^ route);
    line ("theorem " ^ name ^ "_typed_route_matches_native_channels : indices " ^ name ^ "Route = " ^ name ^ ".routes := by"); line "  rfl";
    line ("def " ^ name ^ "Backward (Payload : Expr → Type u)");
    line ("    (inputs : Values Payload (" ^ name ^ ".inputs.map Port.payloadType)) :");
    line ("    Values Payload (" ^ name ^ ".outputs.map Port.payloadType) := execute " ^ name ^ "Route inputs");
    let names = List.mapi (fun index _ -> "payload" ^ nat index) branch.inputs in
    let arguments = List.map2 (fun name (port : port) -> "(" ^ name ^ " : Payload (" ^ ty port.payload_type ^ "))") names branch.inputs in
    let values values = List.fold_right (fun value tail -> ".cons " ^ value ^ " (" ^ tail ^ ")") values ".nil" in
    line ("theorem " ^ name ^ "_routes_existing_payloads (Payload : Expr → Type u) " ^ String.concat " " arguments ^ " :");
    line ("    " ^ name ^ "Backward Payload (" ^ values names ^ ") =");
    line ("      " ^ values (List.map (List.nth names) branch.routes) ^ " := by"); line "  rfl"
  ) witness.branches;
  line "end Auths.Qualification.NativeBorrowWiring";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
