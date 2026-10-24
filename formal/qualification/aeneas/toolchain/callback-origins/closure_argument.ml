(* Preserve the very actual closure aggregate through linear source moves into
   an actual call argument. This binds a value route, not a callback effect or
   native borrow/activation simulation. Captured fields remain attached to the
   original aggregate; nominal type equality alone never creates a route. *)
open Charon
open Types
open Expressions
open LlbcAst

exception Unrelated
type t = {
  capture : Closure_capture.t;
  binding : Source_call.t;
  argument_index : int;
  actual_argument : operand;
  prefix : Source_path.step list;
  moves : statement list;
  constraints : Region_equations.predicates;
}

let derive crate ~(capture : Closure_capture.t) ~(binding : Source_call.t) argument_index =
  if not (Closure_capture.replay crate capture) || not (Source_call.replay crate binding) then
    invalid_arg "a closure argument needs its complete actual source aggregate and call";
  if capture.caller <> binding.caller then raise Unrelated;
  let value_path = try Closure_value_path.create crate ~capture binding.source_statement.statement_id
    with Source_path.Not_dominating -> raise Unrelated in
  let prefix = value_path.prefix in
  let constraints = ref (List.fold_left Region_equations.add_premise value_path.constraints (List.rev binding.constraints.originals)) in
  let equal left right = constraints := Region_equations.add_type !constraints left right in
  let current = value_path.destination in
  if argument_index < 0 || argument_index >= List.length binding.call.args then
    invalid_arg "the complete actual source closure argument position is absent";
  let actual_argument = List.nth binding.call.args argument_index in
  (match actual_argument with Move actual when actual.kind = current.kind -> equal actual.ty current.ty
   | Copy actual when actual.kind = current.kind ->
       invalid_arg "an actual source closure containing an exclusive capture cannot be copied into its consumer"
   | _ -> raise Unrelated);
  List.iteri (fun index source -> if index <> argument_index then match source with
    | Copy place | Move place ->
        let scan = object inherit [_] iter_statement as super
          method! visit_place env place =
            (match place.kind with PlaceLocal id when id = Closure_value_path.local current ->
              invalid_arg "an actual captured closure cannot also escape through another argument" | _ -> ());
            super#visit_place env place
        end in scan#visit_place () place
    | Constant _ -> ()) binding.call.args;
  equal (TAdt capture.reference) (List.nth binding.instantiated_signature.inputs argument_index);
  if not (Region_equations.replay_predicates !constraints) then
    invalid_arg "the original closure aggregate/move/argument/callee typing premises did not replay";
  { capture; binding; argument_index; actual_argument; prefix; moves = value_path.moves; constraints = !constraints }

let replay crate witness = try derive crate ~capture:witness.capture ~binding:witness.binding witness.argument_index = witness
  with Invalid_argument _ | Not_found | Unrelated -> false

let create crate ~capture ~binding argument_index =
  let witness = derive crate ~capture ~binding argument_index in
  if not (replay crate witness) then invalid_arg "the complete actual closure aggregate-to-argument value route did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_capture_statement", `Int (StatementId.to_int witness.capture.statement.statement_id);
    "actual_source_call", Source_call.report crate witness.binding;
    "actual_argument_index", `Int witness.argument_index;
    "actual_source_operand", `String (show_operand witness.actual_argument);
    "conditional_source_prefix", Source_path.report witness.prefix;
    "linear_move_statements", `List (List.map (fun (statement : statement) -> `Int (StatementId.to_int statement.statement_id)) witness.moves);
    "source_typing_premises", region_certificate_json witness.constraints;
    "complete_actual_closure_argument_route_replays", `Bool (replay crate witness);
    "callee_parameter_activation_capture_fields_and_effect_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
