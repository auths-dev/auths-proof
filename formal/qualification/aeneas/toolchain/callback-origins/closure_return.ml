(* Actual source return of a captured closure aggregate. Every normal return
   must have the same explicit aggregate origin; other joins refuse pending a
   richer source value invariant. Source capture labels remain callee-scoped. *)
open Charon
open Types
open Expressions
open LlbcAst

type returned = { statement : statement; value_path : Closure_value_path.t; constraints : Region_equations.predicates }
type t = { capture : Closure_capture.t; returns : returned list; environment : Region_shape.factorization }

let derive crate ~(capture : Closure_capture.t) =
  if not (Closure_capture.replay crate capture) then invalid_arg "a closure return requires its actual full source aggregate";
  let frame = Source_call.frame capture.caller in
  (match frame.signature.output with TAdt reference when reference.id = capture.reference.id -> ()
   | _ -> invalid_arg "the actual closure aggregate and source return identify different nominal types");
  let returns = ref [] in
  let collect = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      (match statement.kind with
       | Return ->
           let value_path = try Closure_value_path.create crate ~capture statement.statement_id
             with Source_path.Not_dominating -> invalid_arg "a normal closure return has no dominating actual aggregate value" in
           (match value_path.destination.kind with PlaceLocal id when LocalId.to_int id = 0 -> ()
            | _ -> invalid_arg "the actual source closure return slot has no paired aggregate value");
           let constraints = Region_equations.add_type value_path.constraints value_path.destination.ty frame.signature.output in
           if not (Region_equations.replay_predicates constraints) then invalid_arg "the complete actual closure return type premises did not replay";
           returns := { statement; value_path; constraints } :: !returns
       | _ -> ()); super#visit_statement env statement
  end in collect#visit_block () frame.body;
  if !returns = [] then invalid_arg "the actual captured closure has no normal source return";
  let environment = Region_shape.factor capture.reference.generics in
  { capture; returns = List.rev !returns; environment }

let replay crate witness = try derive crate ~capture:witness.capture = witness
  with Invalid_argument _ | Not_found | Source_path.Not_dominating -> false

let create crate ~capture =
  let witness = derive crate ~capture in
  if not (replay crate witness) then invalid_arg "the complete actual aggregate/normal-return routes did not replay";
  witness

let report crate witness =
  `Assoc ["source_callee_node", `Int witness.capture.caller.index;
    "actual_source_capture", Closure_capture.report crate witness.capture;
    "normal_return_routes", `List (List.map (fun returned -> `Assoc [
      "actual_value_path", Closure_value_path.report crate returned.value_path;
      "original_return_typing_premises", Diagnostic.region_certificate_json returned.constraints]) witness.returns);
    "complete_actual_closure_returns_replay", `Bool (replay crate witness);
    "native_call_activation_and_capture_return_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
