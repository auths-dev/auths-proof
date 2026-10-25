(* Exact linear route of one original source aggregate up to a real statement.
   The route is conditional on its original branch tests; no callback result,
   native exclusive loan, activation identity or effect summary is supplied. *)
open Charon
open Expressions
open LlbcAst

type t = {
  capture : Closure_capture.t;
  target : statement;
  prefix : Source_path.step list;
  destination : place;
  moves : statement list;
  constraints : Region_equations.predicates;
}

let local (place : place) = match place.kind with PlaceLocal id -> id
  | _ -> invalid_arg "an actual closure value needs its explicit local ownership place"

let derive crate ~(capture : Closure_capture.t) target_id =
  if not (Closure_capture.replay crate capture) then invalid_arg "a closure value path needs its complete actual source aggregate";
  let frame = Source_call.frame capture.caller in
  let target = Prepared_injection.unique_statement frame.body target_id in
  let original = match capture.statement.kind with Assign (({ kind = PlaceLocal _; _ } as destination), _) -> destination
    | _ -> invalid_arg "the source closure aggregate lost its actual local destination" in
  let prefix = Source_path.between frame.body capture.statement.statement_id target_id in
  let constraints = ref capture.constraints in
  let equal left right = constraints := Region_equations.add_type !constraints left right in
  let current = ref original and moves = ref [] in
  List.iter (function
    | Source_path.Execute statement ->
        (match statement.kind with
         | Assign (destination, Use (Move source, NoRetag)) when source.kind = (!current).kind ->
             equal source.ty (!current).ty; ignore (local destination);
             if destination.kind = source.kind then invalid_arg "an actual closure move cannot overwrite its same source slot";
             equal destination.ty source.ty; current := destination; moves := statement :: !moves
         | StorageDead id | StorageLive id when id = local !current ->
             invalid_arg "an actual captured closure crosses dead or replaced source storage"
         | _ when Source_path.mentions_local (local !current) statement ->
             invalid_arg "an intervening closure use/copy/escape needs its complete actual value-effect interface"
         | _ -> ())
    | Source_path.Branch choice ->
        let scan_place place =
          let found = ref false in
          let scan = object inherit [_] iter_statement as super
            method! visit_place env place =
              (match place.kind with PlaceLocal id when id = local !current -> found := true | _ -> ());
              super#visit_place env place
          end in scan#visit_place () place;
          if !found then invalid_arg "the actual closure value participates in an unresolved branch selector" in
        (match choice.selector with Source_path.Value (Copy place | Move place) | Source_path.Discriminant place -> scan_place place
         | Source_path.Value (Constant _) -> ())) prefix;
  if not (Region_equations.replay_predicates !constraints) then invalid_arg "the complete actual closure move typing premises did not replay";
  { capture; target; prefix; destination = !current; moves = List.rev !moves; constraints = !constraints }

let replay crate witness = try derive crate ~capture:witness.capture witness.target.statement_id = witness
  with Invalid_argument _ | Not_found | Source_path.Not_dominating -> false

let create crate ~capture target_id =
  if Function_frame.prepare crate capture.Closure_capture.caller.view <> Source_call.frame capture.caller then
    invalid_arg "a closure value path requires its complete actual source frame";
  let witness = derive crate ~capture target_id in
  if not (replay crate witness) then invalid_arg "the complete actual source closure value path did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_capture_statement", `Int (StatementId.to_int witness.capture.statement.statement_id);
    "actual_target_statement", `Int (StatementId.to_int witness.target.statement_id);
    "actual_value_place", `String (show_place witness.destination);
    "original_conditional_path", Source_path.report witness.prefix;
    "original_linear_moves", `List (List.map (fun (statement : statement) -> `Int (StatementId.to_int statement.statement_id)) witness.moves);
    "complete_actual_value_path_replays", `Bool (replay crate witness);
    "native_ownership_and_capture_loan_simulation_proved", `Bool false]
