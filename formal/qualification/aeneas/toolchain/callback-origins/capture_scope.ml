(* A returned capture crosses two distinct source region scopes. Callee-body
   labels remain private binders; they never become caller-body labels or
   static lifetimes. A native consumer must supply a fresh activation binder
   and prove the returned loans remain live. This module supplies neither. *)
open Charon.Types

type label = Static | Caller of region | Private of region_id
type binding = { original : region; normalized : region; label : label }
type t = {
  source_parameters : region_param list;
  source_body_regions : int;
  caller_parameters : region_param list;
  caller_body_regions : int;
  actual_arguments : region list;
  environment : region list;
  constraints : Region_equations.predicates;
  bindings : binding list;
}

let derive ~source_parameters ~source_body_regions ~caller_parameters ~caller_body_regions
    ~actual_arguments ~environment ~constraints =
  Region_scope.require_parameters source_parameters;
  Region_scope.require_parameters caller_parameters;
  if List.length source_parameters <> List.length actual_arguments then
    invalid_arg "capture transport requires every actual declared callee lifetime argument";
  if not (Region_equations.replay_predicates constraints) then
    invalid_arg "capture transport requires the exact replayed original source premises";
  let source = new Region_scope.check ~body_regions:source_body_regions source_parameters in
  let caller = new Region_scope.check ~body_regions:caller_body_regions caller_parameters in
  List.iter (caller#visit_region []) actual_arguments;
  let arguments = List.combine (List.map (fun (parameter : region_param) -> parameter.index) source_parameters) actual_arguments in
  let bindings = List.map (fun original ->
    source#visit_region [] original;
    let normalized = Region_equations.resolve constraints.solution original in
    source#visit_region [] normalized;
    let label = match normalized with
      | RStatic -> Static
      | RVar (Free id) ->
          (match List.assoc_opt id arguments with
           | Some RStatic -> Static
           | Some region -> Caller region
           | None -> invalid_arg "a captured declared lifetime has no actual source call argument")
      | RBody id -> Private id
      | RErased | RVar (Bound _) -> invalid_arg "a returned capture cannot erase a lifetime or export an unopened quantifier" in
    { original; normalized; label }) environment in
  { source_parameters; source_body_regions; caller_parameters; caller_body_regions;
    actual_arguments; environment; constraints; bindings }

let replay witness = try derive ~source_parameters:witness.source_parameters ~source_body_regions:witness.source_body_regions
  ~caller_parameters:witness.caller_parameters ~caller_body_regions:witness.caller_body_regions
  ~actual_arguments:witness.actual_arguments ~environment:witness.environment ~constraints:witness.constraints = witness
  with Invalid_argument _ -> false

let create ~source_parameters ~source_body_regions ~caller_parameters ~caller_body_regions
    ~actual_arguments ~environment ~constraints =
  let witness = derive ~source_parameters ~source_body_regions ~caller_parameters ~caller_body_regions
    ~actual_arguments ~environment ~constraints in
  if not (replay witness) then invalid_arg "the complete two-scope capture environment did not replay";
  witness

let report witness =
  let label = function Static -> `Assoc ["kind", `String "literal_static"]
    | Caller region -> `Assoc ["kind", `String "actual_caller_region"; "region", `String (show_region region)]
    | Private id -> `Assoc ["kind", `String "private_callee_region"; "source_body_region", `Int (RegionId.to_int id)] in
  `Assoc ["callee_body_region_count", `Int witness.source_body_regions;
    "caller_body_region_count", `Int witness.caller_body_regions;
    "capture_bindings", `List (List.map (fun binding -> `Assoc [
      "original", `String (show_region binding.original); "normalized", `String (show_region binding.normalized);
      "transport", label binding.label]) witness.bindings);
    "complete_capture_scope_replays", `Bool (replay witness);
    "fresh_callee_activation_and_returned_loan_liveness_proved", `Bool false;
    "private_regions_reinterpreted_as_caller_regions", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
