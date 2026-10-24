(* Attach an actual returned closure value to its actual caller result, with
   declared arguments and private callee-body captures kept in distinct scopes. *)
type t = {
  binding : Source_call.t;
  returns : Closure_return.t;
  environments : Capture_scope.t list;
}

let derive crate ~(binding : Source_call.t) ~(returns : Closure_return.t) =
  if not (Source_call.replay crate binding) || not (Closure_return.replay crate returns) then
    invalid_arg "a closure return call requires the exact actual source call and every actual normal return";
  if returns.capture.caller <> binding.callee then invalid_arg "the actual closure return belongs to another complete callee instance";
  let caller_frame = Source_call.frame binding.caller and callee_frame = Source_call.frame binding.callee in
  let environments = List.map (fun (returned : Closure_return.returned) ->
    Capture_scope.create ~source_parameters:binding.callee.view.arguments.parameters
      ~source_body_regions:callee_frame.source_body.bound_body_regions ~caller_parameters:binding.caller.view.arguments.parameters
      ~caller_body_regions:caller_frame.source_body.bound_body_regions ~actual_arguments:binding.normalized_arguments
      ~environment:returns.environment.arguments ~constraints:returned.constraints) returns.returns in
  { binding; returns; environments }

let replay crate witness = try derive crate ~binding:witness.binding ~returns:witness.returns = witness
  with Invalid_argument _ | Not_found -> false

let create crate ~binding ~returns =
  let witness = derive crate ~binding ~returns in
  if not (replay crate witness) then invalid_arg "the actual source closure return/call/private capture scopes did not replay";
  witness

let report crate witness = `Assoc [
  "actual_source_call", Source_call.report crate witness.binding;
  "actual_normal_closure_returns", Closure_return.report crate witness.returns;
  "actual_callee_capture_scopes", `List (List.map Capture_scope.report witness.environments);
  "complete_actual_source_closure_return_call_replays", `Bool (replay crate witness);
  "runtime_return_case_activation_and_loan_simulation_proved", `Bool false;
  "qualified", `Bool false; "program_emitted", `Bool false]
