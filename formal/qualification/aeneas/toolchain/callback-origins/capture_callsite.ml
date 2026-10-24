(* Bind actual normal Box return/capture cases to an actual source call.
   Private source labels remain in their callee scope, separately from the
   caller's source call ABI certificate. No runtime result is supplied. *)
open Charon
open LlbcAst

type case = { returned : Capture_return.returned; environment : Capture_scope.t }
type t = { binding : Source_call.t; returns : Capture_return.t; cases : case list }

let derive crate ~(caller : Source_closure.node) ~(callee : Source_closure.node)
    ~(returns : Capture_return.t) statement_id =
  let binding = Source_call.derive crate ~caller ~callee statement_id in
  let caller_frame = Source_call.frame caller and callee_frame = Source_call.frame callee in
  if returns.view <> callee.view || returns.frame <> callee_frame || not (Capture_return.replay crate returns) then
    invalid_arg "the actual call needs the exact callee's complete source return summary";
  let cases = List.map (fun (returned : Capture_return.returned) ->
    let environment = Capture_scope.create ~source_parameters:callee.view.arguments.parameters
      ~source_body_regions:callee_frame.source_body.bound_body_regions ~caller_parameters:caller.view.arguments.parameters
      ~caller_body_regions:caller_frame.source_body.bound_body_regions ~actual_arguments:binding.normalized_arguments
      ~environment:returned.paired.producer.capture_environment ~constraints:returned.paired.constraints in
    { returned; environment }) returns.returns in
  { binding; returns; cases }

let replay crate witness = try derive crate ~caller:witness.binding.caller ~callee:witness.binding.callee
  ~returns:witness.returns witness.binding.source_statement.statement_id = witness
  with Invalid_argument _ | Not_found -> false

let create crate ~(caller : Source_closure.node) ~(callee : Source_closure.node) ~returns statement_id =
  ignore (Source_call.create crate ~caller ~callee statement_id);
  let witness = derive crate ~caller ~callee ~returns statement_id in
  if not (replay crate witness) then invalid_arg "the complete actual source call/return/capture binding did not replay";
  witness

let report crate witness =
  `Assoc ["actual_source_call", Source_call.report crate witness.binding;
    "normal_source_return_cases", `List (List.map (fun (case : case) -> `Assoc [
      "producer_statement", `Int (StatementId.to_int case.returned.paired.producer.statement.statement_id);
      "source_return_statement", `Int (StatementId.to_int case.returned.statement);
      "source_capture_environment", Capture_scope.report case.environment]) witness.cases);
    "complete_actual_call_return_binding_replays", `Bool (replay crate witness);
    "case_selection_native_activation_loan_ownership_and_unwind_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
