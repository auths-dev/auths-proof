(* Inspect the actual Box wrapper's source footprint. Its prefix only writes
   locals, forwards a borrow of the payload and retains the outer Box. Suffix
   and unwind contain only storage/exit statements. This does NOT discharge
   alias disjointness, native loans or semantic carrier preservation. *)
open Charon
open Types
open LlbcAst

type t = { receiver : Virtual_receiver.t; owner_argument : Expressions.local_id;
  suffix : statement list; unwind : block }

let derive receiver =
  if not (Virtual_receiver.replay receiver) then invalid_arg "a Box footprint requires its exact actual source receiver route";
  let argument = receiver.Virtual_receiver.receiver_origin.argument in
  let index = Expressions.LocalId.to_int argument - 1 in
  if index < 0 || index >= List.length receiver.frame.signature.inputs then invalid_arg "the actual Box wrapper argument is absent";
  (match List.nth receiver.frame.signature.inputs index with
   | TRef (_, box, RMut) when Option.is_some (Capture_return.predicate box) -> ()
   | _ -> invalid_arg "the actual Box footprint needs its original exclusive reference to the owning carrier");
  if receiver.receiver_origin.dereferences <> 2 || receiver.box_accesses = [] then
    invalid_arg "the actual Box wrapper lost its reference/Box access and payload reborrow";
  let rec suffix = function
    | [] -> invalid_arg "the actual payload forwarding statement is absent"
    | statement :: rest when statement = receiver.source_statement -> rest
    | _ :: rest -> suffix rest in
  let suffix = suffix receiver.frame.body.statements in
  List.iter (fun (statement : statement) -> match statement.kind with StorageDead _ | Return | Nop -> ()
    | _ -> invalid_arg "the source Box wrapper changes its carrier after payload forwarding") suffix;
  let unwind = match receiver.source_statement.kind with Call (_, unwind) -> unwind
    | _ -> invalid_arg "the actual Box footprint lost its original virtual source call" in
  List.iter (fun (statement : statement) -> match statement.kind with StorageDead _ | UnwindResume | Nop -> ()
    | _ -> invalid_arg "the actual Box wrapper unwind needs explicit carrier effects") unwind.statements;
  { receiver; owner_argument = argument; suffix; unwind }

let replay witness = try derive witness.receiver = witness with Invalid_argument _ -> false
let create receiver = let witness = derive receiver in
  if not (replay witness) then invalid_arg "the complete actual Box wrapper footprint did not replay"; witness

let report witness = `Assoc ["source_owner_argument", `Int (Expressions.LocalId.to_int witness.owner_argument);
  "source_virtual_statement", `Int (StatementId.to_int witness.receiver.source_statement.statement_id);
  "actual_source_box_wrapper_footprint_replays", `Bool (replay witness);
  "native_alias_disjointness_loans_and_carrier_preservation_proved", `Bool false;
  "qualified", `Bool false; "program_emitted", `Bool false]
