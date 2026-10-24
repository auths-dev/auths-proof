(* Full native field-value adapters around actual selected-view channels.
   Current carriers remain explicit for partial updates; incoming unselected
   fields are never adopted. Native physical/source ABI adequacy is not assumed. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module B = Native_borrow_protocol
module C = Native_borrow_view
module D = Native_borrow_defaults
module E = Native_borrow_execution

type rebuilder = Keep | Empty | Unit | Product of rebuilder * rebuilder | Sum of rebuilder * rebuilder
  | Named of rebuilder | Borrow of rebuilder
let rec rebuild shape plan = match shape, plan with
  | _, D.Keep -> Keep
  | P.Empty, D.Empty -> Empty
  | P.Unit, D.Skip -> Unit
  | P.Product (left, right), D.Product (first, second) -> Product (rebuild left first, rebuild right second)
  | P.Sum (left, right), D.Sum (first, second) -> Sum (rebuild left first, rebuild right second)
  | P.Named (_, body), D.Named contents -> Named (rebuild body contents)
  | P.Borrow (_, _, body), D.Borrow contents -> Borrow (rebuild body contents)
  | _ -> invalid_arg "a full current carrier cannot be materialized from an absent field or skipped atom"
let rec lean_rebuilder = function
  | Keep -> ".keep" | Empty -> ".empty" | Unit -> ".unit"
  | Product (first, second) -> ".product (" ^ lean_rebuilder first ^ ") (" ^ lean_rebuilder second ^ ")"
  | Sum (first, second) -> ".sum (" ^ lean_rebuilder first ^ ") (" ^ lean_rebuilder second ^ ")"
  | Named contents -> ".named (" ^ lean_rebuilder contents ^ ")"
  | Borrow contents -> ".borrow (" ^ lean_rebuilder contents ^ ")"

type channel = {
  input_index : int; output_index : int;
  incoming : E.access; outgoing : E.access;
  whole : bool;
  current_builder : rebuilder;
}
type branch = { target : region_group_id; channels : channel list }
type t = { branches : branch list }

let derive component projection inputs expression forward protocol wiring defaults (execution : E.t) =
  if not (E.replay component projection inputs expression forward protocol wiring defaults execution) then
    invalid_arg "full native field adapters require the complete actual ending execution witness";
  let branches = List.map (fun (branch : E.branch) ->
    let operations = List.concat_map (fun (ending : E.ending) -> ending.operations) branch.endings in
    let inputs = List.mapi (fun index operation -> index, operation) operations |>
      List.filter (fun (_, operation) -> operation.E.kind = E.Receive) in
    let outputs = List.mapi (fun index operation -> index, operation) operations |>
      List.filter (fun (_, operation) -> operation.E.kind = E.Emit) in
    let channels = List.map (fun (output_index, (output : E.operation)) ->
      let input_index, input = match List.filter (fun (_, (input : E.operation)) ->
        input.access.port.value.sv_id = output.access.port.value.sv_id && input.access.port.level = output.access.port.level) inputs with
        | [input] -> input | _ -> invalid_arg "a full native value channel needs one actual incoming binder at its exact level" in
      if input.access.producer.candidate_type <> output.access.producer.candidate_type ||
          input.access.producer.candidate_shape <> output.access.producer.candidate_shape ||
          input.access.producer.selected <> output.access.producer.selected then
        invalid_arg "a full native value adapter cannot reinterpret different source carriers or selected plans";
      { input_index; output_index; incoming = input.access; outgoing = output.access;
        whole = input.access.producer.selected = C.Whole;
        current_builder = rebuild input.access.producer.candidate_shape
          (D.selection_plan input.access.producer.candidate_shape input.access.producer.available) }) outputs in
    if List.length channels <> List.length inputs || channels = [] then
      invalid_arg "full native value interfaces must account for every original incoming and outgoing channel";
    { target = branch.target; channels }) execution.branches in
  { branches }

let replay component projection inputs expression forward protocol wiring defaults execution witness =
  try derive component projection inputs expression forward protocol wiring defaults execution = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution in
  if not (replay component projection inputs expression forward protocol wiring defaults execution witness) then
    invalid_arg "the complete actual full native field adapter witness did not replay";
  witness

let report component projection inputs expression forward protocol wiring defaults execution witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution witness) then
    invalid_arg "full native field adapter report requires the complete actual-source witness";
  `Assoc ["schema", `String "actual-native-full-field-borrow-abi-adapters/v1";
    "actual_full_native_field_adapters_replay", `Bool true;
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "channels", `List (List.map (fun channel -> `Assoc [
        "symbol", `Int (V.SymbolicValueId.to_int channel.incoming.port.value.sv_id);
        "level", `Int channel.incoming.port.level;
        "input_operation", `Int channel.input_index; "output_operation", `Int channel.output_index;
        "whole_pointee_owned", `Bool channel.whole;
        "current_origin", `String (D.lean_origin channel.outgoing.producer.origin);
        "current_available_view", `String (C.selection channel.outgoing.producer.available);
        "current_complete_field_materializer", `String (lean_rebuilder channel.current_builder);
        "complete_incoming_type", `String (P.reflect channel.incoming.port.value.sv_ty);
        "complete_outgoing_type", `String (P.reflect channel.outgoing.port.value.sv_ty);
        "incoming_native_field_shape", `String (P.lean channel.incoming.native_shape);
        "outgoing_native_field_shape", `String (P.lean channel.outgoing.native_shape);
        "selected_candidate_view", `String (C.selection channel.incoming.producer.selected)]) branch.channels)]) witness.branches);
    "partial_updates_retain_current_unowned_fields", `Bool true;
    "incoming_unselected_data_is_authoritative", `Bool false;
    "skipped_atoms_can_be_materialized", `Bool false;
    "original_native_pure_type_abi_correspondence_proved", `Bool false;
    "native_current_carriers_materialized_from_actual_states", `Bool false;
    "original_source_heap_loan_layout_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.FullBorrowABI";
  line "import Auths.Support.BorrowViewMaterialize";
  line "import qualification.aeneas.cases.NativeBorrowExecution";
  line "/- Full native field-value adapters; unelaborated/unqualified.";
  line "   Actual current-state, native pure-type ABI and Rust heap/loan/layout adequacy remain required. -/";
  line "namespace Auths.Qualification.NativeBorrowFullABI";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport Auths.Support.FullBorrowABI";
  line "open Auths.Qualification.NativeBorrowExecution";
  line "open Auths.Support.BorrowViewMaterialize Auths.Support.NativeBorrowDefaults";
  line "universe u";
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target in
    let access index = name ^ "Operation" ^ B.nat index ^ "Access" in
    let channel_name index = name ^ "Channel" ^ B.nat index in
    List.iteri (fun index channel ->
      let ch = channel_name index and input = access channel.input_index and output = access channel.output_index in
      line ("def " ^ ch ^ " : Channel := { candidateShape := " ^ input ^ ".candidateShape, selected := " ^ input ^ ".selected,");
      line ("  incomingShape := " ^ input ^ ".nativeShape, outgoingShape := " ^ output ^ ".nativeShape,");
      line ("  incomingChange := " ^ input ^ ".transport, outgoingChange := " ^ output ^ ".transport }");
      let producer = "Auths.Qualification.NativeBorrowDefaults.branch" ^ B.gid branch.target ^ "Symbol" ^ B.sid channel.incoming.producer.value.sv_id in
      line ("def " ^ ch ^ "CurrentBuilder : Rebuilder " ^ producer ^ "Available := " ^ lean_rebuilder channel.current_builder);
      line ("def " ^ ch ^ "ReadCurrent (Atom : Expr → Type u) (current : Current Atom) : Option (Data Atom " ^ ch ^ ".outgoingShape) :=");
      line ("  readNativeCurrent current (" ^ D.lean_origin channel.outgoing.producer.origin ^ ") " ^ ch ^ "CurrentBuilder " ^ ch ^ ".outgoingChange");
      line ("theorem " ^ ch ^ "_missing_current_is_not_materialized (Atom : Expr → Type u) (current : Current Atom)");
      line ("    (missing : current (" ^ D.lean_origin channel.outgoing.producer.origin ^ ") = none) : " ^ ch ^ "ReadCurrent Atom current = none :=");
      line "  absent_current_is_not_materialized _ _ _ _ missing";
      if channel.whole then (
        line ("theorem " ^ ch ^ "_owns_whole_pointee : " ^ ch ^ ".selected = .keep := by rfl");
        line ("theorem " ^ ch ^ "_needs_no_current_default (Atom : Expr → Type u) (current : Data Atom " ^ ch ^ ".outgoingShape)");
        line ("    (incoming : Data Atom " ^ ch ^ ".incomingShape) : adapt " ^ ch ^ " current incoming = some (wholeValue " ^ ch ^ " incoming) :=");
        line ("  whole_ownership_needs_no_current_default " ^ ch ^ " " ^ ch ^ "_owns_whole_pointee current incoming"));
      line ("theorem " ^ ch ^ "_matching_full_input_is_accepted (Atom : Expr → Type u) (current : Data Atom " ^ ch ^ ".outgoingShape) :");
      line ("    adapt " ^ ch ^ " current (matchingIncoming " ^ ch ^ " current) = some current := matching_incoming_is_accepted _ _");
      line ("theorem " ^ ch ^ "_keeps_current_unselected_fields (Atom : Expr → Type u)");
      line ("    (current after : Data Atom " ^ ch ^ ".outgoingShape) (incoming : Data Atom " ^ ch ^ ".incomingShape)");
      line ("    (accepted : adapt " ^ ch ^ " current incoming = some after) :");
      line ("    get (Auths.Support.CurrentBorrowCarrier.complement " ^ ch ^ ".outgoingPlan) after =");
      line ("      get (Auths.Support.CurrentBorrowCarrier.complement " ^ ch ^ ".outgoingPlan) current := accepted_update_preserves_current_frame _ _ _ _ accepted");
      line ("theorem " ^ ch ^ "_ignores_unselected_incoming_fields (Atom : Expr → Type u)");
      line ("    (current : Data Atom " ^ ch ^ ".outgoingShape) (first second : Data Atom " ^ ch ^ ".incomingShape)");
      line ("    (same : get " ^ ch ^ ".incomingPlan first = get " ^ ch ^ ".incomingPlan second) :");
      line ("    adapt " ^ ch ^ " current first = adapt " ^ ch ^ " current second := unselected_incoming_data_has_no_effect _ _ _ _ same")
    ) branch.channels;
    let current_arguments = String.concat " " (List.mapi (fun index channel -> index, channel) branch.channels |>
      List.filter_map (fun (index, channel) -> if channel.whole then None else Some
        ("(current" ^ B.nat index ^ " : Data Atom " ^ channel_name index ^ ".outgoingShape)"))) in
    let incoming_arguments = String.concat " " (List.mapi (fun index _ ->
      "(incoming" ^ B.nat index ^ " : Data Atom " ^ channel_name index ^ ".incomingShape)") branch.channels) in
    let output_type = match branch.channels with
      | [_] -> "Data Atom " ^ channel_name 0 ^ ".outgoingShape"
      | _ -> "(" ^ String.concat " × " (List.mapi (fun index _ -> "Data Atom " ^ channel_name index ^ ".outgoingShape") branch.channels) ^ ")" in
    line ("def " ^ name ^ "Full (Atom : Expr → Type u) " ^ current_arguments ^ " " ^ incoming_arguments ^ " : Option (" ^ output_type ^ ") := do");
    List.iteri (fun index channel ->
      let ch = channel_name index and incoming = "incoming" ^ B.nat index in
      line ("  let output" ^ B.nat index ^ (if channel.whole then " := wholeValue " ^ ch ^ " " ^ incoming
        else " ← adapt " ^ ch ^ " current" ^ B.nat index ^ " " ^ incoming))) branch.channels;
    let tuple = match branch.channels with [_] -> "output0" | _ -> "(" ^ String.concat ", " (List.mapi (fun index _ -> "output" ^ B.nat index) branch.channels) ^ ")" in
    line ("  pure " ^ tuple);
    line ("def " ^ name ^ "FullExecute (Atom : Expr → Type u)");
    line "    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)";
    line "    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)";
    line ("    " ^ current_arguments ^ " " ^ incoming_arguments ^ " : Option (" ^ output_type ^ ") := do");
    let views = String.concat " " (List.mapi (fun index _ ->
      "(get " ^ channel_name index ^ ".incomingPlan incoming" ^ B.nat index ^ ")") branch.channels) in
    line ("  let views ← " ^ name ^ "Execute Atom (initialCurrent Atom counter writer) " ^ views);
    List.iteri (fun index channel ->
      let view = if List.length branch.channels = 1 then "views" else "views." ^ B.nat (index + 1) in
      line ("  let output" ^ B.nat index ^ (if channel.whole then " := " ^ view else
        " ← put " ^ channel_name index ^ ".outgoingPlan current" ^ B.nat index ^ " " ^ view))) branch.channels;
    line ("  pure " ^ tuple);
    line ("theorem " ^ name ^ "_full_value_adapter_matches_all_endings (Atom : Expr → Type u)");
    line "    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)";
    line "    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)";
    line ("    " ^ current_arguments ^ " " ^ incoming_arguments ^ " :");
    let args = String.concat " " (List.mapi (fun index channel -> if channel.whole then "" else "current" ^ B.nat index) branch.channels |>
      List.filter (fun value -> value <> "")) ^ " " ^ String.concat " " (List.mapi (fun index _ -> "incoming" ^ B.nat index) branch.channels) in
    line ("    " ^ name ^ "FullExecute Atom counter writer " ^ args ^ " = " ^ name ^ "Full Atom " ^ args ^ " := by");
    line ("  simp [" ^ name ^ "FullExecute, " ^ name ^ "_execution_normalizes_all_actual_endings, " ^ name ^ "Full,");
    line ("    " ^ name ^ "Backward, adapt, route, wholeValue, Channel.incomingPlan, Channel.outgoingPlan, " ^
      String.concat ", " (List.mapi (fun index _ -> channel_name index) branch.channels) ^ "]");
    line ("def " ^ name ^ "FullFromEndingState (Atom : Expr → Type u)");
    line "    (counter : Data Atom Auths.Qualification.NativeBorrowDefaults.branch0Symbol7CandidateShape)";
    line "    (writer : Data Atom Auths.Qualification.NativeBorrowDefaults.branch2Symbol11CandidateShape)";
    line ("    " ^ incoming_arguments ^ " : Option (" ^ output_type ^ ") := do");
    let incoming = String.concat " " (List.mapi (fun index _ ->
      "(get " ^ channel_name index ^ ".incomingPlan incoming" ^ B.nat index ^ ")") branch.channels) in
    line ("  let state ← Auths.Support.NativeBorrowExecution.run " ^ name ^ " (initialCurrent Atom counter writer) (" ^ name ^ "Incoming Atom " ^ incoming ^ ")");
    List.iteri (fun index channel ->
      let ch = channel_name index in
      line ("  let view" ^ B.nat index ^ " ← (state.outputs[" ^ B.nat index ^ "]?).bind (castEntry " ^ ch ^ ".outgoingShape " ^ ch ^ ".outgoingPlan)");
      if channel.whole then line ("  let output" ^ B.nat index ^ " := view" ^ B.nat index)
      else (
        line ("  let current" ^ B.nat index ^ " ← " ^ ch ^ "ReadCurrent Atom state.current");
        line ("  let output" ^ B.nat index ^ " ← put " ^ ch ^ ".outgoingPlan current" ^ B.nat index ^ " view" ^ B.nat index))
    ) branch.channels;
    line ("  pure " ^ tuple)
  ) witness.branches;
  line "end Auths.Qualification.NativeBorrowFullABI";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
