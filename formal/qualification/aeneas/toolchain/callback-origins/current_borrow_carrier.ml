(* Focuses are reconstructed from the actual native returned value, not a
   region-erased type search. Restoration always receives the current carrier.
   This is not the native loan-ending/default-continuation interpreter. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_borrow_view
module T = Native_borrow_transport

type focus = Here | First of focus | Second of focus | Named of focus | Borrow of focus
type port = { transport : T.port; focus : focus }
type branch = { target : region_group_id; ports : port list; parents : region_var_group list }
type t = {
  candidate : fun_decl_id;
  output : P.shape;
  inputs : (int * P.shape * focus) list;
  source_move_order : int list;
  branches : branch list;
}

let rec target shape = function
  | Here -> shape
  | First next -> (match shape with P.Product (left, _) -> target left next
      | _ -> invalid_arg "current-carrier first focus has no actual product")
  | Second next -> (match shape with P.Product (_, right) -> target right next
      | _ -> invalid_arg "current-carrier second focus has no actual product")
  | Named next -> (match shape with P.Named (_, body) -> target body next
      | _ -> invalid_arg "current-carrier named focus has no actual nominal/field/Box wrapper")
  | Borrow next -> (match shape with P.Borrow (RMut, _, body) -> target body next
      | _ -> invalid_arg "current-carrier borrow focus has no actual exclusive-reference wrapper")

let record_field shape index =
  let rec fields expected index = function
    | P.Product (P.Named (P.Field (actual, _), _), tail) when actual = expected ->
        if index = 0 then First (Named Here) else Second (fields (expected + 1) (index - 1) tail)
    | _ -> invalid_arg "current-carrier focus cannot omit, reorder or invent a source record field" in
  match shape with P.Named (P.Nominal _, body) when index >= 0 -> Named (fields 0 index body)
  | _ -> invalid_arg "current-carrier field focus requires its actual original nominal"

let rec compose outer inner = match outer with
  | Here -> inner | First next -> First (compose next inner) | Second next -> Second (compose next inner)
  | Named next -> Named (compose next inner) | Borrow next -> Borrow (compose next inner)

let locate output result root =
  let rec walk shape value = match value, root with
    | F.Symbolic identity, C.ForwardSymbol expected when identity = expected -> [Here]
    | F.MutableBorrow (identity, _), C.BorrowPayload expected when identity = expected ->
        (match shape with P.Borrow (RMut, _, _) -> [Borrow Here]
         | _ -> invalid_arg "the actual returned borrow changed its exclusive-reference shape")
    | F.MutableBorrow (_, contents), _ ->
        (match shape with P.Borrow (RMut, _, body) -> List.map (fun next -> Borrow next) (walk body contents)
         | _ -> invalid_arg "a returned borrow cannot be traversed through an unrelated shape")
    | F.Boxed contents, _ ->
        (match shape with P.Named (P.Boxed, body) -> List.map (fun next -> Named next) (walk body contents)
         | _ -> invalid_arg "a returned Box cannot be traversed through an unrelated shape")
    | F.Record (actual, fields), _ when actual = shape ->
        List.concat (List.mapi (fun index value ->
          let field = record_field shape index in
          List.map (compose field) (walk (target shape field) value)) fields)
    | F.Symbolic _, _ -> []
    | _ -> invalid_arg "current-carrier origin search changed the actual complete returned value" in
  match walk output result with
  | [focus] -> focus
  | _ -> invalid_arg "a current-carrier origin must occur exactly once in the actual returned value"

let derive component (projection : P.t) inputs expression forward protocol wiring views transport =
  if not (T.replay component projection inputs expression forward protocol wiring views transport) then
    invalid_arg "current-carrier reconstruction requires its complete actual native transport witness";
  let output = projection.output.shape in
  let inputs = List.map (fun (input : P.root) ->
    let positions = List.mapi (fun index source -> index, source) projection.capture.moved_inputs |>
      List.filter (fun (_, source) -> source = input.index) in
    let position = match positions with [position, _] -> position
      | _ -> invalid_arg "a current input must have one actual returned source-move field" in
    let focus = record_field output position in
    if target output focus <> input.shape then
      invalid_arg "current input recovery changed its complete original shape";
    input.index, input.shape, focus) projection.inputs in
  let branches = List.map (fun (branch : T.branch) ->
    let group = match List.filter (fun (group : region_var_group) -> group.id = branch.target) projection.hierarchy with
      | [group] -> group | _ -> invalid_arg "current-carrier reconstruction lost its actual region hierarchy" in
    let parents = List.map (fun id -> match List.filter (fun (group : region_var_group) -> group.id = id) projection.hierarchy with
      | [group] -> group | _ -> invalid_arg "current-carrier parent has no exact source hierarchy entry") group.parents in
    let ports = List.map (fun (transport : T.port) ->
      let focus = locate output forward.F.result transport.candidate.root in
      if target output focus <> transport.source_shape then
        invalid_arg "actual returned origin and exact native port adapter disagree on complete carrier fields";
      { transport; focus }) branch.ports in
    { target = branch.target; ports; parents }) transport.T.branches in
  { candidate = projection.candidate.def_id; output; inputs;
    source_move_order = projection.capture.moved_inputs; branches }

let replay component projection inputs expression forward protocol wiring views transport witness =
  try derive component projection inputs expression forward protocol wiring views transport = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring views transport =
  let witness = derive component projection inputs expression forward protocol wiring views transport in
  if not (replay component projection inputs expression forward protocol wiring views transport witness) then
    invalid_arg "the complete actual current-carrier reconstruction did not replay";
  witness

let rec lean_focus = function
  | Here -> ".here" | First next -> ".first (" ^ lean_focus next ^ ")"
  | Second next -> ".second (" ^ lean_focus next ^ ")" | Named next -> ".named (" ^ lean_focus next ^ ")"
  | Borrow next -> ".borrow (" ^ lean_focus next ^ ")"

let rec lean_disjoint first second = match first, second with
  | First first, Second second -> Some (".firstSecond (" ^ lean_focus first ^ ") (" ^ lean_focus second ^ ")")
  | Second second, First first -> Some (".secondFirst (" ^ lean_focus second ^ ") (" ^ lean_focus first ^ ")")
  | First first, First second -> Option.map (fun proof -> ".first (" ^ proof ^ ")") (lean_disjoint first second)
  | Second first, Second second -> Option.map (fun proof -> ".second (" ^ proof ^ ")") (lean_disjoint first second)
  | Named first, Named second -> Option.map (fun proof -> ".named (" ^ proof ^ ")") (lean_disjoint first second)
  | Borrow first, Borrow second -> Option.map (fun proof -> ".borrow (" ^ proof ^ ")") (lean_disjoint first second)
  | _ -> None

let report component projection inputs expression forward protocol wiring views transport witness =
  if not (replay component projection inputs expression forward protocol wiring views transport witness) then
    invalid_arg "current-carrier report requires its complete actual-source witness";
  `Assoc ["schema", `String "actual-native-current-carrier-reconstruction/v1";
    "actual_returned_origin_focus_replays", `Bool true;
    "current_carrier_required_for_every_update", `Bool true;
    "original_input_focuses", `List (List.map (fun (input, _, focus) -> `Assoc [
      "source_input", `Int input; "actual_returned_field_focus", `String (lean_focus focus)]) witness.inputs);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "parent_current_views", `List (List.map (fun (parent : region_var_group) -> `Int (RegionGroupId.to_int parent.id)) branch.parents);
      "ports", `List (List.map (fun port -> `Assoc [
        "native_symbol", `Int (V.SymbolicValueId.to_int port.transport.candidate.native.value.sv_id);
        "level", `Int port.transport.candidate.native.level;
        "focus", `String (lean_focus port.focus)]) branch.ports)]) witness.branches);
    "native_parent_default_continuations_lowered", `Bool false;
    "complete_native_backward_abi_lowered", `Bool false;
    "native_source_heap_loan_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.CurrentBorrowCarrier";
  line "import qualification.aeneas.cases.NativeBorrowTransport";
  line "/- Actual current-carrier restoration, unelaborated/unqualified.";
  line "   Native parent/default continuations, full ABI and heap/loan adequacy remain required. -/";
  line "namespace Auths.Qualification.CurrentBorrowCarrier";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.CurrentBorrowCarrier";
  line "open Auths.Qualification.NativeBorrowTransport";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ B.nat (FunDeclId.to_int witness.candidate));
  line "universe u";
  List.iter (fun (input, shape, focus) ->
    let name = "input" ^ B.nat input in
    line ("def " ^ name ^ "Focus : Focus outputShape " ^ name ^ "Shape := " ^ lean_focus focus);
    line ("def recoverInput" ^ B.nat input ^ " (Atom : Expr → Type u) (current : Data Atom outputShape) : Data Atom " ^ name ^ "Shape :=");
    line ("  read " ^ name ^ "Focus current");
    ignore shape) witness.inputs;
  let arguments = String.concat " " (List.map (fun (input, _, _) ->
    "(input" ^ B.nat input ^ " : Data Atom input" ^ B.nat input ^ "Shape)") witness.inputs) in
  let values = String.concat " " (List.map (fun (input, _, _) -> "input" ^ B.nat input) witness.inputs) in
  List.iter (fun (input, _, _) ->
    line ("theorem recover_source_input_" ^ B.nat input ^ " (Atom : Expr → Type u) " ^ arguments ^ " :");
    line ("    recoverInput" ^ B.nat input ^ " Atom (construct Atom " ^ values ^ ") = input" ^ B.nat input ^ " := by rfl")
  ) witness.inputs;
  line "theorem reassemble_current_source_inputs (Atom : Expr → Type u) (current : Data Atom outputShape) :";
  line ("    construct Atom " ^ String.concat " " (List.map (fun (input, _, _) ->
    "(recoverInput" ^ B.nat input ^ " Atom current)") witness.inputs) ^ " = current := by");
  line "  cases current with";
  line "  | named fields =>";
  let rec split_fields indent index name = function
    | [] -> line (indent ^ "cases " ^ name); line (indent ^ "rfl")
    | _ :: rest ->
        let field = "field" ^ B.nat index and tail = "tail" ^ B.nat index in
        line (indent ^ "cases " ^ name ^ " with");
        line (indent ^ "| product " ^ field ^ " " ^ tail ^ " =>");
        line (indent ^ "    cases " ^ field ^ " with");
        line (indent ^ "    | named input" ^ B.nat index ^ " =>");
        split_fields (indent ^ "        ") (index + 1) tail rest in
  split_fields "      " 0 "fields" witness.source_move_order;
  List.iter (fun branch ->
    let branch_name = "branch" ^ B.gid branch.target in
    List.iter (fun (parent : region_var_group) ->
      let name = branch_name ^ "Parent" ^ B.gid parent.id in
      line ("def " ^ name ^ "Plan : Plan outputShape := select " ^
        B.list (fun id -> ".parameter " ^ B.nat (RegionId.to_int id)) parent.regions ^ " outputShape");
      line ("def " ^ name ^ "Current (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom " ^ name ^ "Plan :=");
      line ("  get " ^ name ^ "Plan current");
      line ("theorem " ^ name ^ "_restores_current (Atom : Expr → Type u) (current : Data Atom outputShape) :");
      line ("    put " ^ name ^ "Plan current (" ^ name ^ "Current Atom current) = some current := get_then_put _ _")
    ) branch.parents;
    List.iteri (fun index port ->
      let name = branch_name ^ "Port" ^ B.nat index in
      let schema = "Auths.Qualification.NativeBorrowView." ^ branch_name ^ "Schema" ^ B.nat port.transport.candidate.schema in
      line ("def " ^ name ^ "Focus : Focus outputShape " ^ schema ^ ".shape := " ^ lean_focus port.focus);
      line ("def " ^ name ^ "Extract (Atom : Expr → Type u) (current : Data Atom outputShape) : View Atom " ^ name ^ "NativePlan :=");
      line ("  " ^ name ^ "ToNative Atom (extract " ^ name ^ "Focus " ^ schema ^ ".plan current)");
      line ("def " ^ name ^ "Restore (Atom : Expr → Type u) (current : Data Atom outputShape) (update : View Atom " ^ name ^ "NativePlan) : Option (Data Atom outputShape) :=");
      line ("  restore " ^ name ^ "Focus " ^ schema ^ ".plan current (" ^ name ^ "FromNative Atom update)");
      line ("theorem " ^ name ^ "_restores_extracted_current (Atom : Expr → Type u) (current : Data Atom outputShape) :");
      line ("    " ^ name ^ "Restore Atom current (" ^ name ^ "Extract Atom current) = some current := by");
      line ("  simp [" ^ name ^ "Restore, " ^ name ^ "Extract, " ^ name ^ "_candidate_round_trip, restore_extracted_current]");
      line ("theorem " ^ name ^ "_restored_view_is_exact (Atom : Expr → Type u) (current after : Data Atom outputShape)");
      line ("    (update : View Atom " ^ name ^ "NativePlan) (accepted : " ^ name ^ "Restore Atom current update = some after) :");
      line ("    " ^ name ^ "Extract Atom after = update := by");
      line ("  have exactView := restored_view_is_update " ^ name ^ "Focus " ^ schema ^ ".plan current after (" ^ name ^ "FromNative Atom update) accepted");
      line ("  simpa [" ^ name ^ "Extract, exactView, " ^ name ^ "_native_round_trip]");
      line ("theorem " ^ name ^ "_uses_current_whole_carrier (Atom : Expr → Type u) (current : Data Atom outputShape)");
      line ("    (update : View Atom " ^ name ^ "NativePlan) :");
      line ("    put (liftPlan " ^ name ^ "Focus " ^ schema ^ ".plan) current");
      line ("      (liftView " ^ name ^ "Focus " ^ schema ^ ".plan (" ^ name ^ "FromNative Atom update)) = " ^ name ^ "Restore Atom current update :=");
      line "  restore_is_whole_carrier_put _ _ _ _";
      List.iter (fun (input, _, observer) -> match lean_disjoint port.focus observer with
        | None -> ()
        | Some proof ->
            let suffix = "input" ^ B.nat input in
            line ("theorem " ^ name ^ "_separate_from_" ^ suffix ^ " : Disjoint " ^ name ^ "Focus " ^ suffix ^ "Focus := " ^ proof);
            line ("theorem " ^ name ^ "_preserves_current_" ^ suffix ^ " (Atom : Expr → Type u) (current after : Data Atom outputShape)");
            line ("    (update : View Atom " ^ name ^ "NativePlan) (accepted : " ^ name ^ "Restore Atom current update = some after) :");
            line ("    recoverInput" ^ B.nat input ^ " Atom after = recoverInput" ^ B.nat input ^ " Atom current :=");
            line ("  restoration_preserves_disjoint_current " ^ name ^ "_separate_from_" ^ suffix ^ " " ^ schema ^ ".plan current after (" ^ name ^ "FromNative Atom update) accepted")
      ) witness.inputs
    ) branch.ports
  ) witness.branches;
  line "end Auths.Qualification.CurrentBorrowCarrier";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
