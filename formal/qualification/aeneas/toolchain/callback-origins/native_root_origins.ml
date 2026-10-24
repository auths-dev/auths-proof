(* Derive source-root coordinates from every actual expansion and ending port.
   Origin chains identify a storage position, never a runtime value/default.
   Reads and updates use a supplied current whole carrier. The original native
   signature is retained separately; these coordinates are not its execution. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_borrow_view
module G = Current_borrow_carrier
module N = Native_backward_types

type alias = { source : F.binding; input : int; focus : G.focus }
type port = { original : W.port; event : int; position : int; chain : V.symbolic_value_id list;
  root : C.root; alias : alias; output_focus : G.focus; instance : C.type_instance }
type branch = { target : region_group_id; ports : port list }
type t = { signature : N.t; aliases : alias list; borrows : (V.borrow_id * alias) list; branches : branch list }

let derive component (projection : P.t) inputs symbolic (forward : F.t) (protocol : B.t) (wiring : W.t) levels signature =
  if not (N.replay component projection inputs symbolic forward protocol wiring levels signature) then
    invalid_arg "whole-root source origins require the actual complete native signature and every original source/ending witness";
  let source identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
    | [binding] -> binding | _ -> invalid_arg "a whole-root origin lacks one exact original forward binding" in
  let input_root index = match List.filter (fun (root : P.root) -> root.index = index) projection.inputs with
    | [root] -> root | _ -> invalid_arg "a whole-root origin cannot invent a source parameter" in
  let aliases = ref [] and borrows = ref [] in
  let find identity = match List.filter (fun alias -> alias.source.native.sv_id = identity) !aliases with
    | [alias] -> alias | _ -> invalid_arg "a source-root expansion must use one actual earlier value" in
  let insert input focus (native : V.symbolic_value) =
    let binding = source native.V.sv_id in
    if binding.native <> native || G.target (input_root input).shape focus <> binding.shape ||
        List.exists (fun alias -> alias.source.native.sv_id = native.sv_id) !aliases then
      invalid_arg "an exact source-root focus changed a complete binding, shape or fresh identity";
    let alias = { source = binding; input; focus } in aliases := !aliases @ [alias]; alias in
  List.iter2 (fun (input : P.root) native -> ignore (insert input.index G.Here native)) projection.inputs forward.inputs;
  List.iter (function
    | F.MutableExpansion (identity, borrow, contents) ->
        let parent = find identity in
        (match parent.source.shape with P.Borrow (RMut, _, _) -> ()
         | _ -> invalid_arg "a whole-root mutable expansion lost its actual exclusive source reference");
        if List.mem_assoc borrow !borrows then invalid_arg "whole-root source borrows must retain fresh original identities";
        let alias = insert parent.input (G.compose parent.focus (G.Borrow G.Here)) contents in
        borrows := !borrows @ [borrow, alias]
    | F.RecordExpansion (identity, fields) ->
        let parent = find identity in
        List.iteri (fun index native -> ignore (insert parent.input
          (G.compose parent.focus (G.record_field parent.source.shape index)) native)) fields
    | F.BoxExpansion (identity, contents) ->
        let parent = find identity in
        (match parent.source.shape with P.Named (P.Boxed, _) -> ()
         | _ -> invalid_arg "a whole-root Box expansion lost its original source wrapper");
        ignore (insert parent.input (G.compose parent.focus (G.Named G.Here)) contents)) forward.steps;
  if List.sort compare (List.map (fun alias -> alias.source) !aliases) <> List.sort compare forward.source_bindings then
    invalid_arg "source-root origins must retain every original forward input/expansion binding";
  let branches = List.map (fun (branch : W.branch) ->
    let scope = match List.filter (fun (actual : B.branch) -> actual.target = branch.target) protocol.branches with
      | [scope] -> scope | _ -> invalid_arg "a whole-root origin lost its original branch scope" in
    let definitions = List.concat_map (fun (event : B.event) -> List.filter_map (function
      | B.Define (value, origin) -> Some (value, origin) | _ -> None) event.abstract_values) scope.events |> List.sort_uniq compare in
    let rec trace seen identity =
      if List.mem identity seen then invalid_arg "cyclic static native storage-origin chain";
      match List.filter (fun alias -> alias.source.native.sv_id = identity) !aliases with
      | [alias] -> C.ForwardSymbol identity, alias, [identity]
      | [] ->
          (match List.filter (fun ((value : V.symbolic_value), _) -> value.sv_id = identity) definitions with
           | [_, B.Borrow borrow] ->
               let alias = match List.assoc_opt borrow !borrows with Some alias -> alias
                 | None -> invalid_arg "a whole-root origin names an absent actual forward borrow" in
               C.BorrowPayload borrow, alias, [identity]
           | [_, B.Symbolic parent] ->
               let root, alias, chain = trace (identity :: seen) parent in root, alias, identity :: chain
           | _ -> invalid_arg "a whole-root ending port needs one consistent complete actual producer")
      | _ -> invalid_arg "ambiguous original source-root alias" in
    let ports = List.concat (List.mapi (fun event (ending : W.event) -> List.mapi (fun position (original : W.port) ->
      let root, alias, chain = trace [] original.value.sv_id in
      let move_position = match List.mapi (fun position input -> position, input) projection.capture.moved_inputs |>
          List.filter (fun (_, input) -> input = alias.input) with
        | [position, _] -> position | _ -> invalid_arg "a whole-root source input must occur in one exact original capture move" in
      let move_focus = G.record_field projection.output.shape move_position in
      if G.target projection.output.shape move_focus <> (input_root alias.input).shape then
        invalid_arg "a whole-root capture move changed the original complete input shape";
      let output_focus = G.compose move_focus alias.focus in
      if G.target projection.output.shape output_focus <> alias.source.shape then
        invalid_arg "original input/output origin coordinates changed complete source carrier fields";
      let instance = C.type_instance alias.source.source_type original.value.sv_ty in
      { original; event; position; chain; root; alias; output_focus; instance }) ending.ports) branch.events) in
    { target = branch.target; ports }) wiring.branches in
  { signature; aliases = !aliases; borrows = !borrows; branches }

let replay component projection inputs symbolic forward protocol wiring levels signature witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature =
  let witness = derive component projection inputs symbolic forward protocol wiring levels signature in
  if not (replay component projection inputs symbolic forward protocol wiring levels signature witness) then
    invalid_arg "actual complete source-root origin coordinates did not replay";
  witness

let report component projection inputs symbolic forward protocol wiring levels signature witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature witness) then
    invalid_arg "source-root origin report lost an actual original source/ending/signature field";
  `Assoc ["schema", `String "actual-native-whole-source-root-origins/v1";
    "forward_binding_count", `Int (List.length witness.aliases); "borrow_count", `Int (List.length witness.borrows);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "all_original_ports", `List (List.map (fun port -> `Assoc ["event", `Int port.event; "position", `Int port.position;
        "actual_port", `String (W.lean_port port.original); "source_input", `Int port.alias.input;
        "original_static_identity_chain", `List (List.map (fun id -> `Int (V.SymbolicValueId.to_int id)) port.chain);
        "source_input_focus", `String (G.lean_focus port.alias.focus); "source_output_focus", `String (G.lean_focus port.output_focus);
        "complete_source_carrier", `String (P.lean port.alias.source.shape);
        "complete_source_type", `String (P.reflect port.alias.source.source_type)]) branch.ports)]) witness.branches);
    "every_actual_owned_and_foreign_port_retained", `Bool true;
    "identity_chain_used_to_obtain_runtime_snapshot_or_default", `Bool false;
    "new_external_port_or_caller_argument_introduced", `Bool false;
    "complete_native_argument_value_codec_execution_and_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.CurrentBorrowCarrier";
  line "import Auths.Support.NativeBorrowView";
  line "import qualification.aeneas.cases.NativeBackwardTypes";
  line "import qualification.aeneas.cases.NativeCaptureValue";
  line "/- Actual source-root storage coordinates; unelaborated/unqualified.";
  line "   Native whole-argument codecs, execution, source heap/loan and lifetime adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeRootOrigins";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.CurrentBorrowCarrier";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ B.nat (FunDeclId.to_int projection.candidate.def_id));
  line "universe u";
  let names = List.map (fun (root : P.root) -> "input" ^ B.nat root.index) projection.inputs in
  let arguments = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data Atom " ^ name ^ "Shape)") names) in
  let values = "[" ^ String.concat ", " (List.map (fun name -> "⟨" ^ name ^ "Shape, " ^ name ^ "⟩") names) ^ "]" in
  List.iter (fun branch -> List.iter (fun port ->
    let name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat port.event ^ "Port" ^ B.nat port.position in
    let input = "input" ^ B.nat port.alias.input in
    let schema : C.schema = { payload_type = port.original.payload_type; candidate_type = port.alias.source.source_type;
      shape = port.alias.source.shape; selection = C.Whole } in
    let viewed : C.port = { native = port.original; root = port.root; chain = port.chain; schema = 0; type_instance = port.instance } in
    line ("def " ^ name ^ "NativePort : Auths.Support.NativeBorrowWiring.Port := " ^ W.lean_port port.original);
    line ("def " ^ name ^ "TypeInstance : Auths.Support.NativeBorrowView.TypeInstance := " ^ C.lean_type_instance schema viewed);
    line ("theorem " ^ name ^ "_keeps_complete_type_and_alias_partition : Auths.Support.NativeBorrowView.checkTypeInstance " ^ name ^ "TypeInstance = true := by decide");
    line ("theorem " ^ name ^ "_type_instance_is_the_original_native_port : " ^ name ^ "TypeInstance.native = " ^ name ^ "NativePort.nativeType := by rfl");
    line ("def " ^ name ^ "Shape : Shape := " ^ P.lean port.alias.source.shape);
    line ("def " ^ name ^ "InputFocus : Focus " ^ input ^ "Shape " ^ name ^ "Shape := " ^ G.lean_focus port.alias.focus);
    line ("def " ^ name ^ "OutputFocus : Focus outputShape " ^ name ^ "Shape := " ^ G.lean_focus port.output_focus);
    line ("theorem " ^ name ^ "_prepared_output_has_exact_source_origin (Atom : Expr → Type u) " ^ arguments ^ " :");
    line ("    read " ^ name ^ "OutputFocus (construct Atom " ^ String.concat " " names ^ ") = read " ^ name ^ "InputFocus " ^ input ^ " := by rfl");
    line ("theorem " ^ name ^ "_actual_forward_preparation_has_exact_source_origin (Atom : Expr → Type u) " ^ arguments ^ " :");
    line ("    ((Auths.Support.NativeCaptureValue.run Auths.Qualification.NativeCaptureValue.actualProgram " ^ values ^ ").bind");
    line ("      (Auths.Support.NativeCaptureValue.castData outputShape)).map (read " ^ name ^ "OutputFocus) =");
    line ("      some (read " ^ name ^ "InputFocus " ^ input ^ ") := by");
    line ("  rw [Auths.Qualification.NativeCaptureValue.native_forward_value_matches_source_capture Atom " ^ String.concat " " names ^ "]");
    line "  rfl";
    line ("theorem " ^ name ^ "_current_source_update_is_read_exactly (Atom : Expr → Type u)");
    line ("    (current : Data Atom " ^ input ^ "Shape) (update : Data Atom " ^ name ^ "Shape) :");
    line ("    read " ^ name ^ "InputFocus (write " ^ name ^ "InputFocus current update) = update := read_write _ _ _")
  ) branch.ports) witness.branches;
  line "end Auths.Qualification.NativeRootOrigins";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
