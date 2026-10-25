(* Link every initial SSA current seed to the very same actual forward trace
   and typed returned value. This is not a source heap/permission interpreter,
   nor a replacement for the pinned native default/continuation translator. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module D = Native_borrow_defaults
module N = Native_pure_payload
module X = Native_pure_expressions
module W = Native_current_wiring

type path_step = Field of int | MutableBorrow of V.borrow_id | Boxed
type seed = {
  key : B.origin;
  binding : F.binding;
  path : path_step list;
  codec_helper : X.helper;
}
type t = { seeds : seed list; return_ended_regions : region_id list; wiring : W.t }

let rec paths identity = function
  | F.Symbolic actual -> if actual = identity then [[]] else []
  | F.MutableBorrow (borrow, child) -> List.map (fun path -> MutableBorrow borrow :: path) (paths identity child)
  | F.Boxed child -> List.map (fun path -> Boxed :: path) (paths identity child)
  | F.Record (_, fields) -> List.concat (List.mapi (fun index child ->
      List.map (fun path -> Field index :: path) (paths identity child)) fields)

let rec native_focus path (value : V.tvalue) = match path, value.value with
  | [], _ -> value
  | Field index :: rest, V.VAdt { variant_id = None; fields } ->
      (match List.nth_opt fields index with Some field -> native_focus rest field
       | None -> invalid_arg "a current seed's actual native returned field is absent")
  | MutableBorrow identity :: rest, V.VBorrow (V.VMutBorrow (actual, child)) when actual = identity ->
      native_focus rest child
  | Boxed :: rest, V.VAdt { variant_id = None; fields = [child] } ->
      (match value.ty with
       | TAdt { id = TBuiltin TBox; generics = { types = [_]; _ } } -> native_focus rest child
       | _ -> invalid_arg "a current seed's Box path cannot unwrap an arbitrary one-field record")
  | _ -> invalid_arg "a current seed path changed its original typed native return node or borrow identity"

let derive component projection inputs expression (forward : F.t) protocol wiring defaults execution full_abi payload expressions (current : W.t) =
  if not (W.replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current) then
    invalid_arg "forward seed binding requires the complete actual SSA state program witness";
  let rec delimiter = function
    | S.Meta (_, next) | S.Expansion (_, _, S.ExpandNoBranch (_, next)) -> delimiter next
    | S.Expansion (_, _, S.ExpandAdt [None, _, next]) -> delimiter next
    | S.ForwardEnd (Some (context, returned), _, _, _) -> context, returned
    | _ -> invalid_arg "current seed binding cannot skip an original forward effect or fabricate a returned value" in
  let return_context, returned = delimiter expression in
  let cells = List.concat_map (fun (branch : W.branch) -> branch.seeds) current.branches in
  let unique = List.fold_left (fun seen (cell : W.cell) -> match List.assoc_opt cell.key seen with
    | None -> seen @ [cell.key, cell]
    | Some previous ->
        if previous.W.source_type <> cell.source_type || previous.shape <> cell.shape ||
            previous.available <> cell.available || previous.variable.ty <> cell.variable.ty then
          invalid_arg "different backward branches cannot assign different source carriers to the same initial current key";
        seen) [] cells in
  let seeds = List.map (fun (key, (cell : W.cell)) ->
    if cell.available <> Native_borrow_view.Whole then
      invalid_arg "an initial current seed cannot promote a partial forward view to a full value";
    let identity = match key with
      | B.Symbolic identity -> identity
      | B.Borrow identity ->
          (match List.filter_map (function F.MutableExpansion (_, actual, contents) when actual = identity -> Some contents.sv_id
             | _ -> None) forward.steps with
           | [contents] -> contents
           | _ -> invalid_arg "a current borrow seed needs its unique actual expanded pointee identity") in
    let binding = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
      | [binding] -> binding
      | _ -> invalid_arg "an initial current seed cannot use a missing or ambiguous forward symbolic value" in
    if binding.source_type <> cell.source_type || binding.shape <> cell.shape then
      invalid_arg "the native SSA seed differs from its complete actual forward value carrier";
    let path = match paths identity forward.result with
      | [path] -> path
      | _ -> invalid_arg "an initial current seed needs one exact occurrence in the actual native returned capture" in
    let focused = native_focus path returned in
    (match focused.value with
     | V.VSymbolic actual when actual.sv_id = binding.native.sv_id && actual.sv_ty = binding.native.sv_ty -> ()
     | _ -> invalid_arg "the current seed's returned path does not name its exact original typed native symbolic value");
    if Aeneas.TypesUtils.ty_erase_regions focused.ty <> Aeneas.TypesUtils.ty_erase_regions binding.native.sv_ty then
      invalid_arg "the current seed's native returned leaf has a different executable type";
    let codecs = List.filter (fun (helper : X.helper) -> helper.source.outgoing.access.native_shape = binding.shape &&
      helper.source.outgoing.native_type = cell.variable.ty) expressions.X.helpers in
    let codec_helper = match codecs with
      | first :: rest when List.for_all (fun (other : X.helper) -> other.source.outgoing.codec = first.source.outgoing.codec &&
          other.source.outgoing.layout = first.source.outgoing.layout) rest -> first
      | _ -> invalid_arg "a current seed needs an existing exact whole source-to-native field codec" in
    { key; binding; path; codec_helper }) unique in
  (* The current reflected component's public harness has these two typed
     roles. A different source component must derive its own harness, not reuse
     one merely because its erased types happen to match. *)
  (match List.map (fun seed -> seed.key) seeds with
   | [B.Borrow counter; B.Symbolic writer] when V.BorrowId.to_int counter = 0 && V.SymbolicValueId.to_int writer = 6 -> ()
   | _ -> invalid_arg "a different actual seed roster requires a separately derived typed component harness");
  { seeds; return_ended_regions = RegionId.Set.elements return_context.ended_regions; wiring = current }

let replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current witness =
  try derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current in
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current witness) then
    invalid_arg "the complete forward-current seed binding did not replay";
  witness

let lean_path path = "[" ^ String.concat ", " (List.map (function Field index -> ".field " ^ string_of_int index
  | MutableBorrow _ -> ".mutableBorrow" | Boxed -> ".boxed") path) ^ "]"
let native_path path = `List (List.map (function
  | Field index -> `Assoc ["record_field", `Int index]
  | MutableBorrow identity -> `Assoc ["exclusive_borrow", `Int (V.BorrowId.to_int identity)]
  | Boxed -> `String "originalBox") path)
let payload_name seed = "Auths.Qualification.NativePurePayload.branch" ^ B.gid seed.codec_helper.group ^
  "Channel" ^ string_of_int seed.codec_helper.index

let report component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current witness) then
    invalid_arg "forward current seed report lost its exact actual trace/return/state witness";
  `Assoc ["schema", `String "actual-native-forward-capture-current-seeds/v1";
    "seeds", `List (List.map (fun seed -> `Assoc [
      "current_key", `String (D.lean_origin seed.key);
      "actual_forward_symbol", `Int (V.SymbolicValueId.to_int seed.binding.native.sv_id);
      "complete_native_symbolic_type", `String (P.reflect seed.binding.native.sv_ty);
      "candidate_type", `String (P.reflect seed.binding.source_type);
      "candidate_shape", `String (P.lean seed.binding.shape);
      "actual_native_returned_path", native_path seed.path;
      "pure_data_returned_path", `String (lean_path seed.path);
      "exact_existing_field_codec", `String (payload_name seed ^ "OutgoingCodec")]) witness.seeds);
    "native_return_context_ended_regions", `List (List.map (fun id -> `Int (RegionId.to_int id)) witness.return_ended_regions);
    "typed_native_returned_seed_paths_replayed", `Bool true;
    "backward_seed_values_read_from_same_forward_execution", `Bool true;
    "unrelated_post_forward_seed_arguments_in_composed_interface", `Bool false;
    "ordinary_rust_results_supplied", `Bool false;
    "opaque_environment_equality_used", `Bool false;
    "original_native_environment_permissions_adequacy_proved", `Bool false;
    "original_native_default_activation_continuation_adequacy_proved", `Bool false;
    "original_source_heap_loan_layout_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let buffer = Buffer.create 98304 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeCurrentSeeds";
  line "import qualification.aeneas.cases.NativeCaptureValue";
  line "import qualification.aeneas.cases.NativeCurrentWiring";
  line "/- Forward and backward seeds share the same actual reflected execution.";
  line "   Unelaborated/unqualified; original native environments/permissions/continuations remain open. -/";
  line "namespace Auths.Qualification.NativeCurrentSeeds";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeCurrentSeeds";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "open Auths.Qualification.NativeCaptureValue";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  line "universe u";
  let typing = "Auths.Qualification.NativePurePayload.atomTyping" in
  let source_atom = "SourceAtom " ^ typing ^ " Atom" in
  let input_names = List.map (fun (root : P.root) -> "input" ^ string_of_int root.index) projection.inputs in
  let input_args = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data (" ^ source_atom ^ ") " ^ name ^ "Shape)") input_names) in
  let names = String.concat " " input_names in
  let input_values = "[" ^ String.concat ", " (List.map (fun name -> "⟨" ^ name ^ "Shape, " ^ name ^ "⟩") input_names) ^ "]" in
  let binders = "(Atom : Ty → Type u) " ^ input_args in
  let rec destruct indent name shape finish =
    let add text = line (String.make indent ' ' ^ text) in
    match shape with
    | P.Named (_, body) -> add ("cases " ^ name ^ " with"); add ("| named " ^ name ^ "Body =>"); destruct (indent + 2) (name ^ "Body") body finish
    | P.Borrow (_, _, body) -> add ("cases " ^ name ^ " with"); add ("| borrow " ^ name ^ "Body =>"); destruct (indent + 2) (name ^ "Body") body finish
    | P.Product (first, second) ->
        add ("cases " ^ name ^ " with"); add ("| product " ^ name ^ "First " ^ name ^ "Rest =>");
        destruct (indent + 2) (name ^ "First") first (fun indent -> destruct indent (name ^ "Rest") second finish)
    | P.Unit -> add ("cases " ^ name ^ " with"); add "| unit =>"; finish (indent + 2)
    | P.Empty -> add ("cases " ^ name)
    | P.Atom _ | P.Sum _ -> finish indent in
  let source_cases () =
    let rec all indent = function
      | [] -> line (String.make indent ' ' ^ "rfl")
      | (root : P.root) :: rest -> destruct indent ("input" ^ string_of_int root.index) root.shape (fun indent -> all indent rest) in
    all 2 projection.inputs in
  List.iteri (fun index seed ->
    let name = "seed" ^ string_of_int index in
    line ("def " ^ name ^ "Shape : Shape := " ^ P.lean seed.binding.shape);
    line ("def " ^ name ^ "Path : List PathStep := " ^ lean_path seed.path);
    line ("def " ^ name ^ "FromState " ^ binders ^ " : Option (Data (" ^ source_atom ^ ") " ^ name ^ "Shape) := do");
    line ("  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState actualProgram " ^ input_values);
    line ("  readSeed actualProgram state (" ^ D.lean_origin seed.key ^ ") " ^ name ^ "Shape");
    line ("def " ^ name ^ "FromReturned " ^ binders ^ " : Option (Data (" ^ source_atom ^ ") " ^ name ^ "Shape) := do");
    line ("  let value ← Auths.Support.NativeCaptureValue.run actualProgram " ^ input_values);
    line ("  readReturnedAs " ^ name ^ "Shape " ^ name ^ "Path value");
    line ("theorem " ^ name ^ "_is_exact_returned_capture " ^ binders ^ " :");
    line ("    " ^ name ^ "FromState Atom " ^ names ^ " = " ^ name ^ "FromReturned Atom " ^ names ^ " := by");
    source_cases ()
  ) witness.seeds;
  line "structure Prepared (Atom : Ty → Type u) where";
  line ("  value : Data (" ^ source_atom ^ ") outputShape");
  List.iteri (fun index seed -> line ("  current" ^ string_of_int index ^ " : Value Atom " ^ payload_name seed ^ "Layout")) witness.seeds;
  List.iter (fun from_state ->
    let name = if from_state then "prepare" else "prepareFromReturned" in
    line ("def " ^ name ^ " " ^ binders ^ " : Option (Prepared Atom) := do");
    if from_state then line ("  let (value, state) ← Auths.Support.NativeCaptureValue.runWithState actualProgram " ^ input_values)
    else line ("  let value ← Auths.Support.NativeCaptureValue.run actualProgram " ^ input_values);
    line "  let captured ← Auths.Support.NativeCaptureValue.castData outputShape value";
    List.iteri (fun index seed -> line ("  let current" ^ string_of_int index ^ " ← " ^
      (if from_state then "readSeed actualProgram state (" ^ D.lean_origin seed.key ^ ")"
       else "readReturnedAs") ^ " seed" ^ string_of_int index ^ "Shape" ^
      (if from_state then "" else " seed" ^ string_of_int index ^ "Path value"))) witness.seeds;
    line ("  pure { value := captured, " ^ String.concat ", " (List.mapi (fun index seed ->
      "current" ^ string_of_int index ^ " := encode " ^ payload_name seed ^ "OutgoingCodec current" ^ string_of_int index) witness.seeds) ^ " }")
  ) [true; false];
  line ("theorem prepared_seeds_are_from_returned_capture " ^ binders ^ " :");
  line ("    prepare Atom " ^ names ^ " = prepareFromReturned Atom " ^ names ^ " := by");
  source_cases ();
  line ("theorem prepared_value_is_original_source_capture " ^ binders ^ " :");
  line ("    (prepare Atom " ^ names ^ ").map Prepared.value = some (construct (" ^ source_atom ^ ") " ^ names ^ ") := by");
  source_cases ();
  List.iter (fun (branch : W.branch) ->
    let name = "branch" ^ B.gid branch.source.target in
    let inputs = List.mapi (fun index ((helper : X.helper), _) ->
      let name = "incoming" ^ string_of_int index in
      name, "(" ^ name ^ " : Value Atom " ^ "Auths.Qualification.NativePurePayload.branch" ^ B.gid helper.group ^
        "Channel" ^ string_of_int helper.index ^ "Layout)") branch.inputs in
    let args = String.concat " " (List.map snd inputs) and incoming = String.concat " " (List.map fst inputs) in
    List.iter (fun (suffix, prepared, callee) ->
      line ("def " ^ name ^ suffix ^ " " ^ binders ^ " " ^ args ^ " : Option (Dynamic Atom) := do");
      line ("  let captured ← " ^ prepared ^ " Atom " ^ names);
      line ("  Auths.Qualification.NativeCurrentWiring." ^ name ^ callee ^ " Atom captured.current0 captured.current1 " ^ incoming)
    ) ["FromForward", "prepare", "Run"; "FromReturned", "prepareFromReturned", "Run"; "Expected", "prepare", "Expected"];
    line ("theorem " ^ name ^ "_uses_captured_current " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "FromForward Atom " ^ names ^ " " ^ incoming ^ " = " ^ name ^ "FromReturned Atom " ^ names ^ " " ^ incoming ^ " := by");
    line ("  simp only [" ^ name ^ "FromForward, " ^ name ^ "FromReturned, prepared_seeds_are_from_returned_capture]");
    line ("theorem " ^ name ^ "_refines_explicit_ending_model " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "FromForward Atom " ^ names ^ " " ^ incoming ^ " = " ^ name ^ "Expected Atom " ^ names ^ " " ^ incoming ^ " := by");
    line ("  unfold " ^ name ^ "FromForward " ^ name ^ "Expected");
    line ("  cases prepared : prepare Atom " ^ names ^ " with");
    line "  | none => simp [prepared]";
    line "  | some captured =>";
    line "    simp only [prepared, Option.bind_some]";
    line ("    exact Auths.Qualification.NativeCurrentWiring." ^ name ^ "_executes_explicit_ending_model Atom captured.current0 captured.current1 " ^ incoming)
  ) witness.wiring.branches;
  line "end Auths.Qualification.NativeCurrentSeeds";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
