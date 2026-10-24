(* Execute every actual selected-level ending in a pure-data current-view
   machine. Only given-back ports of strict source ancestors can select defaults. Native
   loan/heap/source adequacy is deliberately not supplied by this constructor. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_borrow_view
module T = Native_borrow_transport
module D = Native_borrow_defaults

type kind = Receive | Default | Emit | Observe
type access = {
  port : W.port;
  producer : D.default;
  native_shape : P.shape;
  mapping : (region * region) list;
  change : T.change;
  nominals : P.nominal list;
}
type operation = { kind : kind; access : access }
type ending = { event : W.event; operations : operation list }
type branch = { target : region_group_id; parents : region_group_id list; endings : ending list }
type t = { branches : branch list }

let derive component (projection : P.t) inputs expression forward protocol (wiring : W.t) (defaults : D.t) =
  if not (D.replay component projection inputs expression forward protocol wiring defaults) then
    invalid_arg "native ending execution requires exact selected-level defaults and the complete actual trace";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native ending access context contains unresolved errors";
  let branches = List.map (fun (branch : W.branch) ->
    let definitions = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) defaults.branches with
      | [actual] -> actual.defaults | _ -> invalid_arg "native ending execution lost its actual producer definitions" in
    let parents = match List.filter (fun (scope : B.branch) -> scope.target = branch.target) protocol.B.branches with
      | [scope] -> List.filter ((<>) branch.target) scope.allowed
      | _ -> invalid_arg "native ending execution lost its complete actual source ancestor hierarchy" in
    let endings = List.map (fun (event : W.event) ->
      let operations = List.map (fun (port : W.port) ->
        let producer = match List.filter (fun (definition : D.default) -> definition.value.sv_id = port.value.sv_id) definitions with
          | [definition] -> definition
          | _ -> invalid_arg "every native ending port must use one actual selected-level producer" in
        if not (List.for_all (fun (occurrence : D.occurrence) -> occurrence.group = port.group) producer.occurrences) then
          invalid_arg "a native ending port cannot reinterpret a producer's selected source region group";
        let kind = if port.group = branch.target then
          if W.external_input port then Receive else if W.external_output port then Emit else
            invalid_arg (Printf.sprintf
              "owned internal symbol %d at abstraction %d, group %d, level %d (%s) needs its existing whole-root argument or continuation binding"
              (V.SymbolicValueId.to_int port.value.sv_id) (V.AbsId.to_int port.abstraction)
              (RegionGroupId.to_int port.group) port.level (if port.input then "input" else "return"))
          else if not (List.mem port.group parents) then
            invalid_arg "a foreign native ending must belong to the exact source ancestor hierarchy"
          else if port.given_back && ((not port.input) || port.level > 0) then Default
          else if not port.given_back then Observe
          else invalid_arg "a foreign native ending cannot be replaced by a default or ignored call" in
        if kind = Default && producer.value <> port.value then
          invalid_arg "a native foreign default must bind its exact actual producer type";
        let instance = C.type_instance producer.candidate_type port.value.sv_ty in
        let mapping = List.combine instance.candidate_arguments instance.native_arguments in
        let parameters = List.map (function RVar (Free index) ->
          { index; name = None; variance = Invariant; mutability = LtUnknown }
          | _ -> invalid_arg "a native ending access requires exact native free region names") instance.native_arguments in
        let expand, nominals = P.make_expander component ~span:projection.candidate.item_meta.span
          ~type_infos:context.type_ctx.type_infos ~parameters in
        let native_shape = expand port.value.sv_ty in
        if native_shape <> T.rename_shape mapping producer.candidate_shape then
          invalid_arg "actual native ending fields disagree with their exact current-view adapter";
        { kind; access = { port; producer; native_shape; mapping;
          change = T.change producer.candidate_shape native_shape; nominals = nominals () } }
      ) event.ports in
      { event; operations }) branch.events in
    let ports kind = List.concat_map (fun ending -> List.filter_map
      (fun operation -> if operation.kind = kind then Some operation.access.port else None) ending.operations) endings in
    if ports Receive <> branch.inputs || ports Emit <> branch.outputs then
      invalid_arg "native ending order differs from the actual higher-level-first backward interface; explicit reordering is required";
    { target = branch.target; parents; endings }) wiring.branches in
  { branches }

let replay component projection inputs expression forward protocol wiring defaults witness =
  try derive component projection inputs expression forward protocol wiring defaults = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults =
  let witness = derive component projection inputs expression forward protocol wiring defaults in
  if not (replay component projection inputs expression forward protocol wiring defaults witness) then
    invalid_arg "the complete actual native ending execution witness did not replay";
  witness

let kind_name = function Receive -> "receive" | Default -> "foreignDefault" | Emit -> "emit" | Observe -> "observe"
let fuel witness =
  1 + List.fold_left (fun n branch -> List.fold_left (fun n ending ->
    List.fold_left (fun n operation -> max n (max (C.shape_depth operation.access.producer.candidate_shape)
      (C.shape_depth operation.access.native_shape))) n ending.operations) n branch.endings) 0 witness.branches
let default_name branch access =
  "Auths.Qualification.NativeBorrowDefaults.branch" ^ B.gid branch.target ^ "Symbol" ^ B.sid access.producer.value.sv_id
let lean_access branch access =
  let producer = default_name branch access in
  "{ candidateShape := " ^ producer ^ "CandidateShape, selected := " ^ producer ^ "Selected, nativeShape := " ^ P.lean access.native_shape ^
  ", transport := " ^ T.lean_change access.change ^ ", mapping := " ^ T.lean_mapping access.mapping ^ " }"

let report component projection inputs expression forward protocol wiring defaults witness =
  if not (replay component projection inputs expression forward protocol wiring defaults witness) then
    invalid_arg "native ending execution report requires the complete actual-source witness";
  `Assoc ["schema", `String "actual-native-selected-level-ending-execution/v1";
    "actual_complete_selected_level_ending_execution_replays", `Bool true;
    "metadata_fuel", `Int (fuel witness);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "parents", `List (List.map (fun group -> `Int (RegionGroupId.to_int group)) branch.parents);
      "endings", `List (List.map (fun ending -> `Assoc [
        "abstraction", `Int (V.AbsId.to_int ending.event.abstraction); "group", `Int (RegionGroupId.to_int ending.event.group);
        "input", `Bool ending.event.input; "level", `Int ending.event.level;
        "operations", `List (List.map (fun operation -> `Assoc ["kind", `String (kind_name operation.kind);
          "actual_native_port", `String (W.lean_port operation.access.port);
          "exact_field_view_adapter", `String (lean_access branch operation.access);
          "native_nominal_requirements", `List (List.map (fun (nominal : P.nominal) -> `Assoc [
            "reference", `String (P.reflect (TAdt nominal.reference));
            "requirements", `String (show_generic_params nominal.inherited_requirements)]) operation.access.nominals)]) ending.operations)]) branch.endings)]) witness.branches);
    "ordinary_rust_function_result_fallbacks", `Int 0;
    "generated_entry_prepares_current_from_actual_forward_state", `Bool true;
    "fixed_counter_writer_seed_names_used", `Bool false;
    "native_parent_default_selection_adequacy_proved", `Bool false;
    "complete_native_adt_backward_abi_adequacy_proved", `Bool false;
    "native_source_heap_loan_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let output = Buffer.create 65536 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeBorrowExecution";
  line "import qualification.aeneas.cases.NativeBorrowDefaults";
  line "import qualification.aeneas.cases.NativeCaptureValue";
  line "/- All actual selected-level synthesis endings, unelaborated/unqualified.";
  line "   Native default-selection, full ABI and source/heap/loan adequacy remain required. -/";
  line "namespace Auths.Qualification.NativeBorrowExecution";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport";
  line "open Auths.Support.NativeBorrowDefaults Auths.Support.NativeBorrowExecution";
  line "universe u";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  let source_names = List.map (fun (root : P.root) -> "sourceInput" ^ B.nat root.index) projection.inputs in
  let source_arguments = String.concat " " (List.map2 (fun name (root : P.root) ->
    "(" ^ name ^ " : Data Atom input" ^ B.nat root.index ^ "Shape)") source_names projection.inputs) in
  let source_values = "[" ^ String.concat ", " (List.map2 (fun name (root : P.root) ->
    "⟨input" ^ B.nat root.index ^ "Shape, " ^ name ^ "⟩") source_names projection.inputs) ^ "]" in
  line "def sourcePreparation := Auths.Qualification.NativeCaptureValue.actualProgram";
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target in
    let operations = List.concat_map (fun ending -> ending.operations) branch.endings in
    List.iteri (fun index operation ->
      let name = name ^ "Operation" ^ B.nat index in
      line ("def " ^ name ^ "Port : Auths.Support.NativeBorrowWiring.Port := " ^ W.lean_port operation.access.port);
      line ("def " ^ name ^ "Access : Access := " ^ lean_access branch operation.access);
      line ("def " ^ name ^ " : Operation := ." ^ kind_name operation.kind ^ " " ^ name ^ "Port " ^
        (if operation.kind = Default then default_name branch operation.access ^ " " ^ T.lean_mapping operation.access.mapping else name ^ "Access"))
    ) operations;
    let offset = ref 0 in
    let endings = List.map (fun ending ->
      let operations = List.mapi (fun index _ -> name ^ "Operation" ^ B.nat (!offset + index)) ending.operations in
      offset := !offset + List.length operations;
      "{ abstraction := " ^ B.aid ending.event.abstraction ^ ", group := " ^ B.gid ending.event.group ^
      ", input := " ^ B.bool ending.event.input ^ ", level := " ^ B.nat ending.event.level ^ ", operations := [" ^
      String.concat ", " operations ^ "] }") branch.endings in
    line ("def " ^ name ^ " : Program := { target := " ^ B.gid branch.target ^ ", parents := " ^ B.list B.gid branch.parents ^
      ", fuel := " ^ B.nat (fuel witness) ^ ", endings := [" ^ String.concat ", " endings ^ "] }");
    line ("theorem " ^ name ^ "_has_exact_typed_ending_roles : check " ^ name ^ " = true := by rfl");
    line ("theorem " ^ name ^ "_successful_execution_visits_all_actual_ports (Atom : Expr → Type u)");
    line ("    (current incoming : Current Atom) (after : State Atom) (accepted : run " ^ name ^ " current incoming = some after) :");
    line ("    after.visited = [" ^ String.concat ", " (List.mapi (fun index _ -> name ^ "Operation" ^ B.nat index ^ "Port") operations) ^ "] :=");
    line "  successful_run_visits_every_port _ _ _ _ accepted";
    let inputs = List.mapi (fun index operation -> index, operation) operations |> List.filter (fun (_, operation) -> operation.kind = Receive) in
    let outputs = List.mapi (fun index operation -> index, operation) operations |> List.filter (fun (_, operation) -> operation.kind = Emit) in
    let access index = name ^ "Operation" ^ B.nat index ^ "Access" in
    let arguments = String.concat " " (List.mapi (fun input (index, _) -> "(input" ^ B.nat input ^ " : View Atom " ^ access index ^ ".nativePlan)") inputs) in
    let names = String.concat " " (List.mapi (fun index _ -> "input" ^ B.nat index) inputs) in
    line ("def " ^ name ^ "Incoming (Atom : Expr → Type u) " ^ arguments ^ " : Current Atom := fun key =>");
    List.iteri (fun input (index, operation) -> line ("  if key = .symbolic " ^ B.sid operation.access.port.value.sv_id ^
      " then some ⟨" ^ access index ^ ".nativeShape, " ^ access index ^ ".nativePlan, input" ^ B.nat input ^ "⟩ else")) inputs;
    line "  none";
    let output_type = match outputs with
      | [index, _] -> "View Atom " ^ access index ^ ".nativePlan"
      | _ -> "(" ^ String.concat " × " (List.map (fun (index, _) -> "View Atom " ^ access index ^ ".nativePlan") outputs) ^ ")" in
    line ("def " ^ name ^ "Execute (Atom : Expr → Type u) (current : Current Atom) " ^ arguments ^ " : Option (" ^ output_type ^ ") := do");
    line ("  let result ← run " ^ name ^ " current (" ^ name ^ "Incoming Atom " ^ names ^ ")");
    List.iteri (fun position (index, _) ->
      line ("  let output" ^ B.nat position ^ " ← (result.outputs[" ^ B.nat position ^ "]?).bind (castEntry " ^ access index ^ ".nativeShape " ^ access index ^ ".nativePlan)")
    ) outputs;
    let tuple = match outputs with [_] -> "output0" | _ -> "(" ^ String.concat ", " (List.mapi (fun position _ -> "output" ^ B.nat position) outputs) ^ ")" in
    line ("  pure " ^ tuple);
    let routed = List.map (fun (output, operation) ->
      let sources = List.mapi (fun argument (input, source) -> argument, input, source) inputs |>
        List.filter (fun (_, _, source) -> source.access.port.value.sv_id = operation.access.port.value.sv_id &&
          source.access.port.level = operation.access.port.level) in
      let argument, input, _ = match sources with [source] -> source
        | _ -> invalid_arg "an actual native normalized output has no unique typed incoming binder" in
      "forwardView " ^ access output ^ ".transport " ^ access output ^ ".selected (backwardView " ^ access input ^
        ".transport " ^ access input ^ ".selected input" ^ B.nat argument ^ ")") outputs in
    let routed = match routed with [value] -> value | _ -> "(" ^ String.concat ", " routed ^ ")" in
    line ("def " ^ name ^ "Backward (Atom : Expr → Type u) " ^ arguments ^ " : " ^ output_type ^ " :=");
    line ("  " ^ routed);
    line ("def " ^ name ^ "PreparedExecute (Atom : Expr → Type u) " ^ source_arguments ^ " " ^ arguments ^ " : Option (" ^ output_type ^ ") := do");
    line ("  let current ← prepareCurrent sourcePreparation " ^ source_values);
    line ("  " ^ name ^ "Execute Atom current " ^ names);
    line ("theorem " ^ name ^ "_execution_normalizes_all_actual_endings (Atom : Expr → Type u)");
    line ("    " ^ source_arguments ^ " " ^ arguments ^ " :");
    line ("    " ^ name ^ "PreparedExecute Atom " ^ String.concat " " source_names ^ " " ^ names ^ " = some (" ^ name ^ "Backward Atom " ^ names ^ ") := by");
    let indent = F.emit_input_cases line "  " source_names projection.inputs in
    line (indent ^ "simp only [" ^ name ^ "PreparedExecute, prepareCurrent, sourcePreparation, Auths.Qualification.NativeCaptureValue.actualProgram,");
    line (indent ^ "  Auths.Support.NativeCaptureValue.runWithState, Auths.Support.NativeCaptureValue.execute,");
    line (indent ^ "  Auths.Support.NativeCaptureValue.initialize, Auths.Support.NativeCaptureValue.expand,");
    line (indent ^ "  Auths.Support.NativeCaptureValue.bindValues, Auths.Support.NativeCaptureValue.find,");
    line (indent ^ "  Auths.Support.NativeCaptureValue.evaluate, Auths.Support.NativeCaptureValue.castData,");
    line (indent ^ "  capturedFields, recordFields, Auths.Support.NativeCaptureValue.buildFields,");
    line (indent ^ "  Option.bind_some, Option.map_some, List.mem_cons, List.not_mem_nil, List.mapM_cons, List.mapM_nil]");
    line (indent ^ "unfold " ^ name ^ "Execute");
    line (indent ^ "rw [run, " ^ name ^ "_has_exact_typed_ending_roles]");
    let operation_defs = List.mapi (fun index _ -> name ^ "Operation" ^ B.nat index) operations in
    let access_defs = List.map (fun name -> name ^ "Access") operation_defs in
    let port_defs = List.map (fun name -> name ^ "Port") operation_defs in
    let recipe_defs = List.map (fun operation -> default_name branch operation.access) operations |> List.sort_uniq String.compare in
    line (indent ^ "simp [" ^ String.concat ", " ([name; name ^ "Incoming"; name ^ "Backward"; "currentOfForward"; "forwardBorrowContents";
      "Auths.Support.NativeCaptureValue.find"; "Auths.Support.NativeCaptureValue.castData";
      "executeEndings"; "executeOperations"; "executeOperation"; "executeValueOperation"; "bindIncoming"; "readNative";
      "evaluate"; "recordCurrent"; "readCurrent"; "castEntry"; "Access.ofRecipe"; "Access.nativePlan"; "Recipe.nativePlan";
      "view_forward_inverse"] @ operation_defs @ access_defs @ port_defs @ recipe_defs) ^ "]")
  ) witness.branches;
  line "end Auths.Qualification.NativeBorrowExecution";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
