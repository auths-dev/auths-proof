(* Independent structural input conditions for the actual native helper and
   registry-driven branch programs. Alias paths follow actual let expressions;
   they do not replace missing current versions or merge borrow authority. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.Pure
module B = Native_borrow_protocol
module N = Native_pure_payload
module X = Native_pure_expressions
module C = Native_current_seeds
module D = Native_default_bindings
module R = Native_binding_closures

type packing = Atom of Q.ty | Nominal of Q.ty * body
and fields = Unit of int | Cons of int * string option * packing * fields
and body = Empty | Fields of fields | Sum of variant * body
and variant = Variant of int * fields

let rec packing = function
  | N.Atom ty -> Atom ty
  | N.Named (N.NativeNominal ty, contents) -> Nominal (ty, body contents)
  | _ -> invalid_arg "a compatible-input output needs a complete supported native root packing witness"
and fields index = function
  | N.Unit -> Unit index
  | N.Product (N.Named (N.NativeField (actual, name), first), rest) when actual = index ->
    Cons (index, name, packing first, fields (index + 1) rest)
  | _ -> invalid_arg "native total packing cannot invent, reorder or omit an actual field"
and body = function
  | N.Empty -> Empty
  | N.Sum (first, rest) -> Sum (variant first, body rest)
  | layout -> Fields (fields 0 layout)
and variant = function
  | N.Named (N.NativeVariant identity, contents) -> Variant (identity, fields 0 contents)
  | _ -> invalid_arg "native total packing must retain every actual variant alternative"
let rec unpack = function Atom ty -> N.Atom ty | Nominal (ty, contents) -> N.Named (N.NativeNominal ty, unpack_body contents)
and unpack_fields = function Unit _ -> N.Unit
  | Cons (index, name, first, rest) -> N.Product (N.Named (N.NativeField (index, name), unpack first), unpack_fields rest)
and unpack_body = function Empty -> N.Empty | Fields value -> unpack_fields value | Sum (first, rest) -> N.Sum (unpack_variant first, unpack_body rest)
and unpack_variant = function Variant (identity, contents) -> N.Named (N.NativeVariant identity, unpack_fields contents)
let packing_type = function Atom ty | Nominal (ty, _) -> ty
let rec packing_fuel = function Atom _ -> 1 | Nominal (_, contents) -> 1 + body_fuel contents
and fields_fuel = function Unit _ -> 1 | Cons (_, _, first, rest) -> 1 + max (packing_fuel first) (fields_fuel rest)
and body_fuel = function Empty -> 1 | Fields value -> 1 + fields_fuel value | Sum (first, rest) -> 1 + max (variant_fuel first) (body_fuel rest)
and variant_fuel = function Variant (_, value) -> 1 + fields_fuel value

let rec lean_packing = function Atom ty -> ".atom (" ^ N.pure ty ^ ")"
  | Nominal (ty, contents) -> ".nominal (" ^ N.pure ty ^ ") (" ^ lean_body contents ^ ")"
and lean_fields = function Unit index -> ".unit " ^ string_of_int index
  | Cons (index, name, first, rest) -> ".cons " ^ string_of_int index ^ " (" ^ X.text name ^ ") (" ^ lean_packing first ^ ") (" ^ lean_fields rest ^ ")"
and lean_body = function Empty -> ".empty" | Fields value -> ".fields (" ^ lean_fields value ^ ")"
  | Sum (first, rest) -> ".sum (" ^ lean_variant first ^ ") (" ^ lean_body rest ^ ")"
and lean_variant = function Variant (identity, value) -> ".variant " ^ string_of_int identity ^ " (" ^ lean_fields value ^ ")"

type kind = Root | Incoming
type source = { kind : kind; index : int; ty : Q.ty }
type cell = { variable : Q.fvar; source : source }
type read = { variable : Q.fvar; source : source; aliases : (Q.fvar * Q.fvar) list }
type operation = Alias of Q.fvar * Q.fvar | Output of read * read
type condition = { helper : X.helper; current : read; incoming : read; packing : packing; witness_current : source }
type branch = { source : R.branch; initial : cell list; operations : operation list;
  snapshots : cell list list; conditions : condition list }
type t = { native : R.t; helpers : (X.helper * packing) list; branches : branch list }

let identity (value : Q.fvar) = Q.FVarId.to_int value.id
let environment (values : (Q.fvar * source * (Q.fvar * Q.fvar) list) list) =
  List.map (fun (variable, source, _) -> ({ variable; source } : cell)) values |>
    List.sort (fun (first : cell) (second : cell) -> Int.compare (identity first.variable) (identity second.variable))
let derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload (expressions : X.t) current (seeds : C.t) closure bindings projectors (native : R.t) =
  if not (R.replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native) then
    invalid_arg "compatible-input native programs require every actual closed branch, native binding and projector witness";
  let helpers = List.map (fun (helper : X.helper) ->
    let witness = packing helper.source.outgoing.layout in
    if unpack witness <> helper.source.outgoing.layout || helper.source.incoming.layout <> helper.source.outgoing.layout ||
        packing_type witness <> helper.source.outgoing.native_type || packing_fuel witness > helper.fuel then
      invalid_arg "a complete actual helper layout lacks a sufficient exact native packing witness";
    helper, witness) expressions.helpers in
  let branches = List.map (fun (branch : R.branch) ->
    let env : (Q.fvar * source * (Q.fvar * Q.fvar) list) list ref = ref (List.mapi (fun index (variable : Q.fvar) -> variable, { kind = Root; index; ty = variable.Q.ty }, []) branch.roots @
      List.mapi (fun index (_, (variable : Q.fvar)) -> variable, { kind = Incoming; index; ty = variable.Q.ty }, []) branch.inputs) in
    let initial = environment !env in
    let lookup (variable : Q.fvar) = match List.filter (fun ((actual : Q.fvar), _, _) -> actual.Q.id = variable.id && actual.ty = variable.ty) !env with
      | [(actual, source, aliases)] -> { variable = actual; source; aliases }
      | _ -> invalid_arg "a current value needs an actual earlier root/input/let, not a default-chain or ordinary result fallback" in
    let add (target : Q.fvar) (bound : Q.texpr) =
      if List.exists (fun ((actual : Q.fvar), _, _) -> actual.Q.id = target.id) !env then invalid_arg "a native value-flow let target is not fresh";
      let source = R.variable bound in
      let value = lookup source in
      if target.ty <> source.ty then invalid_arg "a native value-flow alias changed its complete type";
      env := !env @ [target, value.source, (target, source) :: value.aliases];
      Alias (target, source) in
    let conditions = ref [] in
    let steps = List.map (fun (operation : R.operation) ->
      let step = match operation.action with
        | R.Bind (target, bound) | R.Read (target, bound) -> add target bound
        | R.Output (helper, current, incoming, _, _) ->
          let incoming = lookup incoming in
          let current = lookup (Option.value current ~default:incoming.variable) in
          let input_index = match incoming.source.kind with Incoming -> incoming.source.index
            | Root -> invalid_arg "an emitted incoming value cannot be replaced by a forward root" in
          let incoming_helper, _ = match List.nth_opt branch.inputs input_index with Some value -> value
            | None -> invalid_arg "native output source names an absent actual input index" in
          if incoming_helper <> helper then invalid_arg "a native output cannot swap its actual owned input with another channel";
          let source_layout reference = match reference.kind with
            | Root -> (match List.nth_opt seeds.seeds reference.index with Some seed -> seed.codec_helper.source.outgoing.layout
              | None -> invalid_arg "native current source names an absent actual forward root")
            | Incoming -> (match List.nth_opt branch.inputs reference.index with Some (helper, _) -> helper.source.incoming.layout
              | None -> invalid_arg "native current source names an absent actual input") in
          if source_layout current.source <> helper.source.outgoing.layout || source_layout incoming.source <> helper.source.incoming.layout ||
              current.source.ty <> helper.source.outgoing.native_type || incoming.source.ty <> helper.source.incoming.native_type then
            invalid_arg "a native compatibility condition cannot substitute a different root/input field layout";
          let witness = match List.filter (fun (actual, _) -> actual = helper) helpers with [(_, witness)] -> witness
            | _ -> invalid_arg "a native emitted helper lost its exact source-derived packing witness" in
          if packing_fuel witness > branch.fuel || packing_fuel witness > native.fuel then
            invalid_arg "the actual branch/bundle fuel cannot pack every supported native output";
          let witness_current = match current.source.kind with
            | Root -> current.source
            | Incoming when current.source.index = input_index && helper.strategy = X.Incoming ->
              let registration = match List.filter (fun (registration : D.registration) ->
                registration.port = helper.source.incoming.access.port) branch.bindings.registrations with
                | [registration] -> registration | _ -> invalid_arg "a whole-input witness needs its actual source given-back registration" in
              let value = match D.default_for registration.after (V.SymbolicValueId.to_int registration.port.value.sv_id) with
                | Some (D.Variable (identity, ty)) -> identity, ty
                | _ -> invalid_arg "a whole-input witness needs its immediate registered existing root expression" in
              (match List.filter (fun (cell : cell) -> identity cell.variable = fst value && cell.variable.ty = snd value && cell.source.kind = Root) initial with
               | [cell] -> cell.source
               | _ -> invalid_arg "a whole-input witness cannot invent or chase a missing registered current root")
            | Incoming -> invalid_arg "dependent incoming-current witnesses require explicit earlier-input construction" in
          if source_layout witness_current <> helper.source.incoming.layout || witness_current.ty <> helper.source.incoming.native_type then
            invalid_arg "a useful-input witness changed its actual root field codec";
          conditions := !conditions @ [{ helper; current; incoming; packing = witness; witness_current }];
          Output (current, incoming) in
      step, environment !env) branch.operations in
    let operations, snapshots = List.split steps in
    let expected = List.filter_map (fun (operation : R.operation) -> match operation.action with R.Output (helper, _, _, _, _) -> Some helper | _ -> None) branch.operations in
    if List.map (fun condition -> condition.helper) !conditions <> expected then invalid_arg "a compatibility predicate cannot omit or reorder an actual native output helper";
    { source = branch; initial; operations; snapshots; conditions = !conditions }) native.branches in
  { native; helpers; branches }

let replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native witness =
  try derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native =
  let witness = derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native in
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native witness) then
    invalid_arg "complete structural native-input conditions did not replay";
  witness

let helper_name (helper : X.helper) = "branch" ^ B.gid helper.group ^ "Channel" ^ string_of_int helper.index
let lean_source source = "{ kind := ." ^ (match source.kind with Root -> "root" | Incoming -> "incoming") ^
  ", index := " ^ string_of_int source.index ^ ", type := " ^ N.pure source.ty ^ " }"
let lean_read (read : read) = "{ variable := " ^ R.lean_var read.variable ^ ", source := " ^ lean_source read.source ^ " }"
let lean_environment cells = "[" ^ String.concat ", " (List.map (fun (cell : cell) ->
  "(" ^ string_of_int (identity cell.variable) ^ ", { variable := " ^ R.lean_var cell.variable ^ ", source := " ^ lean_source cell.source ^ " })") cells) ^ "]"
let lean_operation = function
  | Alias (target, source) -> ".alias { target := " ^ R.lean_var target ^ ", source := " ^ R.lean_var source ^ " }"
  | Output (current, incoming) -> ".output (" ^ lean_read current ^ ") (" ^ lean_read incoming ^ ")"
let reference source = match source.kind with
  | Root -> (match source.index with 0 -> "counter" | 1 -> "writer" | _ -> invalid_arg "a different forward root needs its own typed generated harness")
  | Incoming -> "incoming" ^ string_of_int source.index

let report component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native witness =
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors native witness) then
    invalid_arg "compatible-input report lost its complete actual source, registry program or value-flow witness";
  `Assoc ["schema", `String "actual-native-structural-compatible-input-programs/v1";
    "helpers", `List (List.map (fun (helper, packing) -> `Assoc ["name", `String (helper_name helper);
      "complete_layout", `String (N.lean_layout helper.X.source.outgoing.layout);
      "total_native_packing_witness", `String (lean_packing packing); "packing_fuel", `Int (packing_fuel packing)]) witness.helpers);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.source.source.source.target);
      "initial_value_environment", `String (lean_environment branch.initial);
      "complete_ordered_value_flow", `List (List.map (fun operation -> `String (lean_operation operation)) branch.operations);
      "snapshots", `List (List.map (fun snapshot -> `String (lean_environment snapshot)) branch.snapshots);
      "actual_output_conditions", `List (List.map (fun condition -> `Assoc [
        "helper", `String (helper_name condition.helper); "actual_immediate_current", `String (lean_read condition.current);
        "actual_received_input", `String (lean_read condition.incoming);
        "current_actual_let_alias_path", `List (List.map (fun (target, source) -> `List [`Int (identity target); `Int (identity source)]) condition.current.aliases);
        "incoming_actual_let_alias_path", `List (List.map (fun (target, source) -> `List [`Int (identity target); `Int (identity source)]) condition.incoming.aliases);
        "useful_matching_input_source", `String (lean_source condition.witness_current)]) branch.conditions)]) witness.branches);
    "structural_compatibility_independent_of_result_success", `Bool true;
    "total_packing_from_complete_layout_with_explicit_fuel", `Bool true;
    "value_alias_paths_are_actual_let_bindings_not_default_chain_fallback", `Bool true;
    "symbolic_names_regions_and_authority_merged", `Bool false;
    "ordinary_function_results_or_successful_result_premises_supplied", `Bool false;
    "rust_loan_valid_inputs_imply_compatibility_proved", `Bool false;
    "original_infallible_signature_or_complete_dispatch_adequacy_proved", `Bool false;
    "helper_result_layer_removed_or_guards_weakened", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path projection witness =
  let buffer = Buffer.create 262144 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  let payload = "Auths.Qualification.NativePurePayload." and abi = "Auths.Qualification.NativeBorrowFullABI." in
  let helpers = "Auths.Qualification.NativePureExpressions." and native = "Auths.Qualification.NativeBindingClosures." in
  let seeds = "Auths.Qualification.NativeCurrentSeeds." in
  line "import Auths.Support.NativeInputCompatibility";
  line "import Auths.Support.BorrowTagTopology";
  line "import qualification.aeneas.cases.NativeBindingClosures";
  line "/- Complete native helper/program compatibility conditions and computed success outputs.";
  line "   Unelaborated/unqualified; actual Rust input/loan, original environment and dispatch adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeCompatiblePrograms";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection";
  line "open Auths.Qualification.NativePureExpressions";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.Borrow_projection.candidate.def_id));
  line "universe u";
  List.iter (fun ((helper : X.helper), packing) ->
    let name = helper_name helper in
    let channel = abi ^ name and incoming = payload ^ name ^ "IncomingCodec" and outgoing = payload ^ name ^ "OutgoingCodec" in
    let binders = "(Atom : Ty → Type u) (current input : Value Atom " ^ payload ^ name ^ "Layout)" in
    line ("def " ^ name ^ "Packing : Auths.Support.NativeValuePacking.Root " ^ payload ^ name ^ "Layout (" ^ N.pure helper.source.outgoing.native_type ^ ") := " ^ lean_packing packing);
    line ("theorem " ^ name ^ "_packing_fuel_suffices : Auths.Support.NativeValuePacking.rootFuel " ^ name ^ "Packing ≤ " ^ helpers ^ name ^ "Fuel := by decide");
    line ("def " ^ name ^ "Compatible " ^ binders ^ " : Prop := Auths.Support.BorrowViewCompatibility.Native.Compatible " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current input");
    line ("def " ^ name ^ "Total " ^ binders ^ " (valid : " ^ name ^ "Compatible Atom current input) : Value Atom " ^ payload ^ name ^ "Layout :=");
    line ("  Auths.Support.BorrowViewCompatibility.Native.restore " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current input valid");
    line ("def " ^ name ^ "Matching (Atom : Ty → Type u) (current : Value Atom " ^ payload ^ name ^ "Layout) : Value Atom " ^ payload ^ name ^ "Layout :=");
    line ("  matchingNativeInput " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current");
    line ("theorem " ^ name ^ "_matching_input_is_compatible (Atom : Ty → Type u) (current : Value Atom " ^ payload ^ name ^ "Layout) :");
    line ("    " ^ name ^ "Compatible Atom current (" ^ name ^ "Matching Atom current) := Auths.Support.BorrowViewCompatibility.Native.matching_current_is_compatible _ _ _ _");
    if helper.strategy = X.Incoming then (
      line ("theorem " ^ name ^ "_whole_inputs_are_compatible " ^ binders ^ " : " ^ name ^ "Compatible Atom current input :=");
      line ("  Auths.Support.NativeInputCompatibility.whole_input_is_compatible " ^ channel ^ " " ^ channel ^ "_owns_whole_pointee " ^ incoming ^ " " ^ outgoing ^ " current input"));
    line ("theorem " ^ name ^ "_native_helper_has_computed_success " ^ binders ^ " (valid : " ^ name ^ "Compatible Atom current input) :");
    line ("    execute builtins schemas " ^ helpers ^ name ^ "Fuel " ^ helpers ^ name ^ " current input =");
    line ("      some (Auths.Support.NativeValuePacking.success builtins " ^ name ^ "Packing (" ^ name ^ "Total Atom current input valid)) := by");
    line ("  rw [" ^ helpers ^ name ^ "_evaluates_as_selected_adapter]");
    line ("  exact Auths.Support.NativeInputCompatibility.compatible_helper_has_success builtins " ^ helpers ^ name ^ "Fuel " ^ name ^ "Packing " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current input valid " ^ name ^ "_packing_fuel_suffices");
    line ("theorem " ^ name ^ "_matching_input_executes_successfully (Atom : Ty → Type u) (current : Value Atom " ^ payload ^ name ^ "Layout) :");
    line ("    execute builtins schemas " ^ helpers ^ name ^ "Fuel " ^ helpers ^ name ^ " current (" ^ name ^ "Matching Atom current) =");
    line ("      some (Auths.Support.NativeValuePacking.success builtins " ^ name ^ "Packing current) := by");
    line ("  rw [" ^ helpers ^ name ^ "_evaluates_as_selected_adapter]");
    line ("  change expected builtins " ^ helpers ^ name ^ "Fuel _ (adaptNative " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current (" ^ name ^ "Matching Atom current)) = _");
    line ("  rw [matching_native_input_is_accepted]");
    line ("  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ " ^ name ^ "Packing current " ^ name ^ "_packing_fuel_suffices");
    let store_binders = "(Atom : Ty → Type u) (current after : Value Atom " ^ payload ^ name ^ "Layout)" in
    let stores = "Auths.Support.BorrowTagTopology.Native.Stores " ^ channel ^ " " ^ outgoing ^ " current after" in
    line ("theorem " ^ name ^ "_field_stores_supply_compatible_input " ^ store_binders ^ " (stores : " ^ stores ^ ") :");
    line ("    " ^ name ^ "Compatible Atom current (" ^ name ^ "Matching Atom after) :=");
    line ("  Auths.Support.BorrowTagTopology.Native.stores_supply_compatible_native_input " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current after stores");
    line ("theorem " ^ name ^ "_field_stores_execute_exact_final_value " ^ store_binders ^ " (stores : " ^ stores ^ ") :");
    line ("    execute builtins schemas " ^ helpers ^ name ^ "Fuel " ^ helpers ^ name ^ " current (" ^ name ^ "Matching Atom after) =");
    line ("      some (Auths.Support.NativeValuePacking.success builtins " ^ name ^ "Packing after) := by");
    line ("  rw [" ^ helpers ^ name ^ "_evaluates_as_selected_adapter]");
    line ("  change expected builtins " ^ helpers ^ name ^ "Fuel _ (adaptNative " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current (" ^ name ^ "Matching Atom after)) = _");
    line ("  rw [Auths.Support.BorrowTagTopology.Native.stores_reconstruct_exact_native_value " ^ channel ^ " " ^ incoming ^ " " ^ outgoing ^ " current after stores]");
    line ("  exact Auths.Support.NativeValuePacking.expected_some_is_success builtins _ " ^ name ^ "Packing after " ^ name ^ "_packing_fuel_suffices")
  ) witness.helpers;
  let root_seeds = witness.native.projectors.bindings.closure.seeds.seeds in
  let counter_seed, writer_seed = match root_seeds with [counter; writer] -> counter, writer
    | _ -> invalid_arg "a different actual forward root roster needs its own compatible-input harness" in
  let counter = payload ^ "branch0Channel0" and writer = payload ^ "branch2Channel0" in
  let binders = "(Atom : Ty → Type u) (counter : Value Atom " ^ counter ^ "Layout) (writer : Value Atom " ^ writer ^ "Layout)" in
  let fresh = ref 0 in
  let variable () = let name = "v" ^ string_of_int !fresh in incr fresh; name in
  let rec cases indent name layout finish =
    let add text = line (String.make indent ' ' ^ text) in
    match layout with
    | N.Empty -> add ("cases " ^ name)
    | N.Atom _ -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| atom " ^ value ^ " =>"); finish (indent + 2)
    | N.Unit -> add ("cases " ^ name ^ " with"); add "| unit =>"; finish (indent + 2)
    | N.Named (_, body) -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| named " ^ value ^ " =>"); cases (indent + 2) value body finish
    | N.Product (left, right) -> let first = variable () and second = variable () in
      add ("cases " ^ name ^ " with"); add ("| product " ^ first ^ " " ^ second ^ " =>");
      cases (indent + 2) first left (fun indent -> cases indent second right finish)
    | N.Sum (left, right) -> let first = variable () and second = variable () in
      add ("cases " ^ name ^ " with"); add ("| left " ^ first ^ " =>"); cases (indent + 2) first left finish;
      add ("| right " ^ second ^ " =>"); cases (indent + 2) second right finish in
  let branch_inputs branch = List.mapi (fun index ((helper : X.helper), _) -> index, helper) branch.source.inputs in
  let input_binders inputs = String.concat " " (List.map (fun (index, helper) -> "(incoming" ^ string_of_int index ^ " : Value Atom " ^ payload ^ helper_name helper ^ "Layout)") inputs) in
  let input_names inputs = String.concat " " (List.map (fun (index, _) -> "incoming" ^ string_of_int index) inputs) in
  let source_cases inputs finish =
    let rec incoming indent = function
      | [] -> finish indent
      | (index, (helper : X.helper)) :: rest -> cases indent ("incoming" ^ string_of_int index) helper.source.incoming.layout (fun indent -> incoming indent rest) in
    cases 2 "counter" counter_seed.codec_helper.source.outgoing.layout (fun indent ->
      cases indent "writer" writer_seed.codec_helper.source.outgoing.layout (fun indent -> incoming indent inputs)) in
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.source.source.source.target in
    let inputs = branch_inputs branch in
    let args = input_binders inputs and names = input_names inputs in
    line ("def " ^ name ^ "Initial : Auths.Support.NativeInputCompatibility.Environment := " ^ lean_environment branch.initial);
    line ("def " ^ name ^ "Flow : List Auths.Support.NativeInputCompatibility.Operation := [" ^ String.concat ", " (List.map lean_operation branch.operations) ^ "]");
    line ("def " ^ name ^ "Snapshots : List Auths.Support.NativeInputCompatibility.Environment := [" ^ String.concat ", " (List.map lean_environment branch.snapshots) ^ "]");
    line ("theorem " ^ name ^ "_all_value_references_follow_actual_earlier_bindings : Auths.Support.NativeInputCompatibility.scan " ^ name ^ "Initial " ^ name ^ "Flow = some " ^ name ^ "Snapshots := by decide");
    let conditions = List.map (fun condition -> helper_name condition.helper ^ "Compatible Atom " ^ reference condition.current.source ^ " " ^ reference condition.incoming.source) branch.conditions in
    line ("def " ^ name ^ "Compatible " ^ binders ^ " " ^ args ^ " : Prop := " ^ String.concat " ∧ " (conditions @ ["True"]));
    List.iteri (fun index condition ->
      let valid = "valid" ^ String.concat "" (List.init index (fun _ -> ".2")) ^ ".1" in
      line ("def " ^ name ^ "Output" ^ string_of_int index ^ " " ^ binders ^ " " ^ args ^ " (valid : " ^ name ^ "Compatible Atom counter writer " ^ names ^ ") : Value Atom " ^ payload ^ helper_name condition.helper ^ "Layout :=");
      line ("  " ^ helper_name condition.helper ^ "Total Atom " ^ reference condition.current.source ^ " " ^ reference condition.incoming.source ^ " " ^ valid)
    ) branch.conditions;
    let outputs = List.mapi (fun index condition -> "Auths.Support.NativeValuePacking.rootValue " ^ helper_name condition.helper ^ "Packing (" ^ name ^ "Output" ^ string_of_int index ^ " Atom counter writer " ^ names ^ " valid)") branch.conditions in
    line ("def " ^ name ^ "Success " ^ binders ^ " " ^ args ^ " (valid : " ^ name ^ "Compatible Atom counter writer " ^ names ^ ") : Dynamic Atom :=");
    line ("  Auths.Support.NativeValuePacking.successMany builtins [" ^ String.concat ", " outputs ^ "]");
    line ("theorem " ^ name ^ "_compatible_inputs_execute_computed_success " ^ binders ^ " " ^ args ^ " (valid : " ^ name ^ "Compatible Atom counter writer " ^ names ^ ") :");
    line ("    " ^ native ^ name ^ "Run Atom counter writer " ^ names ^ " = some (" ^ name ^ "Success Atom counter writer " ^ names ^ " valid) := by");
    line ("  unfold " ^ native ^ name ^ "Run");
    line ("  rw [checked_packed_runs_body builtins schemas " ^ native ^ name ^ "Fuel " ^ native ^ name ^ " " ^ native ^ name ^ "_well_typed]");
    let simp = name ^ "Compatible, " ^ String.concat ", " (List.map (fun condition -> helper_name condition.helper ^ "Compatible") branch.conditions) ^
      ", Auths.Support.BorrowViewCompatibility.Native.Compatible, Auths.Support.BorrowViewCompatibility.Channel.Compatible, Auths.Support.BorrowViewCompatibility.Compatible" in
    source_cases inputs (fun indent ->
      line (String.make indent ' ' ^ "first");
      line (String.make indent ' ' ^ "| exact False.elim (by simpa [" ^ simp ^ "] using valid)");
      line (String.make indent ' ' ^ "| rfl"));
    line ("theorem " ^ name ^ "_incompatible_inputs_keep_explicit_representation_failure " ^ binders ^ " " ^ args ^ " (invalid : ¬ " ^ name ^ "Compatible Atom counter writer " ^ names ^ ") :");
    line ("    " ^ native ^ name ^ "Run Atom counter writer " ^ names ^ " = some (.constructor (.result (tupleType [" ^ String.concat ", " (List.map N.pure branch.source.source.output_types) ^ "])) (some builtins.resultFail) [.constructor .error (some builtins.errorFailure) []]) := by");
    line ("  unfold " ^ native ^ name ^ "Run");
    line ("  rw [checked_packed_runs_body builtins schemas " ^ native ^ name ^ "Fuel " ^ native ^ name ^ " " ^ native ^ name ^ "_well_typed]");
    source_cases inputs (fun indent ->
      line (String.make indent ' ' ^ "first");
      line (String.make indent ' ' ^ "| exact False.elim (invalid (by simp [" ^ simp ^ "]))");
      line (String.make indent ' ' ^ "| rfl"));
    line ("theorem " ^ name ^ "_compatible_bundle_invocation_succeeds " ^ binders ^ " " ^ args ^ " (valid : " ^ name ^ "Compatible Atom counter writer " ^ names ^ ") :");
    line ("    " ^ native ^ name ^ "Invoke Atom counter writer " ^ names ^ " = some (" ^ name ^ "Success Atom counter writer " ^ names ^ " valid) := by");
    line ("  rw [" ^ native ^ name ^ "_bundle_uses_its_exact_registry_program]");
    line ("  exact " ^ name ^ "_compatible_inputs_execute_computed_success Atom counter writer " ^ names ^ " valid");
    let condition_for_input index = match List.filter (fun condition -> condition.incoming.source.index = index) branch.conditions with
      | [condition] -> condition | _ -> invalid_arg "a useful input must have exactly one actual owned output condition" in
    List.iter (fun (index, helper) ->
      let condition = condition_for_input index in
      line ("def " ^ name ^ "Witness" ^ string_of_int index ^ " " ^ binders ^ " : Value Atom " ^ payload ^ helper_name helper ^ "Layout := " ^ helper_name helper ^ "Matching Atom " ^ reference condition.witness_current)
    ) inputs;
    let witnesses = String.concat " " (List.map (fun (index, _) -> "(" ^ name ^ "Witness" ^ string_of_int index ^ " Atom counter writer)") inputs) in
    line ("theorem " ^ name ^ "_matching_inputs_are_compatible " ^ binders ^ " : " ^ name ^ "Compatible Atom counter writer " ^ witnesses ^ " := by");
    let proofs = List.map (fun condition -> if condition.helper.strategy = X.Incoming then
      helper_name condition.helper ^ "_whole_inputs_are_compatible Atom _ _" else
      helper_name condition.helper ^ "_matching_input_is_compatible Atom _") branch.conditions in
    let rec conjunction = function [] -> "True.intro" | first :: rest -> "⟨" ^ first ^ ", " ^ conjunction rest ^ "⟩" in
    line ("  exact " ^ conjunction proofs);
    line ("theorem " ^ name ^ "_has_successful_inputs_for_every_forward_current " ^ binders ^ " :");
    line ("    " ^ native ^ name ^ "Invoke Atom counter writer " ^ witnesses ^ " = some (" ^ name ^ "Success Atom counter writer " ^ witnesses ^ " (" ^ name ^ "_matching_inputs_are_compatible Atom counter writer)) :=");
    line ("  " ^ name ^ "_compatible_bundle_invocation_succeeds Atom counter writer " ^ witnesses ^ " (" ^ name ^ "_matching_inputs_are_compatible Atom counter writer)")
  ) witness.branches;
  let source_atom = "SourceAtom " ^ payload ^ "atomTyping Atom" in
  let source_inputs = List.map (fun (root : Borrow_projection.root) -> "input" ^ string_of_int root.index) projection.inputs in
  let source_binders = "(Atom : Ty → Type u) " ^ String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data (" ^ source_atom ^ ") " ^ name ^ "Shape)") source_inputs) in
  let source_names = String.concat " " source_inputs in
  line ("theorem preparation_is_total " ^ source_binders ^ " : (" ^ seeds ^ "prepare Atom " ^ source_names ^ ").isSome = true := by");
  line ("  cases result : " ^ seeds ^ "prepare Atom " ^ source_names ^ " with");
  line "  | none =>";
  line ("    have value := " ^ seeds ^ "prepared_value_is_original_source_capture Atom " ^ source_names);
  line "    simp [result] at value";
  line "  | some value => rfl";
  line ("def ownPrepared " ^ source_binders ^ " : " ^ seeds ^ "Prepared Atom := (" ^ seeds ^ "prepare Atom " ^ source_names ^ ").get (preparation_is_total Atom " ^ source_names ^ ")");
  line ("theorem preparation_returns_own_prepared " ^ source_binders ^ " : " ^ seeds ^ "prepare Atom " ^ source_names ^ " = some (ownPrepared Atom " ^ source_names ^ ") := by");
  line ("  cases result : " ^ seeds ^ "prepare Atom " ^ source_names ^ " with");
  line "  | none =>";
  line ("    have present := preparation_is_total Atom " ^ source_names);
  line "    simp [result] at present";
  line "  | some value => simp [ownPrepared, result]";
  let own = "(ownPrepared Atom " ^ source_names ^ ")" in
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.source.source.source.target in
    let inputs = branch_inputs branch in
    let args = input_binders inputs and names = input_names inputs in
    let own_roots = own ^ ".current0 " ^ own ^ ".current1" in
    line ("def " ^ name ^ "OwnForwardCompatible " ^ source_binders ^ " " ^ args ^ " : Prop := " ^ name ^ "Compatible Atom " ^ own_roots ^ " " ^ names);
    line ("theorem " ^ name ^ "_compatible_own_forward_capture_succeeds " ^ source_binders ^ " " ^ args ^ " (valid : " ^ name ^ "OwnForwardCompatible Atom " ^ source_names ^ " " ^ names ^ ") :");
    line ("    " ^ native ^ name ^ "FromCapture Atom " ^ source_names ^ " " ^ names ^ " = some (" ^ name ^ "Success Atom " ^ own_roots ^ " " ^ names ^ " valid) := by");
    line ("  unfold " ^ native ^ name ^ "FromCapture " ^ native ^ "capture");
    line "  rw [preparation_returns_own_prepared]";
    line "  simp only [Option.bind_some]";
    line ("  change " ^ native ^ name ^ "Invoke Atom " ^ own_roots ^ " " ^ names ^ " = _");
    line ("  exact " ^ name ^ "_compatible_bundle_invocation_succeeds Atom " ^ own_roots ^ " " ^ names ^ " valid");
    List.iter (fun (index, helper) ->
      line ("def " ^ name ^ "OwnWitness" ^ string_of_int index ^ " " ^ source_binders ^ " : Value Atom " ^ payload ^ helper_name helper ^ "Layout := " ^ name ^ "Witness" ^ string_of_int index ^ " Atom " ^ own_roots)
    ) inputs;
    let own_witnesses = String.concat " " (List.map (fun (index, _) -> "(" ^ name ^ "OwnWitness" ^ string_of_int index ^ " Atom " ^ source_names ^ ")") inputs) in
    line ("theorem " ^ name ^ "_own_forward_witnesses_are_compatible " ^ source_binders ^ " : " ^ name ^ "OwnForwardCompatible Atom " ^ source_names ^ " " ^ own_witnesses ^ " := " ^ name ^ "_matching_inputs_are_compatible Atom " ^ own_roots);
    line ("theorem " ^ name ^ "_own_forward_capture_has_successful_inputs " ^ source_binders ^ " :");
    line ("    " ^ native ^ name ^ "FromCapture Atom " ^ source_names ^ " " ^ own_witnesses ^ " = some (" ^ name ^ "Success Atom " ^ own_roots ^ " " ^ own_witnesses ^ " (" ^ name ^ "_own_forward_witnesses_are_compatible Atom " ^ source_names ^ ")) :=");
    line ("  " ^ name ^ "_compatible_own_forward_capture_succeeds Atom " ^ source_names ^ " " ^ own_witnesses ^ " (" ^ name ^ "_own_forward_witnesses_are_compatible Atom " ^ source_names ^ ")")
  ) witness.branches;
  line "end Auths.Qualification.NativeCompatiblePrograms";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
