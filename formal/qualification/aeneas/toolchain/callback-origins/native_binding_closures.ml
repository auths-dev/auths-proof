(* Close a real Pure program over the actual focused native registry names.
   Every bind/default/consumed expression is checked against the existing
   selected-view program through an explicit injective typed name mapping.
   Original full EndAbs dispatch/activation/heap adequacy is not assumed. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module P = Borrow_projection
module B = Native_borrow_protocol
module E = Native_borrow_execution
module N = Native_pure_payload
module X = Native_pure_expressions
module W = Native_current_wiring
module C = Native_current_seeds
module H = Native_capture_closures
module D = Native_default_bindings
module L = Native_projector_levels

type pair = { native : Q.fvar; lowered : Q.fvar }
type use = { native : Q.texpr; lowered : Q.texpr }
type action = Bind of Q.fvar * Q.texpr | Read of Q.fvar * Q.texpr
  | Output of X.helper * Q.fvar option * Q.fvar * Q.fvar * Q.fvar
type operation = { original : W.operation; action : action }
type branch = { source : W.branch; bindings : D.branch; roots : Q.fvar list;
  inputs : (X.helper * Q.fvar) list; pairs : pair list; uses : use list;
  operations : operation list; native : Q.texpr; reflected : X.term; fuel : int }
type t = { projectors : L.t; branches : branch list; native : Q.texpr; reflected : X.term; fuel : int }

let reify (variable : D.variable) : Q.fvar =
  { id = Q.FVarId.of_int variable.identity; basename = None; ty = variable.ty }
let symbol state identity = match List.assoc_opt (V.SymbolicValueId.to_int identity) state.D.symbols with
  | Some value -> reify value | None -> invalid_arg "a registry-driven closure cannot invent a symbolic binding"
let expr (state : D.snapshot) = function
  | D.Unit -> U.mk_unit_texpr
  | D.Variable (identity, ty) ->
    (match List.assoc_opt identity state.variables, List.assoc_opt identity state.types with
     | Some variable, Some actual when variable.identity = identity && variable.ty = ty && actual = ty ->
       U.mk_texpr_from_fvar (reify variable)
     | _ -> invalid_arg "a registry-driven closure source expression lost its actual variable/type-table declaration")
let variable (value : Q.texpr) = match value.e with
  | Q.FVar identity -> Q.{ id = identity; basename = None; ty = value.ty }
  | _ -> invalid_arg "the current field-reconstruction API requires an explicit immediate native variable"
let origin state = function
  | B.Symbolic identity -> U.mk_texpr_from_fvar (symbol state identity)
  | B.Borrow identity ->
    (match List.assoc_opt (V.BorrowId.to_int identity) state.D.borrows with
     | Some value -> expr state value
     | None -> invalid_arg "a native current borrow cannot use an absent loop/default alias")

let derive component (projection : P.t) inputs symbolic forward protocol wiring defaults execution full_abi payload expressions (current : W.t) seeds (closure : H.t) bindings (projectors : L.t) =
  if not (L.replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors) then
    invalid_arg "registry-driven native closures require all actual projector trees and ordered consumed reads";
  let span = projection.candidate.item_meta.span in
  let branches = List.map (fun (source : W.branch) ->
    let binding_branch = match List.filter (fun (branch : D.branch) -> branch.target = source.source.target) bindings.D.branches with
      | [branch] -> branch | _ -> invalid_arg "a registry-driven closure lost its actual branch" in
    let roots = List.map (fun (seed : C.seed) -> symbol binding_branch.initial seed.binding.native.sv_id) seeds.C.seeds in
    if List.length roots <> 2 || List.length binding_branch.initial.symbols <> List.length roots then
      invalid_arg "a different focused root roster requires its own complete source-derived closure interface";
    let maximum = List.fold_left (fun count (ending : D.ending_trace) -> max count ending.after.next)
      binding_branch.initial.next binding_branch.endings in
    (* Reserve the actual registry namespace before allocating input/helper
       binders with the real pinned generator. Reification above retains the
       registry identifiers; this does not recreate an opaque original context. *)
    let _, next = Q.FVarId.fresh_stateful_generator () in
    for index = 0 to maximum - 1 do
      if Q.FVarId.to_int (next ()) <> index then invalid_arg "pinned native identifier allocation changed its registry reservation order"
    done;
    let fresh ty : Q.fvar = { id = next (); basename = None; ty } in
    let pairs : pair list ref = ref [] and uses : use list ref = ref [] in
    let add (native : Q.fvar) (lowered : Q.fvar) =
      if native.ty <> lowered.ty then invalid_arg "native/lowered variable names disagree on their complete type";
      match List.filter (fun (pair : pair) -> pair.native.id = native.id || pair.lowered.id = lowered.id) !pairs with
      | [] -> pairs := !pairs @ [{ native; lowered }]
      | [pair] when pair.native.id = native.id && pair.lowered.id = lowered.id && pair.native.ty = native.ty -> ()
      | _ -> invalid_arg "native/lowered variable names must be injective in both directions" in
    let translate (value : Q.texpr) = match value.e with
      | Q.FVar identity -> (match List.filter (fun (pair : pair) -> pair.native.id = identity && pair.native.ty = value.ty) !pairs with
        | [pair] -> U.mk_texpr_from_fvar pair.lowered
        | _ -> invalid_arg "a native immediate expression has no unique existing lowered variable")
      | _ when Q.compare_texpr value U.mk_unit_texpr = 0 -> U.mk_unit_texpr
      | _ -> invalid_arg "native/lowered binding comparison cannot conceal a call, dereference or default-chain evaluation" in
    let use native lowered =
      if Q.compare_texpr (translate native) lowered <> 0 then
        invalid_arg "actual native immediate references differ from the existing selected-view program";
      uses := !uses @ [{ native; lowered }] in
    List.iter (fun (cell : W.cell) -> add (variable (origin binding_branch.initial cell.key)) cell.variable) source.seeds;
    let incoming = List.map (fun ((helper : X.helper), (lowered : Q.fvar)) ->
      let native = fresh helper.source.incoming.native_type in
      add native lowered; helper, native) source.inputs in
    let sources = List.concat_map (fun (ending : D.ending_trace) ->
      List.map (fun (registration : D.registration) -> registration.port, registration.kind, `Registration registration) ending.registrations @
      List.map (fun (read : D.consumed_read) -> read.port, read.kind, `Read read) ending.reads) binding_branch.endings in
    let consumed = ref [] in
    let operations = List.map (fun (original : W.operation) ->
      let port = original.original.access.port and kind = original.original.kind in
      let index, trace = match List.filter_map (fun (index, (actual, actual_kind, trace)) ->
        if actual = port && actual_kind = kind then Some (index, trace) else None) (List.mapi (fun index value -> index, value) sources) with
        | [source] -> source | _ -> invalid_arg "every closure operation needs one exact native registration or consumed read" in
      if List.mem index !consumed then invalid_arg "one actual native operation cannot feed multiple generated closure operations";
      consumed := index :: !consumed;
      let action = match original.action, trace with
        | W.Bind (target, lowered), `Registration registration ->
          let native = symbol registration.after port.value.sv_id in
          add native target.variable;
          let bound = match kind with
            | E.Default -> (match List.assoc_opt (Q.FVarId.to_int native.id) registration.after.defaults with
              | Some value -> expr registration.after value
              | None -> invalid_arg "a foreign default activation needs its actual registered native expression")
            | E.Receive -> (match List.filter (fun ((helper : X.helper), _) -> helper.source.incoming.access.port = port) incoming with
              | [(_, argument)] -> U.mk_texpr_from_fvar argument
              | _ -> invalid_arg "a native receive must retain its exact owned incoming argument")
            | _ -> invalid_arg "a closure binding cannot change its native ending role" in
          if bound.ty <> native.ty then invalid_arg "an actual native binding changed the bound expression type";
          use bound (U.mk_texpr_from_fvar lowered);
          Bind (native, bound)
        | W.Read (source, observed), `Read read ->
          let bound = expr read.state read.value in
          use bound (U.mk_texpr_from_fvar source.variable);
          let native = fresh observed.ty in add native observed;
          Read (native, bound)
        | W.Output (helper, current, incoming, output, error), `Read read ->
          let received = expr read.state read.value in
          use received (U.mk_texpr_from_fvar incoming.variable);
          let current = Option.map (fun (cell : W.cell) ->
            let value = origin read.state cell.key in
            use value (U.mk_texpr_from_fvar cell.variable); variable value) current in
          let native_output = fresh output.ty and native_error = fresh error.ty in
          add native_output output; add native_error error;
          Output (helper, current, variable received, native_output, native_error)
        | _ -> invalid_arg "native registration/consumption polarity differs from the existing generated closure operation" in
      { original; action }) source.operations in
    if List.length !consumed <> List.length sources then invalid_arg "a registry-driven closure cannot omit a native ending operation";
    let output_type = U.mk_simpl_tuple_ty source.output_types in
    let rec body outputs = function
      | [] -> U.mk_result_ok_texpr span (U.mk_simpl_tuple_texpr span (List.map U.mk_texpr_from_fvar outputs))
      | operation :: rest -> match operation.action with
        | Bind (target, bound) | Read (target, bound) ->
          U.mk_closed_let span false (U.mk_tpat_from_fvar None target) bound (body outputs rest)
        | Output (helper, current, incoming, output, error) ->
          let current = Option.value current ~default:incoming in
          let rhs = X.compile_body span helper.source.outgoing.native_type helper.strategy fresh current incoming in
          let ok = U.mk_adt_pat rhs.ty (Some Q.result_ok_id) [U.mk_tpat_from_fvar None output] in
          let fail = U.mk_adt_pat rhs.ty (Some Q.result_fail_id) [U.mk_tpat_from_fvar None error] in
          Q.{ e = Switch (rhs, Match [U.close_branch span ok (body (outputs @ [output]) rest);
            U.close_branch span fail (U.mk_result_fail_texpr span (U.mk_texpr_from_fvar error) output_type)]);
            ty = U.mk_result_ty output_type } in
    let arguments = roots @ List.map snd incoming in
    let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) arguments) (body [] operations) in
    let expected = U.mk_arrows (List.map (fun (variable : Q.fvar) -> variable.ty) arguments) (U.mk_result_ty output_type) in
    if native.ty <> expected then invalid_arg "a registry-driven native closure lost its complete root/input/result arrow";
    let reflected = X.reflect native in
    { source; bindings = binding_branch; roots; inputs = incoming; pairs = !pairs; uses = !uses;
      operations; native; reflected; fuel = 96 + 8 * X.depth reflected }
  ) current.branches in
  let root_types = match branches with first :: _ -> List.map (fun (root : Q.fvar) -> root.ty) first.roots
    | [] -> invalid_arg "a registry-driven native bundle needs every actual backward branch" in
  let _, next = Q.FVarId.fresh_stateful_generator () in
  let arguments = List.map (fun ty -> Q.{ id = next (); basename = None; ty }) root_types in
  if List.map (fun branch -> branch.source.source.target) branches <>
      List.map (fun (group : region_var_group) -> group.id) projection.hierarchy ||
      List.length branches <> List.length closure.members then
    invalid_arg "a registry-driven bundle cannot omit or reorder an original backward region group";
  let members = List.map2 (fun branch (original : H.member) ->
    if List.map (fun (root : Q.fvar) -> root.ty) branch.roots <> root_types then
      invalid_arg "native backward branches disagree on the exact focused forward roots";
    let native = List.fold_left (fun native argument -> U.mk_app __FILE__ __LINE__ span native (U.mk_texpr_from_fvar argument)) branch.native arguments in
    if native.ty <> original.native.ty || original.source.source.target <> branch.source.source.target then
      invalid_arg "a registry-driven bundle changed the exact existing higher-level-first member type";
    native) branches closure.members in
  let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) arguments) (U.mk_simpl_tuple_texpr span members) in
  let reflected = X.reflect native in
  { projectors; branches; native; reflected; fuel = 128 + 12 * X.depth reflected }
let replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors witness =
  try derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors =
  let witness = derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors in
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors witness) then
    invalid_arg "the registry-driven native closure and complete typed naming witness did not replay";
  witness

let lean_var (value : Q.fvar) = "{ identity := " ^ string_of_int (Q.FVarId.to_int value.id) ^ ", type := " ^ N.pure value.ty ^ " }"
let lean_expression value = match value.Q.e with
  | Q.FVar _ -> ".variable (" ^ lean_var (variable value) ^ ")"
  | _ when Q.compare_texpr value U.mk_unit_texpr = 0 -> ".unit"
  | _ -> invalid_arg "a reflected immediate binding use cannot conceal a native expression"
let lean_pairs pairs = "[" ^ String.concat ", " (List.map (fun (pair : pair) -> "{ native := " ^ lean_var pair.native ^ ", lowered := " ^ lean_var pair.lowered ^ " }") pairs) ^ "]"
let lean_uses uses = "[" ^ String.concat ", " (List.map (fun (use : use) -> "{ native := " ^ lean_expression use.native ^ ", lowered := " ^ lean_expression use.lowered ^ " }") uses) ^ "]"

let report component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors witness =
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings projectors witness) then
    invalid_arg "a registry-driven native closure report lost its complete actual-source/binding/projector witness";
  `Assoc ["schema", `String "native-registry-driven-closed-backward-bundle/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.source.source.target);
      "typed_injective_names", `String (lean_pairs branch.pairs); "actual_immediate_expression_uses", `String (lean_uses branch.uses);
      "roots", `List (List.map (fun root -> `String (lean_var root)) branch.roots);
      "complete_native_arrow", `String (N.pure branch.native.ty);
      "complete_native_program", `String (X.lean_term branch.reflected); "interpreter_fuel", `Int branch.fuel]) witness.branches);
    "complete_closed_bundle", `String (X.lean_term witness.reflected); "interpreter_fuel", `Int witness.fuel;
    "native_registry_identifiers_and_immediate_expressions_used", `Bool true;
    "complete_native_ast_roundtrip_required", `Bool true;
    "full_original_synthesis_environment_fabricated", `Bool false;
    "foreign_default_activation_is_proposed_lowering", `Bool true;
    "original_endabs_dispatch_or_infallible_signature_adequacy_proved", `Bool false;
    "legitimate_partial_input_adequacy_proved", `Bool false;
    "original_rust_heap_loan_lifetime_layout_adequacy_proved", `Bool false;
    "original_nested_mutable_or_level_guards_removed", `Bool false;
    "ordinary_rust_results_supplied", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let buffer = Buffer.create 196608 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  let payload = "Auths.Qualification.NativePurePayload." in
  let counter = payload ^ "branch0Channel0" and writer = payload ^ "branch2Channel0" in
  let seeds = witness.projectors.bindings.closure.seeds.seeds in
  let counter_seed, writer_seed = match seeds with [counter; writer] -> counter, writer
    | _ -> invalid_arg "a registry-driven Lean harness needs its exact two forward seed roles" in
  line "import Auths.Support.NativeBindingWiring";
  line "import qualification.aeneas.cases.NativeProjectorLevels";
  line "import qualification.aeneas.cases.NativeCaptureClosures";
  line "/- Native registry names and immediate expressions drive this complete Pure bundle.";
  line "   Unelaborated/unqualified. Full original environment/dispatch/permission adequacy remains open. -/";
  line "namespace Auths.Qualification.NativeBindingClosures";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "open Auths.Qualification.NativePureExpressions";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  line "universe u";
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
  let branch_inputs (branch : branch) = List.mapi (fun index ((helper : X.helper), _) -> index, helper) branch.inputs in
  let channel name (helper : X.helper) = payload ^ name ^ "Channel" ^ string_of_int helper.index in
  let input_binders name inputs = String.concat " " (List.map (fun (index, helper) -> "(incoming" ^ string_of_int index ^
    " : Value Atom " ^ channel name helper ^ "Layout)") inputs) in
  let input_names inputs = String.concat " " (List.map (fun (index, _) -> "incoming" ^ string_of_int index) inputs) in
  let binders = "(Atom : Ty → Type u) (counter : Value Atom " ^ counter ^ "Layout) (writer : Value Atom " ^ writer ^ "Layout)" in
  let source_cases inputs =
    let rec incoming indent = function
      | [] -> line (String.make indent ' ' ^ "rfl")
      | (index, (helper : X.helper)) :: rest -> cases indent ("incoming" ^ string_of_int index) helper.source.incoming.layout (fun indent -> incoming indent rest) in
    cases 2 "counter" counter_seed.codec_helper.source.outgoing.layout (fun indent ->
      cases indent "writer" writer_seed.codec_helper.source.outgoing.layout (fun indent -> incoming indent inputs)) in
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.source.source.target in
    let inputs = branch_inputs branch in
    let args = input_binders name inputs and names = input_names inputs in
    line ("def " ^ name ^ "Names : List Auths.Support.NativeBindingWiring.Pair := " ^ lean_pairs branch.pairs);
    line ("def " ^ name ^ "Uses : List Auths.Support.NativeBindingWiring.Use := " ^ lean_uses branch.uses);
    line ("theorem " ^ name ^ "_all_native_references_map_to_same_typed_lowered_variables : Auths.Support.NativeBindingWiring.usesValid " ^ name ^ "Names " ^ name ^ "Uses = true := by decide");
    line ("def " ^ name ^ " : Term := " ^ X.lean_term branch.reflected);
    line ("def " ^ name ^ "Fuel : Nat := " ^ string_of_int branch.fuel);
    line ("theorem " ^ name ^ "_well_typed : check builtins schemas " ^ name ^ "Fuel [] " ^ name ^ " = true := by decide");
    line ("def " ^ name ^ "Run " ^ binders ^ " " ^ args ^ " : Option (Dynamic Atom) :=");
    line ("  executePacked builtins schemas " ^ name ^ "Fuel " ^ name ^ " [pack " ^ name ^ "Fuel counter, pack " ^ name ^ "Fuel writer" ^
      String.concat "" (List.map (fun (index, _) -> ", pack " ^ name ^ "Fuel incoming" ^ string_of_int index) inputs) ^ "]");
    line ("theorem " ^ name ^ "_native_registry_program_matches_selected_view_program " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "Run Atom counter writer " ^ names ^ " = Auths.Qualification.NativeCurrentWiring." ^ name ^ "Run Atom counter writer " ^ names ^ " := by");
    line ("  unfold " ^ name ^ "Run Auths.Qualification.NativeCurrentWiring." ^ name ^ "Run");
    line ("  rw [checked_packed_runs_body builtins schemas " ^ name ^ "Fuel " ^ name ^ " " ^ name ^ "_well_typed]");
    line ("  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring." ^ name ^ "Fuel Auths.Qualification.NativeCurrentWiring." ^ name ^ " Auths.Qualification.NativeCurrentWiring." ^ name ^ "_well_typed]");
    source_cases inputs
  ) witness.branches;
  line ("def bundle : Term := " ^ X.lean_term witness.reflected);
  line ("def fuel : Nat := " ^ string_of_int witness.fuel);
  line "theorem bundle_well_typed : check builtins schemas fuel [] bundle = true := by decide";
  line ("def build " ^ binders ^ " : Option (Dynamic Atom) :=");
  line "  Auths.Support.NativePureClosures.execute builtins schemas fuel bundle [pack fuel counter, pack fuel writer]";
  let member_type (branch : branch) =
    List.fold_left (fun ty _ -> match ty with Q.TArrow (_, rest) -> rest
      | _ -> invalid_arg "a native registry bundle member lost one of its actual forward root arguments") branch.native.ty branch.roots in
  line ("def memberTypes : List Ty := [" ^ String.concat ", " (List.map (fun branch -> N.pure (member_type branch)) witness.branches) ^ "]");
  line ("theorem build_has_exact_member_types " ^ binders ^ " :");
  line "    (build Atom counter writer).map Dynamic.type = some (.tuple memberTypes) := by";
  line "  unfold build";
  line "  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]";
  source_cases [];
  line ("theorem build_produces_bundle " ^ binders ^ " : ∃ functions, build Atom counter writer = some functions := by");
  line "  cases result : build Atom counter writer with";
  line "  | none =>";
  line "    have accepted := build_has_exact_member_types Atom counter writer";
  line "    simp [result] at accepted";
  line "  | some functions => exact ⟨functions, by simp [result]⟩";
  List.iteri (fun index branch ->
    let name = "branch" ^ B.gid branch.source.source.target in
    let inputs = branch_inputs branch in
    let args = input_binders name inputs and names = input_names inputs in
    let packed = "[" ^ String.concat ", " (List.map (fun (index, _) -> "pack fuel incoming" ^ string_of_int index) inputs) ^ "]" in
    line ("def " ^ name ^ "Invoke " ^ binders ^ " " ^ args ^ " : Option (Dynamic Atom) := do");
    line "  let captured ← build Atom counter writer";
    line ("  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured " ^ string_of_int index ^ " " ^ packed);
    line ("theorem " ^ name ^ "_bundle_uses_its_exact_registry_program " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "Invoke Atom counter writer " ^ names ^ " = " ^ name ^ "Run Atom counter writer " ^ names ^ " := by");
    line ("  unfold " ^ name ^ "Invoke build " ^ name ^ "Run");
    line "  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]";
    line ("  rw [checked_packed_runs_body builtins schemas " ^ name ^ "Fuel " ^ name ^ " " ^ name ^ "_well_typed]");
    source_cases inputs;
    line ("theorem " ^ name ^ "_bundle_matches_selected_view_program " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "Invoke Atom counter writer " ^ names ^ " = Auths.Qualification.NativeCurrentWiring." ^ name ^ "Run Atom counter writer " ^ names ^ " := by");
    line ("  rw [" ^ name ^ "_bundle_uses_its_exact_registry_program, " ^ name ^ "_native_registry_program_matches_selected_view_program]")
  ) witness.branches;
  let source_atom = "SourceAtom " ^ payload ^ "atomTyping Atom" in
  let source_inputs = List.map (fun (root : P.root) -> "input" ^ string_of_int root.index) projection.inputs in
  let input_args = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data (" ^ source_atom ^ ") " ^ name ^ "Shape)") source_inputs) in
  let names = String.concat " " source_inputs in
  let source_seeds = "Auths.Qualification.NativeCurrentSeeds." in
  line "structure Captured (Atom : Ty → Type u) where";
  line ("  value : Data (" ^ source_atom ^ ") outputShape");
  line "  backwards : Dynamic Atom";
  line ("def capture (Atom : Ty → Type u) " ^ input_args ^ " : Option (Captured Atom) := do");
  line ("  let prepared ← " ^ source_seeds ^ "prepare Atom " ^ names);
  line "  let backwards ← build Atom prepared.current0 prepared.current1";
  line "  pure { value := prepared.value, backwards }";
  line ("theorem capture_keeps_prepared_value (Atom : Ty → Type u) " ^ input_args ^ " :");
  line ("    (capture Atom " ^ names ^ ").map Captured.value = (" ^ source_seeds ^ "prepare Atom " ^ names ^ ").map " ^ source_seeds ^ "Prepared.value := by");
  line "  unfold capture";
  line ("  cases prepared : " ^ source_seeds ^ "prepare Atom " ^ names ^ " with");
  line "  | none => simp [prepared]";
  line "  | some value =>";
  line "    obtain ⟨functions, found⟩ := build_produces_bundle Atom value.current0 value.current1";
  line "    simp [prepared, found]";
  line ("theorem capture_keeps_original_source_value (Atom : Ty → Type u) " ^ input_args ^ " :");
  line ("    (capture Atom " ^ names ^ ").map Captured.value = some (construct (" ^ source_atom ^ ") " ^ names ^ ") := by");
  line "  rw [capture_keeps_prepared_value]";
  line ("  exact " ^ source_seeds ^ "prepared_value_is_original_source_capture Atom " ^ names);
  List.iteri (fun index branch ->
    let name = "branch" ^ B.gid branch.source.source.target in
    let inputs = branch_inputs branch in
    let args = input_binders name inputs and incoming = input_names inputs in
    let packed = "[" ^ String.concat ", " (List.map (fun (index, _) -> "pack fuel incoming" ^ string_of_int index) inputs) ^ "]" in
    line ("def " ^ name ^ "FromCapture (Atom : Ty → Type u) " ^ input_args ^ " " ^ args ^ " : Option (Dynamic Atom) := do");
    line ("  let captured ← capture Atom " ^ names);
    line ("  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards " ^ string_of_int index ^ " " ^ packed);
    line ("theorem " ^ name ^ "_captures_its_own_forward_current (Atom : Ty → Type u) " ^ input_args ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "FromCapture Atom " ^ names ^ " " ^ incoming ^ " = " ^ source_seeds ^ name ^ "FromForward Atom " ^ names ^ " " ^ incoming ^ " := by");
    line ("  unfold " ^ name ^ "FromCapture capture " ^ source_seeds ^ name ^ "FromForward");
    line ("  cases prepared : " ^ source_seeds ^ "prepare Atom " ^ names ^ " with");
    line "  | none => simp [prepared]";
    line "  | some value =>";
    line "    simp only [prepared, Option.bind_some]";
    line ("    simpa [" ^ name ^ "Invoke, Option.bind_assoc] using " ^ name ^ "_bundle_matches_selected_view_program Atom value.current0 value.current1 " ^ incoming)
  ) witness.branches;
  line "end Auths.Qualification.NativeBindingClosures";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
