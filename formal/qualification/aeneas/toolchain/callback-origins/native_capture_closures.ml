(* Actual closed Pure closure bundle for the exact current-seeded ending model.
   Lexical environments are explicit in the independent interpreter. This is
   not a fabricated original decomposed signature or a removed native guard. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module P = Borrow_projection
module B = Native_borrow_protocol
module D = Native_borrow_defaults
module N = Native_pure_payload
module X = Native_pure_expressions
module W = Native_current_wiring
module C = Native_current_seeds

type member = { index : int; source : W.branch; native : Q.texpr; original_effect : Q.fun_effect_info }
type t = { seeds : C.t; members : member list; native : Q.texpr; reflected : X.term; fuel : int }

let grouped_types ports =
  let rec groups = function
    | [] -> []
    | (level, ty) :: rest ->
        let rec same types = function
          | (actual, ty) :: rest when actual = level -> same (ty :: types) rest
          | rest -> List.rev types, rest in
        let types, rest = same [ty] rest in
        if List.exists (fun (actual, _) -> actual >= level) rest then
          invalid_arg "native closure input/output levels must retain actual strictly descending group order";
        U.mk_simpl_tuple_ty types :: groups rest in
  groups ports

let derive component (projection : P.t) inputs expression forward protocol wiring defaults execution full_abi payload expressions current (seeds : C.t) =
  if not (C.replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds) then
    invalid_arg "native capture closures require the exact forward/current/returned-seed composition";
  let span = projection.candidate.item_meta.span in
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native capture closure context contains unresolved errors";
  let arguments = List.mapi (fun index (seed : C.seed) ->
    let variable : Q.fvar = { id = Q.FVarId.of_int index; basename = Some ("captured_" ^ W.key_name seed.key);
      ty = seed.codec_helper.source.outgoing.native_type } in seed.key, variable) seeds.seeds in
  let members = List.mapi (fun index (source : W.branch) ->
    let native = List.fold_left (fun (native : Q.texpr) (cell : W.cell) ->
      let argument = match List.assoc_opt cell.key arguments with Some argument -> argument
        | None -> invalid_arg "a native closure cannot capture a current seed absent from its actual forward preparation" in
      if argument.ty <> cell.variable.ty then invalid_arg "native closure capture changed the actual whole seed type";
      (match native.ty with Q.TArrow (input, _) when input = argument.ty -> ()
       | _ -> invalid_arg "native closure seed application does not match its complete real arrow type");
      U.mk_app __FILE__ __LINE__ span native (U.mk_texpr_from_fvar argument)) source.native source.seeds in
    let input_types = List.map (fun ((helper : X.helper), _) ->
      helper.source.incoming.access.port.level, helper.source.incoming.native_type) source.inputs |> grouped_types in
    let output_types = List.filter_map (fun (operation : W.operation) -> match operation.action with
      | W.Output (helper, _, _, _, _) -> Some (operation.original.access.port.level, helper.source.outgoing.native_type)
      | _ -> None) source.operations |> grouped_types in
    let expected = U.mk_arrows input_types (U.mk_result_ty (U.mk_simpl_tuple_ty output_types)) in
    if native.ty <> expected then
      invalid_arg "native closure field-value signature disagrees with actual level-grouped input/output types";
    let original_effect = Aeneas.SymbolicToPureTypes.compute_raw_fun_effect_info (Some span) context.fun_ctx.fun_infos
      (Q.FunId (Types.FRegular projection.candidate.def_id)) (Some source.source.target) in
    { index; source; native; original_effect }) seeds.wiring.branches in
  if List.map (fun member -> member.source.source.target) members <>
      List.map (fun (group : region_var_group) -> group.id) projection.hierarchy then
    invalid_arg "native closure tuple cannot omit, duplicate or reorder an original region-group member";
  let body = U.mk_simpl_tuple_texpr span (List.map (fun (member : member) -> member.native) members) in
  let native = U.mk_closed_lambdas span (List.map (fun (_, variable) -> U.mk_tpat_from_fvar None variable) arguments) body in
  let expected = U.mk_arrows (List.map (fun (_, (variable : Q.fvar)) -> variable.ty) arguments)
    (U.mk_simpl_tuple_ty (List.map (fun (member : member) -> member.native.ty) members)) in
  if native.ty <> expected then invalid_arg "native closure bundle changed its exact capture/member type";
  let reflected = X.reflect native in
  { seeds; members; native; reflected; fuel = 96 + 8 * X.depth reflected }

let replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds witness =
  try derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds in
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds witness) then
    invalid_arg "the native current-capturing closure bundle did not replay";
  witness

let report component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions current seeds witness) then
    invalid_arg "native closure report lost its complete source/current/seed/typed-expression witness";
  `Assoc ["schema", `String "actual-native-current-capturing-closure-bundle/v1";
    "native_arrow", `String (N.pure witness.native.ty);
    "complete_native_ast", `String (X.lean_term witness.reflected);
    "fuel", `Int witness.fuel;
    "members", `List (List.map (fun member -> `Assoc ["index", `Int member.index;
      "region_group", `Int (RegionGroupId.to_int member.source.source.target);
      "field_arrow", `String (N.pure member.native.ty);
      "captured_current_keys", `List (List.map (fun (cell : W.cell) -> `String (D.lean_origin cell.key)) member.source.seeds);
      "input_levels", `List (List.map (fun ((helper : X.helper), _) -> `Int helper.source.incoming.access.port.level) member.source.inputs);
      "original_raw_effect_can_fail", `Bool member.original_effect.can_fail;
      "original_raw_effect_can_diverge", `Bool member.original_effect.can_diverge;
      "original_raw_effect_is_recursive", `Bool member.original_effect.is_rec]) witness.members);
    "uses_pinned_higher_level_first_inputs_and_collected_outputs", `Bool true;
    "helper_result_is_additional_representation_domain_interface", `Bool true;
    "original_complete_signature_effect_adequacy_proved", `Bool false;
    "original_native_environment_default_activation_continuation_adequacy_proved", `Bool false;
    "original_rust_closure_heap_loan_lifetime_layout_adequacy_proved", `Bool false;
    "ordinary_rust_results_or_host_functions_supplied", `Bool false;
    "opaque_native_environment_equality_used", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  let payload = "Auths.Qualification.NativePurePayload." in
  let counter = payload ^ "branch0Channel0" and writer = payload ^ "branch2Channel0" in
  let source_seeds = "Auths.Qualification.NativeCurrentSeeds." in
  line "import Auths.Support.NativePureClosures";
  line "import qualification.aeneas.cases.NativeCurrentSeeds";
  line "/- Actual native lexical closures for the explicit ending model. Unelaborated/unqualified.";
  line "   Original native signatures/effects, defaults and Rust closure/loan/heap adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeCaptureClosures";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "open Auths.Qualification.NativePureExpressions";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  line "universe u";
  line ("def bundle : Term := " ^ X.lean_term witness.reflected);
  line ("def fuel : Nat := " ^ string_of_int witness.fuel);
  line "theorem bundle_well_typed : check builtins schemas fuel [] bundle = true := by decide";
  line ("def build (Atom : Ty → Type u) (counter : Value Atom " ^ counter ^ "Layout) (writer : Value Atom " ^ writer ^ "Layout) : Option (Dynamic Atom) :=");
  line "  Auths.Support.NativePureClosures.execute builtins schemas fuel bundle [pack fuel counter, pack fuel writer]";
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
  let counter_seed, writer_seed = match witness.seeds.seeds with [counter; writer] -> counter, writer | _ -> assert false in
  let binders = "(Atom : Ty → Type u) (counter : Value Atom " ^ counter ^ "Layout) (writer : Value Atom " ^ writer ^ "Layout)" in
  line ("def memberTypes : List Ty := [" ^ String.concat ", " (List.map (fun (member : member) -> N.pure member.native.ty) witness.members) ^ "]");
  line ("theorem build_has_exact_member_types " ^ binders ^ " :");
  line "    (build Atom counter writer).map Dynamic.type = some (.tuple memberTypes) := by";
  line "  unfold build";
  line "  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]";
  cases 2 "counter" counter_seed.codec_helper.source.outgoing.layout (fun indent ->
    cases indent "writer" writer_seed.codec_helper.source.outgoing.layout (fun indent -> line (String.make indent ' ' ^ "rfl")));
  line ("theorem build_produces_bundle " ^ binders ^ " : ∃ functions, build Atom counter writer = some functions := by");
  line "  cases result : build Atom counter writer with";
  line "  | none =>";
  line "    have accepted := build_has_exact_member_types Atom counter writer";
  line "    simp [result] at accepted";
  line "  | some functions => exact ⟨functions, by simp [result]⟩";
  List.iter (fun member ->
    let name = "branch" ^ B.gid member.source.source.target in
    let inputs = List.mapi (fun index ((helper : X.helper), _) -> index, helper) member.source.inputs in
    let args = String.concat " " (List.map (fun (index, (helper : X.helper)) -> "(incoming" ^ string_of_int index ^
      " : Value Atom " ^ payload ^ name ^ "Channel" ^ string_of_int helper.index ^ "Layout)") inputs) in
    let names = String.concat " " (List.map (fun (index, _) -> "incoming" ^ string_of_int index) inputs) in
    let packed = "[" ^ String.concat ", " (List.map (fun (index, _) -> "pack fuel incoming" ^ string_of_int index) inputs) ^ "]" in
    line ("def " ^ name ^ "Invoke " ^ binders ^ " " ^ args ^ " : Option (Dynamic Atom) := do");
    line "  let captured ← build Atom counter writer";
    line ("  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured " ^ string_of_int member.index ^ " " ^ packed);
    line ("theorem " ^ name ^ "_lexical_closure_matches_state_program " ^ binders ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "Invoke Atom counter writer " ^ names ^ " = Auths.Qualification.NativeCurrentWiring." ^ name ^ "Run Atom counter writer " ^ names ^ " := by");
    line ("  unfold " ^ name ^ "Invoke build");
    line "  rw [Auths.Support.NativePureClosures.checked_runs_body builtins schemas fuel bundle bundle_well_typed]";
    line ("  unfold Auths.Qualification.NativeCurrentWiring." ^ name ^ "Run");
    line ("  rw [checked_packed_runs_body builtins schemas Auths.Qualification.NativeCurrentWiring." ^ name ^ "Fuel Auths.Qualification.NativeCurrentWiring." ^ name ^ " Auths.Qualification.NativeCurrentWiring." ^ name ^ "_well_typed]");
    let rec input_cases indent = function
      | [] -> line (String.make indent ' ' ^ "rfl")
      | (index, (helper : X.helper)) :: rest -> cases indent ("incoming" ^ string_of_int index) helper.source.incoming.layout (fun indent -> input_cases indent rest) in
    cases 2 "counter" counter_seed.codec_helper.source.outgoing.layout (fun indent ->
      cases indent "writer" writer_seed.codec_helper.source.outgoing.layout (fun indent -> input_cases indent inputs))
  ) witness.members;
  let source_atom = "SourceAtom " ^ payload ^ "atomTyping Atom" in
  let source_inputs = List.map (fun (root : P.root) -> "input" ^ string_of_int root.index) projection.inputs in
  let input_args = String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data (" ^ source_atom ^ ") " ^ name ^ "Shape)") source_inputs) in
  let names = String.concat " " source_inputs in
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
  line ("  rw [capture_keeps_prepared_value]");
  line ("  exact " ^ source_seeds ^ "prepared_value_is_original_source_capture Atom " ^ names);
  List.iter (fun member ->
    let name = "branch" ^ B.gid member.source.source.target in
    let inputs = List.mapi (fun index ((helper : X.helper), _) -> index, helper) member.source.inputs in
    let args = String.concat " " (List.map (fun (index, (helper : X.helper)) -> "(incoming" ^ string_of_int index ^ " : Value Atom " ^
      payload ^ name ^ "Channel" ^ string_of_int helper.index ^ "Layout)") inputs) in
    let incoming = String.concat " " (List.map (fun (index, _) -> "incoming" ^ string_of_int index) inputs) in
    let packed = "[" ^ String.concat ", " (List.map (fun (index, _) -> "pack fuel incoming" ^ string_of_int index) inputs) ^ "]" in
    line ("def " ^ name ^ "FromCapture (Atom : Ty → Type u) " ^ input_args ^ " " ^ args ^ " : Option (Dynamic Atom) := do");
    line ("  let captured ← capture Atom " ^ names);
    line ("  Auths.Support.NativePureClosures.invoke builtins schemas fuel captured.backwards " ^ string_of_int member.index ^ " " ^ packed);
    line ("theorem " ^ name ^ "_captures_its_own_forward_current (Atom : Ty → Type u) " ^ input_args ^ " " ^ args ^ " :");
    line ("    " ^ name ^ "FromCapture Atom " ^ names ^ " " ^ incoming ^ " = " ^ source_seeds ^ name ^ "FromForward Atom " ^ names ^ " " ^ incoming ^ " := by");
    line ("  unfold " ^ name ^ "FromCapture capture " ^ source_seeds ^ name ^ "FromForward");
    line ("  cases prepared : " ^ source_seeds ^ "prepare Atom " ^ names ^ " with");
    line "  | none => simp [prepared]";
    line "  | some value =>";
    line "    simp only [prepared, Option.bind_some]";
    line ("    simpa [" ^ name ^ "Invoke, Option.bind_assoc] using " ^ name ^ "_lexical_closure_matches_state_program Atom value.current0 value.current1 " ^ incoming)
  ) witness.members;
  line "end Auths.Qualification.NativeCaptureClosures";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
