(* Call the actual native nested type and complete function-signature APIs.
   These are type computations, not a made-up bs_ctx, runtime environment,
   caller payload or proof of full expression/heap/loan correspondence. *)
open Charon
open Types
module Q = Aeneas.Pure
module S = Aeneas.SymbolicToPureTypes
module L = Native_borrow_levels
module B = Native_borrow_protocol
module P = Borrow_projection
module N = Native_type_syntax
module T = Aeneas.SymbolicToPureBorrowLevels

type selection = { group : region_group_id; level : int; root : L.root; selected : Q.ty option }
type t = { levels : L.t; forward : (ty * Q.ty) list; selections : selection list;
  signature : Aeneas.SymbolicToPureCore.fun_sigs }

let derive component (projection : P.t) inputs symbolic forward protocol wiring (levels : L.t) =
  if not (L.replay component projection inputs symbolic forward protocol wiring levels) then
    invalid_arg "native backward types require every original root, complete field tree and exact actual wiring";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native backward type context has unresolved errors";
  let span = Some projection.candidate.item_meta.span in
  let get_group region = match List.assoc_opt region levels.mapping with
    | Some group -> group | None -> invalid_arg "native backward type selection cannot guess a region group" in
  let rec nodes tree = tree :: List.concat_map nodes (T.children tree) in
  let source_types = List.concat_map (fun (root : L.root) -> nodes root.native) levels.roots |>
    List.map (fun (tree : T.tree) -> tree.source) |> List.sort_uniq compare in
  let forward = List.map (fun source -> source, S.translate_fwd_ty span context source) source_types in
  let selections = List.concat_map (fun (count : L.count) ->
    List.concat_map (fun level -> List.map (fun root ->
      let selected = S.translate_back_ty_aux span context get_group count.group level root.L.source in
      (* The complete original tree used by the API is independently retained.
         Do not silently substitute a selected event leaf for a source root. *)
      { group = count.group; level; root; selected }) levels.roots)
      (List.init count.maximum Fun.id)) levels.counts in
  let signature = S.translate_fun_sigs_from_decl context projection.candidate in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "the actual complete native signature contains unresolved errors";
  if signature.dsg.llbc_generics <> projection.candidate.generics then
    invalid_arg "the actual native signature changed an original generic parameter, predicate or associated-type constraint";
  let parameters, predicates = S.translate_generic_params span projection.candidate.generics in
  if parameters <> signature.dsg.generics || predicates <> signature.dsg.preds then
    invalid_arg "the actual native signature lost its complete translated parameters/predicates";
  if List.map fst (RegionGroupId.Map.bindings signature.dsg.fun_ty.back_sg) <>
      List.map (fun (group : region_var_group) -> group.id) projection.hierarchy then
    invalid_arg "the actual complete native signature omitted or reordered an original region group";
  { levels; forward; selections; signature }

let replay component projection inputs symbolic forward protocol wiring levels witness =
  try derive component projection inputs symbolic forward protocol wiring levels = witness
  with Invalid_argument _ | Not_found | T.Unsupported _ -> false

let create component projection inputs symbolic forward protocol wiring levels =
  let witness = derive component projection inputs symbolic forward protocol wiring levels in
  if not (replay component projection inputs symbolic forward protocol wiring levels witness) then
    invalid_arg "the actual complete original backward type/signature witness did not replay";
  witness

let fuel witness =
  let source_depth = List.fold_left (fun size (root : L.root) -> max size (L.depth root.native)) 0 witness.levels.roots in
  let native_depth = List.fold_left (fun size (_, native) -> max size (N.depth (N.reflect native)))
    (N.depth (N.reflect witness.signature.ty)) witness.forward in
  let parameter_depth = N.depth (N.reflect_parameters witness.signature.dsg.generics) in
  let predicate_depth = N.depth (N.reflect_predicates witness.signature.dsg.preds) in
  16 + 4 * max source_depth (max native_depth (max parameter_depth predicate_depth))
let raw_option = function None -> `Null | Some value -> `String (Q.show_ty value)
let raw_rows rows = `List (List.map (fun (level, fields) -> `Assoc [
  "level", `Int level; "fields", `List (List.map (fun (name, value) -> `Assoc [
    "original_name", (match name with None -> `Null | Some name -> `String name);
    "complete_native_type", `String (Q.show_ty value)]) fields)]) rows)

let report component projection inputs symbolic forward protocol wiring levels witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels witness) then
    invalid_arg "native backward type report lost its exact original API inputs";
  `Assoc ["schema", `String "actual-native-complete-backward-types/v1";
    "actual_complete_signature", `String (Q.show_decomposed_fun_sig witness.signature.dsg);
    "actual_final_native_signature", `String (Q.show_fun_sig witness.signature.sg);
    "actual_full_native_arrow", `String (Q.show_ty witness.signature.ty);
    "actual_native_generic_parameters", `String (Q.show_generic_params witness.signature.dsg.generics);
    "actual_native_predicates", `String (Q.show_predicates witness.signature.dsg.preds);
    "complete_original_source_generics_and_predicates", `String (show_generic_params projection.candidate.generics);
    "complete_original_source_generics_retained", `Bool true;
    "native_predicates_equal_complete_original_parameter_translation", `Bool true;
    "forward_type_table", `List (List.map (fun (source, native) -> `Assoc [
      "complete_source_type", `String (P.reflect source); "complete_native_type", `String (Q.show_ty native)]) witness.forward);
    "root_selections", `List (List.map (fun selection -> `Assoc [
      "group", `Int (RegionGroupId.to_int selection.group); "level", `Int selection.level;
      "root", `String (L.root_name selection.root); "complete_native_selected_type", raw_option selection.selected]) witness.selections);
    "groups", `List (List.map (fun (group, (info : Q.back_sg_info)) -> `Assoc [
      "group", `Int (RegionGroupId.to_int group); "native_inputs", raw_rows info.inputs;
      "native_outputs", raw_rows info.outputs; "native_effect", `String (Q.show_fun_effect_info info.effect_info);
      "filtered", `Bool info.filter]) (RegionGroupId.Map.bindings witness.signature.dsg.fun_ty.back_sg));
    "actual_original_full_signature_api_invoked", `Bool true;
    "signature_API_uses_candidate_nested_nominal_backtype_extension", `Bool true;
    "candidate_nested_nominal_represents_every_source_current_version_proved", `Bool false;
    "selected_event_ports_substituted_for_original_root_types", `Bool false;
    "complete_native_expression_environment_continuation_adequacy_proved", `Bool false;
    "original_rust_heap_loan_lifetime_effect_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let lean_option = function None -> "none" | Some ty -> "some (" ^ N.pure ty ^ ")"
let lean_rows rows = B.list (fun (level, fields) -> "(" ^ B.nat level ^ ", " ^
  B.list (fun (_, ty) -> N.pure ty) fields ^ ")") rows

let write_lean path witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeBackwardTypes";
  line "import qualification.aeneas.cases.NativeBorrowLevels";
  line "/- Actual complete native root/signature type computation, unelaborated/unqualified.";
  line "   Runtime expression/continuation, source/layout/heap/loan and effect adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeBackwardTypes";
  line "open Auths.Support.SourceClosureRegions Auths.Support.NativeBorrowLevels Auths.Support.NativeBackwardTypes";
  line "open Auths.Qualification.NativeBorrowLevels";
  line ("def typeFuel : Nat := " ^ B.nat (fuel witness));
  line ("def forwardTypes : ForwardTypes := " ^ B.list (fun (source, native) ->
    "(" ^ P.reflect source ^ ", " ^ N.pure native ^ ")") witness.forward);
  line ("def actualNativeArrow : Auths.Support.NativeTypeSyntax.Expr := " ^ N.pure witness.signature.ty);
  line ("def actualNativeParameters : Auths.Support.NativeTypeSyntax.Expr := " ^ N.lean (N.reflect_parameters witness.signature.dsg.generics));
  line ("def actualNativePredicates : Auths.Support.NativeTypeSyntax.Expr := " ^ N.lean (N.reflect_predicates witness.signature.dsg.preds));
  line "theorem actual_native_arrow_has_complete_type_syntax : Auths.Support.NativeTypeSyntax.validType typeFuel actualNativeArrow = true := by decide";
  line "theorem actual_native_parameters_have_complete_syntax : Auths.Support.NativeTypeSyntax.validParameters typeFuel actualNativeParameters = true := by decide";
  line "theorem actual_native_predicates_have_complete_syntax : Auths.Support.NativeTypeSyntax.validPredicates typeFuel actualNativePredicates = true := by decide";
  line ("def actualNativeForwardInputs : List Auths.Support.NativeTypeSyntax.Expr := " ^ B.list N.pure witness.signature.dsg.fun_ty.fwd_inputs);
  line ("def actualNativeForwardOutput : Auths.Support.NativeTypeSyntax.Expr := " ^ N.pure witness.signature.dsg.fun_ty.fwd_output);
  line ("def sourceRoots : List Root := " ^ B.list (fun (root : L.root) ->
    "{ input := " ^ (match root.index with None -> "none" | Some index -> "some " ^ B.nat index) ^
    ", tree := " ^ L.root_name root ^ " }") witness.levels.roots);
  List.iter (fun selection ->
    let root = L.root_name selection.root in
    let name = "group" ^ B.gid selection.group ^ "Level" ^ B.nat selection.level ^ "_" ^ root in
    line ("theorem " ^ name ^ "_matches_actual_native_root_type :");
    line ("    checked typeFuel mapping forwardTypes " ^ B.gid selection.group ^ " " ^ B.nat selection.level ^
      " " ^ root ^ " = some (" ^ lean_option selection.selected ^ ") := by decide")
  ) witness.selections;
  List.iter (fun (group, (info : Q.back_sg_info)) ->
    let name = "group" ^ B.gid group in
    let count = match List.filter (fun (count : L.count) -> count.group = group) witness.levels.counts with
      | [count] -> count.maximum | _ -> invalid_arg "an actual native signature group lost its complete level count" in
    line ("def " ^ name ^ "Inputs : List (Nat × List Auths.Support.NativeTypeSyntax.Expr) := " ^ lean_rows info.inputs);
    line ("def " ^ name ^ "Outputs : List (Nat × List Auths.Support.NativeTypeSyntax.Expr) := " ^ lean_rows info.outputs);
    line ("theorem " ^ name ^ "_inputs_match_complete_native_signature :");
    line ("    signatureRows typeFuel mapping forwardTypes sourceRoots " ^ B.gid group ^ " " ^ B.nat count ^ " true = some " ^ name ^ "Inputs := by decide");
    line ("theorem " ^ name ^ "_outputs_match_complete_native_signature :");
    line ("    signatureRows typeFuel mapping forwardTypes sourceRoots " ^ B.gid group ^ " " ^ B.nat count ^ " false = some " ^ name ^ "Outputs := by decide")
  ) (RegionGroupId.Map.bindings witness.signature.dsg.fun_ty.back_sg);
  line "end Auths.Qualification.NativeBackwardTypes";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
