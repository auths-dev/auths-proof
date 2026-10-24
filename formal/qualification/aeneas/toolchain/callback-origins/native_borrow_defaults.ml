(* Actual given-back defaults preserve immediate symbolic versions. This is
   value/default preparation, not execution of native continuation calls. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_borrow_view
module T = Native_borrow_transport

type plan = Keep | Skip | Empty | Product of plan * plan | Sum of plan * plan | Named of plan | Borrow of plan
type restriction = Whole of plan | Discard of plan | RProduct of restriction * restriction
  | RSum of restriction * restriction | RNamed of restriction | RBorrow of restriction | REmpty

let rec select regions = function
  | P.Atom _ | P.Unit | P.Borrow (RShared, _, _) -> Skip
  | P.Empty -> Empty
  | P.Product (left, right) -> Product (select regions left, select regions right)
  | P.Sum (left, right) -> Sum (select regions left, select regions right)
  | P.Named (_, body) -> Named (select regions body)
  | P.Borrow (RMut, region, body) -> Borrow (if List.mem region regions then Keep else select regions body)
let selection_plan shape = function C.Whole -> Keep | C.Regions regions -> select regions shape
let rec restrict source target = match source, target with
  | source, Skip -> Discard source
  | Keep, target -> Whole target
  | Empty, Empty -> REmpty
  | Product (sl, sr), Product (tl, tr) -> RProduct (restrict sl tl, restrict sr tr)
  | Sum (sl, sr), Sum (tl, tr) -> RSum (restrict sl tl, restrict sr tr)
  | Named source, Named target -> RNamed (restrict source target)
  | Borrow source, Borrow target -> RBorrow (restrict source target)
  | _ -> invalid_arg "an immediate current view cannot supply an absent field, enum tag or mutable payload"

type occurrence = { abstraction : V.abs_id; group : region_group_id; level : int; event : int }
type default = {
  value : V.symbolic_value;
  origin : B.origin;
  candidate_type : ty;
  candidate_shape : P.shape;
  native_shape : P.shape;
  mapping : (region * region) list;
  change : T.change;
  native_nominals : P.nominal list;
  available : C.selection;
  selected : C.selection;
  restriction : restriction;
  occurrences : occurrence list;
}
type branch = { target : region_group_id; defaults : default list }
type t = { branches : branch list }

let derive component (projection : P.t) inputs expression (forward : F.t) (protocol : B.t) (wiring : W.t) =
  if not (W.replay component projection inputs expression forward protocol wiring) then
    invalid_arg "native defaults require the actual level-aware ports and complete ordered abstraction/continuation witness";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native default expansion context contains unresolved errors";
  let forward_binding identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
    | [binding] -> binding.source_type, binding.shape, C.Whole
    | _ -> invalid_arg "an immediate native default source needs its exact current forward binding" in
  let borrow identity =
    match List.filter_map (function F.MutableExpansion (source, actual, _) when actual = identity -> Some source | _ -> None) forward.steps with
    | [source] ->
        (match forward_binding source with
         | TRef (_, inner, RMut), P.Borrow (RMut, _, shape), _ -> inner, shape, C.Whole
         | _ -> invalid_arg "a native borrow default needs its actual current exclusive pointee")
    | _ -> invalid_arg "a native borrow default names an absent or repeated actual borrow" in
  let branches = List.map (fun (branch : B.branch) ->
    let wiring = match List.filter (fun (actual : W.branch) -> actual.target = branch.target) wiring.branches with
      | [actual] -> actual
      | _ -> invalid_arg "a native default branch lost its actual level-aware event sequence" in
    if List.length wiring.events <> List.length branch.events then
      invalid_arg "native defaults cannot omit an original ending event";
    let defaults = ref [] in
    let current_symbol identity =
      match List.filter (fun default -> default.value.sv_id = identity) !defaults with
      | [default] -> default.candidate_type, default.candidate_shape, default.selected
      | [] -> forward_binding identity
      | _ -> invalid_arg "a native default current version has ambiguous complete candidate types" in
    List.iteri (fun event_index (event : B.event) ->
      let active = List.nth wiring.events event_index in
      if active.abstraction <> event.abstraction || active.group <> event.group ||
          active.input <> event.input || active.level <> event.level then
        invalid_arg "native default metadata and selected-level event order disagree";
      let definitions observations = List.filter_map (function B.Define (value, origin) -> Some (value, origin) | _ -> None) observations in
      let abstract = definitions event.abstract_values and continuation = definitions event.continuation in
      if abstract <> continuation then
        invalid_arg "actual abstraction and continuation defaults disagree on order, complete native types or immediate sources";
      let given_back = List.filter (fun (port : W.port) -> port.given_back) active.ports in
      let abstract = List.map (fun (port : W.port) ->
        match List.filter (fun ((value : V.symbolic_value), _) -> value = port.value) abstract with
        | [definition] -> definition
        | _ -> invalid_arg "a selected-level given-back default lacks one exact immediate metadata producer") given_back in
      List.iter (fun ((value : V.symbolic_value), origin) ->
        let occurrence = { abstraction = event.abstraction; group = event.group; level = event.level; event = event_index } in
        match List.filter (fun default -> default.value.sv_id = value.sv_id) !defaults with
        | [previous] ->
            if previous.value <> value || previous.origin <> origin ||
                List.exists (fun actual -> actual.abstraction <> event.abstraction || actual.group <> event.group) previous.occurrences then
              invalid_arg "a repeated native default changed its original producer, complete type or immediate source";
            defaults := List.map (fun default -> if default.value.sv_id = value.sv_id then
              { default with occurrences = default.occurrences @ [occurrence] } else default) !defaults
        | [] ->
            if List.exists (fun (binding : F.binding) -> binding.native.sv_id = value.sv_id) forward.source_bindings then
              invalid_arg "a native default cannot overwrite a forward input or expansion name";
            let candidate_type, candidate_shape, available = match origin with
              | B.Borrow identity -> borrow identity
              | B.Symbolic identity -> current_symbol identity in
            let selected = match origin with
              | B.Borrow _ -> C.Whole
              | B.Symbolic _ ->
                  (match List.filter (fun (group : region_var_group) -> group.id = event.group) projection.hierarchy with
                   | [group] -> C.Regions (List.map (fun region -> RVar (Free region)) group.regions)
                   | _ -> invalid_arg "an actual native default must retain its producer's owned source regions") in
            let restriction = restrict (selection_plan candidate_shape available) (selection_plan candidate_shape selected) in
            let instance = C.type_instance candidate_type value.sv_ty in
            let mapping = List.combine instance.candidate_arguments instance.native_arguments in
            let parameters = List.map (function RVar (Free index) ->
              { index; name = None; variance = Invariant; mutability = LtUnknown }
              | _ -> invalid_arg "a native default needs exact free native region parameters") instance.native_arguments in
            let expand, nominals = P.make_expander component ~span:projection.candidate.item_meta.span
              ~type_infos:context.type_ctx.type_infos ~parameters in
            let native_shape = expand value.sv_ty in
            if T.rename_shape mapping candidate_shape <> native_shape then
              invalid_arg "actual native default fields differ from the immediate current version's complete candidate fields";
            let default = { value; origin; candidate_type; candidate_shape; native_shape; mapping;
              change = T.change candidate_shape native_shape; native_nominals = nominals ();
              available; selected; restriction; occurrences = [occurrence] } in
            defaults := !defaults @ [default]
        | _ -> invalid_arg "native defaults repeat an ambiguous current version"
      ) abstract
    ) branch.events;
    { target = branch.target; defaults = !defaults }) protocol.branches in
  { branches }

let replay component projection inputs expression forward protocol wiring witness =
  try derive component projection inputs expression forward protocol wiring = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring =
  let witness = derive component projection inputs expression forward protocol wiring in
  if not (replay component projection inputs expression forward protocol wiring witness) then
    invalid_arg "the complete actual immediate-version default witness did not replay";
  witness

let lean_origin = function
  | B.Borrow identity -> ".borrow " ^ B.nat (V.BorrowId.to_int identity)
  | B.Symbolic identity -> ".symbolic " ^ B.nat (V.SymbolicValueId.to_int identity)
let rec lean_plan = function
  | Keep -> ".keep" | Skip -> ".skip" | Empty -> ".empty"
  | Product (left, right) -> ".product (" ^ lean_plan left ^ ") (" ^ lean_plan right ^ ")"
  | Sum (left, right) -> ".sum (" ^ lean_plan left ^ ") (" ^ lean_plan right ^ ")"
  | Named body -> ".named (" ^ lean_plan body ^ ")" | Borrow body -> ".borrow (" ^ lean_plan body ^ ")"
let rec lean_restriction = function
  | Whole plan -> ".whole (" ^ lean_plan plan ^ ")"
  | Discard plan -> ".discard (" ^ lean_plan plan ^ ")"
  | REmpty -> ".empty"
  | RProduct (left, right) -> ".product (" ^ lean_restriction left ^ ") (" ^ lean_restriction right ^ ")"
  | RSum (left, right) -> ".sum (" ^ lean_restriction left ^ ") (" ^ lean_restriction right ^ ")"
  | RNamed body -> ".named (" ^ lean_restriction body ^ ")" | RBorrow body -> ".borrow (" ^ lean_restriction body ^ ")"
let fuel witness =
  1 + List.fold_left (fun n branch -> List.fold_left (fun n default ->
    max n (max (C.shape_depth default.candidate_shape) (C.shape_depth default.native_shape))) n branch.defaults) 0 witness.branches

let report component projection inputs expression forward protocol wiring witness =
  if not (replay component projection inputs expression forward protocol wiring witness) then
    invalid_arg "native default report requires the complete actual source witness";
  `Assoc ["schema", `String "actual-native-immediate-current-defaults/v1";
    "actual_immediate_default_sources_replay", `Bool true; "metadata_fuel", `Int (fuel witness);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "defaults", `List (List.map (fun default -> `Assoc [
        "given_back_symbol", `Int (V.SymbolicValueId.to_int default.value.sv_id);
        "immediate_current_source", `String (lean_origin default.origin);
        "complete_candidate_type", `String (P.reflect default.candidate_type);
        "complete_native_type", `String (P.reflect default.value.sv_ty);
        "candidate_shape", `String (P.lean default.candidate_shape);
        "actual_instantiated_native_shape", `String (P.lean default.native_shape);
        "exact_region_mapping", `String (T.lean_mapping default.mapping);
        "available_immediate_current_view", `String (C.selection default.available);
        "selected_given_back_view", `String (C.selection default.selected);
        "structural_view_restriction", `String (lean_restriction default.restriction);
        "native_nominal_requirements", `List (List.map (fun (nominal : P.nominal) -> `Assoc [
          "reference", `String (P.reflect (TAdt nominal.reference));
          "requirements", `String (show_generic_params nominal.inherited_requirements)]) default.native_nominals);
        "actual_occurrences", `List (List.map (fun occurrence -> `Assoc [
          "abstraction", `Int (V.AbsId.to_int occurrence.abstraction); "group", `Int (RegionGroupId.to_int occurrence.group);
          "level", `Int occurrence.level; "event", `Int occurrence.event]) default.occurrences)]) branch.defaults)]) witness.branches);
    "defaults_install_actual_results_automatically", `Bool false;
    "native_parent_continuation_calls_lowered", `Bool false;
    "complete_native_backward_abi_lowered", `Bool false;
    "native_source_heap_loan_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeBorrowDefaults";
  line "/- Actual immediate current-version default expressions; unelaborated/unqualified.";
  line "   Defaults do not execute native calls or create given-back results. -/";
  line "namespace Auths.Qualification.NativeBorrowDefaults";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport Auths.Support.BorrowViewRestriction Auths.Support.NativeBorrowDefaults";
  line "universe u";
  List.iter (fun branch -> List.iter (fun default ->
    let name = "branch" ^ B.gid branch.target ^ "Symbol" ^ B.sid default.value.sv_id in
    line ("def " ^ name ^ "CandidateShape : Shape := " ^ P.lean default.candidate_shape);
    line ("def " ^ name ^ "NativeShape : Shape := " ^ P.lean default.native_shape);
    line ("def " ^ name ^ "Change : Change " ^ name ^ "CandidateShape " ^ name ^ "NativeShape := " ^ T.lean_change default.change);
    line ("def " ^ name ^ "Mapping : List (Nat × Nat) := " ^ T.lean_mapping default.mapping);
    line ("theorem " ^ name ^ "_exact_native_fields : validMap " ^ name ^ "Mapping && metadataMatch " ^ name ^ "Mapping " ^ B.nat (fuel witness) ^ " " ^ name ^ "Change = true := by rfl");
    line ("theorem " ^ name ^ "_exact_complete_native_type : renameExpr " ^ name ^ "Mapping " ^ B.nat (fuel witness) ^ " (" ^ P.reflect default.candidate_type ^ ") = some (" ^ P.reflect default.value.sv_ty ^ ") := by rfl");
    line ("def " ^ name ^ "Available : Plan " ^ name ^ "CandidateShape := " ^ lean_plan (selection_plan default.candidate_shape default.available));
    line ("def " ^ name ^ "Selected : Plan " ^ name ^ "CandidateShape := " ^ lean_plan (selection_plan default.candidate_shape default.selected));
    line ("def " ^ name ^ "Restriction : Restriction " ^ name ^ "Available " ^ name ^ "Selected := " ^ lean_restriction default.restriction);
    line ("def " ^ name ^ " : Recipe := { target := " ^ B.sid default.value.sv_id ^ ", source := " ^ lean_origin default.origin ^
      ", candidateShape := " ^ name ^ "CandidateShape, nativeShape := " ^ name ^ "NativeShape, transport := " ^ name ^ "Change, available := " ^ name ^
      "Available, selected := " ^ name ^ "Selected, restriction := " ^ name ^ "Restriction }");
    line ("theorem " ^ name ^ "_requires_immediate_current (Atom : Expr → Type u) (current : Current Atom)");
    line ("    (missing : current (" ^ lean_origin default.origin ^ ") = none) : evaluate " ^ name ^ " current = none :=");
    line "  missing_immediate_source_is_refused _ _ missing";
    line ("theorem " ^ name ^ "_reads_exact_current (Atom : Expr → Type u) (current : Current Atom) (value : View Atom " ^ name ^ "Available)");
    line ("    (present : current (" ^ lean_origin default.origin ^ ") = some ⟨" ^ name ^ "CandidateShape, " ^ name ^ "Available, value⟩) :");
    line ("    evaluate " ^ name ^ " current = some (forwardView " ^ name ^ "Change " ^ name ^ "Selected (restrict " ^ name ^ "Restriction value)) := exact_current_source_is_transported _ _ _ present");
    line ("theorem " ^ name ^ "_restriction_matches_source_view (Atom : Expr → Type u) (value : Data Atom " ^ name ^ "CandidateShape) :");
    line ("    restrict " ^ name ^ "Restriction (get " ^ name ^ "Available value) = get " ^ name ^ "Selected value := restriction_matches_extraction _ _");
    line ("theorem " ^ name ^ "_record_actual_preserves_other_versions (Atom : Expr → Type u) (current : Current Atom)");
    line ("    (actual : View Atom " ^ name ^ ".nativePlan) (key : Key) (different : key ≠ .symbolic " ^ B.sid default.value.sv_id ^ ") :");
    line ("    recordCurrent " ^ name ^ " current actual key = current key := recording_preserves_other_versions _ _ _ _ different");
    (match default.origin with B.Borrow _ -> () | B.Symbolic source ->
      match List.filter (fun parent -> parent.value.sv_id = source) branch.defaults with
      | [] -> ()
      | [parent] ->
          let parent = "branch" ^ B.gid branch.target ^ "Symbol" ^ B.sid parent.value.sv_id in
          line ("theorem " ^ name ^ "_default_reads_recorded_immediate_parent (Atom : Expr → Type u) (current : Current Atom)");
          line ("    (actualParent : View Atom " ^ parent ^ ".nativePlan) :");
          line ("    evaluate " ^ name ^ " (recordCurrent " ^ parent ^ " current actualParent) =");
          line ("      some (forwardView " ^ name ^ "Change " ^ name ^ "Selected (restrict " ^ name ^ "Restriction");
          line ("        (backwardView " ^ parent ^ "Change " ^ parent ^ "Selected actualParent))) := by");
          line ("  have present : (recordCurrent " ^ parent ^ " current actualParent) (" ^ lean_origin default.origin ^ ") =");
          line ("      some ⟨" ^ name ^ "CandidateShape, " ^ name ^ "Available, backwardView " ^ parent ^ "Change " ^ parent ^ "Selected actualParent⟩ := by");
          line ("    simp [recordCurrent, " ^ parent ^ "]");
          line "  exact exact_current_source_is_transported _ _ _ present"
      | _ -> invalid_arg "a concrete default chain has an ambiguous immediate current parent")
  ) branch.defaults) witness.branches;
  line "end Auths.Qualification.NativeBorrowDefaults";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
