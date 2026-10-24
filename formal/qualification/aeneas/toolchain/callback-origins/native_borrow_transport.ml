(* Native fields are expanded from actual declarations/arguments, independently
   of the candidate-shape renaming. Existing opaque atoms must be unchanged. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module B = Native_borrow_protocol
module F = Native_capture_value
module W = Native_borrow_wiring
module C = Native_borrow_view

type change = Atom of ty | Empty | Unit | Product of change * change | Sum of change * change
  | Named of P.label * P.label * change | Borrow of ref_kind * region * region * change
type port = {
  candidate : C.port;
  source_shape : P.shape;
  native_shape : P.shape;
  mapping : (region * region) list;
  native_selection : C.selection;
  native_nominals : P.nominal list;
  change : change;
}
type branch = { target : region_group_id; ports : port list }
type t = { branches : branch list }

let rename_region mapping = function
  | RVar (Free _) as region ->
      (match List.assoc_opt region mapping with Some target -> target
       | None -> invalid_arg "native value transport has an unmapped candidate free region")
  | (RStatic | RVar (Bound _)) as region -> region
  | RBody _ | RErased -> invalid_arg "native value transport cannot guess body or erased region correspondence"

let type_mapper mapping = object inherit [_] map_ty
  method! visit_region _ region = rename_region mapping region
end

let label mapping = function
  | P.Nominal reference ->
      let visitor = type_mapper mapping in
      P.Nominal (visitor#visit_type_decl_ref () reference)
  | original -> original

let rec rename_shape mapping = function
  | P.Atom sort ->
      let visitor = type_mapper mapping in
      if visitor#visit_ty () sort <> sort then
        invalid_arg "renaming changes an opaque atom's complete type; an explicit reviewed atom adapter is required";
      P.Atom sort
  | P.Empty -> P.Empty | P.Unit -> P.Unit
  | P.Product (left, right) -> P.Product (rename_shape mapping left, rename_shape mapping right)
  | P.Sum (left, right) -> P.Sum (rename_shape mapping left, rename_shape mapping right)
  | P.Named (identity, contents) -> P.Named (label mapping identity, rename_shape mapping contents)
  | P.Borrow (kind, region, contents) -> P.Borrow (kind, rename_region mapping region, rename_shape mapping contents)

let rec change source target = match source, target with
  | P.Atom source, P.Atom target when source = target -> Atom source
  | P.Empty, P.Empty -> Empty | P.Unit, P.Unit -> Unit
  | P.Product (sl, sr), P.Product (tl, tr) -> Product (change sl tl, change sr tr)
  | P.Sum (sl, sr), P.Sum (tl, tr) -> Sum (change sl tl, change sr tr)
  | P.Named (source, sl), P.Named (target, tl) -> Named (source, target, change sl tl)
  | P.Borrow (source_kind, source, sl), P.Borrow (target_kind, target, tl) when source_kind = target_kind ->
      Borrow (source_kind, source, target, change sl tl)
  | _ -> invalid_arg "native data transport changed an atom, constructor, reference kind or field/sum structure"

let validate (candidate : C.schema) (port : port) =
  if port.source_shape <> candidate.shape || port.native_shape <> rename_shape port.mapping candidate.shape ||
      port.change <> change port.source_shape port.native_shape then
    invalid_arg "native data transport lost its actual candidate shape, exact renaming or structural value isomorphism";
  let visitor = type_mapper port.mapping in
  if visitor#visit_ty () candidate.candidate_type <> port.candidate.native.value.sv_ty then
    invalid_arg "native data transport does not reconstruct its actual complete native port type";
  let expected_selection = match candidate.selection with C.Whole -> C.Whole
    | C.Regions regions -> C.Regions (List.map (rename_region port.mapping) regions) in
  if expected_selection <> port.native_selection then
    invalid_arg "native data transport changed its actual selected region view"

let derive component (projection : P.t) inputs expression forward protocol wiring (views : C.t) =
  if not (C.replay component projection inputs expression forward protocol wiring views) then
    invalid_arg "native field/value transport requires the complete actual candidate view witness";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native transport expansion context contains unresolved errors";
  let branches = List.map (fun (branch : C.branch) ->
    let ports = List.map (fun (candidate : C.port) ->
      let schema = List.nth branch.schemas candidate.schema in
      let instance = candidate.type_instance in
      if List.length instance.candidate_arguments <> List.length instance.native_arguments then
        invalid_arg "native transport region correspondence changed its actual arity";
      let mapping = List.combine instance.candidate_arguments instance.native_arguments in
      let sources = List.map fst mapping and targets = List.map snd mapping in
      if List.length sources <> List.length (List.sort_uniq compare sources) ||
          List.length targets <> List.length (List.sort_uniq compare targets) then
        invalid_arg "native value transport must retain its actual injective region correspondence";
      let parameters = List.map (function RVar (Free index) ->
        { index; name = None; variance = Invariant; mutability = LtUnknown }
        | _ -> invalid_arg "native field expression scope needs actual free region names") instance.native_arguments in
      let expand, nominals = P.make_expander component ~span:projection.candidate.item_meta.span
        ~type_infos:context.type_ctx.type_infos ~parameters in
      let native_shape = expand candidate.native.value.sv_ty in
      let renamed = rename_shape mapping schema.shape in
      if native_shape <> renamed then
        invalid_arg "actual instantiated native fields differ from the complete region-renamed candidate fields";
      let native_selection = match schema.selection with C.Whole -> C.Whole
        | C.Regions regions -> C.Regions (List.map (rename_region mapping) regions) in
      let port = { candidate; source_shape = schema.shape; native_shape; mapping; native_selection;
        native_nominals = nominals (); change = change schema.shape native_shape } in
      validate schema port; port) (branch.inputs @ branch.outputs) in
    { target = branch.target; ports }) views.branches in
  { branches }

let replay component projection inputs expression forward protocol wiring views witness =
  try derive component projection inputs expression forward protocol wiring views = witness with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring views =
  let witness = derive component projection inputs expression forward protocol wiring views in
  if not (replay component projection inputs expression forward protocol wiring views witness) then
    invalid_arg "the complete actual native field/value transport did not replay";
  witness

let rec lean_change = function
  | Atom sort -> ".atom (" ^ P.reflect sort ^ ")" | Empty -> ".empty" | Unit -> ".unit"
  | Product (left, right) -> ".product (" ^ lean_change left ^ ") (" ^ lean_change right ^ ")"
  | Sum (left, right) -> ".sum (" ^ lean_change left ^ ") (" ^ lean_change right ^ ")"
  | Named (_, _, contents) -> ".named (" ^ lean_change contents ^ ")"
  | Borrow (kind, _, _, contents) -> ".borrow " ^ (if kind = RMut then "true" else "false") ^ " (" ^ lean_change contents ^ ")"

let lean_mapping mapping = B.list (fun (source, target) -> match source, target with
  | RVar (Free source), RVar (Free target) -> "(" ^ B.nat (RegionId.to_int source) ^ ", " ^ B.nat (RegionId.to_int target) ^ ")"
  | _ -> invalid_arg "a native transport map contains unsupported region scopes") mapping

let fuel witness =
  1 + List.fold_left (fun n branch -> List.fold_left (fun n port ->
    max n (max (C.shape_depth port.source_shape) (C.shape_depth port.native_shape))) n branch.ports) 0 witness.branches

let report component projection inputs expression forward protocol wiring views witness =
  if not (replay component projection inputs expression forward protocol wiring views witness) then
    invalid_arg "native transport report requires its complete actual-source witness";
  `Assoc ["schema", `String "actual-native-field-value-transport/v1";
    "actual_native_field_value_transport_replays", `Bool true; "metadata_fuel", `Int (fuel witness);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "ports", `List (List.map (fun port -> `Assoc [
        "native_symbol", `Int (V.SymbolicValueId.to_int port.candidate.native.value.sv_id);
        "level", `Int port.candidate.native.level; "mapping", `String (lean_mapping port.mapping);
        "candidate_shape", `String (P.lean port.source_shape); "actual_instantiated_native_shape", `String (P.lean port.native_shape);
        "native_selection", `String (C.selection port.native_selection);
        "structural_transport", `String (lean_change port.change);
        "retained_native_nominal_requirements", `List (List.map (fun (nominal : P.nominal) -> `Assoc [
          "reference", `String (P.reflect (TAdt nominal.reference));
          "instantiated_kind", `String (show_type_decl_kind nominal.instantiated_kind);
          "requirements", `String (show_generic_params nominal.inherited_requirements)]) port.native_nominals)]) branch.ports)]) witness.branches);
    "opaque_atom_types_must_be_unchanged", `Bool true;
    "original_rust_native_projection_region_heap_loan_validity_proved", `Bool false;
    "parent_default_values_lowered", `Bool false; "complete_native_backward_abi_lowered", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let output = Buffer.create 32768 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.BorrowTransport";
  line "import qualification.aeneas.cases.NativeBorrowView";
  line "/- Actual native field shapes and pure-data value/view transports; unelaborated/unqualified.";
  line "   Native projection/lifetime/heap/loan validity, parent defaults and full ABI remain required. -/";
  line "namespace Auths.Qualification.NativeBorrowTransport";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.BorrowTransport";
  line "universe u";
  List.iter (fun branch -> List.iteri (fun index port ->
    let name = "branch" ^ B.gid branch.target ^ "Port" ^ B.nat index in
    let candidate = "Auths.Qualification.NativeBorrowView.branch" ^ B.gid branch.target ^ "Schema" ^ B.nat port.candidate.schema in
    line ("def " ^ name ^ "NativeShape : Shape := " ^ P.lean port.native_shape);
    line ("def " ^ name ^ "Mapping : List (Nat × Nat) := " ^ lean_mapping port.mapping);
    line ("def " ^ name ^ "Change : Change " ^ candidate ^ ".shape " ^ name ^ "NativeShape := " ^ lean_change port.change);
    line ("theorem " ^ name ^ "_metadata_is_exact : validMap " ^ name ^ "Mapping && metadataMatch " ^ name ^ "Mapping " ^ B.nat (fuel witness) ^ " " ^ name ^ "Change = true := by");
    line "  rfl";
    let native_plan = match port.native_selection with C.Whole -> ".keep"
      | C.Regions regions -> "Auths.Support.BorrowProjection.select " ^ B.list Return_region_certificate.lean_region regions ^ " " ^ name ^ "NativeShape" in
    line ("def " ^ name ^ "NativePlan : Plan " ^ name ^ "NativeShape := " ^ native_plan);
    line ("theorem " ^ name ^ "_selected_plan_matches_native : mapPlan " ^ name ^ "Change " ^ candidate ^ ".plan = " ^ name ^ "NativePlan := by"); line "  rfl";
    line ("def " ^ name ^ "ToNative (Atom : Expr → Type u) (value : " ^ candidate ^ ".Payload Atom) : View Atom " ^ name ^ "NativePlan :=");
    line ("  forwardView " ^ name ^ "Change " ^ candidate ^ ".plan value");
    line ("def " ^ name ^ "FromNative (Atom : Expr → Type u) (value : View Atom " ^ name ^ "NativePlan) : " ^ candidate ^ ".Payload Atom :=");
    line ("  backwardView " ^ name ^ "Change " ^ candidate ^ ".plan value");
    line ("theorem " ^ name ^ "_candidate_round_trip (Atom : Expr → Type u) (value : " ^ candidate ^ ".Payload Atom) :");
    line ("    " ^ name ^ "FromNative Atom (" ^ name ^ "ToNative Atom value) = value := by");
    line ("  simp [" ^ name ^ "FromNative, " ^ name ^ "ToNative, view_forward_inverse]");
    line ("theorem " ^ name ^ "_native_round_trip (Atom : Expr → Type u) (value : View Atom " ^ name ^ "NativePlan) :");
    line ("    " ^ name ^ "ToNative Atom (" ^ name ^ "FromNative Atom value) = value := by");
    line ("  simp [" ^ name ^ "FromNative, " ^ name ^ "ToNative, view_inverse_forward]");
    line ("theorem " ^ name ^ "_extraction_commutes (Atom : Expr → Type u) (value : Data Atom " ^ candidate ^ ".shape) :");
    line ("    " ^ name ^ "ToNative Atom (get " ^ candidate ^ ".plan value) =");
    line ("      get " ^ name ^ "NativePlan (forward " ^ name ^ "Change value) := by");
    line ("  simpa [" ^ name ^ "ToNative, ← " ^ name ^ "_selected_plan_matches_native] using extraction_commutes " ^ name ^ "Change " ^ candidate ^ ".plan value");
    line ("theorem " ^ name ^ "_restoration_commutes (Atom : Expr → Type u) (before : Data Atom " ^ candidate ^ ".shape)");
    line ("    (update : " ^ candidate ^ ".Payload Atom) :");
    line ("    put " ^ name ^ "NativePlan (forward " ^ name ^ "Change before) (" ^ name ^ "ToNative Atom update) =");
    line ("      (put " ^ candidate ^ ".plan before update).map (forward " ^ name ^ "Change) := by");
    line ("  simpa [" ^ name ^ "ToNative, ← " ^ name ^ "_selected_plan_matches_native] using restoration_commutes " ^ name ^ "Change " ^ candidate ^ ".plan before update")
  ) branch.ports) witness.branches;
  line "end Auths.Qualification.NativeBorrowTransport";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
