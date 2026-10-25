(* Invoke the actual backend level API, including its new checked finite
   nested-field path. Compare the complete field tree with the existing
   independent source projection, and retain disagreements with symbolic ports.
   No original complete signature, missing event or ordinary result is supplied. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.SymbolicToPureBorrowLevels
module P = Borrow_projection
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module R = Return_region_certificate

type root = { index : int option; source : ty; native : Q.tree; shape : P.shape; native_shape : P.shape }
type count = { group : region_group_id; roots : (root * int) list; maximum : int;
  symbolic_maximum : int; owned_levels : int list; external_levels : int list; internal_levels : int list }
type t = { mapping : (region * region_group_id) list; roots : root list; counts : count list }

let rec shape (tree : Q.tree) = match tree.node with
  | Q.Atom -> P.Atom tree.source
  | Q.Shared (region, child) -> P.Borrow (RShared, region, shape child)
  | Q.Mutable (region, child) -> P.Borrow (RMut, region, shape child)
  | Q.Box child -> P.Named (P.Boxed, shape child)
  | Q.Tuple fields -> P.product (List.mapi (fun index child -> P.Named (P.Field (index, None), shape child)) fields)
  | Q.Nominal (reference, _, rows) ->
      let fields row = P.product (List.map (fun (index, name, child) -> P.Named (P.Field (index, name), shape child)) row.Q.fields) in
      let body = match rows with
        | [{ Q.variant = None; _ } as row] -> fields row
        | rows -> P.sum (List.map (fun (row : Q.row) -> match row.variant with
          | Some identity -> P.Named (P.Variant identity, fields row)
          | None -> invalid_arg "a native nested-field tree mixed structural and enum rows") rows) in
      P.Named (P.Nominal reference, body)
let rec depth tree = 1 + List.fold_left (fun size child -> max size (depth child)) 0 (Q.children tree)

let derive component (projection : P.t) inputs symbolic forward protocol (wiring : W.t) =
  if not (W.replay component projection inputs symbolic forward protocol wiring) then
    invalid_arg "actual native borrow levels require the complete original projection, forward trace, scope and port witness";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native nested-level analysis has unresolved context errors";
  let span = Some projection.candidate.item_meta.span in
  let mapping = List.concat_map (fun (group : region_var_group) -> List.map (fun id -> RVar (Free id), group.id) group.regions) projection.hierarchy in
  if List.length mapping <> List.length (List.sort_uniq (fun (one, _) (two, _) -> Stdlib.compare one two) mapping) then
    invalid_arg "native nested-level analysis cannot merge ambiguous original region groups";
  let get_group region = match List.assoc_opt region mapping with Some group -> group
    | None -> invalid_arg "native nested-level analysis cannot infer an erased, static or escaped group" in
  let roots = List.map (fun ((index, source, expected) : int option * ty * P.shape) ->
    let native = Q.describe span context source in
    let actual = shape native in
    if actual <> expected then invalid_arg "actual native nested fields differ from the complete independently expanded source shape";
    { index; source; native; shape = expected; native_shape = actual })
    (List.map (fun (root : P.root) -> Some root.index, root.source_type, root.shape) projection.inputs @
      [None, projection.output.source_type, projection.output.shape]) in
  let counts = List.map (fun (group : region_var_group) ->
    let roots = List.map (fun root ->
      let tree, exact = Q.compute span context get_group group.id root.source in
      if tree <> root.native then invalid_arg "the actual nested-level invocation changed its complete source field tree";
      let native = Aeneas.SymbolicToPureTypes.compute_back_ty_num_levels span context get_group group.id root.source in
      if native <> exact then invalid_arg "the actual backend level API differs from its checked source field traversal";
      root, native) roots in
    let maximum = List.fold_left (fun result (_, count) -> max result count) 0 roots in
    let native_maximum = Aeneas.SymbolicToPureTypes.compute_back_tys_num_levels span context get_group group.id
      projection.candidate.signature.inputs projection.candidate.signature.output in
    if maximum <> native_maximum then invalid_arg "the actual complete-signature level count omitted a source root";
    let branch = match List.filter (fun (branch : W.branch) -> branch.target = group.id) wiring.branches with
      | [branch] -> branch | _ -> invalid_arg "native nested-level analysis lost its actual symbolic branch" in
    let own_events = List.filter (fun (event : W.event) -> event.group = group.id) branch.events in
    let symbolic_maximum = 1 + List.fold_left (fun level (event : W.event) -> max level event.level) 0 own_events in
    let levels ports = List.map (fun (port : W.port) -> port.level) ports |> List.sort_uniq Int.compare in
    let owned_levels = levels (List.concat_map (fun (event : W.event) -> event.ports) own_events) in
    let external_levels = levels (branch.inputs @ branch.outputs) in
    let internal_levels = levels (List.concat_map (fun (link : W.internal) -> [link.producer; link.consumer]) branch.internal) in
    (* Preserve any mismatch. Do not erase an actual type path or invent an
       absent symbolic event merely to keep the previous interface shape. *)
    { group = group.id; roots; maximum; symbolic_maximum; owned_levels; external_levels; internal_levels }) projection.hierarchy in
  { mapping; roots; counts }
let replay component projection inputs symbolic forward protocol wiring witness =
  try derive component projection inputs symbolic forward protocol wiring = witness
  with Invalid_argument _ | Not_found | Q.Unsupported _ -> false
let create component projection inputs symbolic forward protocol wiring =
  let witness = derive component projection inputs symbolic forward protocol wiring in
  if not (replay component projection inputs symbolic forward protocol wiring witness) then
    invalid_arg "actual native nested-level tree and API counts did not replay";
  witness

let get_group witness region = match List.assoc_opt region witness.mapping with Some group -> group
  | None -> invalid_arg "native level reflection lost its exact source group"
let text value = R.numbers (List.init (String.length value) (fun index -> Char.code value.[index]))
let rec lean_tree witness (tree : Q.tree) =
  let source = "(" ^ P.reflect tree.source ^ ")" in
  match tree.node with
  | Q.Atom -> ".atom " ^ source
  | Q.Shared (region, child) -> ".shared " ^ source ^ " (" ^ R.lean_region region ^ ") (" ^ lean_tree witness child ^ ")"
  | Q.Mutable (region, child) -> ".mutable " ^ source ^ " (" ^ R.lean_region region ^ ") " ^ B.gid (get_group witness region) ^ " (" ^ lean_tree witness child ^ ")"
  | Q.Box child -> ".boxed " ^ source ^ " (" ^ lean_tree witness child ^ ")"
  | Q.Tuple fields -> ".tuple " ^ source ^ " [" ^ String.concat ", " (List.map (lean_tree witness) fields) ^ "]"
  | Q.Nominal (_, requirements, rows) ->
      let row (row : Q.row) = "(" ^ (match row.variant with None -> "none" | Some id -> "some " ^ string_of_int (VariantId.to_int id)) ^
        ", [" ^ String.concat ", " (List.map (fun (index, name, child) -> "(" ^ string_of_int index ^ ", " ^ Native_pure_expressions.text name ^ ", " ^ lean_tree witness child ^ ")") row.fields) ^ "])" in
      ".nominal " ^ source ^ " " ^ text (show_generic_params requirements) ^ " [" ^ String.concat ", " (List.map row rows) ^ "]"
let root_name root = match root.index with None -> "output" | Some index -> "input" ^ string_of_int index
let lean_mapping mapping = "[" ^ String.concat ", " (List.map (fun (region, group) -> "(" ^ R.lean_region region ^ ", " ^ B.gid group ^ ")") mapping) ^ "]"

let report component projection inputs symbolic forward protocol wiring witness =
  if not (replay component projection inputs symbolic forward protocol wiring witness) then
    invalid_arg "native nested-level report lost its complete source/API witness";
  `Assoc ["schema", `String "actual-native-complete-instantiated-borrow-levels/v1";
    "mapping", `String (lean_mapping witness.mapping);
    "roots", `List (List.map (fun root -> `Assoc ["name", `String (root_name root);
      "complete_tree", `String (lean_tree witness root.native); "tree_depth", `Int (depth root.native);
      "complete_native_and_independent_source_fields_agree", `Bool (root.native_shape = root.shape)]) witness.roots);
    "groups", `List (List.map (fun count -> `Assoc ["group", `Int (RegionGroupId.to_int count.group);
      "per_root_counts", `List (List.map (fun (root, levels) -> `Assoc ["root", `String (root_name root); "actual_native_levels", `Int levels]) count.roots);
      "actual_signature_level_maximum", `Int count.maximum;
      "actual_symbolic_event_level_maximum", `Int count.symbolic_maximum;
      "actual_owned_port_levels", `List (List.map (fun level -> `Int level) count.owned_levels);
      "actual_external_port_levels", `List (List.map (fun level -> `Int level) count.external_levels);
      "actual_internal_channel_levels", `List (List.map (fun level -> `Int level) count.internal_levels);
      "native_counts_equal_preceding_symbolic_maximum", `Bool (count.maximum = count.symbolic_maximum)]) witness.counts);
    "actual_original_native_level_api_invoked", `Bool true;
    "static_analysis_requires_dynamic_execution_assumptions", `Bool false;
    "complete_original_signature_fabricated_or_claimed", `Bool false;
    "unsupported_nested_types_receive_guessed_counts", `Bool false;
    "forward_declaration_expression_loan_dispatch_guards_removed", `Bool false;
    "original_rust_source_loan_lifetime_effect_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 196608 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeBorrowLevels";
  line "/- Actual checked native finite source field levels, unelaborated/unqualified.";
  line "   Original complete signature, symbolic event adequacy and Rust loan/source obligations remain. -/";
  line "namespace Auths.Qualification.NativeBorrowLevels";
  line "open Auths.Support.SourceClosureRegions Auths.Support.NativeBorrowLevels";
  line ("def mapping : List (Region × Nat) := " ^ lean_mapping witness.mapping);
  List.iter (fun root ->
    let name = root_name root in
    line ("def " ^ name ^ " : Tree := " ^ lean_tree witness root.native);
    line ("def " ^ name ^ "Fuel : Nat := " ^ string_of_int (depth root.native + 1));
    line ("theorem " ^ name ^ "_all_mutable_regions_have_actual_groups : regionsMatch " ^ name ^ "Fuel mapping " ^ name ^ " = true := by decide")
  ) witness.roots;
  List.iter (fun count ->
    let name = "group" ^ B.gid count.group in
    List.iter (fun (root, levels) ->
      line ("theorem " ^ name ^ "_" ^ root_name root ^ "_matches_actual_native_level_api : checked " ^ root_name root ^ "Fuel mapping " ^ B.gid count.group ^ " " ^ root_name root ^ " = some " ^ string_of_int levels ^ " := by decide")
    ) count.roots;
    line ("def " ^ name ^ "NativeMaximum : Nat := " ^ string_of_int count.maximum);
    line ("def " ^ name ^ "ObservedSymbolicMaximum : Nat := " ^ string_of_int count.symbolic_maximum);
    line ("def " ^ name ^ "OwnedLevels : List Nat := [" ^ String.concat ", " (List.map string_of_int count.owned_levels) ^ "]");
    line ("def " ^ name ^ "ExternalLevels : List Nat := [" ^ String.concat ", " (List.map string_of_int count.external_levels) ^ "]");
    line ("def " ^ name ^ "InternalLevels : List Nat := [" ^ String.concat ", " (List.map string_of_int count.internal_levels) ^ "]");
    line ("theorem " ^ name ^ "_records_actual_level_comparison : (" ^ name ^ "NativeMaximum == " ^ name ^ "ObservedSymbolicMaximum) = " ^ B.bool (count.maximum = count.symbolic_maximum) ^ " := by decide")
  ) witness.counts;
  line "end Auths.Qualification.NativeBorrowLevels";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
