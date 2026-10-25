(* Actual selected-level native classification and original source port bridge.
   No runtime payload, default, region assignment or synthetic event is supplied. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicToPureValues
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module P = Borrow_projection

type selection = { path : W.edge list; current_level : int; source_type : ty; projector : V.aproj;
  selected : (ty * V.ended_proj_borrow_meta) list;
  expected : W.port list; agrees : bool }
let rec path_prefix prefix path = match prefix, path with
  | [], _ -> true
  | first :: rest, actual :: remaining when first = actual -> path_prefix rest remaining
  | _ -> false

(* The selector is the actual library operation used by pattern materialization.
   Expected ports come from the independent complete source-event roster, scoped
   by the exact AV path, never from a default or supplied runtime payload. *)
let given_back_selections span selected root (source : V.tavalue) ports =
  let rec visit current path (source : V.tavalue) =
    let child value = visit current (path @ [W.Child]) value in
    let ended child_value given = child child_value @
      visit (current + 1) (path @ [W.GivenBack]) given in
    match source.value with
    | V.ASymbolic (marker, projector) ->
        B.marker marker;
        let selected = S.select_projector_given_backs span selected current projector source.ty in
        let expected = List.filter (fun (port : W.port) ->
          port.given_back && path_prefix path port.abstract_path) ports in
        let actual = List.map (fun (_, (meta : V.ended_proj_borrow_meta)) -> meta.given_back) selected in
        let agrees = actual = List.map (fun (port : W.port) -> port.value) expected in
        [{path; current_level = current; source_type = source.ty; projector; selected; expected; agrees}]
    | V.AAdt aggregate -> List.concat (List.mapi (fun index field ->
        visit current (path @ [W.Field index]) field) aggregate.fields)
    | V.ALoan (V.AMutLoan (_, _, value) | V.AIgnoredMutLoan (_, value))
    | V.ABorrow (V.AMutBorrow (_, _, value) | V.AIgnoredMutBorrow (_, value)
        | V.AEndedMutBorrow (_, value)) -> child value
    | V.ALoan (V.AEndedMutLoan value) -> ended value.child value.given_back
    | V.ALoan (V.AEndedIgnoredMutLoan value) -> ended value.child value.given_back
    | V.ABorrow (V.AEndedIgnoredMutBorrow value) -> ended value.child value.given_back
    | _ -> []
  in visit 0 [W.Root root] source

type value = { index : int; source : V.tavalue;
  observations : S.projector_kind_observation list; kind : S.proj_kind; ports : W.port list;
  nested_type : bool; observations_agree : bool; ports_agree : bool; selections : selection list }
type ending = { event : W.event; owned_regions : region_id list; values : value list; roster_agrees : bool }
type branch = { target : region_group_id; endings : ending list }
type t = { branches : branch list }

let ports_agree kind ports = match kind with
  | S.BorrowProj S.BMut -> List.for_all (fun (port : W.port) -> port.given_back) ports
  | S.LoanProj S.BMut -> List.for_all (fun (port : W.port) -> not port.given_back) ports
  | _ -> ports = []

let derive component projection inputs symbolic forward protocol wiring =
  if not (W.replay component projection inputs symbolic forward protocol wiring) then
    invalid_arg "projector classification requires the complete actual source event/port roster";
  let context = Aeneas.Interp.compute_contexts component in
  let expressions = B.backward_expressions symbolic in
  let branches = List.map (fun (branch : W.branch) ->
    let actual = match RegionGroupId.Map.find_opt branch.target expressions with
      | Some body -> fst (B.ending_abstractions body)
      | None -> invalid_arg "projector classification lost an original backward branch" in
    if List.length actual <> List.length branch.events then
      invalid_arg "projector classification omitted an original ending";
    let endings = List.map2 (fun ((abstraction : V.abs), level) (event : W.event) ->
      if abstraction.abs_id <> event.abstraction || level <> event.level then
        invalid_arg "projector classification changed actual ending identity/order/level";
      let values = List.mapi (fun index (source : V.tavalue) ->
        let kind, observations = S.observe_tavalue_proj_kind projection.P.candidate.item_meta.span
          context.type_ctx.type_infos abstraction.regions.owned level 0 source in
        let classified = S.classify_projector_kind_observations projection.P.candidate.item_meta.span level observations in
        if kind <> S.compute_tavalue_proj_kind projection.P.candidate.item_meta.span context.type_ctx.type_infos
          abstraction.regions.owned level 0 source then
          invalid_arg "observing a classifier changed the actual native result";
        let observations_agree = classified = kind in
        let ports = List.filter (fun (port : W.port) -> match port.abstract_path with
          | W.Root actual :: _ -> actual = index | _ -> false) event.ports in
        let nested_type = (Aeneas.TypesAnalysis.analyze_ty (Some projection.P.candidate.item_meta.span)
          context.type_ctx.type_infos source.ty).contains_nested_mut in
        let selections = given_back_selections projection.P.candidate.item_meta.span level index source ports in
        { index; source; observations; kind; ports; nested_type; observations_agree; selections;
          ports_agree = ports_agree kind ports }) abstraction.avalues in
      let roster_agrees = List.concat_map (fun value -> value.ports) values = event.ports in
      { event; owned_regions = RegionId.Set.elements abstraction.regions.owned; values; roster_agrees }) actual branch.events in
    { target = branch.target; endings }) wiring.W.branches in
  if !Aeneas.Errors.error_list <> [] then
    invalid_arg "native projector classification has unresolved original diagnostics";
  { branches }
let admitted witness = List.for_all (fun branch -> List.for_all (fun ending ->
  ending.roster_agrees && List.for_all (fun value -> value.observations_agree && value.ports_agree && List.for_all (fun selection -> selection.agrees) value.selections) ending.values) branch.endings) witness.branches
let require_admitted witness =
  List.iter (fun branch -> List.iteri (fun event ending ->
    if not ending.roster_agrees then invalid_arg (Printf.sprintf
      "native projector classification changed the complete source port roster: target=%d event=%d abstraction=%d"
      (RegionGroupId.to_int branch.target) event (V.AbsId.to_int ending.event.abstraction));
    List.iter (fun value ->
    if not value.observations_agree || not value.ports_agree || not (List.for_all (fun selection -> selection.agrees) value.selections) then
      invalid_arg (Printf.sprintf
        "native projector classification mismatch: target=%d event=%d abstraction=%d source_group=%d selected_level=%d root=%d kind=%s nested_type=%b observations_agree=%b ports_agree=%b ports=%d"
        (RegionGroupId.to_int branch.target) event (V.AbsId.to_int ending.event.abstraction)
        (RegionGroupId.to_int ending.event.group) ending.event.level value.index
        (S.show_proj_kind value.kind) value.nested_type value.observations_agree value.ports_agree (List.length value.ports))
  ) ending.values) branch.endings) witness.branches
let analyze = derive
let create component projection inputs symbolic forward protocol wiring =
  let witness = derive component projection inputs symbolic forward protocol wiring in
  require_admitted witness; witness
let replay component projection inputs symbolic forward protocol wiring witness =
  try create component projection inputs symbolic forward protocol wiring = witness
  with Invalid_argument _ | Not_found -> false

let lean_kind = function
  | S.UnknownProj -> ".unknown"
  | S.BorrowProj kind -> ".borrow " ^ B.bool (kind = S.BMut)
  | S.LoanProj kind -> ".loan " ^ B.bool (kind = S.BMut)
let rec source_depth = function
  | Return_region_certificate.Natural _ | Bytes _ | Region _ | OutputSlot _ -> 1
  | Node (_, children) -> 1 + List.fold_left (fun size child -> max size (source_depth child)) 0 children
  | Binder (_, child) -> 1 + source_depth child
let type_shape_fuel observations = 4 + List.fold_left (fun size (value : S.projector_kind_observation) ->
  max size (max (source_depth (Return_region_certificate.reflect_type ~holes:[] value.projector_source_type))
    (source_depth (Return_region_certificate.reflect_type ~holes:[] value.projector_classification_type)))) 0 observations
let lean_observation (value : S.projector_kind_observation) =
  "{ level := " ^ B.nat value.projector_level ^ ", sourceType := " ^ P.reflect value.projector_source_type ^
  ", classificationType := " ^ P.reflect value.projector_classification_type ^
  ", kind := " ^ lean_kind value.projector_kind ^ " }"
let lean_selected (edge_type, (meta : V.ended_proj_borrow_meta)) =
  "{ consumedIdentity := " ^ B.nat (V.SymbolicValueId.to_int meta.consumed) ^
  ", givenIdentity := " ^ B.nat (V.SymbolicValueId.to_int meta.given_back.sv_id) ^
  ", edgeType := " ^ P.reflect edge_type ^ ", currentType := " ^ P.reflect meta.given_back.sv_ty ^ " }"
let rec lean_given_back_tree source_type = function
  | V.AEmpty -> ".empty"
  | V.AProjBorrows node -> ".borrow none " ^ lean_given_back_children node.loans
  | V.AEndedProjBorrows node -> ".borrow (some (" ^ lean_selected (source_type, node.mvalues) ^ ")) " ^ lean_given_back_children node.loans
  | V.AProjLoans node -> ".loan false " ^ lean_given_back_children node.consumed ^ " " ^ lean_given_back_children node.borrows
  | V.AEndedProjLoans node -> ".loan true " ^ lean_given_back_children node.consumed ^ " " ^ lean_given_back_children node.borrows
and lean_given_back_children pairs = B.list (fun ((edge : V.mconsumed_symb), child) ->
  "(" ^ lean_given_back_tree edge.proj_ty child ^ ")") pairs
let rec given_back_tree_fuel = function
  | V.AEmpty -> 1
  | V.AProjBorrows node -> 1 + given_back_children_fuel node.loans
  | V.AEndedProjBorrows node -> 1 + given_back_children_fuel node.loans
  | V.AProjLoans node -> 1 + max (given_back_children_fuel node.consumed) (given_back_children_fuel node.borrows)
  | V.AEndedProjLoans node -> 1 + max (given_back_children_fuel node.consumed) (given_back_children_fuel node.borrows)
and given_back_children_fuel pairs = List.fold_left (fun maximum (_, child) ->
  max maximum (given_back_tree_fuel child)) 0 pairs
let selected_type_fuel headers = 4 + List.fold_left (fun maximum (edge, (meta : V.ended_proj_borrow_meta)) ->
  max maximum (max (source_depth (Return_region_certificate.reflect_type ~holes:[] edge))
    (source_depth (Return_region_certificate.reflect_type ~holes:[] meta.given_back.sv_ty)))) 0 headers
let report witness = `Assoc ["schema", `String "actual-native-selected-projector-kinds/v1";
  "scope", `String "selected source-capture ending AV roots, not the complete shipping closure";
  "actual_backward_branch_count", `Int (List.length witness.branches);
  "actual_ending_count", `Int (List.fold_left (fun count branch -> count + List.length branch.endings) 0 witness.branches);
  "actual_av_root_cell_count", `Int (List.fold_left (fun count branch -> count + List.fold_left
    (fun count ending -> count + List.length ending.values) 0 branch.endings) 0 witness.branches);
  "actual_mutable_port_count", `Int (List.fold_left (fun count branch -> count + List.fold_left
    (fun count ending -> count + List.length ending.event.ports) 0 branch.endings) 0 witness.branches);
  "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
    "endings", `List (List.map (fun ending -> `Assoc ["original_event", `String (W.lean_event ending.event);
      "full_original_port_roster_agrees", `Bool ending.roster_agrees;
      "actual_owned_regions", `List (List.map (fun region -> `Int (RegionId.to_int region)) ending.owned_regions);
      "values", `List (List.map (fun value -> `Assoc ["root_index", `Int value.index;
        "complete_original_av", `String (V.show_tavalue value.source);
        "complete_typed_header_observations", `List (List.map (fun observation -> `String (lean_observation observation)) value.observations);
        "actual_native_kind", `String (lean_kind value.kind);
        "source_root_contains_nested_mutable_type", `Bool value.nested_type;
        "typed_observations_match_native_kind", `Bool value.observations_agree;
        "actual_mutable_port_roster_agrees", `Bool value.ports_agree;
        "actual_projector_given_back_selections", `List (List.map (fun selection -> `Assoc [
          "source_path", `String (B.list W.edge selection.path);
          "actual_projector_root_level", `Int selection.current_level;
          "complete_projector_selection_tree", `String (lean_given_back_tree selection.source_type selection.projector);
          "actual_selected_headers", `List (List.map (fun header -> `String (lean_selected header)) selection.selected);
          "original_source_ports", `List (List.map (fun port -> `String (W.lean_port port)) selection.expected);
          "exact_source_identity_and_type_roster_agrees", `Bool selection.agrees]) value.selections);
        "original_mutable_ports", `List (List.map (fun port -> `String (W.lean_port port)) value.ports)]) ending.values)]) branch.endings)]) witness.branches);
  "all_actual_av_root_cells_admitted", `Bool (admitted witness);
  "original_non_nested_classifier_unchanged", `Bool true;
  "mixed_selected_polarity_refusal_retained", `Bool true;
  "empty_port_roster_can_retain_an_unchanged_container_origin", `Bool true;
  "heap_loan_ending_continuation_or_ABI_adequacy_proved", `Bool false;
  "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path witness =
  require_admitted witness;
  let buffer = Buffer.create 131072 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
  line "import Auths.Support.NativeProjectorKinds";
  line "import qualification.aeneas.cases.NativeBorrowWiring";
  line "namespace Auths.Qualification.NativeProjectorKinds";
  line "open Auths.Support.NativeProjectorKinds Auths.Support.NativeBorrowWiring";
  line "/- Actual source observations and native classifier results; unelaborated/unqualified. -/";
  List.iter (fun branch -> List.iteri (fun event ending -> List.iter (fun value ->
    let name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "Root" ^ B.nat value.index in
    line ("def " ^ name ^ "Observations : List Observation := " ^ B.list lean_observation value.observations);
    line ("def " ^ name ^ "Ports : List Port := " ^ B.list W.lean_port value.ports);
    line ("theorem " ^ name ^ "_retains_complete_edge_and_current_type_shapes :");
    line ("    " ^ name ^ "Observations.all (fun observation => onlyRegionsDiffer " ^ B.nat (type_shape_fuel value.observations) ^
      " observation.sourceType observation.classificationType) = true := by decide");
    line ("theorem " ^ name ^ "_matches_actual_native_classification : classify " ^ B.nat ending.event.level ^
      " " ^ name ^ "Observations = some (" ^ lean_kind value.kind ^ ") := by decide");
    line ("theorem " ^ name ^ "_retains_every_actual_mutable_port : portsAgree (" ^ lean_kind value.kind ^
      ") " ^ name ^ "Ports = true := by decide");
    List.iteri (fun index selection ->
      let selection_name = name ^ "Projector" ^ B.nat index in
      line ("def " ^ selection_name ^ "Selected : List SelectedBorrow := " ^ B.list lean_selected selection.selected);
      line ("def " ^ selection_name ^ "OriginalPorts : List Port := " ^ B.list W.lean_port selection.expected);
      line ("def " ^ selection_name ^ "Tree : GivenBackTree := " ^ lean_given_back_tree selection.source_type selection.projector);
      line ("theorem " ^ selection_name ^ "_native_selector_matches_complete_source_tree :");
      line ("    selectBorrowHeaders " ^ B.nat (given_back_tree_fuel selection.projector + 1) ^ " " ^
        B.nat (selected_type_fuel selection.selected) ^ " " ^ B.nat ending.event.level ^ " " ^
        B.nat selection.current_level ^ " " ^ selection_name ^ "Tree = some " ^
        selection_name ^ "Selected := by decide");

      line ("theorem " ^ selection_name ^ "_selects_exact_original_identities_and_types :");
      line ("    selectedBorrowRoster " ^ selection_name ^ "Selected = givenBackPortRoster " ^
        selection_name ^ "OriginalPorts := by decide")
    ) value.selections
  ) ending.values;
    let event_name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event in
    line ("def " ^ event_name ^ "OwnedRegions : List Nat := " ^ B.list (fun region -> B.nat (RegionId.to_int region)) ending.owned_regions);
    line ("def " ^ event_name ^ "MutablePorts : List Port := (" ^
      B.list (fun value -> event_name ^ "Root" ^ B.nat value.index ^ "Ports") ending.values ^ ").flatten");
    line ("theorem " ^ event_name ^ "_retains_the_exact_original_source_port_roster :");
    line ("    (Auths.Qualification.NativeBorrowWiring.branch" ^ B.gid branch.target ^ ".events[" ^ B.nat event ^ "]?).map (fun event => event.ports) =");
    line ("      some " ^ event_name ^ "MutablePorts := by rfl")
  ) branch.endings) witness.branches;
  line "end Auths.Qualification.NativeProjectorKinds";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
