(* Proposed projections from declared native arguments retain exact current
   versions. Static source origins never prove value correspondence. Every
   installation requires its own source-ending proof; overlapping projections
   also retain an explicit joint representability obligation. *)
open Charon
open Types
module V = Aeneas.Values
module P = Borrow_projection
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module D = Native_borrow_defaults
module R = Native_root_origins
module C = Native_root_payload
module G = Current_borrow_carrier
module J = Native_projector_levels
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module H = Native_payload_layout
module X = Native_root_expressions
module N = Native_type_syntax

type projection = { native_type : Q.ty; layout : H.layout; codec : H.codec;
  native : Q.texpr; term : X.term }
type binding = { port : R.port; producer : D.default; slot : C.slot; focus : G.focus; projection : projection }
type action = Bind of binding | Consume of R.port | Foreign of R.port
type overlap = { first : binding; second : binding }
type context_root = { abstract : J.root; continuation : J.root; abstract_ports : J.port list; continuation_ports : J.port list }
type nested_return = { given : J.port; consumed : J.port; root : int; prior_event : int; prior_root : int; prior_abstraction : V.abs_id; prior_consumed : J.port }
type ending = { event : W.event; roots : context_root list; nested_returns : nested_return list }
type branch = { target : region_group_id; actions : action list; overlaps : overlap list; endings : ending list }
type t = { payload : C.t; defaults : D.t; branches : branch list }

let rec projection_field codec focus = match codec, focus with
  | H.CProduct (first, _), G.First next -> projection_field first next
  | H.CProduct (_, second), G.Second next -> projection_field second next
  | H.CField (index, _, body), G.Named next -> index, body, next
  | _ -> invalid_arg "a native root projection must retain the exact source product/field path"

let structure_fields environment native =
  match List.filter (fun (schema : H.schema) -> schema.native_type = native) environment.H.schemas with
  | first :: rest when List.for_all (fun (other : H.schema) -> other.native_kind = first.native_kind) rest ->
      (match first.native_kind with Q.Struct fields -> fields
       | Q.Enum _ -> invalid_arg "a variant-dependent native argument projection requires an explicit branch/continuation"
       | Q.Opaque -> invalid_arg "opaque fields cannot supply a native argument projection")
  | _ -> invalid_arg "a native argument projection lost its full original instantiated field schema"

(* Compile a projection from one complete, already-declared root carrier.
   This constructor never binds a source symbol or asserts that a caller
   argument represents a particular post-ending version. *)
let compile_projection span environment root target focus =
  let argument : Q.fvar = { id = Q.FVarId.of_int 0; basename = None; ty = root.C.native_type } in
  let result : Q.fvar = { id = Q.FVarId.of_int 1; basename = None; ty = target } in
  let rec pattern native codec focus = match codec, focus with
    | _, G.Here ->
        if native <> target then invalid_arg "a root projection changed the selected complete native type";
        U.mk_tpat_from_fvar None result
    | H.CBorrow (_, _, body), G.Borrow next | H.CBoxed body, G.Named next -> pattern native body next
    | H.CNominal (_, owner, body), G.Named next when owner = native ->
        let index, body, next = projection_field body next in
        let fields = structure_fields environment native in
        if index < 0 || index >= List.length fields then invalid_arg "a native argument projection has no actual declared field";
        U.mk_adt_pat native None (List.mapi (fun position (declaration : Q.field) ->
          if position = index then pattern declaration.field_ty body next else U.mk_ignored_pat declaration.field_ty) fields)
    | _ -> invalid_arg "a native argument projection cannot erase a source wrapper or guess a field/variant" in
  let selected = pattern root.native_type root.codec focus in
  let body = U.mk_closed_let span false selected (U.mk_texpr_from_fvar argument) (U.mk_texpr_from_fvar result) in
  let native = U.mk_closed_lambdas span [U.mk_tpat_from_fvar None argument] body in
  if native.ty <> U.mk_arrows [root.native_type] target then invalid_arg "a native projection changed its complete original argument/result types";
  native, X.reflect native

let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults =
  if not (C.replay component projection inputs symbolic forward protocol wiring levels signature origins payload) ||
      not (D.replay component projection inputs symbolic forward protocol wiring defaults) then
    invalid_arg "whole native given-value binding requires every source field, signature slot, origin and exact immediate producer";
  let source = B.backward_expressions symbolic in
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native argument projection context has unresolved diagnostics";
  let span = projection.P.candidate.item_meta.span in
  let branches = List.map (fun (branch : R.branch) ->
    let actual_defaults = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) defaults.D.branches with
      | [actual] -> actual.defaults | _ -> invalid_arg "a whole-root binding lost its actual default/provenance branch" in
    let wiring_branch = match List.filter (fun (actual : W.branch) -> actual.target = branch.target) wiring.W.branches with
      | [actual] -> actual | _ -> invalid_arg "a source-version context lost its original ending branch" in
    let actual = match RegionGroupId.Map.find_opt branch.target source with
      | Some expression -> fst (B.ending_abstractions expression)
      | None -> invalid_arg "a source-version context has no actual source backward expression" in
    if List.length actual <> List.length wiring_branch.events then
      invalid_arg "a source-version context cannot omit an actual ending";
    let endings = List.map2 (fun ((abs : V.abs), level) (event : W.event) ->
      let input, group = match abs.kind with V.SynthInput group -> true, group | V.SynthRet group -> false, group
        | _ -> invalid_arg "a source-version context needs the original abstraction kind" in
      if abs.abs_id <> event.abstraction || level <> event.level || input <> event.input || group <> event.group then
        invalid_arg "a source-version context changed its exact actual ending occurrence";
      let roots = List.map (fun ((abstract : J.root), (continuation : J.root)) ->
        let abstract_ports = J.select level abstract.level abstract.path abstract.tree in
        let continuation_ports = J.select level continuation.level continuation.path continuation.tree in
        let check (root : J.root) path actual =
          let expected = List.filter (fun (port : W.port) -> J.prefix root.path (path port)) event.ports |>
            List.map (fun (port : W.port) -> { J.value = J.sym port.value; given_back = port.given_back;
              level = port.level; path = path port }) in
          if actual <> expected then
            invalid_arg "a complete source-version projector context changed an original typed selected port" in
        check abstract (fun (port : W.port) -> port.abstract_path) abstract_ports;
        check continuation (fun (port : W.port) -> port.continuation_path) continuation_ports;
        { abstract; continuation; abstract_ports; continuation_ports }) (J.roots abs) in
      { event; roots; nested_returns = [] }) actual wiring_branch.events in
    let endings = List.mapi (fun event_index ending ->
      let rec headers root_index level path (tree : J.tree) =
        let descend tag values = List.concat (List.mapi (fun index (_, child) ->
          headers root_index (level + 1) (path @ [tag index]) child) values) in
        match tree.node with
        | J.Empty -> []
        | J.Loan (_, _, consumed, borrows) ->
            descend (fun index -> W.Consumed index) consumed @ descend (fun index -> W.BorrowReprojection index) borrows
        | J.Borrow (_, given, loans) ->
            let self = match given with
              | Some value when level = ending.event.level && loans <> [] ->
                  let given : J.port = { value; given_back = true; level; path } in
                  let inner = List.init (J.depth tree - 1) (fun offset ->
                    J.select (level + offset + 1) level path tree) |> List.concat |>
                    List.filter (fun (port : J.port) -> not port.given_back) in
                  List.map (fun consumed ->
                    let prior = List.mapi (fun index (earlier : ending) -> index, earlier) endings |>
                      List.filter (fun (index, earlier) -> index < event_index &&
                        earlier.event.abstraction = ending.event.abstraction) |>
                      List.concat_map (fun (index, earlier) -> List.concat (List.mapi (fun prior_root root ->
                        List.filter (fun actual -> actual = consumed) root.abstract_ports |> List.map (fun actual ->
                          index, prior_root, earlier.event.abstraction, actual)) earlier.roots)) in
                    match prior with
                    | [prior_event, prior_root, prior_abstraction, prior_consumed] ->
                        { given; consumed; root = root_index; prior_event; prior_root; prior_abstraction; prior_consumed }
                    | _ -> invalid_arg "a nested return needs one exact earlier same-abstraction consumed current version") inner
              | _ -> [] in
            self @ descend (fun index -> W.LoanReprojection index) loans in
      let nested_returns = List.concat (List.mapi (fun index root ->
        headers index root.abstract.level root.abstract.path root.abstract.tree) ending.roots) in
      { ending with nested_returns }) endings in
    let actions = List.map (fun (port : R.port) ->
      if port.original.group <> branch.target then Foreign port
      else if not port.original.given_back then Consume port
      else
        let producer = match List.filter (fun (actual : D.default) -> actual.value.sv_id = port.original.value.sv_id) actual_defaults with
          | [actual] -> actual | _ -> invalid_arg "an own given-value binding needs its exact actual metadata producer" in
        if producer.candidate_shape <> port.alias.source.shape || producer.candidate_type <> port.alias.source.source_type ||
            not (List.exists (fun (occurrence : D.occurrence) -> occurrence.event = port.event &&
              occurrence.abstraction = port.original.abstraction && occurrence.group = branch.target &&
              occurrence.level = port.original.level) producer.occurrences) then
          invalid_arg "an own given-value binding changed its original source shape/type or defining event";
        let source_root = if port.original.level = 0 then None else Some port.alias.input in
        let slot = match List.filter (fun (slot : C.slot) -> slot.group = branch.target && slot.input &&
          slot.level = port.original.level && slot.root.source.index = source_root) payload.C.slots with
          | [slot] -> slot | _ -> invalid_arg "an own given value has no unique already-declared original native root argument" in
        let focus = match source_root with None -> port.output_focus | Some _ -> port.alias.focus in
        if G.target slot.root.source.shape focus <> producer.candidate_shape then
          invalid_arg "an own given-value argument projection changed complete original source fields";
        let native_type = S.translate_fwd_ty (Some span) context producer.candidate_type in
        if S.translate_fwd_ty (Some span) context port.original.value.sv_ty <> native_type then
          invalid_arg "a native argument projection changed its exact selected source/native type";
        let layout = H.expand payload.environment [] native_type in
        let codec = H.codec context span payload.environment producer.candidate_shape layout in
        let native, term = compile_projection span payload.environment slot.root native_type focus in
        Bind { port; producer; slot; focus; projection = { native_type; layout; codec; native; term } }) branch.ports in
    let bindings = List.filter_map (function Bind binding -> Some binding | _ -> None) actions in
    let identities = List.map (fun binding -> binding.port.original.value.sv_id) bindings in
    if List.length (List.sort_uniq compare identities) <> List.length identities then
      invalid_arg "an own source version cannot be installed from two ending occurrences";
    let rec pairs = function
      | [] -> []
      | first :: rest ->
          List.filter_map (fun second ->
            if first.slot = second.slot && G.lean_disjoint first.focus second.focus = None
            then Some { first; second } else None) rest @ pairs rest in
    { target = branch.target; actions; overlaps = pairs bindings; endings }) origins.R.branches in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native argument projection produced unresolved diagnostics";
  { payload; defaults; branches }

let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature origins payload defaults =
  let witness = derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults in
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults witness) then
    invalid_arg "own given-back projections from complete native root arguments did not replay";
  witness

let port = function Bind binding -> binding.port | Consume port | Foreign port -> port
let kind = function Bind _ -> "proposedProjectionRequiresSourceVersionCorrespondence" | Consume _ -> "consumeCurrent" | Foreign _ -> "foreignContinuationRequired"
let name branch binding = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat binding.port.event ^ "Port" ^ B.nat binding.port.position
let selected binding = D.lean_plan (D.selection_plan binding.producer.candidate_shape binding.producer.selected)

let lean_channel binding =
  "{ target := " ^ B.sid binding.port.original.value.sv_id ^ ", immediate := " ^ D.lean_origin binding.producer.origin ^
  ", group := " ^ B.gid binding.port.original.group ^ ", event := " ^ B.nat binding.port.event ^
  ", level := " ^ B.nat binding.port.original.level ^ ", position := " ^ B.nat binding.port.position ^ " }"
let rec lean_path = function
  | G.Here -> [] | G.First next -> ".first" :: lean_path next | G.Second next -> ".second" :: lean_path next
  | G.Named next -> ".named" :: lean_path next | G.Borrow next -> ".borrow" :: lean_path next
let lean_request binding =
  "{ channel := " ^ lean_channel binding ^ ", slot := { group := " ^ B.gid binding.slot.group ^
  ", level := " ^ B.nat binding.slot.level ^ ", position := " ^ B.nat binding.slot.position ^
  " }, path := " ^ B.list (fun x -> x) (lean_path binding.focus) ^ " }"

let lean_source_symbol (value : J.symbol) =
  "{ identity := " ^ B.sid value.identity ^ ", type := " ^ P.reflect value.source_type ^ " }"
let rec lean_source_tree (tree : J.tree) =
  let pairs values = B.list (fun (symbol, child) -> "(" ^ lean_source_symbol symbol ^ ", " ^ lean_source_tree child ^ ")") values in
  let annotation = "(" ^ P.reflect tree.annotation ^ ")" in
  match tree.node with
  | J.Empty -> ".empty " ^ annotation
  | J.Loan (ended, original, consumed, borrows) -> ".loan " ^ annotation ^ " " ^ B.bool ended ^ " " ^ lean_source_symbol original ^
      " " ^ pairs consumed ^ " " ^ pairs borrows
  | J.Borrow (original, given, loans) -> ".borrow " ^ annotation ^ " " ^ lean_source_symbol original ^ " (" ^
      (match given with None -> "none" | Some symbol -> "some " ^ lean_source_symbol symbol) ^ ") " ^ pairs loans
let lean_projector_port (port : J.port) = "{ symbol := " ^ lean_source_symbol port.value ^ ", givenBack := " ^ B.bool port.given_back ^
  ", level := " ^ B.nat port.level ^ ", path := " ^ J.lean_path port.path ^ " }"

let lean_nested_return event abstraction receipt =
  "{ event := " ^ B.nat event ^ ", priorEvent := " ^ B.nat receipt.prior_event ^
  ", abstraction := " ^ B.aid abstraction ^ ", priorAbstraction := " ^ B.aid receipt.prior_abstraction ^
  ", given := " ^ lean_projector_port receipt.given ^ ", consumed := " ^ lean_projector_port receipt.consumed ^
  ", priorConsumed := " ^ lean_projector_port receipt.prior_consumed ^ " }"

let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults witness) then
    invalid_arg "whole-root binding report lost an original input/producer/port/native argument";
  `Assoc ["schema", `String "proposed-native-whole-argument-version-correspondence/v2";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "original_ending_projector_contexts", `List (List.mapi (fun index ending -> `Assoc [
        "event", `Int index; "abstraction", `Int (V.AbsId.to_int ending.event.abstraction);
        "group", `Int (RegionGroupId.to_int ending.event.group); "input", `Bool ending.event.input;
        "level", `Int ending.event.level;
        "nested_current_return_dependencies", `List (List.map (fun receipt -> `Assoc [
          "given", `String (lean_projector_port receipt.given);
          "nested_consumed", `String (lean_projector_port receipt.consumed);
          "original_projector_root", `Int receipt.root;
          "prior_event", `Int receipt.prior_event; "prior_projector_root", `Int receipt.prior_root;
          "prior_same_abstraction", `Int (V.AbsId.to_int receipt.prior_abstraction);
          "exact_prior_consumed", `String (lean_projector_port receipt.prior_consumed);
          "payload_value_equality_inferred", `Bool false]) ending.nested_returns);
        "every_projector_root", `List (List.map (fun root -> `Assoc [
          "original_abstract_path", `String (J.lean_path root.abstract.path);
          "original_continuation_path", `String (J.lean_path root.continuation.path);
          "root_level", `Int root.abstract.level;
          "complete_abstract_tree", `String (lean_source_tree root.abstract.tree);
          "complete_continuation_tree", `String (lean_source_tree root.continuation.tree);
          "exact_abstract_selected_ports", `List (List.map (fun port -> `String (lean_projector_port port)) root.abstract_ports);
          "exact_continuation_selected_ports", `List (List.map (fun port -> `String (lean_projector_port port)) root.continuation_ports)]) ending.roots)]) branch.endings);
      "every_original_port", `List (List.map (fun action ->
        let original = port action in
        `Assoc (["event", `Int original.event; "position", `Int original.position; "kind", `String (kind action);
          "original_port", `String (W.lean_port original.original)] @ match action with
          | Bind binding -> ["declared_native_argument_level", `Int binding.slot.level;
              "declared_native_argument_position", `Int binding.slot.position;
              "original_source_root", `String (C.root_name binding.slot.root);
              "proposed_argument_focus", `String (G.lean_focus binding.focus);
              "complete_native_argument_projection", `String (Q.show_texpr binding.projection.native);
              "reflected_closed_argument_projection", `String (X.lean binding.projection.term);
              "complete_selected_native_type", `String (Q.show_ty binding.projection.native_type);
              "selected_source_view", `String (selected binding);
              "immediate_current_producer", `String (D.lean_origin binding.producer.origin);
              "exact_source_version_channel", `String (lean_channel binding);
              "source_ending_value_correspondence_required", `Bool true;
              "source_ending_value_correspondence_proved", `Bool false]
          | _ -> [])) branch.actions);
      "overlapping_distinct_versions_proposed_for_one_argument", `List (List.map (fun overlap -> `Assoc [
        "first_channel", `String (lean_channel overlap.first);
        "second_channel", `String (lean_channel overlap.second);
        "first_focus", `String (G.lean_focus overlap.first.focus);
        "second_focus", `String (G.lean_focus overlap.second.focus);
        "same_immediate_current_producer", `Bool (overlap.first.producer.origin = overlap.second.producer.origin);
        "identical_complete_native_projection", `Bool (overlap.first.projection.term = overlap.second.projection.term);
        "source_reachability_forces_shared_projection_values_equal_proved", `Bool false;
        "joint_source_value_representability_proved", `Bool false]) branch.overlaps)]) witness.branches);
    "own_internal_given_values_retain_declared_argument_candidates", `Bool true;
    "own_internal_given_values_value_correspondence_proved", `Bool false;
    "complete_AV_EV_projector_trees_retained_before_execution_lowering", `Bool true;
    "every_selected_projector_port_matches_original_wiring", `Bool true;
    "nested_returns_link_original_current_and_prior_projector_contexts", `Bool true;
    "nested_return_dependency_used_as_payload_value_equality", `Bool false;
    "static_origins_used_to_assert_current_value_equality", `Bool false;
    "closed_native_argument_projections_constructed", `Bool true;
    "projection_results_implicitly_installed_as_fresh_source_values", `Bool false;
    "source_version_correspondence_proofs_automatically_supplied", `Bool false;
    "new_standalone_port_arguments_added", `Bool false;
    "old_default_or_ordinary_function_result_supplied", `Bool false;
    "argument_sharing_is_only_proposed_and_requires_separate_version_proofs", `Bool true;
    "foreign_parent_continuation_execution_implemented", `Bool false;
    "complete_native_ending_expression_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

(* Every constructor case retains arbitrary atom contents. This is proof
   generation over the complete logical carrier, not a fixture evaluator or
   source heap/loan witness. Sum branches remain separate and exhaustive. *)
let rec emit_data_cases line indent name shape finish =
  let constructor constructor arguments =
    line (indent ^ "cases " ^ name ^ " with");
    line (indent ^ "| " ^ constructor ^ (if arguments = [] then "" else " " ^ String.concat " " arguments) ^ " =>") in
  let inside = indent ^ "    " in
  match shape with
  | P.Empty -> line (indent ^ "cases " ^ name)
  | P.Unit -> constructor "unit" []; finish inside
  | P.Atom _ -> constructor "atom" [name ^ "Atom"]; finish inside
  | P.Named (_, body) -> constructor "named" [name ^ "Body"];
      emit_data_cases line inside (name ^ "Body") body finish
  | P.Borrow (_, _, body) -> constructor "borrow" [name ^ "Body"];
      emit_data_cases line inside (name ^ "Body") body finish
  | P.Product (first, second) -> constructor "product" [name ^ "First"; name ^ "Second"];
      emit_data_cases line inside (name ^ "First") first (fun indent ->
        emit_data_cases line indent (name ^ "Second") second finish)
  | P.Sum (first, second) ->
      line (indent ^ "cases " ^ name ^ " with");
      line (indent ^ "| left " ^ name ^ "Left =>");
      emit_data_cases line inside (name ^ "Left") first finish;
      line (indent ^ "| right " ^ name ^ "Right =>");
      emit_data_cases line inside (name ^ "Right") second finish

let write_lean path witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  let payload = "Auths.Qualification.NativeRootPayload." in
  let origin = "Auths.Qualification.NativeRootOrigins." in
  line "import Auths.Support.NativeRootBindings";
  line "import Auths.Support.NativeRootExpressions";
  line "import qualification.aeneas.cases.NativeRootPayload";
  line "/- Proposed whole-argument projections. Every version correspondence remains an explicit premise.";
  line "   No source-ending/heap/loan proof or closed native execution is supplied. Unelaborated/unqualified. -/";
  line "namespace Auths.Qualification.NativeRootBindings";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeRootPayload";
  line "open Auths.Support.NativeRootBindings Auths.Support.CurrentBorrowCarrier";
  line "universe u";
  let current_type = "Auths.Support.NativeBorrowDefaults.Current (SourceAtom " ^ payload ^ "atomTyping Atom)" in
  List.iter (fun branch ->
    List.iteri (fun event ending -> List.iteri (fun index root ->
      let name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "Projector" ^ B.nat index in
      line ("def " ^ name ^ " : SourceProjector := " ^ lean_source_tree root.abstract.tree);
      line ("def " ^ name ^ "Continuation : SourceProjector := " ^ lean_source_tree root.continuation.tree);
      line ("theorem " ^ name ^ "_retains_complete_AV_EV_context : " ^ name ^ " = " ^ name ^ "Continuation := by rfl");
      let selection suffix (native : J.root) ports =
        line ("def " ^ name ^ suffix ^ "Ports : List ProjectorPort := " ^ B.list lean_projector_port ports);
        line ("theorem " ^ name ^ suffix ^ "_selects_exact_original_current_versions :");
        line ("    selectSourcePorts " ^ B.nat (J.depth native.tree) ^ " " ^ B.nat ending.event.level ^ " " ^ B.nat native.level ^
          " " ^ J.lean_path native.path ^ " " ^ name ^ (if suffix = "Continuation" then "Continuation" else "") ^
          " = some " ^ name ^ suffix ^ "Ports := by decide") in
      selection "" root.abstract root.abstract_ports;
      selection "Continuation" root.continuation root.continuation_ports
    ) ending.roots;
      List.iteri (fun index receipt ->
        let name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "NestedReturn" ^ B.nat index in
        line ("def " ^ name ^ " : NestedReturn := " ^ lean_nested_return event ending.event.abstraction receipt);
        line ("theorem " ^ name ^ "_retains_exact_prior_nested_return : validNestedReturn " ^ name ^ " = true := by decide");
        let root = (List.nth ending.roots receipt.root).abstract in
        let root_name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "Projector" ^ B.nat receipt.root in
        let prior_name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat receipt.prior_event ^ "Projector" ^ B.nat receipt.prior_root in
        line ("theorem " ^ name ^ "_given_is_in_original_outer_context : " ^ name ^ ".given ∈ " ^ root_name ^ "Ports := by decide");
        line ("theorem " ^ name ^ "_nested_current_version_is_in_original_tree :");
        line ("    " ^ name ^ ".consumed ∈ (selectSourcePorts " ^ B.nat (J.depth root.tree) ^ " " ^ B.nat receipt.consumed.level ^ " " ^ B.nat root.level ^
          " " ^ J.lean_path root.path ^ " " ^ root_name ^ ").getD [] := by decide");
        line ("theorem " ^ name ^ "_was_consumed_by_original_earlier_context : " ^ name ^ ".priorConsumed ∈ " ^ prior_name ^ "Ports := by decide")
      ) ending.nested_returns
    ) branch.endings;
    let bindings = List.filter_map (function Bind binding -> Some binding | _ -> None) branch.actions in
    List.iter (fun binding ->
      let name = name branch binding in
      let root = payload ^ C.root_name binding.slot.root in
      let shape = origin ^ name ^ "Shape" in
      line ("def " ^ name ^ "Channel : Channel := " ^ lean_channel binding);
      line ("def " ^ name ^ "Request : Request := " ^ lean_request binding);
      line ("def " ^ name ^ "Focus : Focus " ^ root ^ "Shape " ^ shape ^ " := " ^ G.lean_focus binding.focus);
      line ("def " ^ name ^ "Selected : Plan " ^ shape ^ " := " ^ selected binding);
      let projected = binding.projection in
      let fuel = 64 + 8 * max (X.depth projected.term) (max (C.depth binding.slot.root.layout) (C.depth projected.layout)) in
      line ("def " ^ name ^ "NativeProjection : Auths.Support.NativeRootExpressions.Term := " ^ X.lean projected.term);
      line ("def " ^ name ^ "NativeLayout : Layout := " ^ C.lean_layout projected.layout);
      line ("def " ^ name ^ "NativeCodec : Codec " ^ payload ^ "atomTyping " ^ shape ^ " " ^ name ^ "NativeLayout := " ^ C.lean_codec projected.codec);
      line ("theorem " ^ name ^ "_native_projection_is_closed_and_completely_typed :");
      line ("    Auths.Support.NativeRootExpressions.check " ^ payload ^ "schemas " ^ B.nat fuel ^ " [] " ^ name ^ "NativeProjection = true := by decide");
      line ("theorem " ^ name ^ "_native_projection_refines_complete_source_carrier (Atom : NativeType → Type u)");
      line ("    (argument : Data (SourceAtom " ^ payload ^ "atomTyping Atom) " ^ root ^ "Shape) :");
      line ("    Auths.Support.NativeRootExpressions.executeValues " ^ payload ^ "schemas " ^ B.nat fuel ^ " " ^ name ^ "NativeProjection");
      line ("      [Auths.Support.NativeRootExpressions.pack " ^ B.nat fuel ^ " (encode " ^ root ^ "Codec argument)] =");
      line ("    Auths.Support.NativeRootExpressions.pack " ^ B.nat fuel ^ " (encode " ^ name ^ "NativeCodec (read " ^ name ^ "Focus argument)) := by");
      emit_data_cases line "  " "argument" binding.slot.root.source.shape (fun indent -> line (indent ^ "rfl"));
      line ("theorem " ^ name ^ "_native_projection_uses_actual_complete_argument (Atom : NativeType → Type u)");
      line ("    (argument : Value Atom " ^ root ^ "Layout) :");
      line ("    Auths.Support.NativeRootExpressions.executeValues " ^ payload ^ "schemas " ^ B.nat fuel ^ " " ^ name ^ "NativeProjection");
      line ("      [Auths.Support.NativeRootExpressions.pack " ^ B.nat fuel ^ " argument] =");
      line ("    Auths.Support.NativeRootExpressions.pack " ^ B.nat fuel ^ " (encode " ^ name ^ "NativeCodec (read " ^ name ^ "Focus (decode " ^ root ^ "Codec argument))) := by");
      line ("  simpa only [encode_decode] using " ^ name ^ "_native_projection_refines_complete_source_carrier Atom (decode " ^ root ^ "Codec argument)");
      line ("def " ^ name ^ "Corresponds (Atom : NativeType → Type u)");
      line ("    (sourceAfter : " ^ current_type ^ ") (argument : Value Atom " ^ root ^ "Layout) : Prop :=");
      line ("  Represents " ^ root ^ "Codec " ^ name ^ "Focus " ^ name ^ "Selected " ^ name ^ "Channel sourceAfter argument");
      line ("def " ^ name ^ "Install (Atom : NativeType → Type u)");
      line ("    (current sourceAfter : " ^ current_type ^ ") (argument : Value Atom " ^ root ^ "Layout)");
      line ("    (agrees : " ^ name ^ "Corresponds Atom sourceAfter argument) : " ^ current_type ^ " :=");
      line ("  install " ^ root ^ "Codec " ^ name ^ "Focus " ^ name ^ "Selected " ^ name ^ "Channel current sourceAfter argument agrees");
      line ("theorem " ^ name ^ "_conditionally_refines_its_exact_source_version (Atom : NativeType → Type u)");
      line ("    (current sourceAfter : " ^ current_type ^ ") (argument : Value Atom " ^ root ^ "Layout)");
      line ("    (agrees : " ^ name ^ "Corresponds Atom sourceAfter argument) :");
      line ("    Auths.Support.NativeBorrowDefaults.readCurrent (" ^ name ^ "Install Atom current sourceAfter argument agrees)");
      line ("      (.symbolic " ^ name ^ "Channel.target) " ^ shape ^ " " ^ name ^ "Selected =");
      line ("    Auths.Support.NativeBorrowDefaults.readCurrent sourceAfter (.symbolic " ^ name ^ "Channel.target) " ^ shape ^ " " ^ name ^ "Selected :=");
      line ("  installation_refines_exact_source_version _ _ _ _ _ _ _ agrees");
      line ("theorem " ^ name ^ "_uses_declared_candidate_native_input_slot :");
      line ("    ((Auths.Qualification.NativeBackwardTypes.group" ^ B.gid branch.target ^ "Inputs.find? (fun row => row.1 == " ^ B.nat binding.slot.level ^ ")).bind");
      line ("      (fun row => row.2[" ^ B.nat binding.slot.position ^ "]?)) = some " ^ root ^ "NativeType := by rfl")
    ) bindings;
    List.iteri (fun index overlap ->
      let prefix = "branch" ^ B.gid branch.target ^ "Overlap" ^ B.nat index in
      let first = name branch overlap.first and second = name branch overlap.second in
      line ("theorem " ^ prefix ^ "_retains_distinct_current_versions : " ^ first ^ "Channel.target ≠ " ^ second ^ "Channel.target := by decide");
      line ("theorem " ^ prefix ^ "_requires_joint_correspondence : requiresJointCorrespondence " ^ first ^ "Request " ^ second ^ "Request = true := by decide");
      if overlap.first.projection.term = overlap.second.projection.term then (
        line ("theorem " ^ prefix ^ "_has_one_identical_complete_native_projection :");
        line ("    " ^ first ^ "NativeProjection = " ^ second ^ "NativeProjection := by rfl");
        line ("theorem " ^ prefix ^ "_one_projection_cannot_return_two_distinct_versions (Atom : NativeType → Type u)");
        line "    (fuel : Nat) (argument left right : Auths.Support.NativeRootExpressions.Dynamic Atom)";
        line ("    (one : Auths.Support.NativeRootExpressions.execute " ^ payload ^ "schemas fuel " ^ first ^ "NativeProjection [argument] = some left)");
        line ("    (two : Auths.Support.NativeRootExpressions.execute " ^ payload ^ "schemas fuel " ^ second ^ "NativeProjection [argument] = some right) : left = right := by");
        line ("  rw [← " ^ prefix ^ "_has_one_identical_complete_native_projection] at two");
        line "  exact Option.some.inj (one.symm.trans two)"
      )
    ) branch.overlaps;
    List.iter (fun event ->
      let event_bindings = List.filter (fun binding -> binding.port.event = event) bindings in
      let slots = List.map (fun binding -> binding.slot) event_bindings |> List.sort_uniq compare in
      let argument slot = "argumentLevel" ^ B.nat slot.C.level ^ "Position" ^ B.nat slot.position in
      let event_name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "InstallWhenRepresented" in
      line ("def " ^ event_name ^ " (Atom : NativeType → Type u)");
      line ("    (current sourceAfter : " ^ current_type ^ ")");
      List.iter (fun slot -> line ("    (" ^ argument slot ^ " : Value Atom " ^ payload ^ C.root_name slot.C.root ^ "Layout)")) slots;
      List.iter (fun binding -> let name = name branch binding in
        line ("    (" ^ name ^ "Agrees : " ^ name ^ "Corresponds Atom sourceAfter " ^ argument binding.slot ^ ")")) event_bindings;
      line ("    : " ^ current_type ^ " :=");
      let expression = List.fold_left (fun current binding -> let name = name branch binding in
        name ^ "Install Atom (" ^ current ^ ") sourceAfter " ^ argument binding.slot ^ " " ^ name ^ "Agrees") "current" event_bindings in
      line ("  " ^ expression)
    ) (List.map (fun binding -> binding.port.event) bindings |> List.sort_uniq Int.compare)
  ) witness.branches;
  line "end Auths.Qualification.NativeRootBindings";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
