(* Retain actual typed nested projector trees and consume each selected source
   through the shared native lookup at its actual ending. No wrapper guard,
   full native signature, projected-value reconstruction or callback is faked. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module P = Borrow_projection
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module N = Native_pure_payload
module D = Native_default_bindings

type symbol = { identity : V.symbolic_value_id; source_type : ty }
type tree = { annotation : ty; node : node }
and node = Empty | Loan of bool * symbol * (symbol * tree) list * (symbol * tree) list
  | Borrow of symbol * symbol option * (symbol * tree) list
type root = { path : W.edge list; level : int; tree : tree }
type port = { value : symbol; given_back : bool; level : int; path : W.edge list }
type selected_root = { abstract : root; continuation : root; selected : port list }
type receipt = { given : port; consumed : port; prior_ending : int; read : D.consumed_read }
type ending = { event : W.event; roots : selected_root list; trace : D.ending_trace; receipts : receipt list }
type branch = { target : region_group_id; endings : ending list }
type t = { bindings : D.t; branches : branch list; native_types : (ty * Aeneas.Pure.ty) list }

let sym (value : V.symbolic_value) = { identity = value.sv_id; source_type = value.sv_ty }
let meta (value : V.mconsumed_symb) = { identity = value.sv_id; source_type = value.proj_ty }
let rec abstract_tree annotation projector =
  let pairs values = List.map (fun (source, child) -> meta source, abstract_tree source.V.proj_ty child) values in
  let node = match projector with
    | V.AEmpty -> Empty
    | V.AProjLoans node -> Loan (false, { identity = node.proj.sv_id; source_type = node.proj.proj_ty }, pairs node.consumed, pairs node.borrows)
    | V.AEndedProjLoans node -> Loan (true, { identity = node.proj; source_type = annotation }, pairs node.consumed, pairs node.borrows)
    | V.AProjBorrows node -> Borrow ({ identity = node.proj.sv_id; source_type = node.proj.proj_ty }, None, pairs node.loans)
    | V.AEndedProjBorrows node -> Borrow ({ identity = node.mvalues.consumed; source_type = annotation }, Some (sym node.mvalues.given_back), pairs node.loans) in
  { annotation; node }
let rec continuation_tree annotation projector =
  let pairs values = List.map (fun (source, child) -> meta source, continuation_tree source.V.proj_ty child) values in
  let node = match projector with
    | V.EEmpty -> Empty
    | V.EProjLoans node -> Loan (false, { identity = node.proj.sv_id; source_type = node.proj.proj_ty }, pairs node.consumed, pairs node.borrows)
    | V.EEndedProjLoans node -> Loan (true, { identity = node.proj; source_type = annotation }, pairs node.consumed, pairs node.borrows)
    | V.EProjBorrows node -> Borrow ({ identity = node.proj.sv_id; source_type = node.proj.proj_ty }, None, pairs node.loans)
    | V.EEndedProjBorrows node -> Borrow ({ identity = node.mvalues.consumed; source_type = annotation }, Some (sym node.mvalues.given_back), pairs node.loans) in
  { annotation; node }

let roots (abs : V.abs) =
  let rec abstract level path (value : V.tavalue) = match value.value with
    | V.AIgnored _ -> []
    | V.AAdt aggregate -> List.concat (List.mapi (fun index value -> abstract level (path @ [W.Field index]) value) aggregate.fields)
    | V.ASymbolic (marker, projector) -> B.marker marker; [{ path; level; tree = abstract_tree value.ty projector }]
    | V.ABorrow borrow -> (match borrow with
      | V.AMutBorrow (marker, _, child) -> B.marker marker; abstract level (path @ [W.Child]) child
      | V.AIgnoredMutBorrow (_, child) | V.AEndedMutBorrow (_, child) -> abstract level (path @ [W.Child]) child
      | V.AEndedIgnoredMutBorrow ended -> abstract level (path @ [W.Child]) ended.child @
          abstract (level + 1) (path @ [W.GivenBack]) ended.given_back
      | _ -> invalid_arg "projector roots cannot omit an unsupported shared borrow")
    | V.ALoan loan -> (match loan with
      | V.AMutLoan (marker, _, child) -> B.marker marker; abstract level (path @ [W.Child]) child
      | V.AIgnoredMutLoan (_, child) -> abstract level (path @ [W.Child]) child
      | V.AEndedMutLoan node -> abstract level (path @ [W.Child]) node.child @ abstract (level + 1) (path @ [W.GivenBack]) node.given_back
      | V.AEndedIgnoredMutLoan node -> abstract level (path @ [W.Child]) node.child @ abstract (level + 1) (path @ [W.GivenBack]) node.given_back
      | _ -> invalid_arg "projector roots cannot omit an unsupported shared loan")
  and continuation level path (value : V.tevalue) = match value.value with
    | V.EIgnored _ -> []
    | V.EAdt aggregate -> List.concat (List.mapi (fun index value -> continuation level (path @ [W.Field index]) value) aggregate.fields)
    | V.ESymbolic (marker, projector) -> B.marker marker; [{ path; level; tree = continuation_tree value.ty projector }]
    | V.EMutBorrowInput child -> continuation level (path @ [W.Child]) child
    | V.EApp ((V.EInputAbs _ | V.EOutputAbs _), arguments) ->
      List.concat (List.mapi (fun group values -> List.concat (List.mapi (fun index value ->
        continuation level (path @ [W.Argument (group, index)]) value) values)) arguments)
    | V.EValue _ -> []
    | V.EBorrow borrow -> (match borrow with
      | V.EMutBorrow (marker, _, child) -> B.marker marker; continuation level (path @ [W.Child]) child
      | V.EIgnoredMutBorrow (_, child) | V.EEndedMutBorrow (_, child) -> continuation level (path @ [W.Child]) child
      | V.EEndedIgnoredMutBorrow ended -> continuation level (path @ [W.Child]) ended.child @
          continuation (level + 1) (path @ [W.GivenBack]) ended.given_back)
    | V.ELoan loan -> (match loan with
      | V.EMutLoan (marker, _, child) -> B.marker marker; continuation level (path @ [W.Child]) child
      | V.EIgnoredMutLoan (_, child) -> continuation level (path @ [W.Child]) child
      | V.EEndedMutLoan node -> continuation level (path @ [W.Child]) node.child @ continuation (level + 1) (path @ [W.GivenBack]) node.given_back
      | V.EEndedIgnoredMutLoan node -> continuation level (path @ [W.Child]) node.child @ continuation (level + 1) (path @ [W.GivenBack]) node.given_back)
    | _ -> invalid_arg "projector roots cannot conceal a continuation binder, effect or unknown application" in
  let left = List.concat (List.mapi (fun index value -> abstract 0 [W.Root index] value) abs.avalues) in
  let cont = match abs.cont with Some cont -> cont | None -> invalid_arg "missing actual projector continuation" in
  let right = Option.fold ~none:[] ~some:(continuation 0 [W.ContinuationInput]) cont.input @
    Option.fold ~none:[] ~some:(continuation 0 [W.ContinuationOutput]) cont.output in
  if List.map (fun (root : root) -> root.level, root.tree) left <> List.map (fun (root : root) -> root.level, root.tree) right then
    invalid_arg "complete typed AV/EV projector trees, including every meta-symbol and edge annotation, differ";
  List.combine left right

let rec select selected current path tree =
  let one given_back value = if selected = current then [{ value; given_back; level = current; path }] else [] in
  let edges tag pairs = List.concat (List.mapi (fun index (_, child) -> select selected (current + 1) (path @ [tag index]) child) pairs) in
  match tree.node with
  | Empty -> []
  | Loan (ended, original, consumed, borrows) ->
    if not ended && selected = current then invalid_arg "an active selected loan projector requires original continuation semantics";
    let header = if not ended then [] else if consumed = [] then one false original else
      List.concat (List.mapi (fun index (value, _) -> if selected = current then
        [{ value; given_back = false; level = current; path = path @ [W.Consumed index] }] else []) consumed) in
    header @ edges (fun index -> W.Consumed index) consumed @ edges (fun index -> W.BorrowReprojection index) borrows
  | Borrow (_, given, loans) ->
    if given = None && selected = current then invalid_arg "an active selected borrow projector requires original continuation semantics";
    Option.fold ~none:[] ~some:(one true) given @ edges (fun index -> W.LoanReprojection index) loans

let rec prefix left right = match left, right with
  | [], _ -> true | first :: rest, actual :: following -> first = actual && prefix rest following | _ -> false
let rec depth tree = 1 + (match tree.node with Empty -> 0
  | Loan (_, _, first, second) -> List.fold_left (fun n (_, child) -> max n (depth child)) 0 (first @ second)
  | Borrow (_, _, children) -> List.fold_left (fun n (_, child) -> max n (depth child)) 0 children)

let derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings =
  if not (D.replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings) then
    invalid_arg "projector consumption requires actual shared native bindings and the complete source trace";
  let source = B.backward_expressions symbolic in
  let branches = List.map (fun (branch : D.branch) ->
    let actual = match RegionGroupId.Map.find_opt branch.target source with Some expression -> fst (B.ending_abstractions expression)
      | None -> invalid_arg "projector consumption lost its actual source branch" in
    if List.length actual <> List.length branch.endings then invalid_arg "projector consumption lost an ending";
    let endings = List.map2 (fun ((abs : V.abs), level) (trace : D.ending_trace) ->
      if abs.abs_id <> trace.event.abstraction || level <> trace.event.level then invalid_arg "projector consumption changed actual EndAbs order";
      let roots = List.map (fun ((abstract : root), (continuation : root)) ->
        let selected = select level abstract.level abstract.path abstract.tree in
        let counterpart = select level continuation.level continuation.path continuation.tree in
        let check (root : root) path actual =
          let expected = List.filter (fun (port : W.port) -> prefix root.path (path port)) trace.event.ports |>
            List.map (fun (port : W.port) -> { value = sym port.value; given_back = port.given_back; level = port.level; path = path port }) in
          if actual <> expected then invalid_arg "complete nested projector selection differs from actual typed native ports" in
        check abstract (fun (port : W.port) -> port.abstract_path) selected;
        check continuation (fun (port : W.port) -> port.continuation_path) counterpart;
        List.iter (fun (port : port) -> if not port.given_back then (
          match List.filter (fun (read : D.consumed_read) -> read.port.abstract_path = port.path &&
            read.port.value.sv_id = port.value.identity && read.port.value.sv_ty = port.value.source_type && read.port.level = port.level) trace.reads with
          | [_] -> () | _ -> invalid_arg "a selected nested loan lacks its unique actual native consumed-symbol lookup"
        )) selected;
        { abstract; continuation; selected }) (roots abs) in
      { event = trace.event; roots; trace; receipts = [] }) actual branch.endings in
    let rec closed tree = match tree.node with
      | Empty -> true
      | Loan (ended, _, consumed, borrows) -> ended && List.for_all (fun (_, child) -> closed child) (consumed @ borrows)
      | Borrow (_, given, loans) -> Option.is_some given && List.for_all (fun (_, child) -> closed child) loans in
    let endings = List.mapi (fun index ending ->
      let receipts = List.concat_map (fun root -> match root.abstract.tree.node with
        | Borrow (_, Some _, _ :: _) when root.abstract.level = ending.event.level ->
          if not (closed root.abstract.tree) then
            invalid_arg "a selected outer given-back value still contains an active nested projector";
          let given = match List.filter (fun (port : port) -> port.given_back && port.path = root.abstract.path) root.selected with
            | [port] -> port | _ -> invalid_arg "a nested outer borrow lost its unique actual selected header" in
          let inner = List.init (depth root.abstract.tree - 1) (fun offset ->
            select (root.abstract.level + offset + 1) root.abstract.level root.abstract.path root.abstract.tree) |>
            List.concat |> List.filter (fun (port : port) -> not port.given_back) in
          List.map (fun consumed ->
            let candidates = List.concat (List.mapi (fun prior_ending (prior : ending) ->
              if prior_ending >= index || prior.event.abstraction <> ending.event.abstraction then [] else
              List.filter_map (fun (read : D.consumed_read) ->
                if read.port.abstract_path = consumed.path && read.port.value.sv_id = consumed.value.identity &&
                  read.port.value.sv_ty = consumed.value.source_type && read.port.level = consumed.level then
                  Some { given; consumed; prior_ending; read } else None) prior.trace.reads) endings) in
            match candidates with [receipt] -> receipt
              | _ -> invalid_arg "a nested loan return must be consumed exactly once at an earlier level of this actual abstraction"
          ) inner
        | _ -> []) ending.roots in
      { ending with receipts }) endings in
    { target = branch.target; endings }) bindings.D.branches in
  let rec source_types tree =
    let symbol value = [value.source_type] in
    let edges values = List.concat_map (fun (value, child) -> symbol value @ source_types child) values in
    tree.annotation :: (match tree.node with Empty -> []
      | Loan (_, original, consumed, borrows) -> symbol original @ edges consumed @ edges borrows
      | Borrow (original, given, loans) -> symbol original @ Option.fold ~none:[] ~some:symbol given @ edges loans) in
  let sources = List.concat_map (fun branch -> List.concat_map (fun ending ->
    List.concat_map (fun root -> source_types root.abstract.tree @ source_types root.continuation.tree) ending.roots @
    List.map (fun (read : D.consumed_read) -> read.port.value.sv_ty) ending.trace.reads) branch.endings) branches in
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "projector type context contains unresolved native errors";
  let translate = Aeneas.SymbolicToPureTypes.translate_fwd_ty (Some projection.P.candidate.item_meta.span) context in
  let native_types = List.map (fun source -> let native = translate source in ignore (P.reflect source); ignore (N.reflect native); source, native)
    (List.sort_uniq Stdlib.compare sources) in
  { bindings; branches; native_types }
let replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings witness =
  try derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings =
  let witness = derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings in
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings witness) then
    invalid_arg "actual typed nested projector consumption did not replay";
  witness

let native_type witness source = match List.assoc_opt source witness.native_types with
  | Some native -> native | None -> invalid_arg "a reflected projector symbol lost its actual complete native type"
let lean_symbol witness value = "{ identity := " ^ B.sid value.identity ^ ", sourceType := " ^ P.reflect value.source_type ^
  ", nativeType := " ^ N.pure (native_type witness value.source_type) ^ " }"
let rec lean_tree witness tree =
  let pairs values = "[" ^ String.concat ", " (List.map (fun (value, child) -> "(" ^ lean_symbol witness value ^ ", " ^ lean_tree witness child ^ ")") values) ^ "]" in
  let annotation = "(" ^ P.reflect tree.annotation ^ ")" in
  match tree.node with
  | Empty -> ".empty " ^ annotation
  | Loan (ended, original, consumed, borrows) -> ".loan " ^ annotation ^ " " ^ B.bool ended ^ " (" ^ lean_symbol witness original ^ ") " ^ pairs consumed ^ " " ^ pairs borrows
  | Borrow (original, given, loans) -> ".borrow " ^ annotation ^ " (" ^ lean_symbol witness original ^ ") " ^
    (match given with None -> "none" | Some given -> "(some (" ^ lean_symbol witness given ^ "))") ^ " " ^ pairs loans
let lean_path path = "[" ^ String.concat ", " (List.map W.edge path) ^ "]"
let lean_port witness port = "{ symbol := " ^ lean_symbol witness port.value ^ ", givenBack := " ^ B.bool port.given_back ^
  ", level := " ^ B.nat port.level ^ ", path := " ^ lean_path port.path ^ " }"
let ports witness values = "[" ^ String.concat ", " (List.map (lean_port witness) values) ^ "]"

let report component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings witness =
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure bindings witness) then
    invalid_arg "nested projector report requires its complete source and actual native expression witnesses";
  `Assoc ["schema", `String "actual-typed-native-nested-projector-level-consumption/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "endings", `List (List.map (fun ending -> `Assoc ["abstraction", `Int (V.AbsId.to_int ending.event.abstraction);
        "selected_level", `Int ending.event.level;
        "projectors", `List (List.map (fun root -> `Assoc [
          "complete_actual_av_ev_tree", `String (lean_tree witness root.abstract.tree);
          "source_tree_equality_includes_meta_types_and_all_children", `Bool true;
          "abstract_root_path", `String (lean_path root.abstract.path);
          "continuation_root_path", `String (lean_path root.continuation.path);
          "root_level", `Int root.abstract.level; "complete_depth", `Int (depth root.abstract.tree);
          "selected_ports", `String (ports witness root.selected)]) ending.roots);
        "nested_consumption_receipts", `List (List.map (fun receipt -> `Assoc [
          "outer_given_back_port", `String (lean_port witness receipt.given);
          "inner_consumed_port", `String (lean_port witness receipt.consumed);
          "earlier_ending", `Int receipt.prior_ending;
          "actual_immediate_consumed_expression", `String (D.lean_expression receipt.read.value)]) ending.receipts);
        "actual_native_consumed_reads", `List (List.map (fun (read : D.consumed_read) -> `Assoc [
          "actual_port", `String (W.lean_port read.port); "role", `String (Native_borrow_execution.kind_name read.kind);
          "typed_immediate_expression", `String (D.lean_expression read.value);
          "finite_native_state_at_read", `String (D.lean_snapshot read.state)]) ending.trace.reads)]) branch.endings)]) witness.branches);
    "all_nested_edges_and_level_changes_retained", `Bool true;
    "every_selected_consumed_symbol_read_through_actual_shared_native_lookup", `Bool true;
    "default_chains_chased", `Bool false;
    "ordinary_function_results_supplied", `Bool false;
    "original_full_leaf_dispatch_or_default_activation_executed", `Bool false;
    "original_nested_mutable_or_level_guards_removed", `Bool false;
    "projected_value_or_native_continuation_adequacy_proved", `Bool false;
    "rust_heap_loan_lifetime_layout_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeProjectorLevels";
  line "import qualification.aeneas.cases.NativeDefaultBindings";
  line "/- Complete actual AV/EV projector trees and native consumed-variable reads.";
  line "   Unelaborated/unqualified. Original EndAbs/default/heap/loan adequacy remains open. -/";
  line "namespace Auths.Qualification.NativeProjectorLevels";
  line "open Auths.Support.NativeProjectorLevels Auths.Support.NativeBorrowWiring";
  line "open Auths.Support.SourceClosureRegions Auths.Support.NativePurePayload";
  List.iter (fun branch -> List.iteri (fun ending_index ending ->
    let name = "branch" ^ B.gid branch.target ^ "Ending" ^ B.nat ending_index in
    List.iteri (fun root_index root ->
      let name = name ^ "Projector" ^ B.nat root_index in
      line ("def " ^ name ^ " : Tree := " ^ lean_tree witness root.abstract.tree);
      line ("def " ^ name ^ "Ports : List Auths.Support.NativeProjectorLevels.Port := " ^ ports witness root.selected);
      line ("theorem " ^ name ^ "_selects_every_actual_level_port : select " ^ B.nat (depth root.abstract.tree) ^ " " ^ B.nat ending.event.level ^
        " " ^ B.nat root.abstract.level ^ " " ^ lean_path root.abstract.path ^ " " ^ name ^ " = some " ^ name ^ "Ports := by decide");
      let continuation_ports = select ending.event.level root.continuation.level root.continuation.path root.continuation.tree in
      line ("theorem " ^ name ^ "_continuation_selects_same_typed_ports : select " ^ B.nat (depth root.continuation.tree) ^ " " ^ B.nat ending.event.level ^
        " " ^ B.nat root.continuation.level ^ " " ^ lean_path root.continuation.path ^ " " ^ name ^ " = some " ^ ports witness continuation_ports ^ " := by decide")
    ) ending.roots;
    List.iteri (fun index receipt ->
      let name = name ^ "Receipt" ^ B.nat index in
      line ("def " ^ name ^ " : Receipt := { givenEnding := " ^ B.nat ending_index ^ ", consumedEnding := " ^ B.nat receipt.prior_ending ^
        ", given := " ^ lean_port witness receipt.given ^ ", consumed := " ^ lean_port witness receipt.consumed ^
        ", state := " ^ D.lean_snapshot receipt.read.state ^ ", expression := " ^ D.lean_expression receipt.read.value ^ " }");
      line ("theorem " ^ name ^ "_consumes_inner_return_before_outer_binding : receiptValid " ^ name ^ " = true := by decide")
    ) ending.receipts;
    List.iteri (fun index (read : D.consumed_read) ->
      let name = name ^ "Read" ^ B.nat index in
      line ("def " ^ name ^ "State : Auths.Support.NativeDefaultBindings.State := " ^ D.lean_snapshot read.state);
      line ("def " ^ name ^ "Symbol : Symbol := " ^ lean_symbol witness (sym read.port.value));
      line ("theorem " ^ name ^ "_is_actual_native_immediate_variable : read " ^ name ^ "State " ^ name ^ "Symbol = some (" ^ D.lean_expression read.value ^ ") := by decide")
    ) ending.trace.reads
  ) branch.endings) witness.branches;
  line "end Auths.Qualification.NativeProjectorLevels";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
