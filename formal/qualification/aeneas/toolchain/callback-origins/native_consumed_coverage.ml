(* Real give-back receipt coverage, before any nested loan guard is relaxed.
   EndAbs evaluation contexts are the originals stored in the symbolic AST. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module P = Borrow_projection
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module K = Native_projector_kinds

type update = { path : W.edge list; receiver : V.symbolic_value_id; receiver_type : ty;
  receiver_regions : region_id list; edge : V.mconsumed_symb; expected : W.port;
  origin_matches : bool; shapes_agree : bool; native_covers : bool;
  sibling_updates : int; borrow_reprojections : int; child_empty : bool }
type ending = { event : W.event; updates : update list }
type branch = { target : region_group_id; endings : ending list }
type t = { branches : branch list }

let rec ending_contexts = function
  | S.Meta (_, next) -> ending_contexts next
  | S.Return (_, None) -> []
  | S.EndAbs (context, abstraction, level, next) ->
      (context, abstraction, level) :: ending_contexts next
  | _ -> invalid_arg "consumed coverage cannot omit an original source effect or ending"

let derive component projection inputs symbolic forward protocol wiring =
  if not (W.replay component projection inputs symbolic forward protocol wiring) then
    invalid_arg "consumed coverage requires every original source event and port";
  let expressions = B.backward_expressions symbolic in
  let span = projection.P.candidate.item_meta.span in
  let branches = List.map (fun (branch : W.branch) ->
    let actual = match RegionGroupId.Map.find_opt branch.target expressions with
      | Some body -> ending_contexts body
      | None -> invalid_arg "consumed coverage lost an original backward branch" in
    if List.length actual <> List.length branch.events then
      invalid_arg "consumed coverage lost an original ending";
    let endings = List.map2 (fun (context, (abstraction : V.abs), selected) (event : W.event) ->
      if abstraction.abs_id <> event.abstraction || selected <> event.level then
        invalid_arg "consumed coverage changed an actual ending identity or level";
      let updates = ref [] in
      let rec projector current path source_type = function
        | V.AEmpty -> ()
        | V.AProjLoans node -> edges current path (fun n -> W.Consumed n) node.consumed;
            edges current path (fun n -> W.BorrowReprojection n) node.borrows
        | V.AProjBorrows node -> edges current path (fun n -> W.LoanReprojection n) node.loans
        | V.AEndedProjBorrows node -> edges current path (fun n -> W.LoanReprojection n) node.loans
        | V.AEndedProjLoans node ->
            if current = selected then List.iteri (fun index ((edge : V.mconsumed_symb), child) ->
              let actual_path = path @ [W.Consumed index] in
              let expected = match List.filter (fun (port : W.port) ->
                not port.given_back && port.abstract_path = actual_path) event.ports with
                | [port] when port.value.sv_id = edge.sv_id && port.value.sv_ty = edge.proj_ty -> port
                | _ -> invalid_arg "a consumed receipt lost its exact original source port" in
              let origin_matches = edge.received.incoming_id = node.proj in
              let erase = Aeneas.TypesUtils.ty_erase_regions in
              let shapes_agree = erase source_type = erase edge.proj_ty &&
                erase edge.received.incoming_projection_type = erase edge.received.actual_given_type &&
                erase source_type = erase edge.received.actual_given_type in
              let native_covers = Aeneas.InterpBorrowsCore.projection_contains span context
                (RegionId.Set.of_list edge.received.ended_regions) edge.received.incoming_projection_type
                abstraction.regions.owned source_type in
              updates := !updates @ [{ path = actual_path; receiver = node.proj; receiver_type = source_type;
                receiver_regions = RegionId.Set.elements abstraction.regions.owned; edge; expected;
                origin_matches; shapes_agree; native_covers; sibling_updates = List.length node.consumed;
                borrow_reprojections = List.length node.borrows; child_empty = child = V.AEmpty }]
            ) node.consumed;
            edges current path (fun n -> W.Consumed n) node.consumed;
            edges current path (fun n -> W.BorrowReprojection n) node.borrows
      and edges current path edge children = List.iteri (fun index ((meta : V.mconsumed_symb), child) ->
        projector (current + 1) (path @ [edge index]) meta.proj_ty child) children
      and value current path (source : V.tavalue) =
        let child value = value_at current (path @ [W.Child]) value in
        let ended child_value given = child child_value;
          value_at (current + 1) (path @ [W.GivenBack]) given in
        match source.value with
        | V.ASymbolic (marker, tree) -> B.marker marker; projector current path source.ty tree
        | V.AAdt aggregate -> List.iteri (fun index field -> value_at current (path @ [W.Field index]) field) aggregate.fields
        | V.ALoan (V.AMutLoan (_, _, value) | V.AIgnoredMutLoan (_, value))
        | V.ABorrow (V.AMutBorrow (_, _, value) | V.AIgnoredMutBorrow (_, value) | V.AEndedMutBorrow (_, value)) -> child value
        | V.ALoan (V.AEndedMutLoan record) -> ended record.child record.given_back
        | V.ALoan (V.AEndedIgnoredMutLoan record) -> ended record.child record.given_back
        | V.ABorrow (V.AEndedIgnoredMutBorrow record) -> ended record.child record.given_back
        | _ -> ()
      and value_at current path source = value current path source in
      List.iteri (fun index source -> value_at 0 [W.Root index] source) abstraction.avalues;
      { event; updates = !updates }) actual branch.events in
    { target = branch.target; endings }) wiring.W.branches in
  { branches }

let admitted witness = List.for_all (fun branch -> List.for_all (fun ending ->
  List.for_all (fun update -> update.origin_matches && update.shapes_agree) ending.updates) branch.endings) witness.branches
let require_admitted witness = if not (admitted witness) then
  invalid_arg "a real consumed projection receipt changed its original identity or complete type shape"
let analyze = derive
let replay component projection inputs symbolic forward protocol wiring witness =
  try let actual = derive component projection inputs symbolic forward protocol wiring in
    admitted actual && actual = witness
  with Invalid_argument _ | Not_found -> false

let lean_receipt update =
  let original = update.edge.received in
  "{ receiverSymbol := " ^ B.sid update.receiver ^ ", receiverType := " ^ P.reflect update.receiver_type ^
  ", receiverRegions := " ^ B.list (fun id -> B.nat (RegionId.to_int id)) update.receiver_regions ^
  ", incomingSymbol := " ^ B.sid original.incoming_id ^
  ", incomingProjectionType := " ^ P.reflect original.incoming_projection_type ^
  ", incomingRegions := " ^ B.list (fun id -> B.nat (RegionId.to_int id)) original.ended_regions ^
  ", freshSymbol := " ^ B.sid update.edge.sv_id ^ ", actualFreshType := " ^ P.reflect original.actual_given_type ^
  ", edgeType := " ^ P.reflect update.edge.proj_ty ^ " }"
let fuel update = 8 + List.fold_left (fun maximum source -> max maximum
  (K.source_depth (Return_region_certificate.reflect_type ~holes:[] source))) 0
  [update.receiver_type; update.edge.proj_ty; update.edge.received.incoming_projection_type;
   update.edge.received.actual_given_type]
let report witness = `Assoc ["schema", `String "actual-native-consumed-projection-coverage/v1";
  "scope", `String "every selected consumed symbolic edge in the original capture ending traces";
  "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
    "endings", `List (List.map (fun ending -> `Assoc ["original_event", `String (W.lean_event ending.event);
      "updates", `List (List.map (fun update -> `Assoc ["path", `String (B.list W.edge update.path);
        "receipt", `String (lean_receipt update); "source_port", `String (W.lean_port update.expected);
        "incoming_source_identity_matches_receiver", `Bool update.origin_matches;
        "complete_non_lifetime_shapes_agree", `Bool update.shapes_agree;
        "actual_native_incoming_covers_receiver_owned_projection", `Bool update.native_covers;
        "sibling_updates", `Int update.sibling_updates; "borrow_reprojections", `Int update.borrow_reprojections;
        "consumed_child_empty", `Bool update.child_empty]) ending.updates)]) branch.endings)]) witness.branches);
  "all_actual_receipts_admitted", `Bool (admitted witness);
  "coverage_is_total_value_or_heap_adequacy", `Bool false;
  "nested_consumption_guard_relaxed", `Bool false;
  "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path witness =
  require_admitted witness;
  let buffer = Buffer.create 65536 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
  line "import Auths.Support.NativeConsumedCoverage";
  line "import qualification.aeneas.cases.NativeBorrowWiring";
  line "namespace Auths.Qualification.NativeConsumedCoverage";
  line "open Auths.Support.NativeConsumedCoverage Auths.Support.NativeBorrowWiring";
  line "/- Real give-back receipts and native projection coverage; unelaborated/unqualified. -/";
  List.iter (fun branch -> List.iteri (fun event ending -> List.iteri (fun index update ->
    let name = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat event ^ "Update" ^ B.nat index in
    line ("def " ^ name ^ " : Receipt := " ^ lean_receipt update);
    line ("def " ^ name ^ "SourcePort : Port := " ^ W.lean_port update.expected);
    line ("theorem " ^ name ^ "_retains_complete_source_edge_and_fresh_shapes : receiptShapesAgree " ^
      B.nat (fuel update) ^ " " ^ name ^ " = true := by decide");
    line ("theorem " ^ name ^ "_origin_is_the_actual_receiver : " ^ name ^ ".incomingSymbol = " ^
      name ^ ".receiverSymbol := by rfl");
    line ("theorem " ^ name ^ "_coverage_matches_actual_native_comparison : receiptCoverage " ^
      B.nat (fuel update) ^ " " ^ name ^ " = some " ^ B.bool update.native_covers ^ " := by decide");
    line ("theorem " ^ name ^ "_retains_its_actual_source_port : " ^ name ^ ".freshSymbol = " ^ name ^ "SourcePort.identity := by rfl");
    line ("theorem " ^ name ^ "_belongs_to_the_original_source_ending :");
    line ("    (Auths.Qualification.NativeBorrowWiring.branch" ^ B.gid branch.target ^ ".events[" ^ B.nat event ^
      "]?).map (fun source => source.ports.contains " ^ name ^ "SourcePort) = some true := by decide")
  ) ending.updates) branch.endings) witness.branches;
  line "end Auths.Qualification.NativeConsumedCoverage";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
