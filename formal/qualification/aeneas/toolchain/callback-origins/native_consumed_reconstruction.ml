(* Closed reconstruction code from the actual library rule, checked against
   independently expanded complete source shapes and their selected views.
   No actual current/fresh payload or full source context is manufactured. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.Pure
module S = Aeneas.SymbolicToPureValues
module P = Borrow_projection
module B = Native_borrow_protocol
module D = Native_borrow_defaults
module C = Native_borrow_view
module H = Native_payload_layout
module N = Native_root_payload
module R = Native_root_bindings
module X = Native_root_expressions
module T = Native_type_syntax
module K = Native_consumed_coverage

type helper = { target : region_group_id; event : int; update_index : int; update : K.update;
  actual : S.consumed_current_reconstruction; shape : P.shape; selected : D.plan;
  environment : H.t; layout : H.layout; codec : H.codec; code : X.term }
type t = { helpers : helper list }

let derive component projection coverage =
  K.require_admitted coverage;
  let context = Aeneas.Interp.compute_contexts component in
  let span = projection.P.candidate.item_meta.span in
  let helpers = List.concat_map (fun (branch : K.branch) ->
    List.concat (List.mapi (fun event (ending : K.ending) -> List.mapi (fun update_index (update : K.update) ->
      let owned = RegionId.Set.of_list update.receiver_regions in
      let actual = S.compile_consumed_current_reconstruction span context owned update.receiver_type in
      (* This is a naming scope for the actual free IDs in the retained type;
         it supplies no lifetime, outlives or native evaluation-context fact. *)
      let instance = C.type_instance update.receiver_type update.receiver_type in
      let parameters = List.map (function
        | RVar (Free index) -> {index; name = None; variance = Invariant; mutability = LtUnknown}
        | _ -> invalid_arg "consumed reconstruction needs its exact original free source-region names") instance.native_arguments in
      let expand, nominals = P.make_expander component ~span ~type_infos:context.type_ctx.type_infos ~parameters in
      let shape = expand update.receiver_type in
      let selected = D.select (List.map (fun region -> RVar (Free region)) update.receiver_regions) shape in
      let environment = H.create context span ~validate:X.validate [shape] (nominals ()) in
      let native = actual.consumed_plan.consumed_native_type in
      let layout = H.expand environment [] native in
      let codec = H.codec context span environment shape layout in
      let code = X.reflect actual.consumed_native in
      if actual.consumed_native.ty <> Aeneas.PureUtils.mk_arrows [native; native] native then
        invalid_arg "consumed reconstruction changed its exact complete current/fresh interface";
      {target = branch.target; event; update_index; update; actual; shape; selected; environment; layout; codec; code}
    ) ending.updates) branch.endings)) coverage.K.branches in
  {helpers}
let analyze = derive
let replay component projection coverage witness =
  try derive component projection coverage = witness with Invalid_argument _ | Not_found -> false
let helper_name index helper = "branch" ^ B.gid helper.target ^ "Event" ^ B.nat helper.event ^ "Receipt" ^ B.nat index
let fuel helper = 128 + 16 * max (X.depth helper.code) (N.depth helper.layout)
let report witness = `Assoc ["schema", `String "actual-native-consumed-current-reconstruction/v1";
  "scope", `String "every selected consumed symbolic receipt in the original capture ending traces";
  "helpers", `List (List.mapi (fun index helper -> `Assoc ["name", `String (helper_name index helper);
    "receiver_symbol", `Int (V.SymbolicValueId.to_int helper.update.receiver);
    "fresh_symbol", `Int (V.SymbolicValueId.to_int helper.update.edge.sv_id);
    "actual_native_incoming_covers_receiver_owned_projection", `Bool helper.update.native_covers;
    "source_receipt", `String (K.lean_receipt helper.update);
    "complete_source_shape", `String (P.lean helper.shape);
    "source_selected_plan", `String (D.lean_plan helper.selected);
    "complete_native_type", `String (Q.show_ty helper.actual.consumed_plan.consumed_native_type);
    "actual_library_closed_expression", `String (Q.show_texpr helper.actual.consumed_native);
    "reflected_closed_expression", `String (X.lean helper.code)]) witness.helpers);
  "coverage_is_not_current_or_fresh_runtime_availability", `Bool true;
  "native_current_binding_or_fresh_value_supplied", `Bool false;
  "source_context_heap_loan_or_whole_ABI_adequacy_proved", `Bool false;
  "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path witness =
  let buffer = Buffer.create 262144 in
  let line text = Buffer.add_string buffer (text ^ "\n") in
  line "import Auths.Support.NativeRootExpressions";
  line "import qualification.aeneas.cases.NativeConsumedCoverage";
  line "namespace Auths.Qualification.NativeConsumedReconstruction";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection Auths.Support.NativeRootPayload Auths.Support.NativeRootExpressions";
  line "universe u";
  line "/- Actual library helpers; source/current/fresh availability and Rust heap/loan/ABI adequacy remain open. -/";
  List.iteri (fun index helper ->
    let name = helper_name index helper in
    line ("namespace " ^ name);
    let receipt = "Auths.Qualification.NativeConsumedCoverage.branch" ^ B.gid helper.target ^
      "Event" ^ B.nat helper.event ^ "Update" ^ B.nat helper.update_index in
    line ("def originalSourceReceipt : Auths.Support.NativeConsumedCoverage.Receipt := " ^ receipt);
    line ("theorem current_frame_type_is_the_exact_receiving_type : originalSourceReceipt.receiverType = " ^
      P.reflect helper.update.receiver_type ^ " := by rfl");
    line ("theorem incoming_coverage_uses_the_actual_source_receipt :");
    line ("    Auths.Support.NativeConsumedCoverage.receiptCoverage " ^ B.nat (K.fuel helper.update) ^
      " originalSourceReceipt = some " ^ B.bool helper.update.native_covers ^ " := " ^
      receipt ^ "_coverage_matches_actual_native_comparison");

    line ("def schemas : List Schema := " ^ B.list N.lean_schema helper.environment.schemas);
    line "def atomTyping : AtomTyping := fun source =>";
    List.iter (fun (source, native) -> line ("  if source = " ^ P.reflect source ^ " then some (" ^ T.pure native ^ ") else")) helper.environment.atoms;
    line "  none";
    line ("def sourceShape : Shape := " ^ P.lean helper.shape);
    line ("def layout : Layout := " ^ N.lean_layout helper.layout);
    line ("def codec : Codec atomTyping sourceShape layout := " ^ N.lean_codec helper.codec);
    line ("def selected : Plan sourceShape := " ^ D.lean_plan helper.selected);
    line ("def code : Term := " ^ X.lean helper.code);
    line ("def fuel : Nat := " ^ B.nat (fuel helper));
    line "theorem actual_library_helper_is_closed_and_has_complete_native_types : check schemas fuel [] code = true := by decide";
    line "theorem actual_library_helper_reconstructs_the_independent_source_view";
    line "    (Atom : NativeType → Type u)";
    line "    (current returned : Data (SourceAtom atomTyping Atom) sourceShape) :";
    line "    run schemas fuel code [pack fuel (encode codec current), pack fuel (encode codec returned)] =";
    line "      pack fuel (encode codec (reconstruct selected current returned)) := by";
    R.emit_data_cases line "  " "current" helper.shape (fun indent ->
      R.emit_data_cases line indent "returned" helper.shape (fun indent -> line (indent ^ "rfl")));
    line ("end " ^ name)
  ) witness.helpers;
  line "end Auths.Qualification.NativeConsumedReconstruction";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
