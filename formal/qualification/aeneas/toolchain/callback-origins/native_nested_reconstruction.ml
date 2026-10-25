(* Reconstruct a projected native default frame from its captured frame and an
   actual nested return. The original native pattern-decomposition primitive
   selects captured defaults on a nonmatching variant. This is a closed local
   helper, not a replacement for the original function ABI or EndAbs semantics. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module P = Borrow_projection
module B = Native_borrow_protocol
module D = Native_borrow_defaults
module C = Native_root_payload
module R = Native_root_bindings
module H = Native_payload_layout
module E = Native_pure_expressions
module X = Native_root_expressions
module T = Native_type_syntax

type captured_default = { variable : Q.fvar; current_field : Q.fvar; variant : int; field : int }
type helper = { target : region_group_id; event : int; receipt : R.nested_return; producer : D.default;
  native_type : Q.ty; layout : H.layout; codec : H.codec; mask : E.mask; strategy : E.strategy;
  native : Q.texpr; term : X.term; captured_defaults : captured_default list }
type t = { bindings : R.t; helpers : helper list }

let variant_count environment identity =
  let counts = List.filter_map (fun (schema : H.schema) -> match schema.native_type with
    | Q.TAdt (Q.TAdtId actual, _) when actual = identity -> Some (match schema.native_kind with
      | Q.Enum variants -> Some (List.length variants) | Q.Struct _ | Q.Opaque -> None)
    | _ -> None) environment.H.schemas in
  match counts with first :: rest when List.for_all ((=) first) rest -> first
  | _ -> invalid_arg "native pattern decomposition needs its exact original enum variant roster"

let compile span environment native_type strategy =
  let next = ref 0 and captured_defaults = ref [] in
  let fresh ty =
    if !next = Int.max_int then invalid_arg "native context variable identity space is exhausted";
    let variable : Q.fvar = { id = Q.FVarId.of_int !next; basename = None; ty } in
    incr next; variable in
  let current = fresh native_type and incoming = fresh native_type in
  let value = U.mk_texpr_from_fvar in
  let body = match strategy with
    | E.Incoming -> value incoming | E.Current -> value current
    | E.Enumeration rows ->
        let branches = List.map (fun (row : E.row) ->
          let current_fields = List.map (fun (ty, _) -> fresh ty) row.fields in
          let current_pattern = U.mk_adt_pat native_type (Some (VariantId.of_int row.variant))
            (List.map (U.mk_tpat_from_fvar None) current_fields) in
          let selected = List.mapi (fun field (ty, owned) ->
            if owned then (
              let variable = fresh ty in
              let current_field = List.nth current_fields field in
              captured_defaults := !captured_defaults @ [{ variable; current_field; variant = row.variant; field }];
              Some variable) else None) row.fields in
          let pattern = U.mk_adt_pat native_type (Some (VariantId.of_int row.variant))
            (List.mapi (fun field (ty, _) -> match List.nth selected field with
              | None -> U.mk_ignored_pat ty | Some variable -> U.mk_tpat_from_fvar None variable) row.fields) in
          let default (variable : Q.fvar) =
            match List.filter (fun actual -> actual.variable = variable) !captured_defaults with
            | [actual] when actual.current_field.ty = variable.ty -> value actual.current_field
            | _ -> invalid_arg "a native default must name one actual same-typed captured current field" in
          let pattern, returned = U.decompose_let_match_with_variant_count span
            (fun variable -> fresh variable.Q.ty) default (variant_count environment) pattern (value incoming) in
          let fields = List.mapi (fun field _ -> value (match List.nth selected field with
            | Some variable -> variable | None -> List.nth current_fields field)) row.fields in
          let reconstructed = U.mk_adt_texpr span native_type (Some (VariantId.of_int row.variant)) fields in
          let body = U.mk_closed_let span false pattern returned reconstructed in
          U.close_branch span current_pattern body) rows in
        Q.{ e = Switch (value current, Match branches); ty = native_type } in
  let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) [current; incoming]) body in
  if native.ty <> U.mk_arrows [native_type; native_type] native_type then
    invalid_arg "native reconstruction changed its captured-current/nested-return interface";
  native, !captured_defaults

let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings =
  if not (R.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings) then
    invalid_arg "native reconstruction needs original complete root/signature/version/projector contexts";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native reconstruction has unresolved declaration diagnostics";
  let span = projection.P.candidate.item_meta.span in
  let helpers = List.concat_map (fun (branch : R.branch) ->
    let actual_defaults = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) defaults.D.branches with
      | [actual] -> actual.defaults | _ -> invalid_arg "native reconstruction lost its exact default branch" in
    List.concat (List.mapi (fun event (ending : R.ending) -> List.map (fun (receipt : R.nested_return) ->
      let producer = match List.filter (fun (producer : D.default) -> producer.value.sv_id = receipt.given.value.identity) actual_defaults with
        | [producer] -> producer | _ -> invalid_arg "a nested reconstruction lost its exact immediate producer" in
      let native_type = S.translate_fwd_ty (Some span) context producer.candidate_type in
      if S.translate_fwd_ty (Some span) context receipt.consumed.value.source_type <> native_type ||
          S.translate_fwd_ty (Some span) context receipt.given.value.source_type <> native_type then
        invalid_arg "a native nested return requires an exact full-type adapter; no field/dictionary is erased";
      let layout = H.expand payload.C.environment [] native_type in
      let codec = H.codec context span payload.environment producer.candidate_shape layout in
      let mask = E.erase_plan codec (D.selection_plan producer.candidate_shape producer.selected) in
      let strategy = E.strategy layout mask in
      let native, captured_defaults = compile span payload.environment native_type strategy in
      let term = X.reflect native in
      { target = branch.target; event; receipt; producer; native_type; layout; codec; mask; strategy; native; term; captured_defaults }
    ) ending.nested_returns) branch.endings)) bindings.R.branches in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native reconstruction emitted unresolved native diagnostics";
  { bindings; helpers }
let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings =
  let witness = derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings in
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings witness) then
    invalid_arg "complete actual native reconstruction expressions did not replay";
  witness
let name helper = "branch" ^ B.gid helper.target ^ "Event" ^ B.nat helper.event ^ "Symbol" ^ B.sid helper.receipt.given.value.identity
let fuel helper = 64 + 8 * max (X.depth helper.term) (C.depth helper.layout)
let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings witness) then
    invalid_arg "native reconstruction report lost a complete source/field/default/context expression";
  `Assoc ["schema", `String "actual-native-nested-context-reconstruction/v1";
    "helpers", `List (List.map (fun helper -> `Assoc ["target", `Int (RegionGroupId.to_int helper.target);
      "event", `Int helper.event; "given", `Int (Aeneas.Values.SymbolicValueId.to_int helper.receipt.given.value.identity);
      "nested_return", `Int (Aeneas.Values.SymbolicValueId.to_int helper.receipt.consumed.value.identity);
      "exact_immediate_source", `String (D.lean_origin helper.producer.origin);
      "complete_native_type", `String (Q.show_ty helper.native_type);
      "complete_native_expression", `String (Q.show_texpr helper.native);
      "reflected_closed_expression", `String (X.lean helper.term);
      "captured_current_defaults", `List (List.map (fun captured -> `Assoc [
        "variable", `Int (Q.FVarId.to_int captured.variable.id); "current_field_variable", `Int (Q.FVarId.to_int captured.current_field.id);
        "variant", `Int captured.variant; "field", `Int captured.field;
        "complete_type", `String (Q.show_ty captured.variable.ty)]) helper.captured_defaults)]) witness.helpers);
    "original_native_pattern_decomposition_primitive_invoked", `Bool true;
    "complete_types_constants_dictionaries_and_scope_positions_retained", `Bool true;
    "fallback_reads_only_actual_captured_current_field_variables", `Bool true;
    "helper_reconstructs_a_default_frame_not_a_fresh_given_back_binding", `Bool true;
    "fresh_given_back_binding_requires_separate_original_ending_rule", `Bool true;
    "all_source_and_native_enum_variants_retained", `Bool true;
    "ordinary_function_expected_results_supplied", `Bool false;
    "original_function_ABI_replaced_by_helpers", `Bool false;
    "original_forward_declaration_or_EndAbs_guard_removed", `Bool false;
    "original_source_context_to_helper_arguments_adequacy_proved", `Bool false;
    "complete_native_ending_or_source_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let source_value prefix variant codec =
  let wrap constructor value = constructor ^ " (" ^ value ^ ")" in
  let rec value field = function
    | H.CAtom _ -> (match field with Some field -> ".atom " ^ prefix ^ B.nat field
        | None -> invalid_arg "a source reconstruction atom lost its original field position")
    | H.CEmpty -> invalid_arg "an empty source shape cannot provide a reconstruction value"
    | H.CUnit -> ".unit"
    | H.CProduct (first, second) -> ".product (" ^ value field first ^ ") (" ^ value field second ^ ")"
    | H.CSum (first, second) ->
        (match first with H.CVariant (identity, _) when VariantId.to_int identity = variant -> wrap ".left" (value field first)
         | H.CVariant _ -> wrap ".right" (value field second)
         | _ -> invalid_arg "a source reconstruction sum lost its original enum variant labels")
    | H.CField (index, _, body) -> wrap ".named" (value (Some index) body)
    | H.CVariant (_, body) | H.CNominal (_, _, body) | H.CBoxed body -> wrap ".named" (value field body)
    | H.CBorrow (_, _, body) -> wrap ".borrow" (value field body) in
  value None codec

let write_lean path payload witness =
  let output = Buffer.create 262144 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeRootExpressions";
  line "import qualification.aeneas.cases.NativeRootBindings";
  line "/- Closed native default-frame reconstruction helpers, unelaborated/unqualified.";
  line "   Reconstructing a default does not replace the independent fresh given-back input or binding.";
  line "   Full source-context binding, original ABI/EndAbs and Rust heap/loan adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeNestedReconstruction";
  line "open Auths.Support.NativeRootPayload Auths.Support.NativeRootExpressions";
  line "universe u";
  line ("def schemas : List Schema := " ^ B.list C.lean_schema payload.C.environment.schemas);
  List.iter (fun helper ->
    let name = name helper in
    line ("def " ^ name ^ "Type : Ty := " ^ T.pure helper.native_type);
    line ("def " ^ name ^ "SourceShape : Auths.Support.BorrowProjection.Shape := " ^ P.lean helper.producer.candidate_shape);
    line ("def " ^ name ^ "Layout : Layout := " ^ C.lean_layout helper.layout);
    line ("def " ^ name ^ "Codec : Codec Auths.Qualification.NativeRootPayload.atomTyping " ^ name ^ "SourceShape " ^ name ^ "Layout := " ^ C.lean_codec helper.codec);
    line ("def " ^ name ^ "Selected : Auths.Support.BorrowProjection.Plan " ^ name ^ "SourceShape := " ^ D.lean_plan (D.selection_plan helper.producer.candidate_shape helper.producer.selected));
    line ("def " ^ name ^ " : Term := " ^ X.lean helper.term);
    line ("def " ^ name ^ "Fuel : Nat := " ^ B.nat (fuel helper));
    line ("theorem " ^ name ^ "_is_closed_and_uses_complete_native_types : check schemas " ^ name ^ "Fuel [] " ^ name ^ " = true := by decide");
    match helper.strategy with
    | E.Enumeration rows -> List.iter (fun (current : E.row) -> List.iter (fun (incoming : E.row) ->
        let params prefix fields = List.mapi (fun index (ty, _) -> "(" ^ prefix ^ B.nat index ^ " : Atom (" ^ T.pure ty ^ "))") fields |> String.concat " " in
        let values prefix fields = B.list (fun (index, (ty, _)) -> ".atom (" ^ T.pure ty ^ ") " ^ prefix ^ B.nat index) (List.mapi (fun index field -> index, field) fields) in
        let expected = B.list (fun (index, (ty, owned)) -> ".atom (" ^ T.pure ty ^ ") " ^
          (if current.variant = incoming.variant && owned then "incoming" else "current") ^ B.nat index) (List.mapi (fun index field -> index, field) current.fields) in
        line ("theorem " ^ name ^ "_all_values_current" ^ B.nat current.variant ^ "_returned" ^ B.nat incoming.variant ^ " (Atom : Ty → Type u)");
        line ("    " ^ params "current" current.fields ^ " " ^ params "incoming" incoming.fields ^ " :");
        line ("    execute schemas " ^ name ^ "Fuel " ^ name ^ " [");
        line ("      .constructor " ^ name ^ "Type (some " ^ B.nat current.variant ^ ") " ^ values "current" current.fields ^ ",");
        line ("      .constructor " ^ name ^ "Type (some " ^ B.nat incoming.variant ^ ") " ^ values "incoming" incoming.fields ^ "] =");
        line ("    some (.constructor " ^ name ^ "Type (some " ^ B.nat current.variant ^ ") " ^ expected ^ ") := by rfl");
        let source_current = source_value "current" current.variant helper.codec in
        let source_returned = source_value "incoming" incoming.variant helper.codec in
        line ("theorem " ^ name ^ "_source_codec_reconstruction_current" ^ B.nat current.variant ^ "_returned" ^ B.nat incoming.variant ^ " (Atom : Ty → Type u)");
        line ("    " ^ params "current" current.fields ^ " " ^ params "incoming" incoming.fields ^ " :");
        line ("    executeValues schemas " ^ name ^ "Fuel " ^ name ^ " [");
        line ("      pack " ^ name ^ "Fuel (encode " ^ name ^ "Codec (" ^ source_current ^ ")), ");
        line ("      pack " ^ name ^ "Fuel (encode " ^ name ^ "Codec (" ^ source_returned ^ "))] =");
        line ("    pack " ^ name ^ "Fuel (encode " ^ name ^ "Codec (reconstruct " ^ name ^ "Selected (" ^ source_current ^ ") (" ^ source_returned ^ "))) := by rfl")
      ) rows) rows
    | E.Incoming | E.Current -> ()
  ) witness.helpers;
  line "end Auths.Qualification.NativeNestedReconstruction";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
