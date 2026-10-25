(* SSA lowering of the explicit selected-view ending machine. The foreign
   default rule is still a proposed lowering rule, not established semantics
   of the original native EndAbs translator. No source environment, heap,
   ordinary Rust result, or missing current version is manufactured here. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module V = Aeneas.Values
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_borrow_view
module D = Native_borrow_defaults
module E = Native_borrow_execution
module A = Native_borrow_full_abi
module N = Native_pure_payload
module X = Native_pure_expressions

type cell = {
  key : B.origin;
  source_type : ty;
  shape : P.shape;
  available : C.selection;
  variable : Q.fvar;
}
type action =
  | Bind of cell * Q.fvar
  | Read of cell * Q.fvar
  | Output of X.helper * cell option * cell * Q.fvar * Q.fvar
type operation = { original : E.operation; action : action }
type branch = {
  source : E.branch;
  seeds : cell list;
  inputs : (X.helper * Q.fvar) list;
  operations : operation list;
  native : Q.texpr;
  reflected : X.term;
  output_types : Q.ty list;
  fuel : int;
}
type t = { expressions : X.t; branches : branch list }

let key_name = function B.Borrow id -> "borrow_" ^ string_of_int (V.BorrowId.to_int id)
  | B.Symbolic id -> "symbolic_" ^ string_of_int (V.SymbolicValueId.to_int id)

let derive component projection inputs expression (forward : F.t) protocol wiring defaults
    (execution : E.t) full_abi payload (expressions : X.t) =
  if not (X.replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions) then
    invalid_arg "native state wiring requires the complete actual trace, codecs and closed helper expressions";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native state wiring context contains unresolved errors";
  let span = projection.P.candidate.item_meta.span in
  let translate = Aeneas.SymbolicToPureTypes.translate_fwd_ty (Some span) context in
  let forward_binding identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
    | [binding] -> binding.source_type, binding.shape
    | _ -> invalid_arg "an initial current version must be an exact existing forward binding" in
  let seed_source = function
    | B.Symbolic identity -> forward_binding identity
    | B.Borrow identity ->
        let source = match List.filter_map (function
          | F.MutableExpansion (source, actual, _) when identity = actual -> Some source
          | _ -> None) forward.steps with
          | [source] -> source
          | _ -> invalid_arg "an initial borrow current must have one actual forward mutable expansion" in
        (match forward_binding source with
         | TRef (_, inner, RMut), P.Borrow (RMut, _, shape) -> inner, shape
         | _ -> invalid_arg "an initial borrow current needs its existing exclusive pointee") in
  let branches = List.map (fun (source : E.branch) ->
    let next = ref 0 in
    let fresh ?name ty =
      if !next = Int.max_int then invalid_arg "native SSA wiring exceeds the fresh variable identifier space";
      let variable : Q.fvar = { id = Q.FVarId.of_int !next; basename = name; ty } in
      incr next; variable in
    let helper_fresh ty = fresh ty in
    let helpers = List.filter (fun (helper : X.helper) -> helper.group = source.target) expressions.helpers in
    let inputs = List.stable_sort (fun (left : X.helper) right ->
      Int.compare left.source.source.input_index right.source.source.input_index) helpers |>
      List.map (fun (helper : X.helper) -> helper, fresh ~name:("incoming_" ^ B.sid helper.source.incoming.access.port.value.sv_id)
        helper.source.incoming.native_type) in
    let helper_for port = match List.filter (fun (helper : X.helper) ->
      helper.source.outgoing.access.port.value.sv_id = port.W.value.sv_id &&
      helper.source.outgoing.access.port.level = port.level) helpers with
      | [helper] -> helper
      | _ -> invalid_arg "every native emitted value needs one exact owned symbol/level helper" in
    let seeds = ref [] and cells = ref [] in
    let define cell =
      if List.mem_assoc cell.key !cells then invalid_arg "a native SSA current version cannot overwrite an existing version";
      cells := !cells @ [cell.key, cell] in
    let read key = match List.assoc_opt key !cells with
      | Some cell -> cell
      | None ->
          (* This lookup deliberately does not follow a default origin. A
             missing symbol 13 cannot silently become original symbol 6. *)
          let source_type, shape = seed_source key in
          let native_type = translate source_type in
          ignore (N.reflect native_type);
          let cell = { key; source_type; shape; available = C.Whole;
            variable = fresh ~name:("initial_" ^ key_name key) native_type } in
          seeds := !seeds @ [cell]; define cell; cell in
    let require cell (producer : D.default) available =
      if cell.source_type <> producer.candidate_type || cell.shape <> producer.candidate_shape || cell.available <> available then
        invalid_arg "a native current read changed its exact source carrier or available ownership version";
      if cell.variable.ty <> translate producer.candidate_type then
        invalid_arg "a native current read changed its complete translated source type" in
    let require_complete cell =
      ignore (A.rebuild cell.shape (D.selection_plan cell.shape cell.available)) in
    let operations = List.concat_map (fun (ending : E.ending) -> ending.operations) source.endings |>
      List.map (fun (original : E.operation) ->
        let access = original.access and producer = original.access.producer in
        let key = B.Symbolic access.port.value.sv_id in
        let native_type = translate access.port.value.sv_ty in
        ignore (N.reflect native_type);
        let action = match original.kind with
          | E.Default ->
              let current = read producer.origin in
              require current producer producer.available;
              ignore (D.restrict (D.selection_plan current.shape current.available)
                (D.selection_plan producer.candidate_shape producer.selected));
              require_complete current;
              if current.variable.ty <> native_type then invalid_arg "a native default alias cannot change its native value type";
              let target = { key; source_type = producer.candidate_type; shape = producer.candidate_shape;
                available = producer.selected; variable = fresh ~name:("default_" ^ key_name key) native_type } in
              define target; Bind (target, current.variable)
          | E.Receive ->
              let _, incoming = match List.filter (fun ((helper : X.helper), _) ->
                helper.source.incoming.access.port = access.port) inputs with
                | [argument] -> argument
                | _ -> invalid_arg "a native receive must bind its actual higher-level-first input argument" in
              if incoming.ty <> native_type then invalid_arg "a native input argument lost its complete native type";
              let target = { key; source_type = producer.candidate_type; shape = producer.candidate_shape;
                available = producer.selected; variable = fresh ~name:("received_" ^ key_name key) native_type } in
              define target; Bind (target, incoming)
          | E.Observe ->
              let current = read key in
              require current producer producer.selected;
              require_complete current;
              (* An observation reads the version; it neither updates the
                 version table nor substitutes the producer's origin. *)
              Read (current, fresh ~name:("observed_" ^ key_name key) current.variable.ty)
          | E.Emit ->
              let helper = helper_for access.port in
              if helper.source.outgoing.access <> access then
                invalid_arg "a native output helper lost its entire exact source access";
              let incoming = read key in
              require incoming producer producer.selected;
              if incoming.variable.ty <> helper.source.incoming.native_type then
                invalid_arg "a native output changed the received complete value type";
              let current = match helper.strategy with
                | X.Incoming -> None
                | X.Current | X.Enumeration _ ->
                    let current = read producer.origin in
                    require current producer producer.available;
                    require_complete current;
                    if current.variable.ty <> helper.source.outgoing.native_type then
                      invalid_arg "a partial native update changed the immediate current's native type";
                    Some current in
              Output (helper, current, incoming, fresh ~name:("output_" ^ key_name key) native_type,
                fresh ~name:("error_" ^ key_name key) (U.mk_error_ty)) in
        { original; action }) in
    let output_types = List.filter_map (fun operation -> match operation.action with
      | Output (_, _, _, output, _) -> Some output.Q.ty | _ -> None) operations in
    if List.length output_types <> List.length helpers then
      invalid_arg "native SSA wiring must emit every actual selected-level owned channel exactly once";
    let output_type = U.mk_simpl_tuple_ty output_types in
    let rec body outputs = function
      | [] -> U.mk_result_ok_texpr span (U.mk_simpl_tuple_texpr span (List.map U.mk_texpr_from_fvar outputs))
      | operation :: rest -> match operation.action with
          | Bind (target, source) -> U.mk_closed_let span false (U.mk_tpat_from_fvar None target.variable)
              (U.mk_texpr_from_fvar source) (body outputs rest)
          | Read (source, observed) -> U.mk_closed_let span false (U.mk_tpat_from_fvar None observed)
              (U.mk_texpr_from_fvar source.variable) (body outputs rest)
          | Output (helper, current, incoming, output, error) ->
              let current = match current with None -> incoming.variable | Some current -> current.variable in
              let rhs = X.compile_body span helper.source.outgoing.native_type helper.strategy helper_fresh current incoming.variable in
              let ok = U.mk_adt_pat rhs.ty (Some Q.result_ok_id) [U.mk_tpat_from_fvar None output] in
              let fail = U.mk_adt_pat rhs.ty (Some Q.result_fail_id) [U.mk_tpat_from_fvar None error] in
              Q.{ e = Switch (rhs, Match [U.close_branch span ok (body (outputs @ [output]) rest);
                U.close_branch span fail (U.mk_result_fail_texpr span (U.mk_texpr_from_fvar error) output_type)]);
                ty = U.mk_result_ty output_type } in
    let arguments = List.map (fun cell -> cell.variable) !seeds @ List.map snd inputs in
    let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) arguments) (body [] operations) in
    if native.ty <> U.mk_arrows (List.map (fun (value : Q.fvar) -> value.ty) arguments) (U.mk_result_ty output_type) then
      invalid_arg "the native state program changed its minimal seed/input/result interface";
    let reflected = X.reflect native in
    { source; seeds = !seeds; inputs; operations; native; reflected; output_types; fuel = 64 + 6 * X.depth reflected }
  ) execution.branches in
  { expressions; branches }

let replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions witness =
  try derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions =
  let witness = derive component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions in
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions witness) then
    invalid_arg "the complete native SSA state wiring did not replay";
  witness

let cell_json cell = `Assoc ["key", `String (D.lean_origin cell.key);
  "source_type", `String (P.reflect cell.source_type); "candidate_shape", `String (P.lean cell.shape);
  "available", `String (C.selection cell.available);
  "ssa_variable", `Int (Q.FVarId.to_int cell.variable.id); "native_type", `String (N.pure cell.variable.ty)]
let report component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions witness =
  if not (replay component projection inputs expression forward protocol wiring defaults execution full_abi payload expressions witness) then
    invalid_arg "native SSA state report lost its entire source/default/helper witness";
  `Assoc ["schema", `String "native-selected-view-ending-ssa-lowering/v1";
    "branches", `List (List.map (fun branch -> `Assoc [
      "target", `Int (RegionGroupId.to_int branch.source.target);
      "initial_post_forward_current_arguments", `List (List.map cell_json branch.seeds);
      "incoming_arguments", `List (List.map (fun ((helper : X.helper), (variable : Q.fvar)) -> `Assoc [
        "port", `String (W.lean_port helper.source.incoming.access.port);
        "ssa_variable", `Int (Q.FVarId.to_int variable.Q.id)]) branch.inputs);
      "ordered_operations", `List (List.map (fun operation ->
        let details = match operation.action with
          | Bind (target, source) -> ["target", cell_json target; "reads_ssa", `Int (Q.FVarId.to_int source.id)]
          | Read (source, observed) -> ["current", cell_json source; "observation_ssa", `Int (Q.FVarId.to_int observed.id)]
          | Output (helper, current, incoming, output, _) -> ["helper_channel", `Int helper.index;
              "incoming", cell_json incoming; "current", (match current with None -> `Null | Some cell -> cell_json cell);
              "output_ssa", `Int (Q.FVarId.to_int output.id)] in
        `Assoc (["kind", `String (E.kind_name operation.original.kind);
          "port", `String (W.lean_port operation.original.access.port)] @ details)) branch.operations);
      "native_arrow", `String (N.pure branch.native.ty);
      "complete_native_ast", `String (X.lean_term branch.reflected);
      "interpreter_fuel", `Int branch.fuel]) witness.branches);
    "foreign_defaults_use_proposed_selected_view_machine_rule", `Bool true;
    "missing_versions_chased_to_earlier_origins", `Bool false;
    "unselected_received_fields_promoted_to_authority", `Bool false;
    "ordinary_rust_results_supplied", `Bool false;
    "original_native_current_environment_adequacy_proved", `Bool false;
    "original_native_default_activation_continuation_adequacy_proved", `Bool false;
    "original_native_complete_signature_effect_adequacy_proved", `Bool false;
    "original_source_heap_loan_layout_adequacy_proved", `Bool false;
    "pinned_nested_mutable_adt_guard_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import qualification.aeneas.cases.NativePureExpressions";
  line "/- Native SSA lowering of the explicit ending model. Unelaborated/unqualified.";
  line "   Foreign-default selection is proposed; original native environment/continuation/heap adequacy remains open. -/";
  line "namespace Auths.Qualification.NativeCurrentWiring";
  line "open Auths.Support.NativePurePayload Auths.Support.NativePureExpressions";
  line "open Auths.Qualification.NativePureExpressions";
  line "universe u";
  let payload = "Auths.Qualification.NativePurePayload." in
  let counter = payload ^ "branch0Channel0" and writer = payload ^ "branch2Channel0" in
  let helpers = witness.expressions.helpers in
  let counter_layout = (List.find (fun (helper : X.helper) -> RegionGroupId.to_int helper.group = 0 && helper.index = 0) helpers).source.outgoing.layout in
  let writer_layout = (List.find (fun (helper : X.helper) -> RegionGroupId.to_int helper.group = 2 && helper.index = 0) helpers).source.outgoing.layout in
  let fresh = ref 0 in
  let variable () = let name = "v" ^ string_of_int !fresh in incr fresh; name in
  let rec cases indent name layout finish =
    let add text = line (String.make indent ' ' ^ text) in
    match layout with
    | N.Empty -> add ("cases " ^ name)
    | N.Atom _ -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| atom " ^ value ^ " =>"); finish (indent + 2)
    | N.Unit -> add ("cases " ^ name ^ " with"); add "| unit =>"; finish (indent + 2)
    | N.Named (_, body) -> let value = variable () in add ("cases " ^ name ^ " with"); add ("| named " ^ value ^ " =>"); cases (indent + 2) value body finish
    | N.Product (left, right) -> let first = variable () and second = variable () in
        add ("cases " ^ name ^ " with"); add ("| product " ^ first ^ " " ^ second ^ " =>");
        cases (indent + 2) first left (fun indent -> cases indent second right finish)
    | N.Sum (left, right) -> let first = variable () and second = variable () in
        add ("cases " ^ name ^ " with"); add ("| left " ^ first ^ " =>"); cases (indent + 2) first left finish;
        add ("| right " ^ second ^ " =>"); cases (indent + 2) second right finish in
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.source.target in
    let inputs = List.mapi (fun index (helper, _) -> index, helper) branch.inputs in
    let channel (helper : X.helper) = payload ^ name ^ "Channel" ^ string_of_int helper.index in
    let args = String.concat " " (List.map (fun (index, helper) ->
      "(incoming" ^ string_of_int index ^ " : Value Atom " ^ channel helper ^ "Layout)") inputs) in
    let names = String.concat " " (List.map (fun (index, _) -> "incoming" ^ string_of_int index) inputs) in
    line ("def " ^ name ^ " : Term := " ^ X.lean_term branch.reflected);
    line ("def " ^ name ^ "Fuel : Nat := " ^ string_of_int branch.fuel);
    line ("theorem " ^ name ^ "_well_typed : check builtins schemas " ^ name ^ "Fuel [] " ^ name ^ " = true := by decide");
    let arguments = List.map (fun cell -> match cell.key with
      | B.Borrow id when V.BorrowId.to_int id = 0 -> "pack " ^ name ^ "Fuel counter"
      | B.Symbolic id when V.SymbolicValueId.to_int id = 6 -> "pack " ^ name ^ "Fuel writer"
      | _ -> invalid_arg "a new actual initial current needs its explicit typed Lean binder and forward codec") branch.seeds @
      List.map (fun (index, _) -> "pack " ^ name ^ "Fuel incoming" ^ string_of_int index) inputs in
    let binders = "(Atom : Ty → Type u) (counter : Value Atom " ^ counter ^ "Layout) (writer : Value Atom " ^ writer ^ "Layout) " ^ args in
    line ("def " ^ name ^ "Run " ^ binders ^ " : Option (Dynamic Atom) :=");
    line ("  executePacked builtins schemas " ^ name ^ "Fuel " ^ name ^ " [" ^ String.concat ", " arguments ^ "]");
    line ("def " ^ name ^ "Expected " ^ binders ^ " : Option (Dynamic Atom) :=");
    line ("  expectedMany builtins [" ^ String.concat ", " (List.map N.pure branch.output_types) ^ "] (do");
    line ("    let outputs ← Auths.Qualification.NativeBorrowFullABI." ^ name ^ "FullFromEndingState");
    line ("      (SourceAtom " ^ payload ^ "atomTyping Atom) (decode " ^ counter ^ "OutgoingCodec counter) (decode " ^ writer ^ "OutgoingCodec writer)");
    line ("      " ^ String.concat " " (List.map (fun (index, helper) -> "(decode " ^ channel helper ^ "IncomingCodec incoming" ^ string_of_int index ^ ")") inputs));
    let outputs = List.filter_map (fun operation -> match operation.action with Output (helper, _, _, _, _) -> Some helper | _ -> None) branch.operations in
    line ("    pure [" ^ String.concat ", " (List.mapi (fun index helper ->
      "pack " ^ name ^ "Fuel (encode " ^ channel helper ^ "OutgoingCodec " ^
        (if List.length outputs = 1 then "outputs" else "outputs." ^ string_of_int (index + 1)) ^ ")") outputs) ^ "])");
    line ("theorem " ^ name ^ "_executes_explicit_ending_model " ^ binders ^ " :");
    line ("    " ^ name ^ "Run Atom counter writer " ^ names ^ " = " ^ name ^ "Expected Atom counter writer " ^ names ^ " := by");
    line ("  unfold " ^ name ^ "Run");
    line ("  rw [checked_packed_runs_body builtins schemas " ^ name ^ "Fuel " ^ name ^ " " ^ name ^ "_well_typed]");
    let rec input_cases indent = function
      | [] -> line (String.make indent ' ' ^ "rfl")
      | (index, helper) :: rest -> cases indent ("incoming" ^ string_of_int index) helper.X.source.incoming.layout (fun indent -> input_cases indent rest) in
    cases 2 "counter" counter_layout (fun indent -> cases indent "writer" writer_layout (fun indent -> input_cases indent inputs))
  ) witness.branches;
  line "end Auths.Qualification.NativeCurrentWiring";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
