(* Complete algebraic whole-root trace programs. A constructed candidate body
   does not qualify the original ABI, continuation or Rust source semantics. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.Pure
module K = Aeneas.SymbolicToPureBindings
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module C = Native_root_payload
module R = Native_root_bindings
module G = Current_borrow_carrier
module D = Native_borrow_defaults
module O = Native_owned_bindings
module A = Native_foreign_defaults
module H = Native_payload_layout
module L = Native_root_updates
module X = Native_root_expressions
module T = Native_type_syntax

type role = Initialize of V.symbolic_value_id | Given of W.port | Frame
type definition = { role : role; result : Q.fvar; captures : Q.fvar list;
  value : Q.texpr; code : X.term }
type source_action = Initial of Native_root_origins.alias | Own of R.binding * int
  | Foreign of V.symbolic_value_id * V.symbolic_value_id
  | Update of int * string * string * L.t * V.symbolic_value_id
  | Save of C.slot * string
type step = Define of definition | Consume of W.port * Q.fvar | Output of int * Q.fvar
type ending = { event : W.event; steps : step list }
type branch = { target : region_group_id; parents : region_group_id list; inputs : Q.fvar list;
  parameters : Q.generic_params; predicates : Q.predicates;
  forward : (int * Q.fvar * C.root) list; arguments : O.argument list;
  symbols : (V.symbolic_value_id * Q.fvar) list; initialization : definition list;
  endings : ending list; outputs : (C.slot * Q.fvar) list; source : source_action list;
  native : Q.texpr; code : X.term }
type t = { candidate : int; types : (ty * Q.ty) list; branches : branch list;
  function_type : Q.ty; payload_type : Q.ty; may_fail : bool; native : Q.texpr; code : X.term }
let port = function Define { role = Given port; _ } | Consume (port, _) -> Some port | _ -> None
let sid = B.sid
let symbol identity = "symbol" ^ sid identity
let frame index ordinal = "frame" ^ B.nat index ^ "Version" ^ B.nat ordinal
let slot_name slot = "outputLevel" ^ B.nat slot.C.level ^ "Position" ^ B.nat slot.position
let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign owned =
  if not (O.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes owned) ||
      not (A.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign) then
    invalid_arg "whole-root trace needs every exact owned/foreign source, scope, argument and expression witness";
  let context = Aeneas.Interp.compute_contexts component in
  let span = projection.P.candidate.item_meta.span in
  let root index = match List.filter (fun (root : C.root) -> root.source.index = Some index) payload.C.roots with
    | [root] -> root | _ -> invalid_arg "a whole-root program lost an original source input carrier" in
  let source_bind identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.F.source_bindings with
    | [binding] -> binding | _ -> invalid_arg "a whole-root program lacks one original forward symbol" in
  let branches = List.map (fun (branch : R.branch) ->
    let owned = match List.filter (fun (actual : O.branch) -> actual.target = branch.target) owned.O.branches with
      | [actual] -> actual | _ -> invalid_arg "a whole-root program lost its original whole argument declarations" in
    let foreign = match List.filter (fun (actual : A.branch) -> actual.target = branch.target) foreign.A.branches with
      | [actual] -> actual | _ -> invalid_arg "a whole-root program lost exact strict ancestor default lets" in
    let scoped = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) defaults.D.branches with
      | [actual] -> actual | _ -> invalid_arg "a whole-root program lost selected ownership metadata" in
    let _, fresh_fvar_id = Q.FVarId.fresh_stateful_generator () in
    for _ = 1 to owned.declarations.next do ignore (fresh_fvar_id ()) done;
    let state = ref { (A.query_state span owned.declarations) with fresh_fvar_id } in
    let variable identity expected =
      match V.SymbolicValueId.Map.find_opt identity !state.K.sv_to_var with
      | Some variable when variable.ty = expected -> variable
      | _ -> invalid_arg "a whole-root read requires the exact immediate source/native declaration" in
    let forward_inputs = List.mapi (fun index (input : V.symbolic_value) ->
      let root = root index in index, variable input.sv_id root.native_type, root) forward.inputs in
    let inputs = List.map (fun (_, variable, _) -> variable) forward_inputs @ List.map (fun (argument : O.argument) -> argument.variable) owned.arguments in
    if List.map (fun (_, (variable : Q.fvar), _) -> variable.ty) forward_inputs <> signature.Native_backward_types.signature.dsg.fun_ty.fwd_inputs then
      invalid_arg "a whole-root program changed the complete original forward input interface";
    let available = ref (List.map (fun (variable : Q.fvar) -> variable.id) inputs) in
    if List.length !available <> List.length (List.sort_uniq compare !available) then invalid_arg "a whole-root parameter shadows another current argument";
    let all_definitions = ref [] and source = ref [] in
    let definition role (result : Q.fvar) value =
      if List.mem result.id !available then invalid_arg "an SSA source version/current frame cannot be rebound";
      K.check_default_expression result.id value !state;
      let captures = ref [] in
      let visitor = object inherit [_] Q.iter_expr
        method! visit_FVar _ identity = captures := identity :: !captures
      end in visitor#visit_texpr () value;
      let captures = List.sort_uniq compare !captures |> List.map (fun identity ->
        if not (List.mem identity !available) then invalid_arg "a declared future native variable is not an available runtime value";
        match Q.FVarId.Map.find_opt identity !state.fvars with
        | Some variable -> variable | None -> invalid_arg "an SSA capture lost its actual native declaration") in
      let closed = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) captures) value in
      let definition = { role; result; captures; value; code = X.reflect closed } in
      available := !available @ [result.id]; all_definitions := !all_definitions @ [definition]; definition in
    let fresh (value : Q.texpr) =
      let after, result = K.fresh_var None value.Q.ty !state in state := after;
      result, definition Frame result value in
    let initialization = List.filter_map (fun (alias : Native_root_origins.alias) ->
      let original = source_bind alias.source.native.sv_id in
      let root = root alias.input in
      let input = match List.filter (fun (index, _, _) -> index = alias.input) forward_inputs with
        | [_, variable, _] -> variable | _ -> invalid_arg "a forward expansion lost its actual original argument" in
      let native_type = S.translate_fwd_ty (Some span) context original.source_type in
      let result = variable original.native.sv_id native_type in
      source := !source @ [Initial alias];
      if List.mem result.id (List.map (fun (_, (variable : Q.fvar), _) -> variable.id) forward_inputs) then (
        if alias.focus <> G.Here || result <> input then invalid_arg "a direct forward parameter changed its original source identity";
        None)
      else (
        let helper, _ = R.compile_projection span payload.environment root native_type alias.focus in
        let value = U.mk_apps __FILE__ __LINE__ span helper [U.mk_texpr_from_fvar input] in
        Some (definition (Initialize original.native.sv_id) result value))) origins.Native_root_origins.aliases in
    let frames = ref (List.map (fun (index, variable, _) -> index, (variable, "forward" ^ B.nat index)) forward_inputs) in
    let outputs = ref [] and ordinal = ref 0 in
    let output_slots = List.filter (fun (slot : C.slot) -> slot.group = branch.target && not slot.input) payload.slots in
    let exact_origin port = match List.filter (fun action -> (R.port action).original = port) branch.actions with
      | [action] -> R.port action | _ -> invalid_arg "a whole-root step lost an exact actual source port" in
    let producer port = match List.filter (fun (producer : D.default) -> producer.value.sv_id = port.W.value.sv_id) scoped.defaults with
      | [producer] -> producer | _ -> invalid_arg "a whole-root step lost its exact immediate selected producer" in
    let endings = List.mapi (fun event_index (ending : R.ending) ->
      let steps = ref [] in
      List.iter (fun (port : W.port) ->
        let producer = producer port in
        let native_type = S.translate_fwd_ty (Some span) context port.value.sv_ty in
        let result = variable port.value.sv_id native_type in
        if port.given_back then (
          let value = if port.group = branch.target then (
            match List.filter (fun (assignment : O.assignment) -> assignment.binding.port.original = port) owned.assignments with
            | [assignment] when assignment.result = result ->
                let position = match List.mapi (fun index actual -> index, actual) owned.arguments |> List.filter (fun (_, actual) -> actual = assignment.argument) with
                  | [position, _] -> position | _ -> invalid_arg "a given value lost its existing whole argument slot" in
                source := !source @ [Own (assignment.binding, position)]; assignment.value
            | _ -> invalid_arg "a whole-root given value lacks its actual native argument projection")
          else (
            if not (List.mem port.group foreign.parents) then invalid_arg "a whole-root default is outside actual strict source ancestry";
            match List.filter (fun (binding : A.binding) -> binding.event = event_index && binding.port = port) foreign.bindings with
            | [binding] when binding.variable = result ->
                let source_identity = match binding.value.e with
                  | Q.FVar identity ->
                      (match List.filter (fun (_, (variable : Q.fvar)) -> variable.id = identity) owned.declarations.symbols with
                       | [symbol, _] -> symbol | _ -> invalid_arg "a foreign source spec lacks its exact immediate symbolic operand")
                  | _ -> invalid_arg "a foreign default needs an independent complete source expression compiler" in
                let source_shape = match List.filter (fun (actual : D.default) -> actual.value.sv_id = source_identity) scoped.defaults with
                  | [actual] -> actual.candidate_shape | [] -> (source_bind source_identity).shape
                  | _ -> invalid_arg "a foreign source spec has ambiguous current value shapes" in
                if source_shape <> producer.candidate_shape then invalid_arg "foreign source value conversion needs an exact source codec adapter";
                source := !source @ [Foreign (port.value.sv_id, source_identity)]; binding.value
            | _ -> invalid_arg "a whole-root given value lost its actual foreign default let") in
          steps := !steps @ [Define (definition (Given port) result value)]
        ) else (
          if not (List.mem result.id !available) then invalid_arg "a consumed current variable has only a declaration, not an available value";
          steps := !steps @ [Consume (port, result)];
          if port.group = branch.target then (
            let origin = exact_origin port in
            let root = root origin.alias.input in
            let current, previous = match List.assoc_opt origin.alias.input !frames with Some frame -> frame
              | None -> invalid_arg "a consumed value has no actual current whole carrier frame" in
            let helper = L.create context span payload.environment root origin.alias.focus producer in
            if helper.native_type <> result.ty then invalid_arg "a consumed given value changed its complete native field type";
            let value = U.mk_apps __FILE__ __LINE__ span helper.native [U.mk_texpr_from_fvar current; U.mk_texpr_from_fvar result] in
            let next, update = fresh value in
            steps := !steps @ [Define update];
            let name = frame origin.alias.input !ordinal in incr ordinal;
            source := !source @ [Update (origin.alias.input, name, previous, helper, port.value.sv_id)];
            frames := List.map (fun (index, original) -> index, if index = origin.alias.input then (next, name) else original) !frames
          )
        )
      ) ending.event.ports;
      let consumed = List.exists (fun (port : W.port) -> port.group = branch.target && not port.given_back) ending.event.ports in
      if consumed then List.iteri (fun index slot -> if slot.C.level = ending.event.level then (
        if List.exists (fun (actual, _) -> O.same_slot actual slot) !outputs then invalid_arg "a backward output slot was saved at two ending events";
        let output, expression = match slot.root.source.index with
          | Some input -> (match List.assoc_opt input !frames with Some (variable, name) -> variable, name
              | None -> invalid_arg "a backward output lost its actual current input carrier")
          | None ->
              let values = List.map (fun index -> match List.assoc_opt index !frames with Some (variable, _) -> U.mk_texpr_from_fvar variable
                | None -> invalid_arg "a capture output omitted an actual original input") projection.capture.moved_inputs in
              let fields = R.structure_fields payload.environment slot.root.native_type in
              if List.map (fun (field : Q.field) -> field.field_ty) fields <> List.map (fun (value : Q.texpr) -> value.ty) values then
                invalid_arg "a capture output changed complete source field order, types or dictionaries";
              let variable, capture = fresh (U.mk_adt_texpr span slot.root.native_type None values) in
              steps := !steps @ [Define capture];
              let expression = "Auths.Qualification.BorrowProjection.Candidate" ^ B.nat (FunDeclId.to_int projection.candidate.def_id) ^
                ".construct (SourceAtom Auths.Qualification.NativeRootPayload.atomTyping Atom) " ^
                String.concat " " (List.map (fun (input, _, _) -> match List.assoc_opt input !frames with Some (_, name) -> name
                  | None -> invalid_arg "source capture expression lost a current input") forward_inputs) in
              variable, expression in
        if output.ty <> slot.root.native_type then invalid_arg "a saved whole output changed its declared signature type";
        outputs := !outputs @ [slot, output]; source := !source @ [Save (slot, expression)]; steps := !steps @ [Output (index, output)]
      )) output_slots;
      if List.filter_map port !steps <> ending.event.ports then invalid_arg "a whole-root trace dropped, duplicated or reordered an actual ending port";
      { event = ending.event; steps = !steps }) branch.endings in
    let outputs = List.map (fun slot -> match List.filter (fun (actual, _) -> O.same_slot actual slot) !outputs with
      | [actual] -> actual | _ -> invalid_arg "a whole-root program omitted an original complete backward output slot") output_slots in
    let body = U.mk_simpl_tuple_texpr span (List.map (fun (_, variable) -> U.mk_texpr_from_fvar variable) outputs) in
    let body = U.mk_closed_lets span false (List.map (fun definition -> U.mk_tpat_from_fvar None definition.result, definition.value) !all_definitions) body in
    let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) inputs) body in
    let expected = U.mk_arrows (List.map (fun (input : Q.fvar) -> input.ty) inputs)
      (U.mk_simpl_tuple_ty (List.map (fun (slot, _) -> slot.C.root.native_type) outputs)) in
    if native.ty <> expected then invalid_arg "a whole-root program changed its complete forward/whole-backward argument or output interface";
    let groups = RegionGroupId.Map.bindings signature.signature.dsg.fun_ty.back_sg in
    let actual = List.combine groups (S.compute_back_tys_with_info signature.signature.dsg.fun_ty) |>
      List.filter (fun ((group, _), _) -> group = branch.target) in
    (match actual with
     | [(_, Some (_, back_type))] when native.ty = U.mk_arrows (List.map (fun (_, (input : Q.fvar), _) -> input.ty) forward_inputs) back_type -> ()
     | _ -> invalid_arg "a candidate branch must have the actual complete native backward API type, not an independently flattened interface");
    let code = X.reflect native in
    { target = branch.target; parents = foreign.parents; inputs; forward = forward_inputs; arguments = owned.arguments;
      parameters = signature.signature.dsg.generics; predicates = signature.signature.dsg.preds;
      symbols = owned.declarations.symbols; initialization; endings; outputs; source = !source; native; code }
  ) bindings.R.branches in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "whole-root compilation has unresolved original diagnostics";
  let types = List.concat_map (fun (branch : W.branch) -> List.concat_map (fun (event : W.event) -> List.map (fun (port : W.port) -> port.value.sv_ty) event.ports) branch.events) wiring.W.branches |>
    List.sort_uniq compare |> List.map (fun source -> source, S.translate_fwd_ty (Some span) context source) in
  let first = match branches with first :: _ -> first | [] -> invalid_arg "a complete capture function has no original backward branches" in
  let forward_variables = List.map (fun (_, variable, _) -> variable) first.forward in
  let forward_values = List.map U.mk_texpr_from_fvar forward_variables in
  let forward_root = match List.filter (fun (root : C.root) -> root.source.index = None) payload.roots with
    | [root] -> root | _ -> invalid_arg "a complete native capture function lost its original forward result carrier" in
  let fields = R.structure_fields payload.environment forward_root.native_type in
  let captured = List.map (fun index -> match List.nth_opt forward_values index with Some value -> value
    | None -> invalid_arg "a forward capture constructor omitted an original moved input") projection.capture.moved_inputs in
  if List.map (fun (field : Q.field) -> field.field_ty) fields <> List.map (fun (value : Q.texpr) -> value.ty) captured then
    invalid_arg "the complete forward result changed original capture field order/types";
  let forward_result = U.mk_adt_texpr span forward_root.native_type None captured in
  let backwards = List.map (fun branch ->
    if List.map (fun (_, (variable : Q.fvar), _) -> variable.ty) branch.forward <> List.map (fun (variable : Q.fvar) -> variable.ty) forward_variables then
      invalid_arg "backward closure factories disagree on an original forward parameter";
    U.mk_apps __FILE__ __LINE__ span branch.native forward_values) branches in
  let body = U.mk_simpl_tuple_texpr span (forward_result :: backwards) in
  let payload_type = body.ty and may_fail = signature.signature.dsg.fun_ty.fwd_info.effect_info.can_fail in
  let body = if may_fail then
      U.mk_result_ok_texpr span body else body in
  let native = U.mk_closed_lambdas span (List.map (U.mk_tpat_from_fvar None) forward_variables) body in
  if native.ty <> signature.signature.ty then
    invalid_arg "the complete native capture body does not have the actual original function API's full arrow type";
  { candidate = FunDeclId.to_int projection.candidate.def_id; types; branches;
    function_type = signature.signature.ty; payload_type; may_fail; native; code = X.reflect native }
let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign owned witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign owned = witness
  with Invalid_argument _ | Not_found -> false
let create = derive
let lean_role = function Initialize identity -> ".initialize " ^ sid identity | Frame -> ".frame"
  | Given port -> ".given (" ^ W.lean_port port ^ ")"
let lean_variable_with_type print_type (variable : Q.fvar) =
  "{ identity := " ^ B.nat (Q.FVarId.to_int variable.id) ^ ", type := " ^ print_type variable.ty ^ " }"
let lean_definition_with_type print_type definition = "{ role := " ^ lean_role definition.role ^ ", result := " ^ (lean_variable_with_type print_type) definition.result ^
  ", captures := " ^ B.list (lean_variable_with_type print_type) definition.captures ^ ", code := " ^ X.lean_with_type print_type definition.code ^ " }"
let lean_step_with_type print_type = function
  | Define definition -> ".define (" ^ lean_definition_with_type print_type definition ^ ")"
  | Consume (port, variable) -> ".consume (" ^ W.lean_port port ^ ") (" ^ (lean_variable_with_type print_type) variable ^ ")"
  | Output (index, variable) -> ".output " ^ B.nat index ^ " (" ^ (lean_variable_with_type print_type) variable ^ ")"
let fuel (branch : branch) = 96 + 16 * max (X.depth branch.code)
  (max (T.depth (T.reflect_parameters branch.parameters)) (T.depth (T.reflect_predicates branch.predicates)))
let lean_program_with_type print_type print_syntax types branch = "{ target := " ^ B.gid branch.target ^ ", parents := " ^ B.list B.gid branch.parents ^
  ", fuel := " ^ B.nat (fuel branch) ^ ", parameters := " ^ print_syntax (T.reflect_parameters branch.parameters) ^
  ", predicates := " ^ print_syntax (T.reflect_predicates branch.predicates) ^ ", inputs := " ^ B.list (lean_variable_with_type print_type) branch.inputs ^
  ", forwardSymbols := " ^ B.list (function Initial alias -> sid alias.Native_root_origins.source.native.sv_id
    | _ -> invalid_arg "a forward source roster cannot contain an ending") (List.filter (function Initial _ -> true | _ -> false) branch.source) ^
  ", symbols := " ^ B.list (fun (identity, variable) -> "(" ^ sid identity ^ ", " ^ (lean_variable_with_type print_type) variable ^ ")") branch.symbols ^
  ", types := " ^ B.list (fun (source, native) -> "(" ^ P.reflect source ^ ", " ^ print_type native ^ ")") types ^
  ", initialization := " ^ B.list (lean_definition_with_type print_type) branch.initialization ^
  ", endings := " ^ B.list (fun ending -> "{ event := " ^ W.lean_event ending.event ^ ", steps := " ^ B.list (lean_step_with_type print_type) ending.steps ^ " }") branch.endings ^
  ", outputTypes := " ^ B.list (fun (slot, _) -> print_type slot.C.root.native_type) branch.outputs ^
  ", outputs := " ^ B.list (fun (_, variable) -> (lean_variable_with_type print_type) variable) branch.outputs ^ " }"
let lean_program = lean_program_with_type T.pure T.lean
let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign owned witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes foreign owned witness) then
    invalid_arg "a complete whole-root trace lost its exact original ports, current values, updates or outputs";
  `Assoc ["schema", `String "actual-native-whole-root-complete-ending-programs/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "complete_native_parameters", `String (Q.show_generic_params branch.parameters);
      "complete_native_predicates", `String (Q.show_predicates branch.predicates);
      "forward_parameters", `Int (List.length branch.forward); "whole_backward_parameters", `Int (List.length branch.arguments);
      "original_endings", `Int (List.length branch.endings); "original_ports", `Int (List.fold_left (fun n ending -> n + List.length ending.event.ports) 0 branch.endings);
      "whole_backward_outputs", `Int (List.length branch.outputs);
      "complete_program", `String (lean_program witness.types branch);
      "complete_closed_native_branch", `String (Q.show_texpr branch.native);
      "reflected_closed_branch", `String (X.lean branch.code)]) witness.branches);
    "all_original_ending_ports_and_empty_events_retained", `Bool true;
    "complete_original_source_generics", `String (show_generic_params projection.P.candidate.generics);
    "candidate_complete_function_type", `String (Q.show_ty witness.function_type);
    "original_forward_failure_effect_retained", `Bool witness.may_fail;
    "complete_function_result_payload_type", `String (Q.show_ty witness.payload_type);
    "candidate_complete_function_body", `String (Q.show_texpr witness.native);
    "candidate_complete_function_code", `String (X.lean witness.code);
    "candidate_function_and_each_backward_closure_match_actual_native_signature_API", `Bool true;
    "native_generics_and_predicates_retained_not_assumed_discharged", `Bool true;
    "declared_future_variables_are_runtime_values", `Bool false;
    "consumption_uses_immediate_assigned_variable_not_static_origin_or_old_default", `Bool true;
    "carrier_frames_update_from_actual_consumed_values_preserving_unselected_fields", `Bool true;
    "whole_outputs_snapshot_actual_frames_at_original_ending_levels", `Bool true;
    "ordinary_function_results_or_per_port_caller_values_supplied", `Bool false;
    "candidate_whole_nominal_ABI_and_source_version_correspondence_proved", `Bool false;
    "original_EndAbs_context_heap_loan_layout_and_dynamic_writer_adequacy_proved", `Bool false;
    "original_forward_type_or_ending_guard_removed", `Bool false;
    "original_nested_forward_declaration_guard_extended_by_complete_field_checker", `Bool true;
    "complete_original_native_function_extraction_established", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path payload witness =
  let output = Buffer.create 1048576 in
  let line value = Buffer.add_string output (value ^ "\n") in
  let carrier = "Auths.Qualification.NativeRootPayload." in
  line "import Auths.Support.NativeRootPrograms";
  line "import qualification.aeneas.cases.NativeOwnedBindings";
  line "import qualification.aeneas.cases.NativeBorrowWiring";
  line "/- Complete candidate whole-root trace bodies, unelaborated/unqualified.";
  line "   Original EndAbs/ABI/source environment/heap/loan/dynamic-writer adequacy remains open. -/";
  line "namespace Auths.Qualification.NativeRootPrograms";
  line "open Auths.Support.NativeRootPayload Auths.Support.NativeRootExpressions Auths.Support.NativeRootPrograms";
  line "universe u";
  (* Transparent syntax definitions share repeated complete type trees. The
     order is deterministic postorder; every child is emitted before its use.
     They remain ordinary reducible definitions, not opaque type assumptions. *)
  let shared = Hashtbl.create 256 and next = ref 0 and registering = ref true in
  let rec print_syntax syntax = match syntax with
    | T.Natural _ | T.Integer _ | T.Bytes _ -> T.lean syntax
    | T.Node (tag, children) ->
        match Hashtbl.find_opt shared syntax with
        | Some name -> name
        | None ->
            if not !registering then invalid_arg "complete native syntax was not interned before declaration emission";
            let children = List.map print_syntax children in
            let name = "nativeSyntax" ^ B.nat !next in
            incr next;
            line ("private def " ^ name ^ " : NativeType := .node ." ^ tag ^ " [" ^
              String.concat ", " (List.map (fun child -> "(" ^ child ^ ")") children) ^ "]");
            Hashtbl.add shared syntax name;
            name in
  let type_names = Hashtbl.create 128 in
  let print_type native = match Hashtbl.find_opt type_names native with
    | Some name -> name
    | None -> let name = print_syntax (T.reflect native) in
        Hashtbl.add type_names native name; name in
  let remember native = ignore (print_type native) in
  remember witness.function_type; remember witness.payload_type;
  X.iter_types remember witness.code;
  List.iter (fun (_, native) -> remember native) witness.types;
  List.iter (fun branch ->
    ignore (print_syntax (T.reflect_parameters branch.parameters));
    ignore (print_syntax (T.reflect_predicates branch.predicates));
    X.iter_types remember branch.code;
    List.iter (fun (variable : Q.fvar) -> remember variable.ty) branch.inputs;
    List.iter (fun (_, (variable : Q.fvar)) -> remember variable.ty) branch.symbols;
    let definition item =
      remember item.result.ty;
      List.iter (fun (variable : Q.fvar) -> remember variable.ty) item.captures;
      X.iter_types remember item.code in
    List.iter definition branch.initialization;
    List.iter (fun ending -> List.iter (function
      | Define item -> definition item
      | Consume (_, variable) | Output (_, variable) -> remember variable.ty) ending.steps) branch.endings;
    List.iter (fun (slot, (variable : Q.fvar)) -> remember slot.C.root.native_type; remember variable.ty) branch.outputs
  ) witness.branches;
  registering := false;
  let print_term = X.lean_with_type print_type in
  line ("def schemas : List Schema := " ^ B.list C.lean_schema payload.C.environment.schemas);
  line ("def completeFunctionCode : Term := " ^ print_term witness.code);
  line ("def completePayloadType : NativeType := " ^ print_type witness.payload_type);
  line ("def originalForwardMayFail : Bool := " ^ B.bool witness.may_fail);
  line "theorem complete_candidate_function_has_the_exact_original_native_API_arrow :";
  line "    completeFunctionCode.type = Auths.Qualification.NativeBackwardTypes.actualNativeArrow := by rfl";
  let complete_fuel = 96 + 16 * X.depth witness.code in
  line ("theorem complete_candidate_function_is_closed_and_typed : Auths.Support.NativeRootExpressions.check schemas " ^ B.nat complete_fuel ^ " [] completeFunctionCode = true := by decide");
  (match witness.branches with
   | [] -> invalid_arg "a forward function proof lost the original forward environment"
   | first :: _ ->
       let arguments = List.map (fun (index, _, root) -> "forward" ^ B.nat index, root) first.forward in
       let depth = B.nat complete_fuel in
       line "theorem complete_candidate_forward_result_matches_actual_source_capture (Atom : NativeType → Type u)";
       List.iter (fun (name, root) -> line ("    (" ^ name ^ " : Auths.Support.BorrowProjection.Data (SourceAtom " ^ carrier ^
         "atomTyping Atom) " ^ carrier ^ C.root_name root ^ "Shape)")) arguments;
       line ("    : runForward schemas " ^ depth ^ " completeFunctionCode originalForwardMayFail completePayloadType " ^
         B.list (fun (name, root) -> "pack " ^ depth ^ " (encode " ^ carrier ^ C.root_name root ^ "Codec " ^ name ^ ")") arguments ^ " =");
       let output = match List.filter (fun (root : C.root) -> root.source.index = None) payload.C.roots with
         | [root] -> root | _ -> invalid_arg "a forward result proof needs its actual complete source output carrier" in
       line ("      pack " ^ depth ^ " (encode " ^ carrier ^ C.root_name output ^ "Codec (Auths.Qualification.BorrowProjection.Candidate" ^
         B.nat witness.candidate ^ ".construct (SourceAtom " ^ carrier ^ "atomTyping Atom) " ^ String.concat " " (List.map fst arguments) ^ ")) := by");
       let rec cases indent = function [] -> line (indent ^ "rfl") | (name, root) :: rest ->
         R.emit_data_cases line indent name root.C.source.shape (fun indent -> cases indent rest) in
       cases "  " arguments);
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target and depth = B.nat (fuel branch) in
    let source = "Auths.Qualification.NativeBorrowWiring." ^ name in
    line ("def " ^ name ^ " : Program := " ^ lean_program_with_type print_type print_syntax witness.types branch);
    line ("def " ^ name ^ "Code : Term := " ^ print_term branch.code);
    line ("theorem " ^ name ^ "_retains_complete_parameter_and_predicate_context :");
    line ("    " ^ name ^ ".parameters = Auths.Qualification.NativeBackwardTypes.actualNativeParameters ∧");
    line ("    " ^ name ^ ".predicates = Auths.Qualification.NativeBackwardTypes.actualNativePredicates := by constructor <;> rfl");
    line ("theorem " ^ name ^ "_has_exactly_the_complete_forward_and_whole_backward_inputs :");
    line ("    " ^ name ^ ".inputs.map (·.type) = Auths.Qualification.NativeBackwardTypes.actualNativeForwardInputs ++");
    line ("      Auths.Qualification.NativeBackwardTypes.group" ^ B.gid branch.target ^ "Inputs.flatMap (·.2) := by rfl");
    line ("theorem " ^ name ^ "_has_every_complete_backward_output_type :");
    line ("    " ^ name ^ ".outputTypes = Auths.Qualification.NativeBackwardTypes.group" ^ B.gid branch.target ^ "Outputs.flatMap (·.2) := by rfl");
    line ("theorem " ^ name ^ "_retains_every_actual_event_port_and_whole_output : Auths.Support.NativeRootPrograms.check schemas " ^ source ^ " " ^ name ^ " = true := by decide");
    line ("theorem " ^ name ^ "_source_port_roster_is_exact : visitedPorts " ^ name ^ " = " ^ source ^ ".events.flatMap (·.ports) := by rfl");
    line ("theorem " ^ name ^ "_complete_native_branch_is_closed_and_typed : Auths.Support.NativeRootExpressions.check schemas " ^ depth ^ " [] " ^ name ^ "Code = true := by decide");
    let forwards = List.map (fun (index, _, root) -> "forward" ^ B.nat index, root) branch.forward in
    let backwards = List.mapi (fun index (argument : O.argument) -> "argument" ^ B.nat index, argument.slot.root) branch.arguments in
    let arguments = forwards @ backwards in
    let argument_parameters = List.map (fun (name, root) -> "(" ^ name ^ " : Auths.Support.BorrowProjection.Data (SourceAtom " ^ carrier ^
      "atomTyping Atom) " ^ carrier ^ C.root_name root ^ "Shape)") arguments in
    line ("def " ^ name ^ "Spec (Atom : NativeType → Type u) " ^ String.concat " " argument_parameters ^ " : List (Option (Dynamic Atom)) :=");
    List.iter (function
      | Initial alias -> line ("  let " ^ symbol alias.source.native.sv_id ^ " := Auths.Support.CurrentBorrowCarrier.read (" ^ G.lean_focus alias.focus ^ ") forward" ^ B.nat alias.input)
      | Own (binding, argument) ->
          let focus = "Auths.Qualification.NativeRootBindings.branch" ^ B.gid branch.target ^ "Event" ^ B.nat binding.port.event ^ "Port" ^ B.nat binding.port.position ^ "Focus" in
          line ("  let " ^ symbol binding.port.original.value.sv_id ^ " := Auths.Support.CurrentBorrowCarrier.read " ^ focus ^ " argument" ^ B.nat argument)
      | Foreign (given, current) -> line ("  let " ^ symbol given ^ " := " ^ symbol current)
      | Update (_, name, previous, helper, incoming) ->
          let focus = "(" ^ G.lean_focus helper.focus ^ ")" in
          let selected = "(" ^ D.lean_plan (D.selection_plan helper.producer.candidate_shape helper.producer.selected) ^ ")" in
          line ("  let " ^ name ^ " := Auths.Support.CurrentBorrowCarrier.write " ^ focus ^ " " ^ previous ^
            " (reconstruct " ^ selected ^ " (Auths.Support.CurrentBorrowCarrier.read " ^ focus ^ " " ^ previous ^ ") " ^ symbol incoming ^ ")")
      | Save (slot, value) -> line ("  let " ^ slot_name slot ^ " := " ^ value)
    ) branch.source;
    line ("  " ^ B.list (fun (slot, _) -> "pack " ^ depth ^ " (encode " ^ carrier ^ C.root_name slot.C.root ^ "Codec " ^ slot_name slot ^ ")") branch.outputs);
    let packed = B.list (fun (name, root) -> "pack " ^ depth ^ " (encode " ^ carrier ^ C.root_name root ^ "Codec " ^ name ^ ")") arguments in
    let names = String.concat " " (List.map fst arguments) in
    let output_type = U.mk_simpl_tuple_ty (List.map (fun (slot, _) -> slot.C.root.native_type) branch.outputs) in
    let prove () =
      let rec cases indent = function
        | [] -> line (indent ^ "rfl")
        | (name, root) :: rest -> R.emit_data_cases line indent name root.C.source.shape (fun indent -> cases indent rest) in
      cases "  " arguments in
    line ("theorem " ^ name ^ "_complete_native_body_refines_independent_carrier_trace (Atom : NativeType → Type u)");
    List.iter (fun parameter -> line ("    " ^ parameter)) argument_parameters;
    line ("    : executeValues schemas " ^ depth ^ " " ^ name ^ "Code " ^ packed ^ " =");
    line ("      tupleResults (" ^ print_type output_type ^ ") (" ^ name ^ "Spec Atom " ^ names ^ ") := by"); prove ();
    line ("theorem " ^ name ^ "_explicit_runtime_refines_independent_carrier_trace (Atom : NativeType → Type u)");
    List.iter (fun parameter -> line ("    " ^ parameter)) argument_parameters;
    line ("    : runValues schemas " ^ source ^ " " ^ name ^ " " ^ packed ^ " = (" ^ name ^ "Spec Atom " ^ names ^ ").mapM id := by"); prove ();
    let index = match List.mapi (fun index (actual : branch) -> index, actual.target) witness.branches |>
      List.filter (fun (_, target) -> target = branch.target) with
      | [index, _] -> index + 1 | _ -> invalid_arg "a returned closure proof lost its actual function result position" in
    let pack_arguments values = B.list (fun (name, root) -> "pack " ^ B.nat complete_fuel ^ " (encode " ^ carrier ^ C.root_name root ^ "Codec " ^ name ^ ")") values in
    line ("theorem " ^ name ^ "_actual_returned_closure_refines_independent_carrier_trace (Atom : NativeType → Type u)");
    List.iter (fun parameter -> line ("    " ^ parameter)) argument_parameters;
    line ("    : runReturned schemas " ^ B.nat complete_fuel ^ " completeFunctionCode originalForwardMayFail completePayloadType " ^ B.nat index);
    line ("      " ^ pack_arguments forwards ^ " " ^ pack_arguments backwards ^ " =");
    line ("      tupleResults (" ^ print_type output_type ^ ") (" ^ name ^ "Spec Atom " ^ names ^ ") := by"); prove ();
    List.iteri (fun index (slot, _) ->
      line ("theorem " ^ name ^ "_output" ^ B.nat index ^ "_is_the_actual_whole_signature_slot :");
      line ("    ((Auths.Qualification.NativeBackwardTypes.group" ^ B.gid branch.target ^ "Outputs.find? (fun row => row.1 == " ^ B.nat slot.C.level ^
        ")).bind (fun row => row.2[" ^ B.nat slot.position ^ "]?)) = some (" ^ print_type slot.root.native_type ^ ") := by rfl")
    ) branch.outputs
  ) witness.branches;
  line "end Auths.Qualification.NativeRootPrograms";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
