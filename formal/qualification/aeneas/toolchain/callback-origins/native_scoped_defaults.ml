(* Lazy full-type defaults in the actual shared native registry. Preparation
   declares original current symbols; it neither supplies their values nor
   pretends to be a complete bs_ctx. Fresh result bindings remain independent. *)
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
module D = Native_default_bindings
module R = Native_root_bindings
module C = Native_root_payload
module N = Native_nested_reconstruction
module X = Native_root_expressions
module T = Native_type_syntax

type capture = { symbol : V.symbolic_value_id; variable : Q.fvar }
type entry = { symbol : V.symbolic_value_id; variable : Q.fvar; captures : capture list; native : Q.texpr; code : X.term }
type snapshot = { next : int; symbols : (V.symbolic_value_id * Q.fvar) list; variables : (Q.fvar_id * Q.fvar) list;
  types : (Q.fvar_id * Q.ty) list; defaults : (Q.fvar_id * entry) list }
type registration = { event : int; port : W.port; nested : bool; before : snapshot; after : snapshot; entry : entry }
type branch = { target : region_group_id; registrations : registration list }
type t = { reconstruction : N.t; branches : branch list }

let symbolic_for_variable (state : K.t) identity =
  match V.SymbolicValueId.Map.bindings state.sv_to_var |> List.filter (fun (_, (variable : Q.fvar)) -> variable.id = identity) with
  | [symbol, variable] -> symbol, variable
  | _ -> invalid_arg "a native default capture needs one exact current symbolic/native variable binding"
let entry span (state : K.t) variable (native : Q.texpr) =
  let symbol, variable = symbolic_for_variable state variable in
  if variable.ty <> native.Q.ty then invalid_arg "a registered native default changed its fresh target type";
  let ids = ref [] in
  let visitor = object inherit [_] Q.iter_expr
    method! visit_FVar _ identity = ids := identity :: !ids
  end in
  visitor#visit_texpr () native;
  let captures = List.sort_uniq compare !ids |> List.map (fun identity ->
    let symbol, variable = symbolic_for_variable state identity in
    if Q.FVarId.Map.find_opt variable.id state.fvars = Some variable &&
        Q.FVarId.Map.find_opt variable.id state.fvars_tys = Some variable.ty then ({ symbol; variable } : capture)
    else invalid_arg "a native captured default disagrees with its actual current declarations") in
  if List.exists (fun (capture : capture) -> capture.variable.id = variable.id) captures then
    invalid_arg "a lazy default cannot capture its own unbound fresh result";
  let closed = U.mk_closed_lambdas span (List.map (fun (capture : capture) -> U.mk_tpat_from_fvar None capture.variable) captures) native in
  if closed.ty <> U.mk_arrows (List.map (fun (capture : capture) -> capture.variable.ty) captures) variable.ty then
    invalid_arg "a native default closure changed its exact captured current-variable interface";
  { symbol; variable; captures; native; code = X.reflect closed }
let snapshot span generator (state : K.t) =
  { next = Q.FVarId.to_int (Q.FVarId.get_counter_value !generator); symbols = V.SymbolicValueId.Map.bindings state.sv_to_var; variables = Q.FVarId.Map.bindings state.fvars;
    types = Q.FVarId.Map.bindings state.fvars_tys;
    defaults = Q.FVarId.Map.bindings state.var_id_to_default |> List.map (fun (variable, native) -> variable, entry span state variable native) }

let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction =
  if not (N.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction) then
    invalid_arg "native lazy defaults need all original nested/current/source/field/expression contexts";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native scoped-default declarations have unresolved diagnostics";
  let span = projection.P.candidate.item_meta.span in
  let translate source = let ty = S.translate_fwd_ty (Some span) context source in X.validate ty; ty in
  let source = B.backward_expressions symbolic in
  let branches = List.map (fun (branch : R.branch) ->
    let actual = match RegionGroupId.Map.find_opt branch.target source with Some expression -> fst (B.ending_abstractions expression)
      | None -> invalid_arg "native scoped defaults lost an actual source branch" in
    if List.length actual <> List.length branch.endings then invalid_arg "native scoped defaults cannot omit an original ending";
    let make_state () =
      let generator, fresh_fvar_id = Q.FVarId.fresh_stateful_generator () in
      let empty : K.t = { span; sv_to_var = V.SymbolicValueId.Map.empty; fresh_fvar_id;
        fvars = Q.FVarId.Map.empty; fvars_tys = Q.FVarId.Map.empty;
        mut_borrow_to_consumed = V.BorrowId.Map.empty; var_id_to_default = Q.FVarId.Map.empty } in
      let state = List.fold_left (fun state (binding : F.binding) ->
        if V.SymbolicValueId.Map.mem binding.native.sv_id state.K.sv_to_var then
          invalid_arg "native current declaration preparation cannot merge original forward versions";
        fst (K.bind_symbolic None binding.native.sv_id (translate binding.native.sv_ty) state)) empty forward.F.source_bindings in
      let state = List.fold_left (fun (state : K.t) -> function
        | F.MutableExpansion (_, borrow, contents) ->
            if V.BorrowId.Map.mem borrow state.mut_borrow_to_consumed then invalid_arg "repeated actual source borrow";
            let value = K.symbolic_value_to_texpr contents.sv_id (translate contents.sv_ty) state in
            { state with mut_borrow_to_consumed = V.BorrowId.Map.add borrow value state.mut_borrow_to_consumed }
        | _ -> state) state forward.steps in
      generator, state in
    let generator_a, initial_a = make_state () and generator_e, initial_e = make_state () in
    let state_a = ref initial_a and state_e = ref initial_e in
    if snapshot span generator_a !state_a <> snapshot span generator_e !state_e then invalid_arg "native AV/EV initial current declarations differ";
    let registrations = List.concat (List.mapi (fun event (((abs : V.abs), level), (ending : R.ending)) ->
      if abs.abs_id <> ending.event.abstraction || level <> ending.event.level then
        invalid_arg "native default registration changed actual EndAbs order or level";
      List.filter_map (fun (port : W.port) -> if not port.given_back then None else (
        let left, right = D.leaves abs port in
        if left <> right then invalid_arg "native AV/EV default leaves disagree on the exact immediate source/projector context";
        let helpers = List.filter (fun (helper : N.helper) -> helper.target = branch.target && helper.event = event &&
          helper.receipt.given.value.identity = port.value.sv_id && helper.receipt.given.value.source_type = port.value.sv_ty) reconstruction.N.helpers in
        let helper = match helpers with [] -> None | [helper] -> Some helper
          | _ -> invalid_arg "a nested default has more than one actual reconstruction expression" in
        let register generator (state : K.t) leaf =
          if V.SymbolicValueId.Map.mem leaf.D.given.sv_id state.sv_to_var then
            invalid_arg "a native fresh given-back declaration cannot overwrite an existing current version";
          let state, variable = K.bind_symbolic None leaf.given.sv_id (translate leaf.given.sv_ty) state in
          let before = snapshot span generator state in
          let after = match leaf.origin, leaf.projection_type, leaf.projection_loans, helper with
            | B.Borrow borrow, None, None, None -> K.register_borrow_default variable.id borrow state
            | B.Symbolic source, Some projection, Some 0, None -> K.register_projection_default variable.id source (translate projection) state
            | B.Symbolic source, Some _, Some count, Some helper when count > 0 ->
                if helper.producer.origin <> B.Symbolic source then
                  invalid_arg "native nested default changed its original immediate version";
                let current = K.symbolic_value_to_texpr source helper.native_type state in
                let returned = K.symbolic_value_to_texpr helper.receipt.consumed.value.identity helper.native_type state in
                if current.ty <> helper.native_type || returned.ty <> helper.native_type then
                  invalid_arg "native nested default needs exact complete current/returned type adapters";
                let value = U.mk_apps __FILE__ __LINE__ span helper.native [current; returned] in
                K.register_checked_default_expression variable.id value state
            | _ -> invalid_arg "a native default has an unsupported or unmatched complete nested context" in
          if !Aeneas.Errors.error_list <> [] then invalid_arg "actual native scoped-default lookup produced a missing-symbol diagnostic";
          if after.sv_to_var <> state.sv_to_var || after.fvars <> state.fvars || after.fvars_tys <> state.fvars_tys || after.mut_borrow_to_consumed <> state.mut_borrow_to_consumed ||
              before.next <> Q.FVarId.to_int (Q.FVarId.get_counter_value !generator) then
            invalid_arg "lazy native default registration overwrote a fresh/current variable binding";
          let value = match Q.FVarId.Map.find_opt variable.id after.var_id_to_default with
            | Some value -> value | None -> invalid_arg "an actual source synthesis default was not registered" in
          let entry = entry span after variable.id value in
          after, { event; port; nested = Option.is_some helper; before; after = snapshot span generator after; entry } in
        let after_a, registration_a = register generator_a !state_a left and after_e, registration_e = register generator_e !state_e right in
        if registration_a <> registration_e then invalid_arg "native AV/EV scoped-default registrations or captures differ";
        state_a := after_a; state_e := after_e; Some registration_a
      )) ending.event.ports
    ) (List.combine actual branch.endings)) in
    { target = branch.target; registrations }) bindings.R.branches in
  { reconstruction; branches }
let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction =
  derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction

let lean_variable (variable : Q.fvar) = "{ identity := " ^ B.nat (Q.FVarId.to_int variable.id) ^ ", type := " ^ T.pure variable.ty ^ " }"
let lean_capture (capture : capture) = "{ symbol := " ^ B.sid capture.symbol ^ ", variable := " ^ lean_variable capture.variable ^ " }"
let lean_entry (entry : entry) = "{ symbol := " ^ B.sid entry.symbol ^ ", variable := " ^ lean_variable entry.variable ^
  ", captures := " ^ B.list lean_capture entry.captures ^ ", code := " ^ X.lean entry.code ^ " }"
let lean_snapshot snapshot = "{ next := " ^ B.nat snapshot.next ^ ", symbols := " ^ B.list (fun (symbol, variable) -> "(" ^ B.sid symbol ^ ", " ^ lean_variable variable ^ ")") snapshot.symbols ^
  ", variables := " ^ B.list (fun (identity, variable) -> "(" ^ B.nat (Q.FVarId.to_int identity) ^ ", " ^ lean_variable variable ^ ")") snapshot.variables ^
  ", types := " ^ B.list (fun (identity, ty) -> "(" ^ B.nat (Q.FVarId.to_int identity) ^ ", " ^ T.pure ty ^ ")") snapshot.types ^
  ", defaults := " ^ B.list (fun (identity, entry) -> "(" ^ B.nat (Q.FVarId.to_int identity) ^ ", " ^ lean_entry entry ^ ")") snapshot.defaults ^ " }"
let fuel (entry : entry) = 64 + 8 * X.depth entry.code
let name branch registration = "branch" ^ B.gid branch.target ^ "Event" ^ B.nat registration.event ^ "Symbol" ^ B.sid registration.port.value.sv_id
let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction witness) then
    invalid_arg "native scoped-default report changed actual source occurrences, scopes or stored expressions";
  `Assoc ["schema", `String "actual-native-full-type-scoped-lazy-defaults/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "registrations", `List (List.map (fun registration -> `Assoc ["event", `Int registration.event;
        "given", `Int (V.SymbolicValueId.to_int registration.port.value.sv_id); "nested", `Bool registration.nested;
        "exact_port", `String (W.lean_port registration.port);
        "before", `String (lean_snapshot registration.before); "after", `String (lean_snapshot registration.after);
        "stored_lazy_default", `String (lean_entry registration.entry)]) branch.registrations)]) witness.branches);
    "actual_shared_native_registration_APIs_executed", `Bool true;
    "nested_default_captures_immediate_and_exact_prior_return_versions", `Bool true;
    "fresh_given_back_symbol_bindings_preserved", `Bool true;
    "defaults_or_ordinary_function_results_evaluated_or_supplied", `Bool false;
    "default_origin_chains_followed", `Bool false;
    "minimal_declaration_registry_replaced_complete_bs_ctx", `Bool false;
    "original_full_source_context_value_ending_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path payload witness =
  let output = Buffer.create 1048576 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeScopedDefaults";
  line "import qualification.aeneas.cases.NativeNestedReconstruction";
  line "/- Actual native variable/default registry preparation, unelaborated/unqualified.";
  line "   No runtime values, fresh result binding, full bs_ctx or source/EndAbs/heap adequacy is supplied. -/";
  line "namespace Auths.Qualification.NativeScopedDefaults";
  line "open Auths.Support.NativeRootPayload Auths.Support.NativeScopedDefaults";
  line ("def schemas : List Schema := " ^ B.list C.lean_schema payload.C.environment.schemas);
  List.iter (fun branch -> List.iter (fun registration ->
    let name = name branch registration in
    line ("def " ^ name ^ "Before : State := " ^ lean_snapshot registration.before);
    line ("def " ^ name ^ "Entry : Default := " ^ lean_entry registration.entry);
    line ("def " ^ name ^ "After : State := " ^ lean_snapshot registration.after);
    line ("theorem " ^ name ^ "_matches_actual_native_registration : register schemas " ^ B.nat (fuel registration.entry) ^
      " " ^ name ^ "Before " ^ name ^ "Entry = some " ^ name ^ "After := by decide");
    line ("theorem " ^ name ^ "_keeps_the_independent_fresh_symbol : " ^ name ^ "After.symbols = " ^ name ^ "Before.symbols := by rfl")
  ) branch.registrations) witness.branches;
  line "end Auths.Qualification.NativeScopedDefaults";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
