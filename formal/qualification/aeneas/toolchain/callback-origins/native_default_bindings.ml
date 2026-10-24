(* Execute the shared registration primitives now used by the actual pinned
   AV/EV wrappers, through their exact minimal state. This does not activate
   defaults, invoke full EndAbs dispatch or fabricate a complete signature. *)
open Charon
open Types
module V = Aeneas.Values
module S = Aeneas.SymbolicAst
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module K = Aeneas.SymbolicToPureBindings
module P = Borrow_projection
module F = Native_capture_value
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module E = Native_borrow_execution
module N = Native_pure_payload
module X = Native_pure_expressions
module C = Native_current_seeds
module H = Native_capture_closures

type leaf = { given : V.symbolic_value; origin : B.origin; projection_type : ty option;
  projection_loans : int option }
let nth values index = if index < 0 then invalid_arg "negative native leaf field" else
  match List.nth_opt values index with Some value -> value | None -> invalid_arg "absent native leaf field"

let rec abstract path (value : V.tavalue) = match path, value.value with
  | [], V.ABorrow (V.AEndedMutBorrow (meta, _)) ->
      { given = meta.given_back; origin = B.Borrow meta.bid; projection_type = None; projection_loans = None }
  | W.Field index :: rest, V.AAdt adt -> abstract rest (nth adt.fields index)
  | W.Child :: rest, V.ALoan (V.AMutLoan (_, _, child) | V.AIgnoredMutLoan (_, child)) -> abstract rest child
  | W.Child :: rest, V.ALoan (V.AEndedMutLoan ended) -> abstract rest ended.child
  | W.GivenBack :: rest, V.ALoan (V.AEndedMutLoan ended) -> abstract rest ended.given_back
  | W.Child :: rest, V.ALoan (V.AEndedIgnoredMutLoan ended) -> abstract rest ended.child
  | W.GivenBack :: rest, V.ALoan (V.AEndedIgnoredMutLoan ended) -> abstract rest ended.given_back
  | W.Child :: rest, V.ABorrow (V.AMutBorrow (_, _, child) | V.AIgnoredMutBorrow (_, child) | V.AEndedMutBorrow (_, child)) -> abstract rest child
  | W.Child :: rest, V.ABorrow (V.AEndedIgnoredMutBorrow ended) -> abstract rest ended.child
  | W.GivenBack :: rest, V.ABorrow (V.AEndedIgnoredMutBorrow ended) -> abstract rest ended.given_back
  | path, V.ASymbolic (marker, projector) -> B.marker marker; aproj path value.ty projector
  | _ -> invalid_arg "a default registration needs its exact actual abstract leaf, not a flattened observation"
and aproj path sort projector =
  let pair rest pairs index = let (source : V.mconsumed_symb), child = nth pairs index in aproj rest source.proj_ty child in
  match path, projector with
  | [], V.AEndedProjBorrows node -> { given = node.mvalues.given_back;
      origin = B.Symbolic node.mvalues.consumed; projection_type = Some sort; projection_loans = Some (List.length node.loans) }
  | W.Consumed index :: rest, V.AProjLoans node -> pair rest node.consumed index
  | W.Consumed index :: rest, V.AEndedProjLoans node -> pair rest node.consumed index
  | W.BorrowReprojection index :: rest, V.AProjLoans node -> pair rest node.borrows index
  | W.BorrowReprojection index :: rest, V.AEndedProjLoans node -> pair rest node.borrows index
  | W.LoanReprojection index :: rest, V.AProjBorrows node -> pair rest node.loans index
  | W.LoanReprojection index :: rest, V.AEndedProjBorrows node -> pair rest node.loans index
  | _ -> invalid_arg "an abstract default path lost an actual typed projector node"

let rec continuation path (value : V.tevalue) = match path, value.value with
  | [], V.EBorrow (V.EEndedMutBorrow (meta, _)) ->
      { given = meta.given_back; origin = B.Borrow meta.bid; projection_type = None; projection_loans = None }
  | W.Field index :: rest, V.EAdt adt -> continuation rest (nth adt.fields index)
  | W.Child :: rest, V.EMutBorrowInput child -> continuation rest child
  | W.Argument (group, index) :: rest, V.EApp ((V.EInputAbs _ | V.EOutputAbs _), arguments) -> continuation rest (nth (nth arguments group) index)
  | W.Child :: rest, V.ELoan (V.EMutLoan (_, _, child) | V.EIgnoredMutLoan (_, child)) -> continuation rest child
  | W.Child :: rest, V.ELoan (V.EEndedMutLoan ended) -> continuation rest ended.child
  | W.GivenBack :: rest, V.ELoan (V.EEndedMutLoan ended) -> continuation rest ended.given_back
  | W.Child :: rest, V.ELoan (V.EEndedIgnoredMutLoan ended) -> continuation rest ended.child
  | W.GivenBack :: rest, V.ELoan (V.EEndedIgnoredMutLoan ended) -> continuation rest ended.given_back
  | W.Child :: rest, V.EBorrow (V.EMutBorrow (_, _, child) | V.EIgnoredMutBorrow (_, child) | V.EEndedMutBorrow (_, child)) -> continuation rest child
  | W.Child :: rest, V.EBorrow (V.EEndedIgnoredMutBorrow ended) -> continuation rest ended.child
  | W.GivenBack :: rest, V.EBorrow (V.EEndedIgnoredMutBorrow ended) -> continuation rest ended.given_back
  | path, V.ESymbolic (marker, projector) -> B.marker marker; eproj path value.ty projector
  | _ -> invalid_arg "a default registration needs its exact actual continuation leaf, not an opaque environment"
and eproj path sort projector =
  let pair rest pairs index = let (source : V.mconsumed_symb), child = nth pairs index in eproj rest source.proj_ty child in
  match path, projector with
  | [], V.EEndedProjBorrows node -> { given = node.mvalues.given_back;
      origin = B.Symbolic node.mvalues.consumed; projection_type = Some sort; projection_loans = Some (List.length node.loans) }
  | W.Consumed index :: rest, V.EProjLoans node -> pair rest node.consumed index
  | W.Consumed index :: rest, V.EEndedProjLoans node -> pair rest node.consumed index
  | W.BorrowReprojection index :: rest, V.EProjLoans node -> pair rest node.borrows index
  | W.BorrowReprojection index :: rest, V.EEndedProjLoans node -> pair rest node.borrows index
  | W.LoanReprojection index :: rest, V.EProjBorrows node -> pair rest node.loans index
  | W.LoanReprojection index :: rest, V.EEndedProjBorrows node -> pair rest node.loans index
  | _ -> invalid_arg "a continuation default path lost an actual typed projector node"

let leaves (abs : V.abs) (port : W.port) =
  let left = match port.abstract_path with W.Root index :: rest -> abstract rest (nth abs.avalues index)
    | _ -> invalid_arg "an actual abstract default path needs its original root" in
  let cont = match abs.cont with Some cont -> cont | None -> invalid_arg "an actual default leaf lost its continuation" in
  let right = match port.continuation_path with
    | W.ContinuationInput :: rest -> (match cont.input with Some value -> continuation rest value | None -> invalid_arg "missing native continuation input")
    | W.ContinuationOutput :: rest -> (match cont.output with Some value -> continuation rest value | None -> invalid_arg "missing native continuation output")
    | _ -> invalid_arg "an actual continuation default path needs its original input/output root" in
  if left.given.sv_id <> port.value.sv_id || left.given.sv_ty <> port.value.sv_ty ||
      right.given.sv_id <> port.value.sv_id || right.given.sv_ty <> port.value.sv_ty || left.origin <> right.origin then
    invalid_arg "actual AV/EV default leaves changed their complete given-back type, identity or immediate origin";
  left, right

type alias = { borrow : V.borrow_id; source : F.binding; pointee : F.binding;
  seed : C.seed; steps : F.step list; codec_helper : X.helper }
type expression = Variable of int * Q.ty | Unit
type variable = { identity : int; ty : Q.ty }
type snapshot = { next : int; symbols : (int * variable) list; variables : (int * variable) list;
  types : (int * Q.ty) list; borrows : (int * expression) list; defaults : (int * expression) list }
type registration = { port : W.port; kind : E.kind; abstract_leaf : leaf; continuation_leaf : leaf;
  native_type : Q.ty; projection_type : Q.ty option; after : snapshot }
type consumed_read = { port : W.port; kind : E.kind; native_type : Q.ty;
  value : expression; state : snapshot }
type ending_trace = { event : W.event; before : snapshot; after : snapshot;
  registrations : registration list; reads : consumed_read list }
type branch = { target : region_group_id; initial : snapshot; registrations : registration list;
  endings : ending_trace list }
type t = { closure : H.t; aliases : alias list; branches : branch list }

let variable (value : Q.fvar) =
  if value.basename <> None then invalid_arg "this native default projection requires explicit handling of nonempty variable names";
  ignore (N.reflect value.ty);
  { identity = Q.FVarId.to_int value.id; ty = value.ty }
let expression (state : K.t) (value : Q.texpr) =
  ignore (N.reflect value.ty);
  match value.e with
  | Q.FVar identity ->
      let var = match Q.FVarId.Map.find_opt identity state.fvars with Some var -> var
        | None -> invalid_arg "a native default expression references an absent variable" in
      if var.ty <> value.ty then invalid_arg "a native default expression has an inconsistent complete variable type";
      Variable (Q.FVarId.to_int identity, value.ty)
  | _ when Q.compare_texpr value U.mk_unit_texpr = 0 -> Unit
  | _ -> invalid_arg "native registry reflection cannot conceal a call, error placeholder, dereference or supplied value"
let snapshot generator (state : K.t) = {
  next = Q.FVarId.to_int (Q.FVarId.get_counter_value !generator);
  symbols = List.map (fun (key, value) -> V.SymbolicValueId.to_int key, variable value) (V.SymbolicValueId.Map.bindings state.sv_to_var);
  variables = List.map (fun (key, value) -> Q.FVarId.to_int key, variable value) (Q.FVarId.Map.bindings state.fvars);
  types = List.map (fun (key, value) -> ignore (N.reflect value); Q.FVarId.to_int key, value) (Q.FVarId.Map.bindings state.fvars_tys);
  borrows = List.map (fun (key, value) -> V.BorrowId.to_int key, expression state value) (V.BorrowId.Map.bindings state.mut_borrow_to_consumed);
  defaults = List.map (fun (key, value) -> Q.FVarId.to_int key, expression state value) (Q.FVarId.Map.bindings state.var_id_to_default);
}

let derive component (projection : P.t) inputs symbolic (forward : F.t) protocol wiring defaults execution full_abi payload expressions current seeds (closure : H.t) =
  if not (H.replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure) then
    invalid_arg "shared native default primitives require every actual closure/current/seed/source witness";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native default registry context contains unresolved errors";
  let span = projection.candidate.item_meta.span in
  let translate = Aeneas.SymbolicToPureTypes.translate_fwd_ty (Some span) context in
  let binding identity = match List.filter (fun (binding : F.binding) -> binding.native.sv_id = identity) forward.source_bindings with
    | [binding] -> binding | _ -> invalid_arg "a consumed-borrow alias needs its exact actual forward binding" in
  let rec follow seen identity =
    if List.mem identity seen then invalid_arg "cyclic native forward alias";
    match List.filter (fun (seed : C.seed) -> seed.binding.native.sv_id = identity) closure.seeds.seeds with
    | [seed] -> seed, []
    | [] ->
        let step, child = match List.filter_map (fun step -> match step with
          | F.MutableExpansion (source, _, child) | F.BoxExpansion (source, child) when source = identity -> Some (step, child)
          | _ -> None) forward.steps with [step] -> step
          | _ -> invalid_arg "a consumed-borrow alias cannot skip a record, call or absent forward expansion" in
        let parent = binding identity and child_binding = binding child.sv_id in
        (match step, parent.source_type, parent.shape with
         | F.MutableExpansion _, TRef (_, inner, RMut), P.Borrow (RMut, _, shape)
             when inner = child_binding.source_type && shape = child_binding.shape -> ()
         | F.BoxExpansion _, TAdt { id = TBuiltin TBox; generics = { types = [inner]; _ } }, P.Named (P.Boxed, shape)
             when inner = child_binding.source_type && shape = child_binding.shape -> ()
         | _ -> invalid_arg "a forward alias changed the complete actual mutable/Box pointee carrier");
        if translate parent.native.sv_ty <> translate child_binding.native.sv_ty then
          invalid_arg "pinned native forward translation does not erase this actual alias wrapper";
        let seed, remaining = follow (identity :: seen) child.sv_id in seed, step :: remaining
    | _ -> invalid_arg "a consumed-borrow alias has repeated actual forward seeds" in
  let aliases = List.filter_map (function F.MutableExpansion (source, borrow, contents) ->
    let source = binding source and pointee = binding contents.sv_id in
    let seed, steps = follow [] source.native.sv_id in
    let codecs = List.filter (fun (helper : X.helper) -> helper.source.outgoing.access.producer.candidate_shape = pointee.shape &&
      helper.source.outgoing.native_type = translate pointee.native.sv_ty) expressions.X.helpers in
    let codec_helper = match codecs with first :: rest when List.for_all (fun (other : X.helper) ->
      other.source.outgoing.codec = first.source.outgoing.codec && other.source.outgoing.layout = first.source.outgoing.layout) rest -> first
      | _ -> invalid_arg "a consumed-borrow alias needs its complete existing pointee field codec" in
    if codec_helper.source.outgoing.layout <> seed.codec_helper.source.outgoing.layout then
      invalid_arg "actual consumed-borrow and focused seed encodings have different native field layouts";
    Some { borrow; source; pointee; seed; steps; codec_helper }
    | _ -> None) forward.steps in
  let rec delimiter = function
    | S.Meta (_, next) | S.Expansion (_, _, S.ExpandNoBranch (_, next)) -> delimiter next
    | S.Expansion (_, _, S.ExpandAdt [None, _, next]) -> delimiter next
    | S.ForwardEnd (_, _, _, backward) -> backward
    | _ -> invalid_arg "native default registration cannot skip an actual intervening source effect" in
  let rec endings = function
    | S.Meta (_, next) -> endings next
    | S.EndAbs (_, abs, level, next) -> (abs, level) :: endings next
    | S.Return (_, None) -> []
    | _ -> invalid_arg "native default registration requires every actual ending before the void return" in
  let source_branches = delimiter symbolic in
  let branches = List.map (fun (branch : E.branch) ->
    let actual = match RegionGroupId.Map.find_opt branch.target source_branches with Some value -> endings value
      | None -> invalid_arg "native default registration lost an actual branch" in
    if List.length actual <> List.length branch.endings then invalid_arg "native registration cannot omit an ending event";
    let make_state () =
      let generator, fresh_fvar_id = Q.FVarId.fresh_stateful_generator () in
      let state : K.t = { span; sv_to_var = V.SymbolicValueId.Map.empty; fresh_fvar_id;
        fvars = Q.FVarId.Map.empty; fvars_tys = Q.FVarId.Map.empty;
        mut_borrow_to_consumed = V.BorrowId.Map.empty; var_id_to_default = Q.FVarId.Map.empty } in
      let state = List.fold_left (fun state (seed : C.seed) ->
        fst (K.bind_symbolic None seed.binding.native.sv_id (translate seed.binding.native.sv_ty) state)) state closure.seeds.seeds in
      let state = List.fold_left (fun (state : K.t) alias ->
        let value = K.symbolic_value_to_texpr alias.seed.binding.native.sv_id (translate alias.seed.binding.native.sv_ty) state in
        { state with mut_borrow_to_consumed = V.BorrowId.Map.add alias.borrow value state.mut_borrow_to_consumed }) state aliases in
      generator, state in
    let generator_a, initial_a = make_state () and generator_e, initial_e = make_state () in
    let initial = snapshot generator_a initial_a in
    if initial <> snapshot generator_e initial_e then invalid_arg "actual AV/EV initial finite binding projections disagree";
    let state_a = ref initial_a and state_e = ref initial_e in
    let register (state : K.t) leaf =
      let native_type = translate leaf.given.sv_ty in
      let state, variable = K.bind_symbolic None leaf.given.sv_id native_type state in
      let state = match leaf.origin, leaf.projection_type with
        | B.Borrow identity, None -> K.register_borrow_default variable.id identity state
        | B.Symbolic identity, Some source -> K.register_projection_default variable.id identity (translate source) state
        | _ -> invalid_arg "a selected actual native leaf lost its source registration kind" in
      if !Aeneas.Errors.error_list <> [] then invalid_arg "shared native registration produced an actual missing-symbol diagnostic";
      state in
    let ending_traces = List.map2 (fun ((abs : V.abs), level) (ending : E.ending) ->
      if abs.abs_id <> ending.event.abstraction || level <> ending.event.level then
        invalid_arg "native registration event order differs from actual EndAbs";
      let before = snapshot generator_a !state_a in
      if before <> snapshot generator_e !state_e then
        invalid_arg "actual AV/EV native binding states differ before an ending";
      let registrations = ref [] and reads = ref [] in
      List.iter (fun (operation : E.operation) ->
        let port = operation.access.port in
        match operation.kind with
        | E.Receive | E.Default ->
          let abstract_leaf, continuation_leaf = leaves abs port in
          if abstract_leaf.origin <> operation.access.producer.origin then invalid_arg "an actual leaf has a different immediate default source";
          let native_type = translate abstract_leaf.given.sv_ty in
          let projection_type = Option.map translate abstract_leaf.projection_type in
          if native_type <> translate continuation_leaf.given.sv_ty || projection_type <> Option.map translate continuation_leaf.projection_type then
            invalid_arg "actual AV/EV default leaf translation has different complete native types";
          state_a := register !state_a abstract_leaf;
          state_e := register !state_e continuation_leaf;
          let after = snapshot generator_a !state_a in
          if after <> snapshot generator_e !state_e then invalid_arg "actual shared AV/EV registry primitives produced different finite binding states";
          registrations := { port; kind = operation.kind; abstract_leaf; continuation_leaf; native_type; projection_type; after } :: !registrations
        | E.Emit | E.Observe ->
          (* This reads the exact consumed symbol at this ending, including a
             higher-level reprojected result. It is not a default activation or
             a supplied ordinary function result. Never chase its default. *)
          let native_type = translate port.value.sv_ty in
          let read (state : K.t) =
            let value = K.symbolic_value_to_texpr port.value.sv_id native_type state in
            if value.ty <> native_type || !Aeneas.Errors.error_list <> [] then
              invalid_arg "an actual consumed projector symbol lacks its exact native typed binding";
            expression state value in
          let value = read !state_a in
          if value <> read !state_e then invalid_arg "actual AV/EV consumed reads name different immediate variables";
          reads := { port; kind = operation.kind; native_type; value;
            state = snapshot generator_a !state_a } :: !reads
      ) ending.operations;
      let after = snapshot generator_a !state_a in
      if after <> snapshot generator_e !state_e then
        invalid_arg "actual AV/EV native binding states differ after an ending";
      { event = ending.event; before; after; registrations = List.rev !registrations; reads = List.rev !reads }
    ) actual branch.endings in
    let registrations = List.concat_map (fun (ending : ending_trace) -> ending.registrations) ending_traces in
    { target = branch.target; initial; registrations; endings = ending_traces }) execution.E.branches in
  { closure; aliases; branches }

let replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure witness =
  try derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure =
  let witness = derive component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure in
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure witness) then
    invalid_arg "the actual shared native registration trace did not replay";
  witness

let lean_variable variable = "{ identity := " ^ B.nat variable.identity ^ ", type := " ^ N.pure variable.ty ^ " }"
let lean_expression = function Variable (identity, ty) -> ".variable { identity := " ^ B.nat identity ^ ", type := " ^ N.pure ty ^ " }" | Unit -> ".unit"
let table key value entries = "[" ^ String.concat ", " (List.map (fun (one, two) -> "(" ^ key one ^ ", " ^ value two ^ ")") entries) ^ "]"
let lean_snapshot state = "{ next := " ^ B.nat state.next ^ ", symbols := " ^ table B.nat lean_variable state.symbols ^
  ", variables := " ^ table B.nat lean_variable state.variables ^ ", types := " ^ table B.nat N.pure state.types ^
  ", borrows := " ^ table B.nat lean_expression state.borrows ^ ", defaults := " ^ table B.nat lean_expression state.defaults ^ " }"
let lean_registration registration =
  let origin = match registration.abstract_leaf.origin, registration.projection_type with
    | B.Borrow identity, None -> ".borrow " ^ B.nat (V.BorrowId.to_int identity)
    | B.Symbolic identity, Some ty -> ".projection " ^ B.sid identity ^ " (" ^ N.pure ty ^ ")"
    | _ -> invalid_arg "native reflected registration lost its actual leaf kind" in
  "{ symbol := " ^ B.sid registration.port.value.sv_id ^ ", type := " ^ N.pure registration.native_type ^ ", origin := " ^ origin ^ " }"
let default_for state symbol = match List.assoc_opt symbol state.symbols with
  | None -> None | Some variable -> List.assoc_opt variable.identity state.defaults

let report component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure witness =
  if not (replay component projection inputs symbolic forward protocol wiring defaults execution full_abi payload expressions current seeds closure witness) then
    invalid_arg "native shared registration report lost its complete actual source/leaf/minimal-state witness";
  `Assoc ["schema", `String "actual-native-shared-default-binding-primitives/v1";
    "forward_consumed_aliases", `List (List.map (fun alias -> `Assoc [
      "borrow", `Int (V.BorrowId.to_int alias.borrow); "source_symbol", `Int (V.SymbolicValueId.to_int alias.source.native.sv_id);
      "pointee_symbol", `Int (V.SymbolicValueId.to_int alias.pointee.native.sv_id);
      "focused_seed_symbol", `Int (V.SymbolicValueId.to_int alias.seed.binding.native.sv_id);
      "actual_forward_alias_steps", `List (List.map (fun step -> `String (F.lean_step step)) alias.steps);
      "complete_pointee_shape", `String (P.lean alias.pointee.shape);
      "candidate_to_native_output_transport", `String (Native_borrow_transport.lean_change alias.codec_helper.source.outgoing.access.change)]) witness.aliases);
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "initial_finite_projection", `String (lean_snapshot branch.initial);
      "registrations", `List (List.map (fun (registration : registration) -> `Assoc [
        "actual_port", `String (W.lean_port registration.port); "ending_model_role", `String (E.kind_name registration.kind);
        "shared_primitive_input", `String (lean_registration registration);
        "abstract_projection_type", (match registration.abstract_leaf.projection_type with None -> `Null | Some ty -> `String (P.reflect ty));
        "continuation_projection_type", (match registration.continuation_leaf.projection_type with None -> `Null | Some ty -> `String (P.reflect ty));
        "abstract_projection_loan_count", (match registration.abstract_leaf.projection_loans with None -> `Null | Some n -> `Int n);
        "continuation_projection_loan_count", (match registration.continuation_leaf.projection_loans with None -> `Null | Some n -> `Int n);
        "finite_binding_projection_after_both_paths", `String (lean_snapshot registration.after);
        "registered_default", (match default_for registration.after (V.SymbolicValueId.to_int registration.port.value.sv_id) with
          None -> `Null | Some value -> `String (lean_expression value))]) branch.registrations)]) witness.branches);
    "actual_shared_native_primitives_invoked", `Bool true;
    "both_original_av_ev_wrappers_use_shared_implementation", `Bool true;
    "complete_function_signature_fabricated", `Bool false;
    "fresh_generator_or_opaque_environment_equality_used", `Bool false;
    "registration_only_not_foreign_default_activation", `Bool true;
    "original_full_leaf_dispatch_and_guards_executed", `Bool false;
    "original_native_environment_default_activation_continuation_adequacy_proved", `Bool false;
    "original_rust_heap_loan_lifetime_layout_adequacy_proved", `Bool false;
    "ordinary_rust_function_results_supplied", `Bool false;
    "original_nested_mutable_or_level_guards_removed", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let write_lean path (projection : P.t) witness =
  let buffer = Buffer.create 131072 in
  let line value = Buffer.add_string buffer (value ^ "\n") in
  line "import Auths.Support.NativeDefaultBindings";
  line "import qualification.aeneas.cases.NativeCurrentSeeds";
  line "/- Actual shared native registry projections, not complete EndAbs execution.";
  line "   Unelaborated/unqualified; original dispatch/default activation/heap/loan adequacy remains open. -/";
  line "namespace Auths.Qualification.NativeDefaultBindings";
  line "open Auths.Support.NativeDefaultBindings Auths.Support.NativePurePayload";
  line "open Auths.Support.SourceClosureRegions Auths.Support.BorrowProjection";
  line ("open Auths.Qualification.BorrowProjection.Candidate" ^ string_of_int (FunDeclId.to_int projection.candidate.def_id));
  line "universe u";
  let initial = match witness.branches with first :: _ -> first.initial | [] -> invalid_arg "native registry has no actual branches" in
  line ("def inputs : List (Nat × Ty) := " ^ table B.nat N.pure (List.map (fun (id, variable) -> id, variable.ty) initial.symbols));
  line ("def consumedBorrows : List (Nat × Nat) := " ^ table B.nat B.nat (List.map (fun alias ->
    V.BorrowId.to_int alias.borrow, V.SymbolicValueId.to_int alias.seed.binding.native.sv_id) witness.aliases));
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target in
    line ("def " ^ name ^ "Initial : State := " ^ lean_snapshot branch.initial);
    line ("def " ^ name ^ "Registrations : List Registration := [" ^ String.concat ", " (List.map lean_registration branch.registrations) ^ "]");
    line ("def " ^ name ^ "Snapshots : List State := [" ^ String.concat ", " (List.map (fun (registration : registration) -> lean_snapshot registration.after) branch.registrations) ^ "]");
    line ("theorem " ^ name ^ "_initial_native_projection_matches : initialize inputs consumedBorrows = some " ^ name ^ "Initial := by decide");
    line ("theorem " ^ name ^ "_all_shared_native_registrations_match : scan " ^ name ^ "Initial " ^ name ^ "Registrations = some " ^ name ^ "Snapshots := by decide");
    let final = match List.rev branch.registrations with first :: _ -> first.after | [] -> branch.initial in
    line ("def " ^ name ^ "Final : State := " ^ lean_snapshot final);
    List.iter (fun (registration : registration) ->
      let symbol = V.SymbolicValueId.to_int registration.port.value.sv_id in
      line ("theorem " ^ name ^ "_symbol" ^ B.nat symbol ^ "_default_names_immediate_variable : defaultForSymbol " ^ name ^ "Final " ^ B.nat symbol ^ " = " ^
        (match default_for final symbol with None -> "none" | Some value -> "some (" ^ lean_expression value ^ ")") ^ " := by decide")
    ) branch.registrations
  ) witness.branches;
  let typing = "Auths.Qualification.NativePurePayload.atomTyping" in
  let source_atom = "SourceAtom " ^ typing ^ " Atom" in
  let source_inputs = List.map (fun (root : P.root) -> "input" ^ string_of_int root.index) projection.inputs in
  let binders = "(Atom : Ty → Type u) " ^ String.concat " " (List.map (fun name -> "(" ^ name ^ " : Data (" ^ source_atom ^ ") " ^ name ^ "Shape)") source_inputs) in
  let names = String.concat " " source_inputs in
  let values = "[" ^ String.concat ", " (List.map (fun name -> "⟨" ^ name ^ "Shape, " ^ name ^ "⟩") source_inputs) ^ "]" in
  let rec destruct indent name shape finish =
    let add text = line (String.make indent ' ' ^ text) in
    match shape with
    | P.Named (_, body) -> add ("cases " ^ name ^ " with"); add ("| named " ^ name ^ "Body =>"); destruct (indent + 2) (name ^ "Body") body finish
    | P.Borrow (_, _, body) -> add ("cases " ^ name ^ " with"); add ("| borrow " ^ name ^ "Body =>"); destruct (indent + 2) (name ^ "Body") body finish
    | P.Product (first, second) -> add ("cases " ^ name ^ " with"); add ("| product " ^ name ^ "First " ^ name ^ "Rest =>");
        destruct (indent + 2) (name ^ "First") first (fun indent -> destruct indent (name ^ "Rest") second finish)
    | P.Unit -> add ("cases " ^ name ^ " with"); add "| unit =>"; finish (indent + 2)
    | P.Empty -> add ("cases " ^ name)
    | P.Atom _ -> add ("cases " ^ name ^ " with"); add ("| atom " ^ name ^ "Value =>"); finish (indent + 2)
    | P.Sum (first, second) ->
        add ("cases " ^ name ^ " with");
        add ("| left " ^ name ^ "Left =>"); destruct (indent + 2) (name ^ "Left") first finish;
        add ("| right " ^ name ^ "Right =>"); destruct (indent + 2) (name ^ "Right") second finish in
  let source_cases () =
    let rec all indent = function
      | [] -> line (String.make indent ' ' ^ "rfl")
      | (root : P.root) :: rest -> destruct indent ("input" ^ string_of_int root.index) root.shape (fun indent -> all indent rest) in
    all 2 projection.inputs in
  List.iter (fun alias ->
    let name = "borrow" ^ B.nat (V.BorrowId.to_int alias.borrow) in
    let codec = "Auths.Qualification.NativePurePayload.branch" ^ B.gid alias.codec_helper.group ^ "Channel" ^ B.nat alias.codec_helper.index in
    let carrier = "Auths.Qualification.NativeBorrowFullABI.branch" ^ B.gid alias.codec_helper.group ^ "Channel" ^ B.nat alias.codec_helper.index in
    let seed_codec = C.payload_name alias.seed in
    let seed_index = match List.filter_map (fun (index, (seed : C.seed)) -> if seed.binding.native.sv_id = alias.seed.binding.native.sv_id then Some index else None)
      (List.mapi (fun index value -> index, value) witness.closure.seeds.seeds) with [index] -> index | _ -> invalid_arg "native consumed seed index is ambiguous" in
    line ("def " ^ name ^ "FromForward " ^ binders ^ " : Option (Value Atom " ^ seed_codec ^ "Layout) := do");
    line ("  let (_, state) ← Auths.Support.NativeCaptureValue.runWithState Auths.Qualification.NativeCaptureValue.actualProgram " ^ values);
    line ("  let pointee ← Auths.Support.NativeCurrentSeeds.readSeed Auths.Qualification.NativeCaptureValue.actualProgram state (.borrow " ^ B.nat (V.BorrowId.to_int alias.borrow) ^ ") " ^ carrier ^ ".candidateShape");
    line ("  pure (encode " ^ codec ^ "OutgoingCodec (Auths.Support.BorrowTransport.forward " ^ carrier ^ ".outgoingChange pointee))");
    line ("def " ^ name ^ "FromFocusedSeed " ^ binders ^ " : Option (Value Atom " ^ seed_codec ^ "Layout) := do");
    line ("  let value ← Auths.Qualification.NativeCurrentSeeds.seed" ^ B.nat seed_index ^ "FromState Atom " ^ names);
    line ("  pure (encode " ^ seed_codec ^ "OutgoingCodec value)");
    line ("theorem " ^ name ^ "_consumed_alias_is_same_forward_value " ^ binders ^ " :");
    line ("    " ^ name ^ "FromForward Atom " ^ names ^ " = " ^ name ^ "FromFocusedSeed Atom " ^ names ^ " := by");
    source_cases ()
  ) witness.aliases;
  line "end Auths.Qualification.NativeDefaultBindings";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents buffer); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
