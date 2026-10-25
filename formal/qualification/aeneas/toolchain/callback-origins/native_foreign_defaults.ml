(* Foreign default lets are internal expressions over existing native current
   declarations. No additional caller backward argument/result is supplied. *)
open Charon
open Types
module V = Aeneas.Values
module Q = Aeneas.Pure
module K = Aeneas.SymbolicToPureBindings
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module B = Native_borrow_protocol
module W = Native_borrow_wiring
module P = Borrow_projection
module C = Native_root_payload
module R = Native_root_bindings
module D = Native_scoped_defaults
module X = Native_root_expressions
module T = Native_type_syntax

type operation = Bind of W.port * D.snapshot * D.entry | Observe of W.port * D.snapshot * Q.fvar
type binding = { event : int; port : W.port; variable : Q.fvar; pattern : Q.tpat; value : Q.texpr }
type branch = { target : region_group_id; parents : region_group_id list; ports : W.port list;
  operations : operation list; bindings : binding list; captures : D.capture list; native : Q.texpr;
  term : X.term; output_type : Q.ty; expected : int list option }
type t = { scopes : D.t; types : (ty * Q.ty) list; branches : branch list }

let query_state span (snapshot : D.snapshot) : K.t =
  { span; sv_to_var = List.fold_left (fun values (key, value) -> V.SymbolicValueId.Map.add key value values) V.SymbolicValueId.Map.empty snapshot.symbols;
    fvars = List.fold_left (fun values (key, value) -> Q.FVarId.Map.add key value values) Q.FVarId.Map.empty snapshot.variables;
    fvars_tys = List.fold_left (fun values (key, value) -> Q.FVarId.Map.add key value values) Q.FVarId.Map.empty snapshot.types;
    var_id_to_default = List.fold_left (fun values (key, (entry : D.entry)) -> Q.FVarId.Map.add key entry.native values) Q.FVarId.Map.empty snapshot.defaults;
    mut_borrow_to_consumed = V.BorrowId.Map.empty;
    fresh_fvar_id = (fun () -> invalid_arg "native default materialization may not allocate a caller result") }
let port = function Bind (port, _, _) | Observe (port, _, _) -> port
let compile span (initial : D.snapshot) (bindings : binding list) =
  let variables = List.map (fun binding -> binding.variable) bindings in
  let body = U.mk_simpl_tuple_texpr span (List.map U.mk_texpr_from_fvar variables) in
  let output_type = body.Q.ty in
  let native = U.mk_closed_lets span false (List.map (fun binding -> binding.pattern, binding.value) bindings) body in
  let ids = ref [] in
  let visitor = object inherit [_] Q.iter_expr
    method! visit_FVar _ identity = ids := identity :: !ids
  end in visitor#visit_texpr () native;
  let captures = List.sort_uniq compare !ids |> List.map (fun identity ->
    match List.filter (fun (_, (variable : Q.fvar)) -> variable.id = identity) initial.symbols with
    | [symbol, variable] -> ({ D.symbol; variable } : D.capture)
    | _ -> invalid_arg "a foreign activation fragment needs its exact existing current forward variable") in
  let closed = U.mk_closed_lambdas span (List.map (fun (capture : D.capture) -> U.mk_tpat_from_fvar None capture.variable) captures) native in
  if closed.ty <> U.mk_arrows (List.map (fun (capture : D.capture) -> capture.variable.ty) captures) output_type then
    invalid_arg "native default materialization changed its internal capture/output interface";
  let values = ref (List.mapi (fun index (capture : D.capture) -> capture.variable.id, index) captures) in
  let simple = List.for_all (fun binding -> match binding.value.e with
    | Q.FVar identity -> (match List.assoc_opt identity !values with
        | Some value -> values := (binding.variable.id, value) :: !values; true | None -> false)
    | _ -> false) bindings in
  let expected = if simple then Some (List.map (fun (variable : Q.fvar) -> match List.assoc_opt variable.id !values with
    | Some index -> index | None -> invalid_arg "materialized default lacks an actual executed variable definition") variables) else None in
  captures, closed, X.reflect closed, output_type, expected

let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes =
  if not (D.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes) then
    invalid_arg "native default activation needs every original source/default/current scope";
  let context = Aeneas.Interp.compute_contexts component in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native foreign defaults contain unresolved diagnostics";
  let span = projection.P.candidate.item_meta.span in
  let translate source = let ty = S.translate_fwd_ty (Some span) context source in X.validate ty; ty in
  let branches = List.map (fun (branch : R.branch) ->
    let protocol_branch = match List.filter (fun (actual : B.branch) -> actual.target = branch.target) protocol.B.branches with
      | [actual] -> actual | _ -> invalid_arg "foreign activation lost its complete region ancestry" in
    let parents = List.filter ((<>) branch.target) protocol_branch.allowed in
    let scoped = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) scopes.D.branches with
      | [actual] -> actual | _ -> invalid_arg "foreign activation lost its actual native declaration/default branch" in
    let initial = match scoped.registrations with first :: _ -> first.D.before
      | [] -> invalid_arg "source synthesis has no actual default declaration state" in
    let current = ref initial and actual_bindings = ref [] in
    let operations = List.concat (List.mapi (fun event (ending : R.ending) ->
      let registrations = List.filter (fun (registration : D.registration) -> registration.event = event) scoped.registrations in
      (match List.rev registrations with last :: _ -> current := last.after | [] -> ());
      let foreign = List.filter (fun (port : W.port) -> port.group <> branch.target) ending.event.ports in
      if List.exists (fun (port : W.port) -> not (List.mem port.group parents)) foreign then
        invalid_arg "foreign materialization is outside original strict source ancestry";
      let given = List.filter (fun (port : W.port) -> port.given_back) foreign in
      if List.exists (fun (port : W.port) -> port.input && port.level = 0) given then
        invalid_arg "a foreign level-zero input cannot receive an invented default";
      let state = query_state span !current in
      let patterns = List.map (fun (port : W.port) ->
        match List.filter (fun (registration : D.registration) -> registration.port = port) registrations with
        | [registration] -> U.mk_tpat_from_fvar None registration.entry.variable
        | _ -> invalid_arg "foreign given port needs one exact registered native binder") given in
      let materialized = K.materialize_pattern_defaults patterns state in
      if List.length materialized <> List.length given then invalid_arg "native materialization omitted or duplicated a foreign given port";
      List.iter (fun ((pattern : Q.tpat), value) ->
        let variable = match pattern.pat with Q.POpen (variable, None) -> variable
          | _ -> invalid_arg "native materialization changed its exact original leaf binder" in
        let port = match List.filter (fun (registration : D.registration) -> registration.entry.variable = variable) registrations with
          | [registration] when List.mem registration.port given -> registration.port
          | _ -> invalid_arg "native materialization introduced an unrequested variable" in
        actual_bindings := !actual_bindings @ [{ event; port; variable; pattern; value }]
      ) materialized;
      List.map (fun (port : W.port) ->
        let native_type = translate port.value.sv_ty in
        if port.given_back then (
          match List.filter (fun (registration : D.registration) -> registration.port = port) registrations with
          | [registration] when registration.entry.variable.ty = native_type -> Bind (port, !current, registration.entry)
          | _ -> invalid_arg "foreign default changed its complete original native type")
        else (
          let expression = K.symbolic_value_to_texpr port.value.sv_id native_type state in
          match expression.e with Q.FVar identity when expression.ty = native_type ->
            let variable = match Q.FVarId.Map.find_opt identity state.fvars with Some variable when variable.ty = native_type -> variable
              | _ -> invalid_arg "foreign consumed symbol has no exact current native declaration" in
            Observe (port, !current, variable)
          | _ -> invalid_arg "foreign consumption requires the actual immediate variable, never an older default")
      ) foreign) branch.endings) in
    let ports = List.filter_map (fun action -> let source = R.port action in
      if source.original.group <> branch.target then Some source.original else None) branch.actions in
    if List.map port operations <> ports then invalid_arg "foreign activation omitted or reordered a source port";
    let captures, native, term, output_type, expected = compile span initial !actual_bindings in
    { target = branch.target; parents; ports; operations; bindings = !actual_bindings; captures; native; term; output_type; expected }
  ) bindings.R.branches in
  let source_types = List.concat_map (fun branch -> List.map (fun operation -> (port operation).value.sv_ty) branch.operations) branches |> List.sort_uniq compare in
  let types = List.map (fun source -> source, translate source) source_types in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "foreign activation has unresolved native lookup diagnostics";
  { scopes; types; branches }
let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes = witness
  with Invalid_argument _ | Not_found -> false
let create component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes =
  derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes
let fuel branch = 64 + 8 * List.fold_left (fun size -> function Bind (_, _, entry) -> max size (X.depth entry.D.code)
  | Observe (_, _, variable) -> max size (T.depth (T.reflect variable.Q.ty))) (X.depth branch.term) branch.operations
let lean_operation = function
  | Bind (port, registry, entry) -> ".bind (" ^ W.lean_port port ^ ") (" ^ D.lean_snapshot registry ^ ") (" ^ D.lean_entry entry ^ ")"
  | Observe (port, registry, variable) -> ".observe (" ^ W.lean_port port ^ ") (" ^ D.lean_snapshot registry ^ ") (" ^ D.lean_variable variable ^ ")"
let lean_program types branch = "{ target := " ^ B.gid branch.target ^ ", parents := " ^ B.list B.gid branch.parents ^
  ", fuel := " ^ B.nat (fuel branch) ^ ", types := " ^ B.list (fun (source, native) -> "(" ^ P.reflect source ^ ", " ^ T.pure native ^ ")") types ^
  ", ports := " ^ B.list W.lean_port branch.ports ^ ", operations := " ^ B.list lean_operation branch.operations ^ " }"
let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness) then
    invalid_arg "foreign default report lost source ancestry, current variables, default expressions or source order";
  `Assoc ["schema", `String "actual-native-foreign-current-default-materialization/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "given_default_lets", `Int (List.length branch.bindings); "all_foreign_ports", `Int (List.length branch.ports);
      "exact_current_captures", `List (List.map (fun (capture : D.capture) -> `String (D.lean_capture capture)) branch.captures);
      "complete_native_fragment", `String (Q.show_texpr branch.native);
      "complete_closed_fragment", `String (X.lean branch.term);
      "all_foreign_given_and_consumed_ports", `String (lean_program witness.types branch)]) witness.branches);
    "actual_shared_native_default_materialization_primitive_invoked", `Bool true;
    "default_lets_follow_exact_source_event_and_dependency_order", `Bool true;
    "fragment_parameters_are_only_existing_current_captures", `Bool true;
    "new_public_backward_argument_or_ordinary_function_result_supplied", `Bool false;
    "consumed_ports_validated_through_exact_immediate_native_lookup", `Bool true;
    "native_fragment_adds_runtime_observation_statements", `Bool false;
    "owned_internal_or_fresh_caller_result_implicitly_defaulted", `Bool false;
    "complete_original_dispatch_abi_source_environment_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path payload witness =
  let output = Buffer.create 1048576 in
  let line value = Buffer.add_string output (value ^ "\n") in
  line "import Auths.Support.NativeForeignDefaults";
  line "import qualification.aeneas.cases.NativeScopedDefaults";
  line "/- Actual native foreign default let fragments and consumed-name checks.";
  line "   Internal captures are not new caller arguments. Owned/source/ABI/heap adequacy remains open. Unelaborated/unqualified. -/";
  line "namespace Auths.Qualification.NativeForeignDefaults";
  line "open Auths.Support.NativeRootPayload Auths.Support.NativeRootExpressions Auths.Support.NativeForeignDefaults";
  line "universe u";
  line ("def schemas : List Schema := " ^ B.list C.lean_schema payload.C.environment.schemas);
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target in
    line ("def " ^ name ^ " : Program := " ^ lean_program witness.types branch);
    line ("theorem " ^ name ^ "_keeps_every_foreign_port : Auths.Support.NativeForeignDefaults.check schemas " ^ name ^ " = true := by decide");
    line ("def " ^ name ^ "Code : Term := " ^ X.lean branch.term);
    line ("theorem " ^ name ^ "_default_lets_are_closed_and_typed : Auths.Support.NativeRootExpressions.check schemas " ^ B.nat (fuel branch) ^
      " [] " ^ name ^ "Code = true := by decide");
    (match branch.expected with
     | None -> ()
     | Some results ->
         let arguments = List.mapi (fun index _ -> "current" ^ B.nat index) branch.captures in
         line ("theorem " ^ name ^ "_native_default_lets_use_actual_current_values (Atom : Ty → Type u)");
         List.iteri (fun index (capture : D.capture) ->
           let argument = List.nth arguments index in
           line ("    (" ^ argument ^ " : Dynamic Atom) (type" ^ B.nat index ^ " : " ^ argument ^ ".type = " ^ T.pure capture.variable.ty ^ ")");
           line ("    (valid" ^ B.nat index ^ " : validValue schemas " ^ B.nat (fuel branch) ^ " " ^ argument ^ " = true)")
         ) branch.captures;
         let selected = List.map (fun index -> List.nth arguments index) results in
         let expected = match selected with [one] -> one
           | values -> ".constructor (" ^ T.pure branch.output_type ^ ") none " ^ B.list (fun value -> value) values in
         line ("    : Auths.Support.NativeRootExpressions.execute schemas " ^ B.nat (fuel branch) ^ " " ^ name ^ "Code " ^ B.list (fun value -> value) arguments ^ " =");
         line ("      some (" ^ expected ^ ") := by");
         line ("  rw [Auths.Support.NativeRootExpressions.execute, " ^ name ^ "_default_lets_are_closed_and_typed]");
         line ("  simp only [" ^ String.concat ", " (List.mapi (fun index _ -> "valid" ^ B.nat index) arguments @
           ["List.all_cons"; "List.all_nil"; "Bool.true_and"; "Bool.and_true"; "ite_true"]) ^ "]");
         line ("  simp [" ^ String.concat ", " ([name ^ "Code"; "applyArguments"; "evaluate"; "applications"; "matchPattern";
           "fields"; "rows"; "arrows"; "arrow"; "Dynamic.type"] @ List.mapi (fun index _ -> "type" ^ B.nat index) arguments) ^ "]");
         (* Derive only SSA variable identities from the actual native let AST.
            Runtime contents remain arbitrary theorem parameters; no host
            execution result or default-origin chain supplies them. *)
         let initial = List.mapi (fun index (capture : D.capture) -> capture.variable.id, List.nth arguments index) branch.captures in
         let final = List.fold_left2 (fun values (binding : binding) result ->
           if List.mem_assoc binding.variable.id values then invalid_arg "foreign runtime proof would overwrite an existing current value";
           (binding.variable.id, List.nth arguments result) :: values) initial branch.bindings results |> List.sort compare in
         let table values = B.list (fun (identity, value) -> "(" ^ B.nat (Q.FVarId.to_int identity) ^ ", " ^ value ^ ")") values in
         line ("theorem " ^ name ^ "_all_foreign_operations_succeed_on_actual_current_values (Atom : Ty → Type u)");
         List.iteri (fun index (capture : D.capture) ->
           let argument = List.nth arguments index in
           line ("    (" ^ argument ^ " : Dynamic Atom) (type" ^ B.nat index ^ " : " ^ argument ^ ".type = " ^ T.pure capture.variable.ty ^ ")");
           line ("    (valid" ^ B.nat index ^ " : validValue schemas " ^ B.nat (fuel branch) ^ " " ^ argument ^ " = true)")
         ) branch.captures;
         line ("    : run schemas " ^ name ^ " " ^ table initial ^ " = some ⟨" ^ table final ^ ", " ^ name ^ ".ports⟩ := by");
         line ("  rw [run, " ^ name ^ "_keeps_every_foreign_port]");
         line ("  simp [" ^ String.concat ", " ([name; "executeOperations"; "executeOperation";
           "Auths.Support.NativeScopedDefaults.activate"; "Auths.Support.NativeDefaultBindings.lookup";
           "Auths.Support.NativeDefaultBindings.put"; "Auths.Support.NativeRootExpressions.execute";
           "Auths.Support.NativeRootExpressions.check";
           "applyArguments"; "evaluate"; "applications"; "matchPattern"; "fields"; "rows"; "arrows"; "arrow"; "Dynamic.type"] @
           List.mapi (fun index _ -> "type" ^ B.nat index) arguments @ List.mapi (fun index _ -> "valid" ^ B.nat index) arguments) ^ "]"));
    line ("theorem " ^ name ^ "_successful_activation_visits_every_foreign_port (Atom : Ty → Type u)");
    line ("    (values : Auths.Support.NativeDefaultBindings.Table (Dynamic Atom)) (after : Runtime Atom)");
    line ("    (accepted : run schemas " ^ name ^ " values = some after) : after.visited = " ^ name ^ ".ports :=");
    line "  successful_run_visits_every_foreign_port _ _ _ _ accepted"
  ) witness.branches;
  line "end Auths.Qualification.NativeForeignDefaults";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
