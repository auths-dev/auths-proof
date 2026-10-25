(* Internal native given-value lets over the original whole argument roster.
   These expressions are not a source-version or complete EndAbs/ABI witness. *)
open Charon
open Types
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
module F = Native_foreign_defaults
module X = Native_root_expressions
module T = Native_type_syntax

type argument = { slot : C.slot; variable : Q.fvar }
type assignment = { binding : R.binding; argument : argument; result : Q.fvar;
  pattern : Q.tpat; value : Q.texpr }
type branch = { target : region_group_id; arguments : argument list; assignments : assignment list;
  declarations : D.snapshot; native : Q.texpr; code : X.term }
type t = { types : (ty * Q.ty) list; branches : branch list }

let same_slot (one : C.slot) (two : C.slot) =
  one.group = two.group && one.level = two.level && one.input = two.input && one.position = two.position
let derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes =
  if not (D.replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes) then
    invalid_arg "native owned assignments require every original argument/root/source/default/version context";
  let span = projection.P.candidate.item_meta.span in
  let branches = List.map (fun (branch : R.branch) ->
    let scoped = match List.filter (fun (actual : D.branch) -> actual.target = branch.target) scopes.D.branches with
      | [actual] -> actual | _ -> invalid_arg "owned assignments lost their exact declaration branch" in
    let original = match List.rev scoped.registrations with last :: _ -> last.D.after
      | [] -> invalid_arg "owned assignments have no actual source declaration scope" in
    let generator, fresh_fvar_id = Q.FVarId.fresh_stateful_generator () in
    for _ = 1 to original.next do ignore (fresh_fvar_id ()) done;
    let initial = { (F.query_state span original) with fresh_fvar_id } in
    let slots = List.filter (fun (slot : C.slot) -> slot.group = branch.target && slot.input) payload.C.slots in
    let state, arguments = List.fold_left_map (fun state slot ->
      let state, variable = K.fresh_var None slot.C.root.native_type state in
      state, { slot; variable }) initial slots in
    let declarations = D.snapshot span generator state in
    if declarations.symbols <> original.symbols || declarations.defaults <> original.defaults ||
        declarations.next <> original.next + List.length slots ||
        List.length declarations.variables <> List.length original.variables + List.length slots ||
        not (List.for_all (fun (identity, variable) -> Q.FVarId.Map.find_opt identity state.fvars = Some variable) original.variables) ||
        not (List.for_all (fun (identity, ty) -> Q.FVarId.Map.find_opt identity state.fvars_tys = Some ty) original.types) then
      invalid_arg "declaring original whole arguments changed source names/defaults or allocated extra caller parameters";
    let assignments = List.filter_map (function R.Bind binding ->
      let argument = match List.filter (fun argument -> same_slot argument.slot binding.slot) arguments with
        | [argument] when argument.slot.root = binding.slot.root -> argument
        | _ -> invalid_arg "an owned value needs exactly its already-declared whole argument, never a new per-port parameter" in
      let registrations = List.filter (fun (registration : D.registration) -> registration.event = binding.port.event &&
        registration.port = binding.port.original) scoped.registrations in
      let result = match registrations with [registration] -> registration.entry.variable
        | _ -> invalid_arg "an owned native assignment lost its exact fresh source/native variable declaration" in
      if Q.FVarId.Map.find_opt result.id state.fvars <> Some result ||
          Q.FVarId.Map.find_opt result.id state.fvars_tys <> Some result.ty ||
          Aeneas.Values.SymbolicValueId.Map.find_opt binding.port.original.value.sv_id state.sv_to_var <> Some result ||
          result.ty <> binding.projection.native_type then
        invalid_arg "an owned assignment changed the source version or full native target type";
      let value = U.mk_apps __FILE__ __LINE__ span binding.projection.native [U.mk_texpr_from_fvar argument.variable] in
      (* The shared algebraic expression/declaration checker is read-only.
         This is a given-value RHS, not a lazy default registration. *)
      K.check_default_expression result.id value state;
      let pattern = U.mk_tpat_from_fvar None result in
      Some { binding; argument; result; pattern; value }
      | R.Consume _ | R.Foreign _ -> None) branch.actions in
    let before = D.snapshot span generator state in
    let body = U.mk_simpl_tuple_texpr span (List.map (fun assignment -> U.mk_texpr_from_fvar assignment.result) assignments) in
    let body = U.mk_closed_lets span false (List.map (fun assignment -> assignment.pattern, assignment.value) assignments) body in
    let native = U.mk_closed_lambdas span (List.map (fun argument -> U.mk_tpat_from_fvar None argument.variable) arguments) body in
    let code = X.reflect native in
    if D.snapshot span generator state <> before then invalid_arg "native given-value materialization altered declarations, defaults or the allocator";
    let expected = List.filter_map (fun action -> let port = R.port action in
      if port.original.group = branch.target && port.original.given_back then Some port.original else None) branch.actions in
    if List.map (fun assignment -> assignment.binding.port.original) assignments <> expected then
      invalid_arg "native owned assignments omitted or reordered an original given-back port";
    { target = branch.target; arguments; assignments; declarations; native; code }) bindings.R.branches in
  let context = Aeneas.Interp.compute_contexts component in
  let types = List.concat_map (fun branch -> List.map (fun assignment -> assignment.binding.port.original.value.sv_ty) branch.assignments) branches |>
    List.sort_uniq compare |> List.map (fun source -> source, S.translate_fwd_ty (Some span) context source) in
  if !Aeneas.Errors.error_list <> [] then invalid_arg "native owned assignments have unresolved original lookup/type diagnostics";
  { types; branches }
let replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness =
  try derive component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes = witness
  with Invalid_argument _ | Not_found -> false
let create = derive
let lean_slot (slot : C.slot) = "{ group := " ^ B.gid slot.group ^ ", level := " ^ B.nat slot.level ^ ", position := " ^ B.nat slot.position ^ " }"
let lean_argument argument = "{ slot := " ^ lean_slot argument.slot ^ ", variable := " ^ D.lean_variable argument.variable ^ " }"
let lean_assignment assignment = "{ port := " ^ W.lean_port assignment.binding.port.original ^ ", slot := " ^ lean_slot assignment.argument.slot ^
  ", result := " ^ D.lean_variable assignment.result ^ ", projection := " ^ X.lean assignment.binding.projection.term ^ " }"
let fuel branch = 64 + 8 * List.fold_left (fun maximum (argument : argument) -> max maximum (C.depth argument.slot.root.layout))
  (X.depth branch.code) branch.arguments
let lean_program types branch = "{ target := " ^ B.gid branch.target ^ ", fuel := " ^ B.nat (fuel branch) ^ ", declarations := " ^ D.lean_snapshot branch.declarations ^
  ", types := " ^ B.list (fun (source, native) -> "(" ^ P.reflect source ^ ", " ^ T.pure native ^ ")") types ^
  ", arguments := " ^ B.list lean_argument branch.arguments ^ ", ports := " ^ B.list (fun assignment -> W.lean_port assignment.binding.port.original) branch.assignments ^
  ", assignments := " ^ B.list lean_assignment branch.assignments ^ " }"
let report component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness =
  if not (replay component projection inputs symbolic forward protocol wiring levels signature origins payload defaults bindings reconstruction scopes witness) then
    invalid_arg "native owned assignment report changed an original argument, given port or current declaration";
  `Assoc ["schema", `String "actual-native-owned-whole-argument-let-bindings/v1";
    "branches", `List (List.map (fun branch -> `Assoc ["target", `Int (RegionGroupId.to_int branch.target);
      "original_whole_arguments", `Int (List.length branch.arguments); "owned_given_lets", `Int (List.length branch.assignments);
      "exact_program", `String (lean_program witness.types branch); "native_let_fragment", `String (Q.show_texpr branch.native);
      "closed_native_fragment", `String (X.lean branch.code)]) witness.branches);
    "original_whole_argument_roster_retained", `Bool true;
    "one_new_caller_parameter_per_port", `Bool false;
    "lazy_default_or_ordinary_function_result_used_as_given_value", `Bool false;
    "source_names_defaults_and_declarations_preserved_during_let_materialization", `Bool true;
    "argument_variable_allocation_is_the_original_full_bs_ctx_order", `Bool false;
    "minimal_declarations_replaced_full_bs_ctx", `Bool false;
    "source_version_or_joint_overlap_correspondence_implicitly_discharged", `Bool false;
    "complete_original_EndAbs_continuation_ABI_environment_heap_loan_adequacy_proved", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]
let write_lean path payload witness =
  let output = Buffer.create 1048576 in
  let line text = Buffer.add_string output (text ^ "\n") in
  let carrier = "Auths.Qualification.NativeRootPayload." in
  line "import Auths.Support.NativeOwnedBindings";
  line "import qualification.aeneas.cases.NativeRootBindings";
  line "/- Actual native given-value assignment fragments. Source version/joint overlap,";
  line "   original continuation/ABI/environment and Rust heap/loan adequacy remain open. -/";
  line "namespace Auths.Qualification.NativeOwnedBindings";
  line "open Auths.Support.NativeRootPayload Auths.Support.NativeRootExpressions Auths.Support.NativeOwnedBindings";
  line "universe u";
  line ("def schemas : List Schema := " ^ B.list C.lean_schema payload.C.environment.schemas);
  List.iter (fun branch ->
    let name = "branch" ^ B.gid branch.target and depth = B.nat (fuel branch) in
    line ("def " ^ name ^ " : Program := " ^ lean_program witness.types branch);
    line ("def " ^ name ^ "Code : Term := " ^ X.lean branch.code);
    line ("theorem " ^ name ^ "_retains_all_original_owned_given_slots : Auths.Support.NativeOwnedBindings.check schemas " ^ name ^ " = true := by decide");
    line ("theorem " ^ name ^ "_actual_native_let_fragment_is_closed_and_typed : Auths.Support.NativeRootExpressions.check schemas " ^ depth ^ " [] " ^ name ^ "Code = true := by decide");
    List.iteri (fun index argument ->
      line ("theorem " ^ name ^ "_argument" ^ B.nat index ^ "_is_an_existing_complete_signature_slot :");
      line ("    ((Auths.Qualification.NativeBackwardTypes.group" ^ B.gid branch.target ^ "Inputs.find? (fun row => row.1 == " ^ B.nat argument.slot.level ^
        ")).bind (fun row => row.2[" ^ B.nat argument.slot.position ^ "]?)) = some (" ^ T.pure argument.variable.ty ^ ") := by rfl")
    ) branch.arguments;
    let arguments = List.mapi (fun index argument -> "argument" ^ B.nat index, argument) branch.arguments in
    line ("theorem " ^ name ^ "_given_lets_use_only_original_whole_arguments (Atom : NativeType → Type u)");
    List.iter (fun (name, argument) -> line ("    (" ^ name ^ " : Auths.Support.BorrowProjection.Data (SourceAtom " ^ carrier ^
      "atomTyping Atom) " ^ carrier ^ C.root_name argument.slot.root ^ "Shape)")) arguments;
    line ("    : executeValues schemas " ^ depth ^ " " ^ name ^ "Code [");
    List.iteri (fun index (name, argument) -> line ("      pack " ^ depth ^ " (encode " ^ carrier ^ C.root_name argument.slot.root ^ "Codec " ^ name ^ ")" ^
      (if index + 1 = List.length arguments then "] =" else ","))) arguments;
    let results = List.map (fun assignment ->
      let argument = match List.filter (fun (_, (argument : argument)) -> argument = assignment.argument) arguments with
        | [name, _] -> name | _ -> invalid_arg "an assignment proof changed its exact whole argument" in
      let binding_name = "Auths.Qualification.NativeRootBindings.branch" ^ B.gid branch.target ^
        "Event" ^ B.nat assignment.binding.port.event ^ "Port" ^ B.nat assignment.binding.port.position in
      "pack " ^ depth ^ " (encode " ^ binding_name ^ "NativeCodec (Auths.Support.CurrentBorrowCarrier.read " ^ binding_name ^ "Focus " ^ argument ^ "))") branch.assignments in
    (match results with
     | [one] -> line ("      " ^ one ^ " := by")
     | _ ->
         line "      (do";
         List.iteri (fun index result -> line ("        let result" ^ B.nat index ^ " ← " ^ result)) results;
         let result_type = U.mk_simpl_tuple_ty (List.map (fun assignment -> assignment.result.ty) branch.assignments) in
         line ("        pure (.constructor (" ^ T.pure result_type ^ ") none " ^ B.list (fun (index, _) -> "result" ^ B.nat index) (List.mapi (fun index value -> index, value) results) ^ ")) := by"));
    let rec cases indent = function
      | [] -> line (indent ^ "rfl")
      | (name, argument) :: rest -> R.emit_data_cases line indent name argument.slot.root.source.shape (fun indent -> cases indent rest) in
    cases "  " arguments;
    line ("theorem " ^ name ^ "_successful_assignment_visits_every_original_given_port (Atom : NativeType → Type u)");
    line ("    (arguments : Arguments Atom) (current : Auths.Support.NativeDefaultBindings.Table (Dynamic Atom)) (after : Runtime Atom)");
    line ("    (accepted : run schemas " ^ name ^ " arguments current = some after) : after.visited = " ^ name ^ ".ports :=");
    line "  successful_run_visits_every_owned_given_port _ _ _ _ _ accepted"
  ) witness.branches;
  line "end Auths.Qualification.NativeOwnedBindings";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_binary; Open_excl] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
