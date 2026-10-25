(* Instantiate a concrete caller/shim family with an actual strictly resolved
   source vtable global. All non-region captures must be closed; its captured
   lifetime environment is imported once, with exact alias structure and fresh
   IDs. This constructs isolated ASTs, not a whole emitted/qualified program. *)
open Charon
open Types
open Expressions
open LlbcAst

type method_call = { statement_id : statement_id; source : fn_ptr;
  resolution : Static_targets.resolved; signature : fun_sig }
type t = {
  family : Vtable_specialization.t;
  source_global : Global_view.t;
  strict_resolution : Static_targets.global_resolution;
  capture_renaming : (region_param * region_param) list;
  capture_parameters : region_param list;
  owner_arguments : generic_args;
  dictionary_bindings : (trait_param * trait_ref) list;
  caller_candidate : fun_decl;
  shim_candidate : fun_decl;
  native_call_pointer : fn_ptr;
  native_call_signature : fun_sig;
  native_call_requirements : generic_params;
  source_method_calls : method_call list;
}

let body (declaration : fun_decl) = match declaration.body with StructuredBody body -> body
  | _ -> invalid_arg "a native instance candidate must keep its actual structured body"

let capture_arguments ~(captured : generic_params) ~(actual : generic_args) ~(enclosing : generic_params) =
  Static_targets.require_argument_arity captured actual;
  Region_scope.require_parameters captured.regions;
  Region_scope.require_parameters enclosing.regions;
  if not (List.for_all (fun parameter -> List.mem parameter enclosing.regions) captured.regions) then
    invalid_arg "a capture substitution parameter is absent from its complete enclosing scope";
  if enclosing.types <> captured.types || enclosing.const_generics <> captured.const_generics ||
     List.map (fun (clause : trait_param) -> clause.clause_id) enclosing.trait_clauses <>
       List.map (fun (clause : trait_param) -> clause.clause_id) captured.trait_clauses then
    invalid_arg "a capture substitution needs every enclosing non-region parameter explicitly bound";
  let bindings = List.combine (List.map (fun (parameter : region_param) -> parameter.index) captured.regions) actual.regions in
  let arguments = { actual with regions = List.map (fun (parameter : region_param) ->
    match List.assoc_opt parameter.index bindings with Some region -> region
    | None -> RVar (Free parameter.index)) enclosing.regions } in
  Static_targets.require_argument_arity enclosing arguments;
  arguments

let derive crate ~(family : Vtable_specialization.t) ~(source_global : Global_view.t) ~caller_id ~shim_id =
  if not (Vtable_specialization.replay crate family) then
    invalid_arg "a native vtable instance needs its complete original caller/shim family";
  if source_global.declaration <> family.branch.source_vtable.global || source_global.self_evidence <> None ||
     Global_view.create crate source_global.source_resolution <> source_global then
    invalid_arg "a native vtable instance changed its complete actual source global view";
  if caller_id = shim_id || List.exists (fun id -> FunDeclId.to_int id < 0 || FunDeclId.Map.mem id crate.fun_decls ||
      id = family.caller_candidate.def_id || id = family.shim_candidate.def_id) [caller_id; shim_id] then
    invalid_arg "instantiated vtable functions need distinct fresh declaration IDs";
  Closed_arguments.require ~parameters:source_global.arguments.parameters source_global.call_arguments;
  let strict_resolution = Static_targets.resolve_global crate {
    id = source_global.declaration.def_id; generics = source_global.call_arguments } in
  if strict_resolution.global_obligations <> [] || strict_resolution.global_reference.generics <> source_global.call_arguments then
    invalid_arg "the complete source capture environment does not replay strict global normalization";
  let occupied = family.caller_candidate.generics.regions @ family.shim_candidate.generics.regions @
    source_global.arguments.parameters in
  let largest = List.fold_left (fun current (parameter : region_param) ->
    Stdlib.max current (RegionId.to_int parameter.index)) (-1) occupied in
  if largest >= Int.max_int - List.length source_global.arguments.parameters - 1 then
    invalid_arg "instantiated vtable capture lifetimes exceed the construction identifier space";
  let capture_renaming = List.mapi (fun index (parameter : region_param) ->
    parameter, { parameter with index = RegionId.of_int (largest + index + 1) }) source_global.arguments.parameters in
  let capture_parameters = List.map snd capture_renaming in
  let rename = object inherit [_] map_statement
    method! visit_region _ region = Vtable_specialization.rename_captured_region capture_renaming region
  end in
  let global_substitution = Substitute.make_subst_from_generics source_global.declaration.generics source_global.call_arguments Self in
  let owner = Substitute.st_substitute_visitor#visit_trait_impl_ref global_substitution family.branch.source_vtable.owner in
  let owner_arguments = rename#visit_generic_args () owner.generics in
  Closed_arguments.require ~parameters:capture_parameters owner_arguments;
  Static_targets.require_argument_arity family.captured_parameters owner_arguments;
  let substitution = Substitute.make_subst_from_generics family.captured_parameters owner_arguments Self in
  let caller_substitution = Substitute.make_subst_from_generics family.caller_candidate.generics
    (capture_arguments ~captured:family.captured_parameters ~actual:owner_arguments ~enclosing:family.caller_candidate.generics) Self in
  let shim_substitution = Substitute.make_subst_from_generics family.shim_candidate.generics
    (capture_arguments ~captured:family.captured_parameters ~actual:owner_arguments ~enclosing:family.shim_candidate.generics) Self in
  let captured_requirements = Substitute.predicates_substitute substitution family.captured_parameters in
  let dictionary_bindings = List.map2 (fun (clause : trait_param) evidence ->
    if clause.trait <> evidence.trait_decl_ref then
      invalid_arg "an instantiated capture dictionary differs from the complete original source predicate";
    clause, evidence) captured_requirements.trait_clauses owner_arguments.trait_refs in
  let original_binding = match family.branch.source_slot.function_binding with Some binding -> binding
    | None -> invalid_arg "the native source instance lost its actual shim binding" in
  let shim_own_parameters = original_binding.cast_signature_binding.own_source_parameters in
  let native_arguments = { TypesUtils.empty_generic_args with regions =
    List.map (fun (parameter : region_param) -> RVar (Free parameter.index)) capture_parameters @ family.branch.own_call_arguments } in
  let native_call_pointer : fn_ptr = { kind = FunId (FRegular shim_id); generics = native_arguments } in
  let caller_inherited = Substitute.predicates_substitute caller_substitution family.caller_candidate.generics in
  let shim_inherited = Substitute.predicates_substitute shim_substitution family.shim_candidate.generics in
  let parameters (original : generic_params) (inherited : generic_params) regions : generic_params =
    if original.types <> family.captured_parameters.types ||
       original.const_generics <> family.captured_parameters.const_generics ||
       List.map (fun (clause : trait_param) -> clause.clause_id) original.trait_clauses <>
         List.map (fun (clause : trait_param) -> clause.clause_id) family.captured_parameters.trait_clauses then
      invalid_arg "a native instance has additional uninstantiated source capture parameters";
    { inherited with regions; types = []; const_generics = []; trait_clauses = [] } in
  let caller_generics = parameters family.caller_candidate.generics caller_inherited
    (family.dispatch.caller.generics.regions @ capture_parameters) in
  let shim_generics = parameters family.shim_candidate.generics shim_inherited (capture_parameters @ shim_own_parameters) in
  let caller_source_body = body family.caller_candidate in
  let substituted_family_pointer = Substitute.st_substitute_visitor#visit_fn_ptr caller_substitution family.native_call_pointer in
  let caller_mapper = object
    inherit [_] map_statement as super
    method! visit_statement env (statement : statement) =
      if statement.statement_id = family.dispatch.source_statement.statement_id then
        match statement.kind with
        | Call (({ func = FnOpRegular pointer; _ } as call), unwind) when pointer = substituted_family_pointer ->
            { statement with kind = Call ({ call with func = FnOpRegular native_call_pointer }, unwind) }
        | _ -> invalid_arg "the original concrete family call changed before native capture instantiation"
      else super#visit_statement env statement
  end in
  let caller_locals, substituted_caller_body = Substitute.expr_body_substitute caller_substitution caller_source_body in
  let caller_body = { caller_source_body with locals = { caller_source_body.locals with locals = caller_locals };
    body = caller_mapper#visit_block () substituted_caller_body } in
  let shim_source_body = body family.shim_candidate in
  let shim_locals, substituted_shim_body = Substitute.expr_body_substitute shim_substitution shim_source_body in
  let shim_body = { shim_source_body with locals = { shim_source_body.locals with locals = shim_locals };
    body = substituted_shim_body } in
  let caller_candidate = { family.caller_candidate with def_id = caller_id; generics = caller_generics;
    signature = Substitute.st_substitute_visitor#visit_fun_sig caller_substitution family.caller_candidate.signature;
    item_meta = { family.caller_candidate.item_meta with name = Vtable_specialization.fresh_name
      family.caller_candidate.item_meta.name ("__auths_instance_" ^ string_of_int (FunDeclId.to_int caller_id)) };
    body = StructuredBody caller_body } in
  let shim_candidate = { family.shim_candidate with def_id = shim_id; generics = shim_generics;
    signature = Substitute.st_substitute_visitor#visit_fun_sig shim_substitution family.shim_candidate.signature;
    item_meta = { family.shim_candidate.item_meta with name = Vtable_specialization.fresh_name
      family.shim_candidate.item_meta.name ("__auths_instance_" ^ string_of_int (FunDeclId.to_int shim_id)) };
    body = StructuredBody shim_body } in
  Static_targets.require_argument_arity shim_generics native_arguments;
  let native_substitution = Substitute.make_subst_from_generics shim_generics native_arguments Self in
  let native_call_signature = Substitute.st_substitute_visitor#visit_fun_sig native_substitution shim_candidate.signature in
  let native_call_requirements = Substitute.predicates_substitute native_substitution shim_generics in
  let call_count = ref 0 in
  let verify_call = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = family.dispatch.source_statement.statement_id then (
        match statement.kind with
        | Call ({ func = FnOpRegular pointer; args; dest }, _) when pointer = native_call_pointer &&
            List.map Vtable_dispatch.operand_type args = native_call_signature.inputs &&
            dest.ty = native_call_signature.output -> incr call_count
        | _ -> invalid_arg "the instantiated caller/shim pair disagrees in its complete native call signature");
      super#visit_statement env statement
  end in
  verify_call#visit_block () caller_body.body;
  if !call_count <> 1 then invalid_arg "the instantiated source pair lost its unique original call";
  let source_method_calls = ref [] in
  let source_calls = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      (match statement.kind with
       | Call ({ func = FnOpRegular pointer; args; dest }, _) ->
           let resolution = Static_targets.resolve crate pointer in
           if resolution.obligations <> [] then invalid_arg "the actual instantiated implementation method has unresolved source conditions";
           let source = resolution.pointer in
           let definition, method_substitution = Callable_instance.source_substitution crate source in
           let signature = Substitute.st_substitute_visitor#visit_fun_sig method_substitution definition.signature in
           if List.map Vtable_dispatch.operand_type args <> signature.inputs || dest.ty <> signature.output then
             invalid_arg "the instantiated shim disagrees with its complete actual implementation-method call ABI";
           source_method_calls := { statement_id = statement.statement_id; source = pointer; resolution; signature } :: !source_method_calls
       | Call ({ func = FnOpDynamic _; _ }, _) -> invalid_arg "an instantiated source shim has an unresolved dynamic call"
       | _ -> ());
      super#visit_statement env statement
  end in
  source_calls#visit_block () shim_body.body;
  let verify (declaration : fun_decl) (body : expr_body) =
    let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions declaration.generics.regions in
    scope#visit_generic_params [] declaration.generics;
    scope#visit_fun_sig [] declaration.signature;
    List.iter (scope#visit_local []) body.locals.locals;
    scope#visit_block [] body.body;
    let closed = new Closed_arguments.statement_check ~body_regions:body.bound_body_regions declaration.generics.regions in
    closed#visit_generic_params [] declaration.generics;
    closed#visit_fun_sig [] declaration.signature;
    List.iter (closed#visit_local []) body.locals.locals;
    closed#visit_block [] body.body;
    let lowered = object inherit [_] iter_statement as super
      method! visit_ty env = function
        | TDynTrait _ | TFnPtr _ | TFnDef _ ->
            invalid_arg "an instantiated concrete unit reintroduced an unlowered dynamic or function-pointer type"
        | ty -> super#visit_ty env ty
    end in
    lowered#visit_generic_params () declaration.generics;
    lowered#visit_fun_sig () declaration.signature;
    List.iter (lowered#visit_local ()) body.locals.locals;
    lowered#visit_block () body.body in
  verify caller_candidate caller_body;
  verify shim_candidate shim_body;
  { family; source_global; strict_resolution; capture_renaming; capture_parameters; owner_arguments;
    dictionary_bindings; caller_candidate; shim_candidate; native_call_pointer; native_call_signature;
    native_call_requirements; source_method_calls = List.rev !source_method_calls }

let replay crate witness =
  try derive crate ~family:witness.family ~source_global:witness.source_global
    ~caller_id:witness.caller_candidate.def_id ~shim_id:witness.shim_candidate.def_id = witness
  with Invalid_argument _ -> false

let create crate ~family ~source_global ~caller_id ~shim_id =
  let witness = derive crate ~family ~source_global ~caller_id ~shim_id in
  if not (replay crate witness) then invalid_arg "the complete actual captured vtable instance did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let declaration (definition : fun_decl) = `Assoc ["id", `Int (FunDeclId.to_int definition.def_id);
    "parameters", `String (show_generic_params definition.generics);
    "signature", `String (show_fun_sig definition.signature);
    "locals", `List (List.map (fun local -> `String (show_local local)) (body definition).locals.locals);
    "body", `String (show_block (body definition).body)] in
  `Assoc ["source_global", `Int (GlobalDeclId.to_int witness.source_global.declaration.def_id);
    "complete_normalized_source_captures", `String (show_generic_args witness.source_global.call_arguments);
    "native_capture_parameters", `List (List.map (fun (parameter : region_param) -> `Int (RegionId.to_int parameter.index)) witness.capture_parameters);
    "instantiated_owner_arguments", `String (show_generic_args witness.owner_arguments);
    "source_dictionary_bindings", `List (List.map (fun ((clause : trait_param), evidence) -> `Assoc [
      "source_clause", `String (show_trait_decl_ref clause.trait.binder_value);
      "actual_dictionary", `String (show_trait_ref evidence)]) witness.dictionary_bindings);
    "caller", declaration witness.caller_candidate; "shim", declaration witness.shim_candidate;
    "direct_call", `String (show_fn_ptr witness.native_call_pointer);
    "direct_call_signature", `String (show_fun_sig witness.native_call_signature);
    "direct_call_requirements", `String (show_generic_params witness.native_call_requirements);
    "actual_source_method_calls", `List (List.map (fun (call : method_call) -> `Assoc [
      "statement_id", `Int (StatementId.to_int call.statement_id); "original", `String (show_fn_ptr call.source);
      "resolved", `String (show_fn_ptr call.resolution.pointer); "signature", `String (show_fun_sig call.signature)]) witness.source_method_calls);
    "complete_captured_instance_replays", `Bool (replay crate witness);
    "runtime_selection_exhaustive_and_source_loan_ownership_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
