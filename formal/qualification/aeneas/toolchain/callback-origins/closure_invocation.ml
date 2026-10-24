(* Bind a real closure receiver call to its real source callable dictionary and
   own-lifetime route. Creator-value/field provenance, callback effects and
   native loan/activation simulation remain separate required obligations. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  binding : Source_call.t;
  closure_reference : type_decl_ref;
  source_type : type_decl;
  actual_info : closure_info;
  role : closure_kind;
  owner : trait_impl_ref;
  source_method : fun_decl_ref binder;
  routing : Method_instance.t;
  actual_receiver : operand;
}

let candidate crate (call : call) =
  let receiver_type = match call.args with first :: _ -> Some (Vtable_dispatch.operand_type first) | [] -> None in
  let reference = match receiver_type with
    | Some (TAdt ({ id = TAdtId _; _ } as reference))
    | Some (TRef (_, TAdt ({ id = TAdtId _; _ } as reference), _)) -> Some reference
    | _ -> None in
  match reference, call.func with
  | Some reference, FnOpRegular { kind = FunId (FRegular id); _ } ->
      (match FunDeclId.Map.find_opt id crate.fun_decls with
       | Some { src = TraitImplItem (_, _, AssocIdMethod _, _); _ } -> Closure_capture.is_box_capture crate reference
       | _ -> false)
  | _ -> false

let derive crate ~(binding : Source_call.t) =
  if not (Source_call.replay crate binding) then invalid_arg "a closure invocation needs its exact actual source call";
  let actual_receiver = match binding.call.args with first :: _ -> first
    | [] -> invalid_arg "the actual closure invocation has no receiver operand" in
  let closure_reference, role_from_receiver = match binding.instantiated_signature.inputs with
    | TAdt ({ id = TAdtId _; _ } as reference) :: _ -> reference, FnOnce
    | TRef (_, TAdt ({ id = TAdtId _; _ } as reference), RMut) :: _ -> reference, FnMut
    | TRef (_, TAdt ({ id = TAdtId _; _ } as reference), RShared) :: _ -> reference, Fn
    | _ -> invalid_arg "the actual callable method lost its complete nominal closure receiver ABI" in
  let source_type = match closure_reference.id with TAdtId id ->
      (match TypeDeclId.Map.find_opt id crate.type_decls with Some source -> source
       | None -> invalid_arg "the actual closure receiver type is absent")
    | _ -> invalid_arg "a closure invocation cannot use a tuple surrogate for its source receiver" in
  let source_info = match source_type.src with ClosureItem info -> info
    | _ -> invalid_arg "the actual callable receiver is not its source closure type" in
  let type_resolution = Type_view.resolve crate closure_reference in
  if type_resolution.reference <> closure_reference || type_resolution.obligations <> [] then
    invalid_arg "the actual closure invocation receiver retains unresolved source type predicates";
  let substitution = Type_view.source_substitution source_type closure_reference.generics type_resolution.self_evidence in
  let actual_info = Closure_capture.instantiate_info substitution source_info in
  let owner_reference = match role_from_receiver with
    | FnOnce -> actual_info.fn_once_impl
    | FnMut -> (match actual_info.fn_mut_impl with Some reference -> reference
        | None -> invalid_arg "the actual mutable closure call has no source FnMut dictionary")
    | Fn -> (match actual_info.fn_impl with Some reference -> reference
        | None -> invalid_arg "the actual shared closure call has no source Fn dictionary") in
  if owner_reference.binder_regions <> [] then invalid_arg "a closure call must instantiate its actual higher-ranked owner explicitly";
  let owner = Substitute.extract_from_binder Substitute.st_substitute_visitor#visit_trait_impl_ref owner_reference in
  let pointer = match binding.call.func with FnOpRegular pointer -> pointer
    | _ -> invalid_arg "the actual closure source pointer is absent" in
  let definition, method_substitution = Callable_instance.source_substitution crate pointer in
  let declared_owner, method_id = match definition.src with
    | TraitImplItem (source_owner, _, AssocIdMethod method_id, _) ->
        Substitute.st_substitute_visitor#visit_trait_impl_ref method_substitution source_owner, method_id
    | _ -> invalid_arg "the actual closure call did not target its source callable implementation method" in
  if declared_owner <> owner then invalid_arg "the actual closure receiver and source method select different complete captured dictionaries";
  let implementation = match TraitImplId.Map.find_opt owner.id crate.trait_impls with Some source -> source
    | None -> invalid_arg "the actual closure invocation dictionary is absent" in
  let original_method = match TraitMethodId.Map.find_opt method_id implementation.methods with Some source -> source
    | None -> invalid_arg "the exact closure method is absent from its actual source implementation" in
  let source_method = Substitute.apply_args_to_item_binder (TraitImpl owner) owner.generics
    (Substitute.st_substitute_visitor#visit_binder Substitute.st_substitute_visitor#visit_fun_decl_ref)
    { item_binder_params = implementation.generics; item_binder_value = original_method } in
  let routing = Method_instance.create source_method pointer in
  let frame = Source_call.frame binding.caller in
  let scope = new Region_scope.statement_check ~body_regions:frame.source_body.bound_body_regions binding.caller.view.arguments.parameters in
  scope#visit_type_decl_ref [] closure_reference;
  scope#visit_trait_impl_ref [] owner;
  { binding; closure_reference; source_type; actual_info; role = role_from_receiver; owner; source_method; routing; actual_receiver }

let replay crate witness = try derive crate ~binding:witness.binding = witness
  with Invalid_argument _ | Not_found -> false

let create crate ~binding =
  let witness = derive crate ~binding in
  if not (replay crate witness) then invalid_arg "the complete actual closure receiver/dictionary/method invocation did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["actual_source_call", Source_call.report crate witness.binding;
    "actual_source_closure_type", `String (show_type_decl_ref witness.closure_reference);
    "actual_receiver_operand", `String (show_operand witness.actual_receiver);
    "callable_role", `String (show_closure_kind witness.role);
    "source_own_lifetime_routing", Method_instance.report witness.routing;
    "complete_actual_closure_invocation_replays", `Bool (replay crate witness);
    "creator_capture_value_provenance_and_native_callback_effect_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
