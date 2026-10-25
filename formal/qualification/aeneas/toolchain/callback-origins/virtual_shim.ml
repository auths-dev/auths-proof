(* One actual prepared vtable capture supplies a concrete method shim behind a
   real Dyn interface. The entry is valid only after the matching runtime case
   opens this captured environment and restores that receiver. It is never
   inserted as a selected target in the original source frame. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  interface : Dynamic_method.t;
  source_global : Global_view.t;
  source_vtable : Vtable_initializer.t;
  source_slot : Vtable_initializer.slot;
  capture_parameters : region_param list;
  capture_arguments : generic_args;
  concrete_self : ty;
  declaration : fun_decl;
  entry : fn_ptr;
  entry_signature : fun_sig;
  concrete_interface_signature : fun_sig;
  entry_requirements : generic_params;
  actual_source_methods : Vtable_instance.method_call list;
  caller_parameters : region_param list;
  caller_body_regions : int;
}

let derive crate ~(interface : Dynamic_method.t) ~(source_global : Global_view.t)
    ~caller_parameters ~caller_body_regions ~id =
  if not (Dynamic_method.replay crate interface) || Global_view.create crate source_global.source_resolution <> source_global then
    invalid_arg "a virtual shim requires the complete actual interface and prepared source global";
  if FunDeclId.to_int id < 0 || FunDeclId.Map.mem id crate.fun_decls then
    invalid_arg "a virtual concrete shim requires a fresh declaration ID";
  let caller_scope = new Region_scope.statement_check ~body_regions:caller_body_regions caller_parameters in
  caller_scope#visit_fn_ptr [] interface.pointer;
  caller_scope#visit_fun_sig [] interface.signature;
  Closed_arguments.require ~parameters:source_global.arguments.parameters source_global.call_arguments;
  let strict = Static_targets.resolve_global crate { id = source_global.declaration.def_id; generics = source_global.call_arguments } in
  if strict.global_obligations <> [] || strict.global_reference.generics <> source_global.call_arguments then
    invalid_arg "the virtual source capture is not strictly normalized";
  if source_global.ty <> TAdt interface.vtable_reference then
    invalid_arg "the virtual capture uses a different complete source vtable type";
  let source_vtable = Vtable_initializer.create crate source_global.declaration in
  if source_vtable.shape.source_trait.def_id <> interface.trait_declaration.def_id then
    invalid_arg "the virtual capture declares another source trait";
  let source_slot = match List.filter (fun (slot : Vtable_initializer.slot) ->
    slot.field.index = interface.field.index && slot.field.role = VTableMethod interface.method_id) source_vtable.slots with
    | [slot] -> slot | _ -> invalid_arg "the actual virtual capture has no unique matching original method slot" in
  let binding = match source_slot.function_binding with Some binding -> binding
    | None -> invalid_arg "the selected virtual field has no actual source shim" in
  if not (Vtable_receiver.replay binding.receiver_lowering) then
    invalid_arg "the original concrete receiver lowering did not replay";
  let occupied = caller_parameters @ binding.definition.generics.regions @ source_global.arguments.parameters in
  let largest = List.fold_left (fun current (parameter : region_param) ->
    Stdlib.max current (RegionId.to_int parameter.index)) (-1) occupied in
  if largest >= Int.max_int - List.length source_global.arguments.parameters - 1 then
    invalid_arg "virtual captured lifetime IDs exceed construction space";
  let renaming = List.mapi (fun index (parameter : region_param) ->
    parameter, { parameter with index = RegionId.of_int (largest + index + 1) }) source_global.arguments.parameters in
  let capture_parameters = List.map snd renaming in
  let rename = object inherit [_] map_ty
    method! visit_region _ region = Vtable_specialization.rename_captured_region renaming region
  end in
  let global_substitution = Substitute.make_subst_from_generics source_global.declaration.generics source_global.call_arguments Self in
  let owner = Substitute.st_substitute_visitor#visit_trait_impl_ref global_substitution source_vtable.owner in
  let capture_arguments = rename#visit_generic_args () owner.generics in
  Closed_arguments.require ~parameters:capture_parameters capture_arguments;
  let full_arguments = Vtable_instance.capture_arguments ~captured:source_vtable.implementation.generics
    ~actual:capture_arguments ~enclosing:binding.definition.generics in
  let substitution = Substitute.make_subst_from_generics binding.definition.generics full_arguments Self in
  let concrete_self = Substitute.ty_substitute substitution binding.receiver_lowering.self_type in
  let inherited = Substitute.predicates_substitute substitution binding.definition.generics in
  let generics = { inherited with regions = capture_parameters @ binding.cast_signature_binding.own_source_parameters;
    types = []; const_generics = []; trait_clauses = [] } in
  let source_body = binding.receiver_lowering.concrete_body in
  let locals, block = Substitute.expr_body_substitute substitution source_body in
  let body = { source_body with locals = { source_body.locals with locals }; body = block } in
  let signature = Substitute.st_substitute_visitor#visit_fun_sig substitution binding.receiver_lowering.concrete_signature in
  let declaration = { binding.definition with def_id = id; src = TopLevelItem; generics; signature; body = StructuredBody body;
    item_meta = { binding.definition.item_meta with name = Vtable_specialization.fresh_name binding.definition.item_meta.name
      ("__auths_virtual_capture_" ^ string_of_int (FunDeclId.to_int id)) } } in
  let entry_arguments = { TypesUtils.empty_generic_args with regions =
    List.map (fun (parameter : region_param) -> RVar (Free parameter.index)) capture_parameters @ interface.pointer.generics.regions } in
  Dynamic_method.arity generics entry_arguments;
  let entry = { kind = FunId (FRegular id); generics = entry_arguments } in
  let entry_substitution = Substitute.make_subst_from_generics generics entry_arguments Self in
  let entry_signature = Substitute.st_substitute_visitor#visit_fun_sig entry_substitution signature in
  let entry_requirements = Substitute.predicates_substitute entry_substitution generics in
  let concrete_interface_signature = match interface.signature.inputs with
    | TRef (borrow, self, mutability) :: rest when self = interface.self_type ->
        { interface.signature with inputs = TRef (borrow, concrete_self, mutability) :: rest }
    | _ -> invalid_arg "the virtual interface lost its exact original borrowed Self receiver" in
  if entry_signature <> concrete_interface_signature then
    invalid_arg "the actual virtual case and concrete shim differ beyond the exact restored Self receiver";
  let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions generics.regions in
  scope#visit_generic_params [] generics; scope#visit_fun_sig [] signature;
  List.iter (scope#visit_local []) locals; scope#visit_block [] block;
  let closed = new Closed_arguments.statement_check ~body_regions:body.bound_body_regions generics.regions in
  closed#visit_generic_params [] generics; closed#visit_fun_sig [] signature;
  List.iter (closed#visit_local []) locals; closed#visit_block [] block;
  let branch_scope = new Region_scope.statement_check ~body_regions:caller_body_regions (caller_parameters @ capture_parameters) in
  branch_scope#visit_fn_ptr [] entry; branch_scope#visit_fun_sig [] entry_signature;
  branch_scope#visit_generic_params [] entry_requirements;
  let actual_source_methods = ref [] in
  let methods = object inherit [_] iter_statement as super
    method! visit_ty env ty =
      (match ty with TDynTrait _ | TFnPtr _ | TFnDef _ ->
        invalid_arg "an actual virtual case reintroduced an unlowered dynamic/function-pointer type" | _ -> ());
      super#visit_ty env ty
    method! visit_statement env statement =
      (match statement.kind with
       | Call ({ func = FnOpRegular pointer; args; dest }, _) ->
           let resolution = Static_targets.resolve crate pointer in
           if resolution.obligations <> [] then invalid_arg "the actual virtual implementation method retains unresolved source conditions";
           let definition, method_substitution = Callable_instance.source_substitution crate resolution.pointer in
           let signature = Substitute.st_substitute_visitor#visit_fun_sig method_substitution definition.signature in
           if List.map Vtable_dispatch.operand_type args <> signature.inputs || dest.ty <> signature.output then
             invalid_arg "the concrete virtual shim changed its actual implementation-method ABI";
           actual_source_methods := { Vtable_instance.statement_id = statement.statement_id;
             source = pointer; resolution; signature } :: !actual_source_methods
       | Call ({ func = FnOpDynamic _; _ }, _) -> invalid_arg "a concrete virtual shim has an unresolved indirect call"
       | _ -> ());
      super#visit_statement env statement
  end in
  methods#visit_generic_params () generics; methods#visit_fun_sig () signature;
  List.iter (methods#visit_local ()) locals; methods#visit_block () block;
  { interface; source_global; source_vtable; source_slot; capture_parameters; capture_arguments;
    concrete_self; declaration; entry; entry_signature; concrete_interface_signature; entry_requirements;
    actual_source_methods = List.rev !actual_source_methods; caller_parameters; caller_body_regions }

let replay crate witness =
  try derive crate ~interface:witness.interface ~source_global:witness.source_global
    ~caller_parameters:witness.caller_parameters ~caller_body_regions:witness.caller_body_regions
    ~id:witness.declaration.def_id = witness
  with Invalid_argument _ -> false

let create crate ~interface ~source_global ~caller_parameters ~caller_body_regions ~id =
  let witness = derive crate ~interface ~source_global ~caller_parameters ~caller_body_regions ~id in
  if not (replay crate witness) then invalid_arg "the complete actual virtual capture/shim interface did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let body = Vtable_instance.body witness.declaration in
  `Assoc ["source_global", `Int (GlobalDeclId.to_int witness.source_global.declaration.def_id);
    "source_method", `Int (TraitMethodId.to_int witness.interface.method_id);
    "source_field", `Int (FieldId.to_int witness.source_slot.field.index);
    "native_capture_parameters", `List (List.map (fun (parameter : region_param) -> `Int (RegionId.to_int parameter.index)) witness.capture_parameters);
    "actual_captured_owner", `String (show_generic_args witness.capture_arguments);
    "concrete_self", `String (show_ty witness.concrete_self);
    "candidate_id", `Int (FunDeclId.to_int witness.declaration.def_id);
    "parameters", `String (show_generic_params witness.declaration.generics);
    "signature", `String (show_fun_sig witness.declaration.signature);
    "locals", `List (List.map (fun value -> `String (show_local value)) body.locals.locals);
    "actual_concrete_source_body", `String (show_block body.body);
    "case_entry_after_capture_opening", `String (show_fn_ptr witness.entry);
    "case_entry_signature", `String (show_fun_sig witness.entry_signature);
    "restored_self_interface_signature", `String (show_fun_sig witness.concrete_interface_signature);
    "entry_where_requirements", `String (show_generic_params witness.entry_requirements);
    "required_self_outlives_original_object", `Assoc ["self", `String (show_ty witness.concrete_self);
      "object_region", `String (show_region witness.interface.object_region)];
    "actual_source_method_calls", `List (List.map (fun (call : Vtable_instance.method_call) -> `Assoc [
      "pointer", `String (show_fn_ptr call.resolution.pointer); "signature", `String (show_fun_sig call.signature)]) witness.actual_source_methods);
    "complete_virtual_capture_replays", `Bool (replay crate witness);
    "entry_only_valid_after_matching_runtime_capture_case", `Bool true;
    "capture_opening_receiver_restoration_exhaustiveness_and_execution_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
