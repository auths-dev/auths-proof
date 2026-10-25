(* A real Dyn trait dictionary supplies a virtual interface, never a guessed
   implementation. Bind its exact declared method, vtable role and fully
   instantiated signature. Runtime receiver provenance/selection and actual
   branch execution remain explicit obligations outside this source view. *)
open Charon
open Types
open LlbcAst

type t = {
  pointer : fn_ptr;
  reference : trait_ref;
  method_id : trait_method_id;
  trait_declaration : trait_decl;
  source_method : trait_method binder;
  captured_method : fun_sig binder;
  owner_requirements : generic_params;
  method_requirements : generic_params;
  signature : fun_sig;
  self_type : ty;
  object_region : region;
  vtable_reference : type_decl_ref;
  vtable_shape : Vtable_shape.t;
  field : Vtable_shape.field_view;
  field_invocation : Signature_instance.t;
}

let arity (parameters : generic_params) (arguments : generic_args) =
  List.iter (fun (expected, actual) -> if expected <> actual then
    invalid_arg "a virtual method changed its complete source generic arity") [
    List.length parameters.regions, List.length arguments.regions;
    List.length parameters.types, List.length arguments.types;
    List.length parameters.const_generics, List.length arguments.const_generics;
    List.length parameters.trait_clauses, List.length arguments.trait_refs]

let derive crate (pointer : fn_ptr) =
  let reference, method_id = match pointer.kind with
    | TraitMethod (({ kind = Dyn; _ } as reference), method_id) -> reference, method_id
    | _ -> invalid_arg "a virtual method interface requires the original Dyn dictionary and method ID" in
  if reference.trait_decl_ref.binder_regions <> [] then
    invalid_arg "a higher-ranked dynamic owner requires its actual source instantiation";
  let owner = Substitute.extract_from_binder Substitute.st_substitute_visitor#visit_trait_decl_ref reference.trait_decl_ref in
  let trait_declaration = match TraitDeclId.Map.find_opt owner.id crate.trait_decls with
    | Some declaration -> declaration | None -> invalid_arg "the actual virtual method trait is absent" in
  arity trait_declaration.generics owner.generics;
  let self_type, predicate = match owner.generics.types with
    | (TDynTrait predicate as self) :: _ -> self, predicate
    | _ -> invalid_arg "a Dyn dictionary must retain its actual dynamic Self type" in
  let source_method = match TraitMethodId.Map.find_opt method_id trait_declaration.methods with
    | Some method_ -> method_ | None -> invalid_arg "the actual dynamic trait method is absent" in
  if source_method.binder_params.types <> [] || source_method.binder_params.const_generics <> [] ||
     source_method.binder_params.trait_clauses <> [] then
    invalid_arg "a virtual method needs explicit lowering for additional own type/const/dictionary parameters";
  let source_signature = { binder_params = source_method.binder_params;
    binder_value = source_method.binder_value.signature } in
  let captured_method = Substitute.apply_args_to_item_binder reference.kind owner.generics
    (Substitute.st_substitute_visitor#visit_binder Substitute.st_substitute_visitor#visit_fun_sig)
    { item_binder_params = trait_declaration.generics; item_binder_value = source_signature } in
  arity captured_method.binder_params pointer.generics;
  let signature = Substitute.apply_args_to_binder pointer.generics
    Substitute.st_substitute_visitor#visit_fun_sig captured_method in
  let method_requirements = Substitute.apply_args_to_binder pointer.generics
    Substitute.st_substitute_visitor#visit_generic_params
    { captured_method with binder_value = captured_method.binder_params } in
  let owner_substitution = Substitute.make_subst_from_generics trait_declaration.generics owner.generics reference.kind in
  let owner_requirements = Substitute.predicates_substitute owner_substitution trait_declaration.generics in
  let vtable_reference = match trait_declaration.vtable with
    | Some reference -> Substitute.st_substitute_visitor#visit_type_decl_ref owner_substitution reference
    | None -> invalid_arg "the actual dynamic trait has no source vtable" in
  let source_type = match vtable_reference.id with
    | TAdtId id -> (match TypeDeclId.Map.find_opt id crate.type_decls with
        | Some declaration -> declaration | None -> invalid_arg "the virtual interface's actual vtable type is absent")
    | _ -> invalid_arg "a virtual method cannot substitute a built-in tuple for its source vtable" in
  arity source_type.generics vtable_reference.generics;
  let vtable_shape = Vtable_shape.create crate source_type in
  if vtable_shape.source_trait.def_id <> trait_declaration.def_id then
    invalid_arg "the virtual method and actual vtable declare different owner traits";
  let field = match List.filter (fun (field : Vtable_shape.field_view) -> field.role = VTableMethod method_id) vtable_shape.fields with
    | [field] -> field | _ -> invalid_arg "the virtual method has no unique actual source vtable field" in
  let family = match field.function_field with Some family -> family
    | None -> invalid_arg "the actual virtual field has no source function signature" in
  let table_substitution = Substitute.make_subst_from_generics source_type.generics vtable_reference.generics Self in
  let source_predicate = Substitute.st_substitute_visitor#visit_dyn_predicate table_substitution vtable_shape.source_predicate in
  let object_region = Vtable_shape.object_annotation source_predicate predicate in
  if object_region = RErased then invalid_arg "a virtual method's actual receiver has no source object provenance";
  let source_field = Substitute.st_substitute_visitor#visit_region_binder
    Substitute.st_substitute_visitor#visit_fun_sig table_substitution family.parameterized in
  let field_invocation = Signature_instance.create source_field signature in
  if field_invocation.arguments <> pointer.generics.regions @ [object_region] then
    invalid_arg "the virtual method changed its declared own lifetime routing or original object annotation";
  (match signature.inputs with TRef (_, actual, _) :: _ when actual = self_type -> ()
   | _ -> invalid_arg "the actual virtual method needs its original borrowed Self receiver ABI");
  { pointer; reference; method_id; trait_declaration; source_method; captured_method;
    owner_requirements; method_requirements; signature; self_type; object_region;
    vtable_reference; vtable_shape; field; field_invocation }

let replay crate witness = try derive crate witness.pointer = witness with Invalid_argument _ -> false

let create crate pointer =
  let witness = derive crate pointer in
  if not (replay crate witness) then invalid_arg "the complete actual virtual method interface did not replay";
  witness

let call_requirements witness (call : call) =
  (match call.func with FnOpRegular pointer when pointer = witness.pointer -> ()
   | _ -> invalid_arg "a virtual call ABI must retain the exact normalized source pointer of its interface");
  let inputs = List.map (function Expressions.Move place | Expressions.Copy place -> place.ty
    | Expressions.Constant value -> value.ty) call.args in
  if List.length inputs <> List.length witness.signature.inputs then
    invalid_arg "the actual virtual call changed the complete source argument arity";
  List.combine witness.signature.inputs inputs @ [witness.signature.output, call.dest.ty]

let report crate witness =
  let open Diagnostic in
  `Assoc ["original_dynamic_pointer", `String (show_fn_ptr witness.pointer);
    "source_trait", `Int (TraitDeclId.to_int witness.trait_declaration.def_id);
    "source_method", `Int (TraitMethodId.to_int witness.method_id);
    "source_self", `String (show_ty witness.self_type);
    "source_object_region", `String (show_region witness.object_region);
    "source_vtable", `String (show_type_decl_ref witness.vtable_reference);
    "source_field", `Int (FieldId.to_int witness.field.index);
    "source_interface_signature", `String (show_fun_sig witness.signature);
    "source_owner_requirements", `String (show_generic_params witness.owner_requirements);
    "source_method_requirements", `String (show_generic_params witness.method_requirements);
    "source_field_abi", Signature_instance.report witness.field_invocation;
    "complete_virtual_interface_replays", `Bool (replay crate witness);
    "concrete_target_selected", `Bool false;
    "runtime_receiver_metadata_loan_and_execution_binding_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
