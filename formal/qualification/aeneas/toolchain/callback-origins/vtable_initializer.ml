(* Exact source data flow for the generated straight-line vtable initializer.
   This reads assignments and moves; it does not execute layout operations or
   method bodies. Unsupported control/effects, stale reads and missing source
   functions refuse. Cast/field ABI, loans, ownership and execution refinement
   remain explicit obligations, not consequences of this construction. *)
open Charon
open Types
open Expressions
open LlbcAst

type value = {
  ty : ty;
  source_statement : statement_id option;
  node : value_node;
}
and value_node =
  | ConstantValue of constant_expr
  | LayoutValue of nullop * ty
  | FunctionCast of ty * ty * value
  | SourceUse of with_retag * value
  | AggregateValue of type_decl_ref * value list

type function_binding = {
  source_pointer : fn_ptr;
  definition : fun_decl;
  shim_body : expr_body;
  calls : fn_ptr list;
  declared_implementation_method : fun_decl_ref binder option;
  method_route : Method_instance.t option;
  field_signature_binding : Vtable_field.t;
  cast_signature_binding : Vtable_cast.t;
  receiver_lowering : Vtable_receiver.t;
}
type slot = {
  field : Vtable_shape.field_view;
  actual_value : value;
  function_binding : function_binding option;
}
type t = {
  global : global_decl;
  owner : trait_impl_ref;
  implementation : trait_impl;
  initializer_pointer : fn_ptr;
  initializer_definition : fun_decl;
  source_body : expr_body;
  shape : Vtable_shape.t;
  slots : slot list;
}

let trace (source : expr_body) =
  if source.locals.arg_count <> 0 then
    invalid_arg "a generated vtable initializer cannot accept runtime operands";
  if source.bound_body_regions < 0 then invalid_arg "a source vtable initializer has a negative body-region binder";
  let region_scope = object
    inherit [_] iter_statement
    method! visit_region _ = function
      | RBody id when RegionId.to_int id < 0 || RegionId.to_int id >= source.bound_body_regions ->
          invalid_arg "a source vtable initializer captures a region outside its actual body binder"
      | _ -> ()
  end in
  List.iter (region_scope#visit_local ()) source.locals.locals;
  region_scope#visit_block () source.body;
  let declarations = List.fold_left (fun table (local : local) ->
    if LocalId.Map.mem local.index table then invalid_arg "a vtable initializer repeats a local ID";
    LocalId.Map.add local.index local table) LocalId.Map.empty source.locals.locals in
  let storage = ref LocalId.Map.empty in
  let returned = ref None in
  let seen_statements = ref StatementId.Set.empty in
  let local_type id = match LocalId.Map.find_opt id declarations with
    | Some local -> local.local_ty
    | None -> invalid_arg "a vtable initializer references an undeclared source local" in
  let place_local (place : place) = match place.kind with
    | PlaceLocal id when place.ty = local_type id -> id
    | PlaceLocal _ -> invalid_arg "a vtable initializer place type disagrees with its actual local"
    | _ -> invalid_arg "a vtable initializer data-flow view cannot guess a projected or external place" in
  let operand = function
    | Constant value ->
        (match value.kind with
         | CLiteral _ | CFnDef _ | CFnPtr _ -> ()
         | _ -> invalid_arg "a source vtable initializer constant needs an explicit supported source value");
        { ty = value.ty; source_statement = None; node = ConstantValue value }
    | (Copy place | Move place) as operand ->
        let id = place_local place in
        let value = match LocalId.Map.find_opt id !storage with
          | Some (Some value) when value.ty = place.ty -> value
          | _ -> invalid_arg "a vtable initializer reads an uninitialized, moved or dead source local" in
        (match operand with Move _ -> storage := LocalId.Map.add id None !storage | _ -> ());
        value in
  List.iter (fun (statement : statement) ->
    if StatementId.Set.mem statement.statement_id !seen_statements then
      invalid_arg "a source vtable initializer repeats a statement identifier";
    seen_statements := StatementId.Set.add statement.statement_id !seen_statements;
    if Option.is_some !returned then invalid_arg "a vtable initializer has source statements after return";
    match statement.kind with
    | StorageLive id -> ignore (local_type id); storage := LocalId.Map.add id None !storage
    | StorageDead id -> ignore (local_type id); storage := LocalId.Map.remove id !storage
    | Assign (place, source_rvalue) ->
        let id = place_local place in
        if not (LocalId.Map.mem id !storage) then
          invalid_arg "a vtable initializer writes a source local outside its actual storage lifetime";
        let node = match source_rvalue with
          | Use (source, retag) ->
              let source = operand source in
              if source.ty <> place.ty then invalid_arg "a vtable initializer use changes its complete source type";
              SourceUse (retag, source)
          | NullaryOp ((SizeOf | AlignOf) as operation, input) ->
              if place.ty <> Vtable_shape.usize then invalid_arg "a source layout slot is not usize";
              LayoutValue (operation, input)
          | UnaryOp (Cast (CastFnPtr (from, into)), source) ->
              let source = operand source in
              if source.ty <> from || place.ty <> into then
                invalid_arg "a source vtable function cast changes its declared operand/destination types";
              FunctionCast (from, into, source)
          | Aggregate (AggregatedAdt (reference, None, None), operands) ->
              if place.ty <> TAdt reference then invalid_arg "a source vtable aggregate has a different destination type";
              (* Preserve source operand order and moves; do not reorder slots. *)
              AggregateValue (reference, List.map operand operands)
          | _ -> invalid_arg "a generated vtable initializer contains an unsupported source computation" in
        storage := LocalId.Map.add id (Some { ty = place.ty;
          source_statement = Some statement.statement_id; node }) !storage
    | Return ->
        (match LocalId.Map.find_opt (LocalId.of_int 0) !storage with
         | Some (Some value) -> returned := Some value
         | _ -> invalid_arg "a vtable initializer returns an absent or moved aggregate")
    | _ -> invalid_arg "a generated vtable initializer contains control flow or an effect requiring a separate proof")
    source.body.statements;
  match !returned with
  | Some value -> value
  | None -> invalid_arg "a generated vtable initializer has no complete source return"

let rec unwrap_use value = match value.node with SourceUse (_, source) -> unwrap_use source | _ -> value

let function_pointer value = match (unwrap_use value).node with
  | FunctionCast ((TFnDef definition as from), TFnPtr _, operand) ->
      (match (unwrap_use operand).node with
       | ConstantValue ({ kind = CFnDef pointer; ty; _ })
           when ty = from && definition.binder_value = pointer -> pointer
       | _ -> invalid_arg "a vtable function slot has no exact source function-item cast operand")
  | ConstantValue { kind = CFnPtr pointer; ty = TFnPtr _ } -> pointer
  | _ -> invalid_arg "a vtable function slot cannot be supplied by a guessed or opaque callback"

let create crate (global : global_decl) =
  let owner = match global.src with
    | VTableInstanceItem owner -> owner
    | _ -> invalid_arg "source vtable initialization needs its actual implementation-owned global" in
  if global.global_kind <> Static then invalid_arg "a source vtable instance must retain its actual static global kind";
  let implementation = match TraitImplId.Map.find_opt owner.id crate.trait_impls with
    | Some implementation -> implementation
    | None -> invalid_arg "the source vtable implementation is absent" in
  let initializer_pointer, initializer_id = match global.value.kind with
    | CCall ({ kind = FunId (FRegular id); _ } as pointer, []) -> pointer, id
    | _ -> invalid_arg "the source vtable global needs its actual zero-operand initializer" in
  let initializer_definition = match FunDeclId.Map.find_opt initializer_id crate.fun_decls with
    | Some declaration -> declaration
    | None -> invalid_arg "the source vtable initializer declaration is absent" in
  Static_targets.require_argument_arity initializer_definition.generics initializer_pointer.generics;
  Static_targets.require_argument_arity implementation.generics owner.generics;
  if initializer_definition.is_global_initializer <> Some global.def_id || initializer_definition.src <> global.src ||
     initializer_definition.signature.inputs <> [] || initializer_definition.signature.output <> global.ty ||
     initializer_definition.signature.is_unsafe || initializer_definition.signature.abi <> AbiRust ||
     initializer_definition.signature.is_variadic ||
     global.value.ty <> global.ty then
    invalid_arg "source vtable global/initializer ownership or complete return signature disagrees";
  let source_body = match initializer_definition.body with
    | StructuredBody body -> body
    | _ -> invalid_arg "the source vtable initializer needs its actual structured body" in
  let returned = trace source_body in
  let reference, values = match returned.node, global.ty with
    | AggregateValue (reference, values), TAdt expected when reference = expected -> reference, values
    | _ -> invalid_arg "the returned source aggregate is not the exact vtable global" in
  let source_type = match reference.id with
    | TAdtId id -> (match TypeDeclId.Map.find_opt id crate.type_decls with
        | Some source -> source | None -> invalid_arg "the actual source vtable type is absent")
    | _ -> invalid_arg "a source vtable initializer cannot construct a builtin aggregate" in
  let shape = Vtable_shape.create crate source_type in
  Static_targets.require_argument_arity source_type.generics reference.generics;
  if implementation.impl_trait.id <> shape.source_trait.def_id || List.length shape.fields <> List.length values then
    invalid_arg "the source vtable implementation trait or aggregate slot arity disagrees";
  let substitution = Substitute.make_subst_from_generics implementation.generics owner.generics (TraitImpl owner) in
  let actual_trait = Substitute.trait_decl_ref_substitute substitution implementation.impl_trait in
  let self_type = match actual_trait.generics.types with
    | self :: _ -> self
    | _ -> invalid_arg "the source vtable implementation has no concrete/template Self type" in
  let slots = List.map2 (fun (field : Vtable_shape.field_view) actual_value ->
    let plain = unwrap_use actual_value in
    let function_binding = match field.role with
      | VTableSize | VTableAlign ->
          (match plain.node with
           | LayoutValue (operation, input) when input = self_type &&
               operation = (if field.role = VTableSize then SizeOf else AlignOf) -> ()
           | _ -> invalid_arg "a source size/align slot is not the original layout operation on this implementation's Self");
          None
      | VTableSuperTrait _ ->
          invalid_arg "a source supertrait vtable initializer needs its exact referenced instance binding"
      | VTableDrop | VTableMethod _ ->
          let field_family = match field.function_field with
            | Some family -> family
            | None -> invalid_arg "a source function field is missing its actual signature family" in
          let actual_signature = match actual_value.ty with
            | TFnPtr signature -> signature
            | _ -> invalid_arg "a stored vtable function value does not retain its actual function-pointer type" in
          let field_signature_binding = Vtable_field.create
            ~parameters:source_type.generics ~arguments:reference.generics
            ~free_parameters:initializer_definition.generics.regions
            ~body_regions:source_body.bound_body_regions ~owner:shape.source_predicate
            field_family actual_signature in
          let source_pointer = function_pointer actual_value in
          let definition = match source_pointer.kind with
            | FunId (FRegular id) -> (match FunDeclId.Map.find_opt id crate.fun_decls with
                | Some declaration -> declaration
                | None -> invalid_arg "a vtable source function-item target is absent")
            | _ -> invalid_arg "a source vtable slot must retain its actual regular shim target" in
          (match definition.src with VTableMethodShimItem -> ()
           | _ -> invalid_arg "the source vtable field does not point at an actual generated shim");
          Static_targets.require_argument_arity definition.generics source_pointer.generics;
          let from_type, into_type = match plain.node with
            | FunctionCast (from_type, into_type, _) -> from_type, into_type
            | _ -> invalid_arg "a generated vtable function slot needs its actual source function-item cast" in
          let cast_signature_binding = Vtable_cast.create ~definition
            ~owner_parameters:implementation.generics ~owner_arguments:owner.generics
            ~field:field_signature_binding ~source_pointer ~from_type ~into_type in
          let receiver_lowering = Vtable_receiver.create ~cast_signature:cast_signature_binding ~implementation in
          let shim_body = match definition.body with
            | StructuredBody body -> body
            | _ -> invalid_arg "a source vtable shim must retain its actual body" in
          let calls = ref [] in
          let collector = object
            inherit [_] iter_statement as super
            method! visit_statement env statement =
              (match statement.kind with
               | Call ({ func = FnOpRegular pointer; _ }, _) -> calls := pointer :: !calls
               | Call ({ func = FnOpDynamic _; _ }, _) ->
                   invalid_arg "a source vtable shim has an unresolved dynamic target"
               | _ -> ());
              super#visit_statement env statement
          end in
          collector#visit_block () shim_body.body;
          let calls = List.rev !calls in
          let declared_implementation_method, method_route = match field.role with
            | VTableMethod method_id ->
                let method_ = match TraitMethodId.Map.find_opt method_id implementation.methods with
                  | Some method_ -> method_
                  | None -> invalid_arg "the vtable method slot has no actual source implementation method" in
                let targets = List.filter (fun (pointer : fn_ptr) -> pointer.kind = FunId (FRegular method_.binder_value.id)) calls in
                let original_call = match targets with
                  | [call] -> call
                  | _ -> invalid_arg "a vtable shim has no unique source callsite for its declared implementation method" in
                let _, shim_substitution = Callable_instance.source_substitution crate source_pointer in
                let actual_call = Substitute.st_substitute_visitor#visit_fn_ptr shim_substitution original_call in
                let expected = Substitute.st_substitute_visitor#visit_binder
                  Substitute.st_substitute_visitor#visit_fun_decl_ref substitution method_ in
                Some method_, Some (Method_instance.create expected actual_call)
            | _ -> None, None in
          Some { source_pointer; definition; shim_body; calls; declared_implementation_method; method_route;
            field_signature_binding; cast_signature_binding; receiver_lowering } in
    { field; actual_value; function_binding }) shape.fields values in
  { global; owner; implementation; initializer_pointer; initializer_definition; source_body; shape; slots }

let report view =
  let open Diagnostic in
  `Assoc ["source_global_id", `Int (GlobalDeclId.to_int view.global.def_id);
    "source_implementation_id", `Int (TraitImplId.to_int view.owner.id);
    "source_implementation_arguments", `String (show_generic_args view.owner.generics);
    "source_initializer_id", `Int (FunDeclId.to_int view.initializer_definition.def_id);
    "source_initializer_pointer", `String (show_fn_ptr view.initializer_pointer);
    "source_initializer_body", `String (show_block view.source_body.body);
    "slots", `List (List.map (fun slot -> `Assoc [
      "index", `Int (FieldId.to_int slot.field.index);
      "role", `String (Types.show_v_table_field slot.field.role);
      "actual_source_type", `String (show_ty slot.actual_value.ty);
      "declared_source_type", `String (show_ty slot.field.source_field.field_ty);
      "source_shim", (match slot.function_binding with
        | None -> `Null
        | Some binding -> `Assoc [
            "pointer", `String (show_fn_ptr binding.source_pointer);
            "function_id", `Int (FunDeclId.to_int binding.definition.def_id);
            "signature", `String (show_fun_sig binding.definition.signature);
            "stored_field_signature", Vtable_field.report binding.field_signature_binding;
            "source_cast_signature", Vtable_cast.report binding.cast_signature_binding;
            "receiver_lowering_candidate", Vtable_receiver.report binding.receiver_lowering;
            "body", `String (show_block binding.shim_body.body);
            "calls", `List (List.map (fun pointer -> `String (show_fn_ptr pointer)) binding.calls);
            "source_method_argument_route", (match binding.method_route with
              | None -> `Null | Some route -> Method_instance.report route);
            "declared_implementation_method", (match binding.declared_implementation_method with
              | None -> `Null
              | Some method_ -> `Assoc ["function_id", `Int (FunDeclId.to_int method_.binder_value.id);
                  "own_parameters", `String (show_generic_params method_.binder_params);
                  "arguments", `String (show_generic_args method_.binder_value.generics)])])]) view.slots);
    "layout_values_invented", `Bool false;
    "template_instantiation_cast_and_slot_abi_discharged", `Bool false;
    "native_loan_ownership_and_execution_adequacy_discharged", `Bool false;
    "source_program_emitted", `Bool false; "qualified", `Bool false]
