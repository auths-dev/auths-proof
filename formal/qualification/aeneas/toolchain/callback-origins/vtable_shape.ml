(* Source representation candidate for generated polymorphic vtables. The
   single erased object-lifetime annotation is exposed as a fresh *local*
   function-pointer parameter, with exact erasure replay. This is not a proof
   of lifetime/loan preservation, field ABI, a vtable initializer or a method
   shim. Type_view's source-provenance refusal is deliberately unchanged. *)
open Charon
open Types
open Values
open LlbcAst

type function_field = {
  original : fun_sig region_binder;
  parameterized : fun_sig region_binder;
  object_parameter : region_param;
  dynamic_occurrences : int;
}

type field_view = {
  index : field_id;
  role : v_table_field;
  source_field : field;
  function_field : function_field option;
  source_method : trait_method binder option;
}

type t = {
  source_type : type_decl;
  source_trait : trait_decl;
  source_predicate : dyn_predicate;
  fields : field_view list;
  supertrait_map : field_id option list;
}

let unit = TAdt { id = TTuple; generics = TypesUtils.empty_generic_args }
let usize = TLiteral (TUInt Usize)

let object_annotation owner predicate =
  let source = predicate.binder.binder_params in
  match source.types_outlive with
  | [({ binder_regions = []; binder_value = (ty, region) } as bound)] ->
      let erased = { binder = { predicate.binder with binder_params = {
        source with types_outlive = [{ bound with binder_value = ty, RErased }] } } } in
      if erased <> owner then invalid_arg "a dynamic receiver differs from its complete source owner predicate";
      region
  | _ -> invalid_arg "a dynamic receiver lacks its exact source object annotation"

let require_object_marker (owner : dyn_predicate) =
  let parameters = owner.binder.binder_params in
  let self_id = match parameters.types, owner.binder.binder_value with
    | [parameter], TVar (Bound (0, id)) when parameter.index = id -> id
    | _ -> invalid_arg "a generated vtable needs its exact existential Self binder" in
  if parameters.regions <> [] || parameters.const_generics <> [] then
    invalid_arg "a generated vtable object binder has unsupported additional parameters";
  match parameters.types_outlive with
  | [{ binder_regions = []; binder_value = (TVar (Bound (1, id)), RErased) }]
      when id = self_id -> ()
  | _ -> invalid_arg "a generated vtable needs exactly its original erased object-bound marker"

let forget_object_parameter (field : function_field) =
  let forget = object
    inherit [_] Region_shape.binder_map
    method! visit_region depth = function
      | RVar (Bound (binder, id)) when binder = depth && id = field.object_parameter.index -> RErased
      | region -> region
  end in
  { binder_regions = List.filter (fun (parameter : region_param) ->
      parameter.index <> field.object_parameter.index) field.parameterized.binder_regions;
    binder_value = forget#visit_fun_sig 0 field.parameterized.binder_value }

let parameterize owner (original : fun_sig region_binder) =
  require_object_marker owner;
  Region_scope.require_parameters original.binder_regions;
  if List.exists (fun (parameter : region_param) -> RegionId.to_int parameter.index = Int.max_int)
      original.binder_regions then
    invalid_arg "a generated vtable object parameter exceeds its construction identifier limit";
  let next = List.fold_left (fun next (parameter : region_param) ->
    Stdlib.max next (RegionId.to_int parameter.index + 1)) 0 original.binder_regions in
  let object_parameter : region_param = {
    index = RegionId.of_int next; name = Some "'vtable_object";
    variance = Invariant; mutability = LtUnknown } in
  let occurrences = ref 0 in
  let expose = object
    inherit [_] Region_shape.binder_map as super
    method! visit_dyn_predicate depth predicate =
      if predicate <> owner then super#visit_dyn_predicate depth predicate else (
        incr occurrences;
        let parameters = predicate.binder.binder_params in
        let types_outlive = List.map (fun source ->
          let ty, _ = source.binder_value in
          (* Under the existential Self binder and its empty outlives binder.
             Additional enclosing binders are included, never flattened. *)
          { source with binder_value = ty,
              RVar (Bound (depth + 2, object_parameter.index)) }) parameters.types_outlive in
        super#visit_dyn_predicate depth { binder = {
          predicate.binder with binder_params = { parameters with types_outlive } } })
  end in
  let parameterized = {
    binder_regions = original.binder_regions @ [object_parameter];
    binder_value = expose#visit_fun_sig 0 original.binder_value } in
  if !occurrences = 0 then invalid_arg "a generated vtable function field has no exact source dynamic receiver";
  let result = { original; parameterized; object_parameter; dynamic_occurrences = !occurrences } in
  if forget_object_parameter result <> original then
    invalid_arg "generated vtable object parameterization did not reconstruct the complete original field signature";
  result

let replay_function owner field =
  try parameterize owner field.original = field && forget_object_parameter field = field.original
  with Invalid_argument _ -> false

let create crate (declaration : type_decl) =
  let owner, roles, supertrait_map = match declaration.src with
    | VTableTyItem (owner, roles, supertrait_map) -> owner, roles, supertrait_map
    | _ -> invalid_arg "vtable shape evidence requires the actual generated source origin" in
  require_object_marker owner;
  let owner_clause = match owner.binder.binder_params.trait_clauses with
    | clause :: _ when clause.trait.binder_regions = [] -> clause
    | _ -> invalid_arg "generated vtable owner needs its actual non-quantified primary trait predicate" in
  let trait_id = owner_clause.trait.binder_value.id in
  (match owner.binder.binder_value, owner_clause.trait.binder_value.generics.types with
   | TVar (Bound (0, self)), TVar (Bound (1, actual)) :: _ when self = actual -> ()
   | _ -> invalid_arg "the generated vtable's primary trait predicate does not bind its exact existential Self");
  let source_trait = match TraitDeclId.Map.find_opt trait_id crate.trait_decls with
    | Some declaration -> declaration
    | None -> invalid_arg "the generated vtable's actual trait declaration is absent" in
  (match source_trait.vtable with
   | Some { id = TAdtId id; _ } when id = declaration.def_id -> ()
   | _ -> invalid_arg "the source trait does not name this generated vtable declaration");
  if declaration.ptr_metadata <> NoMetadata then
    invalid_arg "a generated vtable struct must retain its actual sized pointer metadata";
  let source_fields = match declaration.kind with
    | Struct fields -> fields
    | _ -> invalid_arg "generated vtable field evidence requires actual source struct fields" in
  if List.length source_fields <> List.length roles then
    invalid_arg "the generated vtable's source fields and role map have different arities";
  (match roles with
   | VTableSize :: VTableAlign :: VTableDrop :: _ -> ()
   | _ -> invalid_arg "the generated vtable source prefix differs from size/align/drop");
  let unique = List.sort_uniq Types.compare_v_table_field roles in
  if List.length unique <> List.length roles then
    invalid_arg "the generated vtable source role map contains duplicate slots";
  List.iteri (fun clause_id -> function
    | None -> ()
    | Some field ->
        (match List.nth_opt roles (FieldId.to_int field) with
         | Some (VTableSuperTrait actual) when TraitClauseId.to_int actual = clause_id -> ()
         | _ -> invalid_arg "the actual vtable supertrait map disagrees with its source field role")) supertrait_map;
  let fields = List.mapi (fun index (source_field, role) ->
    let index = FieldId.of_int index in
    let require_name expected = if source_field.field_name <> Some expected then
      invalid_arg "the actual generated vtable field name disagrees with its source role" in
    let function_field, source_method = match role with
      | VTableSize | VTableAlign ->
          require_name (if role = VTableSize then "size" else "align");
          if source_field.field_ty <> usize then
            invalid_arg "a generated size/align slot is not its actual usize field";
          None, None
      | VTableDrop ->
          require_name "drop";
          let signature = match source_field.field_ty with
            | TFnPtr signature -> signature
            | _ -> invalid_arg "a polymorphic generated drop field needs its actual function pointer" in
          (match signature.binder_regions, signature.binder_value.inputs with
           | [parameter], [TRef (RVar (Bound (0, id)), TDynTrait receiver, RMut)]
               when parameter.index = id && receiver = owner && signature.binder_value.is_unsafe &&
                 signature.binder_value.abi = AbiRust && not signature.binder_value.is_variadic &&
                 signature.binder_value.output = unit -> ()
           | _ -> invalid_arg "a generated drop field disagrees with the exact source drop-glue ABI");
          Some (parameterize owner signature), None
      | VTableMethod method_id ->
          let method_ = match TraitMethodId.Map.find_opt method_id source_trait.methods with
            | Some method_ -> method_
            | None -> invalid_arg "a generated method field has no actual source trait method" in
          require_name ("method_" ^ method_.binder_value.name);
          let signature = match source_field.field_ty with
            | TFnPtr signature -> signature
            | _ -> invalid_arg "a generated method field needs its actual polymorphic function pointer" in
          Some (parameterize owner signature), Some method_
      | VTableSuperTrait clause_id ->
          let clauses = List.filter (fun (clause : trait_param) -> clause.clause_id = clause_id)
            source_trait.implied_clauses in
          if List.length clauses <> 1 ||
             List.nth_opt supertrait_map (TraitClauseId.to_int clause_id) <> Some (Some index) then
            invalid_arg "a generated supertrait field has no exact source clause and reverse slot mapping";
          (match source_field.field_ty with
           | TRef (RStatic, TAdt { id = TAdtId _; _ }, RShared) -> ()
           | _ -> invalid_arg "a generated supertrait field needs its original static vtable reference");
          None, None in
    (match function_field with
     | None -> ()
     | Some field ->
         if not (replay_function owner field) then invalid_arg "generated vtable function-field reconstruction failed";
         let scope = new Region_scope.check declaration.generics.regions in
         scope#visit_ty [] (TFnPtr field.parameterized));
    { index; role; source_field; function_field; source_method }) (List.combine source_fields roles) in
  { source_type = declaration; source_trait; source_predicate = owner; fields; supertrait_map }

let report view =
  let open Diagnostic in
  let signature signature = show_ty (TFnPtr signature) in
  `Assoc ["source_type_id", `Int (TypeDeclId.to_int view.source_type.def_id);
    "source_trait_id", `Int (TraitDeclId.to_int view.source_trait.def_id);
    "original_source_context", `String (show_item_source view.source_type.src);
    "fields", `List (List.map (fun field -> `Assoc [
      "index", `Int (FieldId.to_int field.index);
      "role", `String (Types.show_v_table_field field.role);
      "original_source_type", `String (show_ty field.source_field.field_ty);
      "function_lifetime_view", (match field.function_field with
        | None -> `Null
        | Some value -> `Assoc ["original_signature", `String (signature value.original);
            "parameterized_signature", `String (signature value.parameterized);
            "object_parameter", `String (show_region_param value.object_parameter);
            "dynamic_occurrences", `Int value.dynamic_occurrences;
            "complete_source_erasure_replays", `Bool (replay_function view.source_predicate value)]);
      "actual_method_signature", (match field.source_method with
        | None -> `Null
        | Some method_ -> `Assoc ["parameters", `String (show_generic_params method_.binder_params);
            "signature", `String (show_fun_sig method_.binder_value.signature)])]) view.fields);
    "source_provenance_gate_relaxed", `Bool false;
    "native_lifetime_and_loan_adequacy_discharged", `Bool false;
    "initializer_shim_and_call_bindings_discharged", `Bool false;
    "source_program_emitted", `Bool false;
    "qualified", `Bool false]
