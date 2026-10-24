(* Conditional native representation of the actual closed source Write cases.
   This constructs a logical datatype overlay, never a native machine-layout
   claim. Outer-reference narrowing, source value reachability, original Box
   allocation/ownership and runtime case opening remain required proofs. *)
open Charon
open Types
open Values
open LlbcAst

type role = MainWriter | ObjectBuffer
type case = {
  role : role;
  source_global_index : int;
  source_case : Virtual_shim.t;
  producers : Prepared_injection.t list;
  original_outer_region : region;
  original_inner_type : ty;
  native_payload : ty;
  variant : variant;
}
type t = {
  source : Source_closure.t;
  adapters : Vtable_graph.t;
  owner : type_decl;
  field_index : int;
  source_field : field;
  source_field_tree : Return_region_certificate.expr;
  source_object : dyn_predicate;
  object_region : region;
  box_borrow : region;
  parent_writer : type_param;
  enum_declaration : type_decl;
  lifted_owner : type_decl;
  cases : case list;
  parent_writer_object_bound : (ty, region) outlives_pred region_binder;
  object_borrow_bound : region_outlives region_binder;
}

let boxed = function
  | TRef (borrow, TAdt { id = TBuiltin TBox; generics = { regions = []; types = [TDynTrait object_type]; const_generics = []; trait_refs = [] } }, RMut) ->
      Some (borrow, object_type)
  | _ -> None

let trait_id predicate = match predicate.binder.binder_params.trait_clauses with
  | [{ trait = { binder_regions = []; binder_value = reference }; _ }] -> reference.id
  | _ -> invalid_arg "a closed writer carrier needs its exact single original trait predicate"

let derive crate ~(source : Source_closure.t) ~(adapters : Vtable_graph.t) ~owner_id ~enum_id =
  if TypeDeclId.to_int enum_id < 0 || TypeDeclId.Map.mem enum_id crate.type_decls then
    invalid_arg "a native writer datatype needs a fresh source-distinct identity";
  let owner = match TypeDeclId.Map.find_opt owner_id crate.type_decls with Some owner -> owner
    | None -> invalid_arg "the actual writer-capturing source type is absent" in
  let fields = match owner.src, owner.kind with ClosureItem _, Struct fields -> fields
    | _ -> invalid_arg "the writer overlay requires an actual source closure struct" in
  let matches = List.mapi (fun index (field : field) -> index, field, boxed field.field_ty) fields
    |> List.filter_map (function index, field, Some shape -> Some (index, field, shape) | _ -> None) in
  let field_index, source_field, (box_borrow, source_object) = match matches with
    | [actual] -> actual | _ -> invalid_arg "the source closure must identify one exact borrowed dynamic Box field" in
  let source_field_tree = Return_region_certificate.reflect_type ~holes:[] source_field.field_ty in
  let parent_writer = match owner.generics.types, owner.generics.const_generics with
    | [parameter], [] -> parameter
    | _ -> invalid_arg "this source writer family needs its complete parent writer type parameter" in
  let id = trait_id source_object in
  let sources = List.filter_map (fun (_, _, global, (candidate : Virtual_shim.t), methods) ->
    if candidate.interface.trait_declaration.def_id <> id then None else (
      if candidate.interface.source_method.binder_value.name <> "write_all" ||
          candidate.interface.field.source_field.field_name <> Some "method_write_all" then
        invalid_arg "this source writer family requires the actual write_all method interface";
      if not (Virtual_shim.replay crate candidate) || List.exists (fun (_, node) -> node = None) methods then
        invalid_arg "the source writer case has an unreplayed shim or missing actual method body dependency";
      Some (global, candidate))) adapters.virtual_instances in
  if List.length sources <> 2 || List.length (List.sort_uniq Int.compare (List.map fst sources)) <> 2 then
    invalid_arg "the actual writer runtime must retain both distinct complete prepared-global cases";
  let shapes = List.map (fun (global, (candidate : Virtual_shim.t)) ->
    let object_region = Vtable_shape.object_annotation candidate.source_vtable.shape.source_predicate source_object in
    let outer, inner = match candidate.concrete_self with TRef (outer, inner, RMut) -> outer, inner
      | _ -> invalid_arg "the actual writer payload is not its original exclusive reference" in
    global, candidate, object_region, outer, inner) sources in
  let nested = List.filter (fun (_, _, _, _, inner) -> match inner with TRef (_, _, RMut) -> true | _ -> false) shapes in
  let direct = List.filter (fun (_, _, _, _, inner) -> match inner with TRef _ -> false | _ -> true) shapes in
  let main, buffer = match nested, direct with [main], [buffer] -> main, buffer
    | _ -> invalid_arg "the exact source writer cases are not the nested main writer and direct object buffer" in
  let _, _, object_region, _, main_inner = main in
  let _, _, buffer_object, _, buffer_type = buffer in
  if object_region <> buffer_object then invalid_arg "the writer cases disagree about the original source object annotation";
  let base = match main_inner with TRef (_, base, RMut) -> base | _ -> assert false in
  if base <> buffer_type then invalid_arg "the actual main writer and object buffer do not share their complete original byte-buffer type";
  let is_byte_buffer = match base with
    | TAdt { generics = { types = [TLiteral (TUInt U8)]; _ }; _ } -> true | _ -> false in
  if not is_byte_buffer then invalid_arg "the actual source writer family is not its complete source byte-buffer instantiation";
  (* The parent W instances are source evidence. Shape agreement does not prove
     runtime value origin or lifetime equality; both remain obligations. *)
  let owner_instances = List.filter (fun (node : Source_closure.type_node) ->
    node.view.source_resolution.declaration.def_id = owner_id) source.type_nodes in
  if owner_instances = [] then invalid_arg "the source writer closure has no actual complete type instance";
  List.iter (fun (node : Source_closure.type_node) ->
    match node.view.call_arguments.types with
    | [actual] when Return_signature.region_shape actual = Return_signature.region_shape main_inner -> ()
    | _ -> invalid_arg "an actual source parent writer instance differs outside its recorded lifetime environment") owner_instances;
  let object_parameter = { index = RegionId.of_int 0; name = Some "'auths_writer_object";
    variance = Invariant; mutability = LtMutable } in
  let native_object = RVar (Free object_parameter.index) in
  let native_parent = { parent_writer with index = TypeVarId.of_int 0; variance = Invariant } in
  let parent_writer_object_bound = { binder_regions = [];
    binder_value = TVar (Free parent_writer.index), object_region } in
  (* The lifted field is &'box mut Box<ClosedWriter<'object, W>>.
     Native region hierarchy analysis visits nominal predicates and generic
     arguments, not instantiated fields. Make the field's required liveness
     edge explicit alongside W:'object. It is conditional representation WF,
     not new source evidence: source value/reference and object-liveness
     interpretation must justify it before any source refinement is claimed. *)
  let object_borrow_bound = { binder_regions = [];
    binder_value = object_region, box_borrow } in
  let enum_bound = { binder_regions = []; binder_value = TVar (Free native_parent.index), native_object } in
  let make role ordinal (global, (candidate : Virtual_shim.t), _, original_outer_region, original_inner_type) =
    let producers = List.filter_map (fun (injection : Vtable_graph.injection) ->
      if injection.source_global_index <> global then None else match injection.producer.carrier with
      | Vtable_injection.OwnedBox _ ->
          if not (Prepared_injection.replay crate injection.producer) then invalid_arg "an actual writer Box producer did not replay";
          ignore (Prepared_injection.virtual_self ~candidate injection.producer);
          Some injection.producer
      | _ -> None) adapters.injections in
    if producers = [] then invalid_arg "a writer runtime case has no original owned Box producer";
    let inner = match role with MainWriter -> TVar (Free native_parent.index) | ObjectBuffer -> base in
    let native_payload = TRef (native_object, inner, RMut) in
    let payload_field = { source_field with field_name = Some "payload"; field_ty = native_payload } in
    let variant = { id = VariantId.of_int ordinal; span = source_field.span; attr_info = source_field.attr_info;
      variant_name = (match role with MainWriter -> "MainWriter" | ObjectBuffer -> "ObjectBuffer");
      fields = [payload_field]; discriminant = VScalar (UnsignedScalar (U8, Z.of_int ordinal)) } in
    { role; source_global_index = global; source_case = candidate; producers;
      original_outer_region; original_inner_type; native_payload; variant } in
  let cases = [make MainWriter 0 main; make ObjectBuffer 1 buffer] in
  let globals = List.map (fun case -> case.source_global_index) cases |> List.sort Int.compare in
  let actual_globals = List.filter_map (fun (injection : Vtable_graph.injection) ->
    match injection.producer.carrier with
    | Vtable_injection.OwnedBox _ when trait_id injection.producer.original.source_vtable.shape.source_predicate = id -> Some injection.source_global_index
    | _ -> None) adapters.injections |> List.sort_uniq Int.compare in
  if globals <> actual_globals then invalid_arg "the runtime writer family omitted or invented an actual owned source case";
  let enum_declaration : type_decl = { def_id = enum_id; src = TopLevelItem;
    item_meta = { owner.item_meta with name = owner.item_meta.name @
      [PeIdent ("__auths_closed_write", Disambiguator.of_int 0)] };
    generics = { TypesUtils.empty_generic_params with regions = [object_parameter]; types = [native_parent]; types_outlive = [enum_bound] };
    kind = Enum (List.map (fun case -> case.variant) cases); layout = []; ptr_metadata = NoMetadata } in
  let native_reference = { id = TAdtId enum_id; generics = { TypesUtils.empty_generic_args with
    regions = [object_region]; types = [TVar (Free parent_writer.index)] } } in
  let native_field = { source_field with field_ty = TRef (box_borrow,
    TAdt { id = TBuiltin TBox; generics = { TypesUtils.empty_generic_args with types = [TAdt native_reference] } }, RMut) } in
  let lifted_owner = { owner with kind = Struct (List.mapi (fun index field -> if index = field_index then native_field else field) fields);
    generics = { owner.generics with types = [{ parent_writer with variance = Invariant }];
      types_outlive = owner.generics.types_outlive @ [parent_writer_object_bound];
      regions_outlive = owner.generics.regions_outlive @
        (if List.mem object_borrow_bound owner.generics.regions_outlive then [] else [object_borrow_bound]) };
    layout = [] } in
  { source; adapters; owner; field_index; source_field; source_field_tree; source_object; object_region; box_borrow; parent_writer;
    enum_declaration; lifted_owner; cases; parent_writer_object_bound; object_borrow_bound }

let replay crate witness = try derive crate ~source:witness.source ~adapters:witness.adapters
  ~owner_id:witness.owner.def_id ~enum_id:witness.enum_declaration.def_id = witness
  with Invalid_argument _ | Not_found -> false

let create crate ~source ~adapters ~owner_id ~enum_id =
  let witness = derive crate ~source ~adapters ~owner_id ~enum_id in
  if not (replay crate witness) then invalid_arg "the complete actual source writer runtime family did not replay";
  witness

let native_types crate witness =
  if not (replay crate witness) then invalid_arg "the native writer type overlay lost its complete source evidence";
  TypeDeclId.Map.add witness.enum_declaration.def_id witness.enum_declaration
    (TypeDeclId.Map.add witness.owner.def_id witness.lifted_owner crate.type_decls)

let native_view crate witness =
  let type_decls = native_types crate witness in
  let rec add = function
    | [] -> invalid_arg "the lifted source writer closure has no original declaration group"
    | (TypeGroup group as original) :: rest when
        List.mem witness.owner.def_id (match group with NonRecGroup id -> [id] | RecGroup ids -> ids) ->
        TypeGroup (NonRecGroup witness.enum_declaration.def_id) :: original :: rest
    | original :: rest -> original :: add rest in
  { crate with type_decls; declarations = add crate.declarations;
    item_names = (IdType witness.enum_declaration.def_id, witness.enum_declaration.item_meta.name) :: crate.item_names;
    short_names = (IdType witness.enum_declaration.def_id, witness.enum_declaration.item_meta.name) :: crate.short_names }

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_owner", `Int (TypeDeclId.to_int witness.owner.def_id);
    "source_field", `Int witness.field_index;
    "source_field_type", `String (show_ty witness.source_field.field_ty);
    "native_enum", `Int (TypeDeclId.to_int witness.enum_declaration.def_id);
    "native_enum_kind", `String (show_type_decl_kind witness.enum_declaration.kind);
    "native_enum_requirements", `String (show_generic_params witness.enum_declaration.generics);
    "lifted_source_field", (match witness.lifted_owner.kind with Struct fields -> `String (show_ty (List.nth fields witness.field_index).field_ty) | _ -> `Null);
    "added_native_input_wellformedness", `String (show_generic_params { TypesUtils.empty_generic_params with
      types_outlive = [witness.parent_writer_object_bound]; regions_outlive = [witness.object_borrow_bound] });
    "source_box_borrow", `String (show_region witness.box_borrow);
    "required_native_object_outlives_box_borrow", `String
      (show_region (fst witness.object_borrow_bound.binder_value) ^ " : " ^ show_region (snd witness.object_borrow_bound.binder_value));
    "source_reference_and_object_liveness_justify_native_region_edge_proved", `Bool false;
    "original_dynamic_box_field_complete_structural_type_reflection_replays", `Bool
      (Return_region_certificate.replays_type ~holes:[] witness.source_field.field_ty witness.source_field_tree);
    "actual_cases", `List (List.map (fun case -> `Assoc [
      "variant", `Int (VariantId.to_int case.variant.id);
      "source_global_index", `Int case.source_global_index;
      "source_global_id", `Int (GlobalDeclId.to_int case.source_case.source_global.declaration.def_id);
      "complete_source_capture_arguments", `String (show_generic_args case.source_case.capture_arguments);
      "original_self", `String (show_ty case.source_case.concrete_self);
      "original_outer_region", `String (show_region case.original_outer_region);
      "original_inner_type", `String (show_ty case.original_inner_type);
      "native_payload", `String (show_ty case.native_payload);
      "actual_box_producers", `List (List.map (Prepared_injection.report crate) case.producers);
      "outer_reference_narrowing_preserving_inner_type_proved", `Bool false]) witness.cases);
    "source_runtime_tag_origin_and_capture_opening_proved", `Bool false;
    "source_reachable_inputs_satisfy_native_parent_writer_bound_proved", `Bool false;
    "allocation_layout_alias_loan_drop_and_unwind_refinement_proved", `Bool false;
    "complete_source_family_replays", `Bool (replay crate witness);
    "native_overlay_is_original_source_type_map", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]

let write_lean path witness =
  let main, buffer = match witness.cases with
    | [{ role = MainWriter; _ } as main; ({ role = ObjectBuffer; _ } as buffer)] -> main, buffer
    | _ -> invalid_arg "the actual writer certificate lost its complete ordered case family" in
  let reflect value = Return_region_certificate.reflect_type ~holes:[] value |> Return_region_certificate.lean in
  let output = Buffer.create 8192 in
  let line text = Buffer.add_string output (text ^ "\n") in
  line "import Auths.Support.ClosedWriterRuntime";
  line "import Auths.Support.WriterInputBound";
  line "/- Actual complete-source writer cases. Unelaborated/unqualified component data.";
  line "   Source tag/origin, narrowing, added WF and native loan/layout refinement remain required. -/";
  line "namespace Auths.Qualification.ClosedWriterRuntime";
  line "open Auths.Support.SourceClosureRegions Auths.Support.ClosedWriterRuntime";
  line "universe u";
  line ("def sourceOwner : Nat := " ^ string_of_int (TypeDeclId.to_int witness.owner.def_id));
  line ("def sourceField : Nat := " ^ string_of_int witness.field_index);
  let pointee = match witness.source_field.field_ty with TRef (region, pointee, RMut) when region = witness.box_borrow -> pointee
    | _ -> invalid_arg "the writer lifetime rule lost its exact original source Box field" in
  line ("def originalBoxField : Expr := " ^ Return_region_certificate.lean witness.source_field_tree);
  line ("def originalBoxPointee : Expr := " ^ reflect pointee);
  line ("def originalBoxBorrow : Region := " ^ Return_region_certificate.lean_region witness.box_borrow);
  line ("def originalObjectRegion : Region := " ^ Return_region_certificate.lean_region witness.object_region);
  line "theorem original_box_field_has_exact_source_structure :";
  line "    originalBoxField = .node .mutRef [.region originalBoxBorrow, originalBoxPointee] := by decide";
  line "theorem original_object_annotation_matches_complete_existential_predicate :";
  line "    Auths.Support.WriterInputBound.boxedObjectAnnotation originalBoxPointee = some originalObjectRegion := by decide";
  line "theorem source_box_reference_supplies_required_native_region_edge {Point : Type u}";
  line "    (regions : Auths.Support.WriterInputBound.RegionMeaning Point) (typeLive : Expr → Point → Prop)";
  line "    (typed : Auths.Support.WriterInputBound.ReferenceLifetimeWF regions typeLive originalBoxField)";
  line "    (objectLive : ∀ point, typeLive originalBoxPointee point → point ∈ regions originalObjectRegion) :";
  line "    regions originalBoxBorrow ⊆ regions originalObjectRegion := by";
  line "  rw [original_box_field_has_exact_source_structure] at typed";
  line "  exact Auths.Support.WriterInputBound.source_reference_supplies_nested_object_edge regions typeLive originalBoxBorrow originalObjectRegion originalBoxPointee typed objectLive";
  line "theorem checked_source_box_field_supplies_required_native_region_edge {Point : Type u}";
  line "    (regions : Auths.Support.WriterInputBound.RegionMeaning Point) (typeLive : Expr → Point → Prop)";
  line "    (meaning : Auths.Support.WriterInputBound.BoxObjectInterpretation regions typeLive)";
  line "    (typed : Auths.Support.WriterInputBound.ReferenceLifetimeWF regions typeLive originalBoxField) :";
  line "    regions originalBoxBorrow ⊆ regions originalObjectRegion := by";
  line "  rw [original_box_field_has_exact_source_structure] at typed";
  line "  exact Auths.Support.WriterInputBound.checked_source_object_field_supplies_nested_edge regions typeLive originalBoxBorrow originalObjectRegion originalBoxPointee original_object_annotation_matches_complete_existential_predicate meaning typed";
  line ("def mainGlobalInstance : Nat := " ^ string_of_int main.source_global_index);
  line ("def bufferGlobalInstance : Nat := " ^ string_of_int buffer.source_global_index);
  line ("def mainGlobalDeclaration : Nat := " ^ string_of_int (GlobalDeclId.to_int main.source_case.source_global.declaration.def_id));
  line ("def bufferGlobalDeclaration : Nat := " ^ string_of_int (GlobalDeclId.to_int buffer.source_case.source_global.declaration.def_id));
  line ("def mainSourceSelf : Expr := " ^ reflect main.source_case.concrete_self);
  line ("def bufferSourceSelf : Expr := " ^ reflect buffer.source_case.concrete_self);
  line ("def mainOriginalInner : Expr := " ^ reflect main.original_inner_type);
  line ("def bufferOriginalInner : Expr := " ^ reflect buffer.original_inner_type);
  line ("def mainNativeSchema : Expr := " ^ reflect main.native_payload);
  line ("def bufferNativePayload : Expr := " ^ reflect buffer.native_payload);
  line "theorem actual_source_cases_distinct : mainGlobalInstance ≠ bufferGlobalInstance := by decide";
  line "theorem actual_source_self_types_distinct : mainSourceSelf ≠ bufferSourceSelf := by decide";
  line "theorem main_source_inner_exact : innerExclusiveReference mainSourceSelf = some mainOriginalInner := by decide";
  line "theorem buffer_source_inner_exact : innerExclusiveReference bufferSourceSelf = some bufferOriginalInner := by decide";
  line "theorem main_native_specialization_keeps_invariant_inner :";
  line "    (instantiateMainPayload mainNativeSchema mainOriginalInner).bind innerExclusiveReference =";
  line "      some mainOriginalInner := by decide";
  line "theorem buffer_native_payload_keeps_invariant_inner :";
  line "    innerExclusiveReference bufferNativePayload = some bufferOriginalInner := by decide";
  if main.source_case.source_global.declaration.def_id = buffer.source_case.source_global.declaration.def_id then (
    line "theorem a_global_declaration_is_not_a_runtime_case_identity :";
    line "    mainGlobalDeclaration = bufferGlobalDeclaration ∧ mainSourceSelf ≠ bufferSourceSelf := by decide");
  line "end Auths.Qualification.ClosedWriterRuntime";
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try output_string channel (Buffer.contents output); close_out channel with error ->
    close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error
