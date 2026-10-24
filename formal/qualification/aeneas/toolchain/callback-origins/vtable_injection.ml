(* Pair a real concrete-to-dynamic source cast with its real dictionary and
   static vtable. Region equations are source reconstruction constraints, not
   a proof of loans, subtyping or dynamic value flow. Borrow shortening and
   object liveness remain separate, explicit obligations. No program is emitted. *)
open Charon
open Types
open Expressions
open LlbcAst

type carrier =
  | Borrowed of region * region * ref_kind
  | OwnedBox of type_decl_ref * type_decl_ref

let classify_carrier ~owner ~from_type ~into_type operand =
  let operand_type = match operand with Move place | Copy place -> place.ty
    | Constant constant -> constant.ty in
  if operand_type <> from_type then invalid_arg "the original dynamic injection operand type changed";
  let actual_object predicate =
    let region = Vtable_shape.object_annotation owner predicate in
    if region = RErased then invalid_arg "an injected dynamic receiver needs actual source object provenance";
    region in
  match from_type, into_type with
  | TRef (source_borrow, source_self, source_mutability), TRef (dynamic_borrow, TDynTrait predicate, target_mutability)
      when source_mutability = target_mutability ->
      (match source_mutability, operand with
       | RMut, Copy _ -> invalid_arg "a dynamic injection cannot copy an exclusive source borrow"
       | _ -> ());
      Borrowed (source_borrow, dynamic_borrow, source_mutability), actual_object predicate, source_self
  | TAdt ({ id = TBuiltin TBox; generics = { types = [source_self]; _ } } as source_box),
      TAdt ({ id = TBuiltin TBox; generics = { types = [TDynTrait predicate]; _ } } as target_box)
      when source_box.generics = { TypesUtils.empty_generic_args with types = [source_self] } &&
        target_box.generics = { TypesUtils.empty_generic_args with types = [TDynTrait predicate] } ->
      (match operand with Move _ -> ()
       | _ -> invalid_arg "a dynamic Box injection must retain the actual owned source move");
      OwnedBox (source_box, target_box), actual_object predicate, source_self
  | _ -> invalid_arg "a dynamic injection needs its original borrowed or owned Box carrier and complete concrete/dynamic types"

type t = {
  caller : fun_decl;
  source_statement : statement;
  from_type : ty;
  into_type : ty;
  operand : operand;
  dictionary : trait_ref;
  metadata : constant_expr;
  global_reference : global_decl_ref;
  source_vtable : Vtable_initializer.t;
  metadata_owner : trait_impl_ref;
  static_owner : trait_impl_ref;
  instantiated_self : ty;
  region_constraints : Region_equations.predicates;
  carrier : carrier;
  object_region : region;
  inherited_requirements : generic_params;
}

let derive crate ~(caller : fun_decl) (source_statement : statement) =
  (match FunDeclId.Map.find_opt caller.def_id crate.fun_decls with
   | Some source when source = caller -> ()
   | _ -> invalid_arg "a dynamic injection caller must be the complete actual source declaration");
  let body = match caller.body with StructuredBody body -> body
    | _ -> invalid_arg "a dynamic injection requires the actual caller source body" in
  let occurrences = ref 0 in
  let find = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = source_statement.statement_id then (
        if statement <> source_statement then invalid_arg "a dynamic injection source statement ID was substituted";
        incr occurrences);
      super#visit_statement env statement
  end in
  find#visit_block () body.body;
  if !occurrences <> 1 then invalid_arg "a dynamic injection must identify one exact source statement";
  let destination, from_type, into_type, dictionary, metadata, operand = match source_statement.kind with
    | Assign (destination, UnaryOp (Cast (CastUnsize (from_type, into_type, MetaVTable (dictionary, metadata))), operand)) ->
        destination, from_type, into_type, dictionary, metadata, operand
    | _ -> invalid_arg "a dynamic injection needs its original value-to-vtable cast" in
  let global_reference, value_type = match metadata.kind, metadata.ty with
    | CRef ({ kind = CGlobal reference; ty }, None), TRef (RStatic, outer, RShared)
        when ty = outer -> reference, ty
    | _ -> invalid_arg "a dynamic injection requires its actual static shared vtable reference" in
  let global = match GlobalDeclId.Map.find_opt global_reference.id crate.global_decls with
    | Some global -> global | None -> invalid_arg "the injected source vtable global is absent" in
  let source_vtable = Vtable_initializer.create crate global in
  Static_targets.require_argument_arity global.generics global_reference.generics;
  let global_substitution = Substitute.make_subst_from_generics global.generics global_reference.generics Self in
  if Substitute.ty_substitute global_substitution global.ty <> value_type then
    invalid_arg "the actual source metadata reference differs from its instantiated global type";
  let static_owner = Substitute.st_substitute_visitor#visit_trait_impl_ref global_substitution source_vtable.owner in
  let metadata_owner = match dictionary.kind with
    | TraitImpl owner when owner.id = static_owner.id -> owner
    | _ -> invalid_arg "the source dynamic dictionary and static vtable select different implementations" in
  let implementation = source_vtable.implementation in
  Static_targets.require_argument_arity implementation.generics metadata_owner.generics;
  Static_targets.require_argument_arity implementation.generics static_owner.generics;
  let substitution = Substitute.make_subst_from_generics implementation.generics metadata_owner.generics dictionary.kind in
  let instantiated_trait = Substitute.trait_decl_ref_substitute substitution implementation.impl_trait in
  let instantiated_self = match instantiated_trait.generics.types with
    | self :: _ -> self | [] -> invalid_arg "the injected implementation has no actual source Self" in
  let carrier, object_region, source_self = classify_carrier ~owner:source_vtable.shape.source_predicate
    ~from_type ~into_type operand in
  let constraints = Region_equations.add_arguments Region_equations.empty_predicates
    metadata_owner.generics static_owner.generics in
  let constraints = Region_equations.add_predicate constraints
    { binder_regions = []; binder_value = instantiated_trait } dictionary.trait_decl_ref in
  let constraints = Region_equations.add_type constraints instantiated_self source_self in
  let constraints = Region_equations.add_type constraints into_type destination.ty in
  if not (Region_equations.replay_predicates constraints) then
    invalid_arg "the complete source dynamic dictionary/static/value constraints did not replay";
  let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions caller.generics.regions in
  scope#visit_statement [] source_statement;
  let inherited_requirements = Substitute.predicates_substitute substitution implementation.generics in
  scope#visit_generic_params [] inherited_requirements;
  { caller; source_statement; from_type; into_type; operand; dictionary; metadata; global_reference;
    source_vtable; metadata_owner; static_owner; instantiated_self; region_constraints = constraints;
    carrier; object_region; inherited_requirements }

let replay crate witness =
  try derive crate ~caller:witness.caller witness.source_statement = witness
  with Invalid_argument _ -> false

let create crate ~caller statement =
  let witness = derive crate ~caller statement in
  if not (replay crate witness) then invalid_arg "the complete actual source dynamic injection did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let carrier = match witness.carrier with
    | Borrowed (source_borrow, dynamic_borrow, mutability) -> `Assoc [
        "kind", `String "borrowed"; "mutability", `String (Types.show_ref_kind mutability);
        "required_borrow_shortening", `List [`String (show_region source_borrow); `String (show_region dynamic_borrow)];
        "required_object_outlives_borrow", `List [`String (show_region witness.object_region); `String (show_region dynamic_borrow)]]
    | OwnedBox (source_box, target_box) -> `Assoc ["kind", `String "owned_box";
        "source_box", `String (show_type_decl_ref source_box); "target_box", `String (show_type_decl_ref target_box);
        "actual_source_move_retained", `Bool true;
        "allocation_layout_unique_ownership_drop_and_unwind_proved", `Bool false] in
  `Assoc ["source_function_id", `Int (FunDeclId.to_int witness.caller.def_id);
    "source_statement_id", `Int (StatementId.to_int witness.source_statement.statement_id);
    "source_vtable_global_id", `Int (GlobalDeclId.to_int witness.global_reference.id);
    "source_implementation_id", `Int (TraitImplId.to_int witness.metadata_owner.id);
    "original_operand", `String (show_operand witness.operand);
    "original_from_type", `String (show_ty witness.from_type);
    "original_into_type", `String (show_ty witness.into_type);
    "actual_metadata_dictionary", `String (show_trait_ref witness.dictionary);
    "actual_static_metadata", `String (show_constant_expr witness.metadata);
    "instantiated_self", `String (show_ty witness.instantiated_self);
    "source_reconstruction_constraints", region_certificate_json witness.region_constraints;
    "source_where_requirements", `String (show_generic_params witness.inherited_requirements);
    "source_carrier", carrier;
    "required_self_outlives_object", `Assoc ["type", `String (show_ty witness.instantiated_self);
      "region", `String (show_region witness.object_region)];
    "complete_source_injection_replays", `Bool (replay crate witness);
    "source_constraints_loan_and_where_requirements_proved", `Bool false;
    "caller_dynamic_value_flow_and_source_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
