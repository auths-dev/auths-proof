(* Concrete receiver specialization of actual generated source shims. This is
   an isolated lowering candidate, never a replacement source declaration.
   The caller must establish that its dynamic receiver carries this exact
   implementation; signature replay cannot supply that runtime invariant.
   Calls, drops, unwinds, storage, moves and every source statement ID survive.
   Only a single generated receiver concretization becomes a typed move. *)
open Charon
open Types
open Expressions
open LlbcAst

type annotation = { original : ty; concrete : ty; object_region : region }
type cast_edit = { statement_id : statement_id; original : rvalue; concrete : rvalue }
type t = {
  cast_signature : Vtable_cast.t;
  implementation : trait_impl;
  source_owner : dyn_predicate;
  self_type : ty;
  source_body : expr_body;
  concrete_signature : fun_sig;
  concrete_body : expr_body;
  annotations : annotation list;
  cast_edits : cast_edit list;
}

let derive ~(cast_signature : Vtable_cast.t) ~(implementation : trait_impl) =
  if not (Vtable_cast.replay cast_signature) then
    invalid_arg "receiver lowering requires the complete source cast signature witness";
  let definition = cast_signature.definition in
  let source_owner = cast_signature.field.owner in
  Vtable_shape.require_object_marker source_owner;
  if implementation.generics <> cast_signature.owner_parameters then
    invalid_arg "receiver lowering changed the captured source implementation environment";
  let primary = match source_owner.binder.binder_params.trait_clauses with
    | [clause] when clause.trait.binder_regions = [] -> clause.trait.binder_value
    | _ -> invalid_arg "a receiver with additional source trait predicates needs explicit dictionary lowering" in
  let self_type = match implementation.impl_trait.generics.types with
    | [self_type] when implementation.impl_trait.id = primary.id &&
        implementation.impl_trait.generics = { TypesUtils.empty_generic_args with types = [self_type] } &&
        (match primary.generics.types with
         | [TVar (Bound (1, _))] -> primary.generics = { TypesUtils.empty_generic_args with types = primary.generics.types }
         | _ -> false) -> self_type
    | _ -> invalid_arg "receiver lowering requires the complete actual implementation Self/trait arguments" in
  let source_body = match definition.body with
    | StructuredBody body -> body
    | _ -> invalid_arg "receiver lowering requires the actual generated structured shim body" in
  let has_dyn = ref false in
  let scan_self = object inherit [_] iter_ty
    method! visit_dyn_predicate _ _ = has_dyn := true
  end in
  scan_self#visit_ty () self_type;
  if !has_dyn then invalid_arg "a dynamic implementation Self needs a separately typed nested receiver representation";
  let annotations = ref [] in
  let receiver_ty original = match original with
    | TRef (borrow, TDynTrait predicate, mutability) ->
        let object_region = Vtable_shape.object_annotation source_owner predicate in
        (match object_region with
         | RErased -> () (* Retained generated source marker, never promoted to a region witness. *)
         | region -> (new Region_scope.check ~body_regions:source_body.bound_body_regions
             definition.generics.regions)#visit_region [] region);
        let concrete = TRef (borrow, self_type, mutability) in
        annotations := { original; concrete; object_region } :: !annotations;
        concrete
    | _ -> invalid_arg "a generated shim receiver must be the original borrowed dynamic value" in
  let first, rest = match definition.signature.inputs with
    | first :: rest -> first, rest
    | [] -> invalid_arg "a generated shim must retain its source receiver argument" in
  let concrete_signature = { definition.signature with inputs = receiver_ty first :: rest } in
  let receiver_id = LocalId.of_int 1 in
  let source_receiver = match List.filter (fun (local : local) -> local.index = receiver_id) source_body.locals.locals with
    | [local] when source_body.locals.arg_count = List.length definition.signature.inputs -> local
    | _ -> invalid_arg "the generated shim's first source argument/local is absent or ambiguous" in
  let concrete_receiver = receiver_ty source_receiver.local_ty in
  if concrete_receiver <> List.hd concrete_signature.inputs then
    invalid_arg "the source receiver local disagrees with the complete source signature";
  let concrete_only = object
    inherit [_] iter_statement
    method! visit_dyn_predicate _ _ =
      invalid_arg "a dynamic value outside the unique receiver concretization needs separate flow/ABI evidence"
  end in
  List.iter (concrete_only#visit_ty ()) rest;
  concrete_only#visit_ty () concrete_signature.output;
  let cast_edits = ref [] in
  let type_mapper = object
    inherit [_] map_statement as super
    method! visit_ty env = function
      | (TRef (_, TDynTrait _, _) as original) -> receiver_ty original
      | TDynTrait _ -> invalid_arg "an unborrowed dynamic value cannot become a concrete receiver"
      | ty -> super#visit_ty env ty
  end in
  let map_place (place : place) =
    (match place.ty with
     | TRef (_, TDynTrait _, _) when place.kind <> PlaceLocal receiver_id ->
         invalid_arg "a generated dynamic receiver escapes its actual first argument local"
     | _ -> ());
    type_mapper#visit_place () place in
  let mapper = object
    inherit [_] map_statement as super
    method! visit_ty _ ty = concrete_only#visit_ty () ty; ty
    method! visit_place _ place = concrete_only#visit_place () place; place
    method! visit_statement env (statement : statement) =
      let kind = match statement.kind with
        | Assign (destination, (UnaryOp (Cast (CastConcretize (from_ty, into_ty)), operand) as original)) ->
            let source = match operand with
              | Move place when place.kind = PlaceLocal receiver_id -> place
              | _ -> invalid_arg "a generated receiver concretization must move its actual first argument" in
            let concrete_from = receiver_ty from_ty in
            if concrete_from <> into_ty || (map_place source).ty <> into_ty then
              invalid_arg "the original concretization changes the receiver borrow, mutability or concrete Self";
            if destination.ty <> into_ty then
              invalid_arg "the generated concretization destination differs from its original concrete type";
            let concrete = Use (Move (map_place source), NoRetag) in
            cast_edits := { statement_id = statement.statement_id; original; concrete } :: !cast_edits;
            Assign (map_place destination, concrete)
        | Assign (_, Aggregate (AggregatedAdt ({ id = TTuple; generics }, None, None), []))
            when generics = TypesUtils.empty_generic_args ->
            (super#visit_statement env statement).kind
        | StorageLive _ | StorageDead _ | Return | UnwindResume -> statement.kind
        | Call ({ func = FnOpRegular _; _ }, _) | Drop _ ->
            (super#visit_statement env statement).kind
        | _ -> invalid_arg "the generated shim contains an unsupported receiver flow or effect" in
      { statement with kind }
  end in
  let locals = List.map (fun (local : local) ->
    match local.local_ty with
    | TRef (_, TDynTrait _, _) when local.index <> receiver_id ->
        invalid_arg "the source shim contains another dynamic local requiring explicit flow evidence"
    | TRef (_, TDynTrait _, _) -> { local with local_ty = type_mapper#visit_ty () local.local_ty }
    | _ -> concrete_only#visit_ty () local.local_ty; local) source_body.locals.locals in
  let concrete_body = { source_body with locals = { source_body.locals with locals };
    body = mapper#visit_block () source_body.body } in
  let cast_edits = List.rev !cast_edits in
  if List.length cast_edits <> 1 then
    invalid_arg "the generated shim needs exactly one source receiver concretization";
  let check = new Region_scope.statement_check ~body_regions:source_body.bound_body_regions definition.generics.regions in
  check#visit_fun_sig [] concrete_signature;
  List.iter (fun (local : local) -> check#visit_ty [] local.local_ty) locals;
  check#visit_block [] concrete_body.body;
  { cast_signature; implementation; source_owner; self_type; source_body; concrete_signature; concrete_body;
    annotations = List.rev !annotations; cast_edits }

let replay witness =
  try derive ~cast_signature:witness.cast_signature ~implementation:witness.implementation = witness
  with Invalid_argument _ -> false

let create ~cast_signature ~implementation =
  let witness = derive ~cast_signature ~implementation in
  if not (replay witness) then invalid_arg "the complete generated receiver lowering candidate did not replay";
  witness

let report witness =
  let open Diagnostic in
  `Assoc ["source_function_id", `Int (FunDeclId.to_int witness.cast_signature.definition.def_id);
    "implementation_self_template", `String (show_ty witness.self_type);
    "concrete_signature", `String (show_fun_sig witness.concrete_signature);
    "concrete_locals", `List (List.map (fun (local : local) -> `Assoc [
      "id", `Int (LocalId.to_int local.index); "type", `String (show_ty local.local_ty)]) witness.concrete_body.locals.locals);
    "concrete_source_body", `String (show_block witness.concrete_body.body);
    "retained_source_object_annotations", `List (List.map (fun (entry : annotation) -> `Assoc [
      "original", `String (show_ty entry.original); "concrete", `String (show_ty entry.concrete);
      "object_region", `String (show_region entry.object_region)]) witness.annotations);
    "receiver_cast_edits", `List (List.map (fun (entry : cast_edit) -> `Assoc [
      "statement_id", `Int (StatementId.to_int entry.statement_id);
      "original", `String (show_rvalue entry.original);
      "concrete", `String (show_rvalue entry.concrete)]) witness.cast_edits);
    "complete_candidate_replays", `Bool (replay witness);
    "caller_receiver_implementation_invariant_proved", `Bool false;
    "native_value_loan_ownership_drop_and_unwind_simulation_proved", `Bool false;
    "program_emitted", `Bool false]
