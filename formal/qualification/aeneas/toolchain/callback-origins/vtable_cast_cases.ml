(* Source-cast regressions, authored only. The final batch must build/run these.
   This component reconstructs signatures; it makes no native call/loan claim. *)
open Charon
open Types
open LlbcAst

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let empty = TypesUtils.empty_generic_args
let rid = RegionId.of_int
let free id = RVar (Free (rid id))
let body id = RBody (rid id)
let bound id = RVar (Bound (0, rid id))
let boolean = TLiteral Charon.Values.TBool
let parameter index : region_param = { index = rid index; name = None;
  variance = Invariant; mutability = LtShared }
let self_id = TypeVarId.of_int 0
let owner target : dyn_predicate = { binder = {
  binder_params = { TypesUtils.empty_generic_params with
    types = [{ index = self_id; name = "_dyn"; variance = VaUnknown }];
    trait_clauses = [{ clause_id = TraitClauseId.of_int 0; span = None; origin = OriginDyn;
      trait = { binder_regions = []; binder_value = {
        id = TraitDeclId.of_int 4; generics = { empty with types = [TVar (Bound (1, self_id))] } } } }];
    types_outlive = [{ binder_regions = []; binder_value = TVar (Bound (1, self_id)), target }] };
  binder_value = TVar (Bound (0, self_id)) } }
let source_owner = owner RErased
let borrowed region target = TRef (region, TDynTrait (owner target), RShared)
let signature borrow captured object_region : fun_sig = {
  is_unsafe = false; abi = AbiRust; is_variadic = false;
  inputs = [borrowed borrow object_region; TRef (captured, boolean, RShared)]; output = boolean }
let original = { binder_regions = [parameter 7];
  binder_value = signature (bound 7) (free 99) RErased }
let parameters = { TypesUtils.empty_generic_params with regions = [parameter 99] }
let arguments = { empty with regions = [free 3] }
let actual = { binder_regions = [parameter 7];
  binder_value = signature (bound 7) (free 3) (body 4) }
let field = Vtable_field.create ~parameters ~arguments ~free_parameters:[parameter 3]
  ~body_regions:8 ~owner:source_owner (Vtable_shape.parameterize source_owner original) actual
let location : Meta.loc = { line = 1; col = 0 }
let span : Meta.span = { data = {
  file = { name = Meta.NotReal "source-vtable-cast-fixture";
    crate_name = "construction_fixture"; contents = None };
  beg_loc = location; end_loc = location }; generated_from_span = None }
let attributes : Meta.attr_info = { attributes = []; inline = None; rename = None; public = true }
let metadata : item_meta = { name = []; span; source_text = None; attr_info = attributes;
  is_local = true; opacity = Transparent; lang_item = None }
let definition : fun_decl = { def_id = FunDeclId.of_int 12; item_meta = metadata;
  generics = { parameters with regions = [parameter 99; parameter 1] };
  signature = signature (free 1) (free 99) RErased;
  src = VTableMethodShimItem; is_global_initializer = None; body = OpaqueBody }
let pointer : fn_ptr = { kind = FunId (FRegular definition.def_id);
  generics = { empty with regions = [free 3; body 0] } }
let from pointer = TFnDef { binder_regions = original.binder_regions;
  binder_value = Substitute.st_substitute_visitor#visit_fn_ptr Substitute.move_under_binder_subst pointer }
let create ?(definition = definition) ?(owner_arguments = arguments) ?(field = field)
    ?(from_type = None) ?(into_type = TFnPtr actual) pointer =
  Vtable_cast.create ~definition ~owner_parameters:parameters ~owner_arguments ~field
    ~source_pointer:pointer ~from_type:(match from_type with Some ty -> ty | None -> from pointer) ~into_type

let () =
  let witness = create pointer in
  require "a generated shim re-exposes only its own late suffix in the original field binder"
    (witness.reexposed_item.binder_value.generics.regions = [free 3; bound 7] &&
     witness.source_signature = field.original && witness.reconstructed_source_from = from pointer &&
     Vtable_cast.replay witness);
  require "a captured owner argument remains rigid"
    (refuses (fun () -> ignore (create { pointer with generics = { empty with regions = [RStatic; body 0] } })));
  require "a static argument cannot be passed off as a fresh own placeholder"
    (refuses (fun () -> ignore (create { pointer with generics = { empty with regions = [free 3; RStatic] } })));
  require "a placeholder cannot alias the actual stored object annotation"
    (refuses (fun () -> ignore (create { pointer with generics = { empty with regions = [free 3; body 4] } })));
  require "a missing own suffix cannot be inferred from the target signature"
    (refuses (fun () -> ignore (create { pointer with generics = { empty with regions = [free 3] } })));
  require "a different regular source function cannot inherit the shim witness"
    (refuses (fun () -> ignore (create { pointer with kind = FunId (FRegular (FunDeclId.of_int 13)) })));
  List.iter (fun signature ->
    require "the complete actual shim ABI must match the stored prototype"
      (refuses (fun () -> ignore (create ~definition:{ definition with signature } pointer))))
    [{ definition.signature with is_unsafe = true }; { definition.signature with abi = AbiC };
     { definition.signature with is_variadic = true }; { definition.signature with inputs = [] }];
  require "a regular function cannot claim compiler-generated shim provenance"
    (refuses (fun () -> ignore (create ~definition:{ definition with src = TopLevelItem } pointer)));
  require "the exact original source cast operand is part of the witness"
    (refuses (fun () -> ignore (create ~from_type:(Some (TFnPtr actual)) pointer)));
  require "the exact source cast destination is part of the witness"
    (refuses (fun () -> ignore (create ~into_type:(TFnPtr field.original) pointer)));
  require "changing retained source ABI evidence invalidates replay"
    (not (Vtable_cast.replay { witness with source_signature = { witness.source_signature with
      binder_value = { witness.source_signature.binder_value with is_unsafe = true } } }));
  require "changing the original source descriptor invalidates replay"
    (not (Vtable_cast.replay { witness with reconstructed_source_from = TFnPtr actual }))

(* Receiver lowering preserves the actual body beyond the single concretize.
   These cases are deliberately still unbuilt/unrun. *)
let () =
  let open Expressions in
  let receiver = borrowed (free 1) (body 4) in
  let concrete_receiver = TRef (free 1, boolean, RShared) in
  let place index ty : place = { kind = PlaceLocal (LocalId.of_int index); ty } in
  let local index local_ty : local = { index = LocalId.of_int index; name = None; span; local_ty } in
  let statement index kind : statement = { span; statement_id = StatementId.of_int index;
    kind; comments_before = [] } in
  let cleanup = { span; statements = [statement 31 (StorageDead (LocalId.of_int 3));
    statement 32 UnwindResume] } in
  let source_cast = Assign (place 3 concrete_receiver,
    UnaryOp (Cast (CastConcretize (borrowed (free 1) (body 5), concrete_receiver)), Move (place 1 receiver))) in
  let source_call = Call ({ func = FnOpRegular { kind = FunId (FRegular (FunDeclId.of_int 20));
    generics = empty }; args = [Move (place 3 concrete_receiver);
      Move (place 2 (TRef (free 99, boolean, RShared)))]; dest = place 0 boolean }, cleanup) in
  let source_body : expr_body = { span; bound_body_regions = 8;
    locals = { arg_count = 2; locals = [local 0 boolean; local 1 receiver;
      local 2 (TRef (free 99, boolean, RShared)); local 3 concrete_receiver] };
    body = { span; statements = [statement 1 (StorageLive (LocalId.of_int 0));
      statement 2 (StorageLive (LocalId.of_int 3)); statement 3 source_cast;
      statement 4 source_call; statement 5 (StorageDead (LocalId.of_int 3)); statement 6 Return] } } in
  let implementation : trait_impl = { def_id = TraitImplId.of_int 8; item_meta = metadata;
    impl_trait = { id = TraitDeclId.of_int 4; generics = { empty with types = [boolean] } };
    generics = parameters; implied_trait_refs = []; consts = AssocConstId.Map.empty;
    types = AssocTypeId.Map.empty; methods = TraitMethodId.Map.empty; vtable = None } in
  let lower ?(implementation = implementation) body =
    Vtable_receiver.create ~implementation ~cast_signature:(create
      ~definition:{ definition with body = StructuredBody body } pointer) in
  let lowered = lower source_body in
  require "the full source receiver specialization must replay"
    (Vtable_receiver.replay lowered && lowered.self_type = boolean &&
     List.hd lowered.concrete_signature.inputs = concrete_receiver);
  let at index (body : expr_body) = List.find (fun (statement : statement) ->
    statement.statement_id = StatementId.of_int index) body.body.statements in
  require "the original source call, operands, destination and unwind block survive unchanged"
    (at 4 lowered.concrete_body = at 4 source_body);
  require "only the original concretization becomes a move of the concrete receiver"
    ((at 3 lowered.concrete_body).kind = Assign (place 3 concrete_receiver,
      Use (Move (place 1 concrete_receiver), NoRetag)) && List.length lowered.cast_edits = 1);
  require "stored erased metadata is retained as source metadata, never lifetime evidence"
    (List.exists (fun (entry : Vtable_receiver.annotation) -> entry.object_region = RErased) lowered.annotations);
  let replace_cast kind = { source_body with body = { source_body.body with statements =
    List.map (fun (statement : statement) -> if statement.statement_id = StatementId.of_int 3
      then { statement with kind } else statement) source_body.body.statements } } in
  require "another implementation Self cannot inherit the concrete source cast"
    (refuses (fun () -> ignore (lower ~implementation:{ implementation with impl_trait = {
      implementation.impl_trait with generics = { empty with types = [TLiteral (Charon.Values.TUInt Charon.Values.U64)] } } } source_body)));
  require "receiver lowering cannot manufacture a copy in place of the original move"
    (refuses (fun () -> ignore (lower (replace_cast (Assign (place 3 concrete_receiver,
      UnaryOp (Cast (CastConcretize (receiver, concrete_receiver)), Copy (place 1 receiver))))))));
  require "a changed receiver borrow cannot be hidden by concretization"
    (refuses (fun () -> ignore (lower (replace_cast (Assign (place 3 concrete_receiver,
      UnaryOp (Cast (CastConcretize (borrowed (free 99) (body 5), concrete_receiver)), Move (place 1 receiver))))))));
  require "a second dynamic local needs separate flow evidence"
    (refuses (fun () -> ignore (lower { source_body with locals = { source_body.locals with
      locals = source_body.locals.locals @ [local 4 receiver] } })));
  require "the unique generated concretization cannot be duplicated"
    (refuses (fun () -> ignore (lower { source_body with body = { source_body.body with
      statements = statement 7 source_cast :: source_body.body.statements } })));
  require "a dynamic receiver passed to another source call needs separate ABI evidence"
    (refuses (fun () -> ignore (lower { source_body with body = { source_body.body with statements =
      List.map (fun (statement : statement) -> if statement.statement_id = StatementId.of_int 4 then
        { statement with kind = Call ({ func = FnOpRegular { kind = FunId (FRegular (FunDeclId.of_int 20));
          generics = empty }; args = [Move (place 1 receiver)]; dest = place 0 boolean }, cleanup) }
        else statement) source_body.body.statements } })));
  require "a changed concrete body cannot replay the source lowering witness"
    (not (Vtable_receiver.replay { lowered with concrete_body = source_body }))

let () =
  let open Expressions in
  let box ty = TAdt { id = TBuiltin TBox; generics = { empty with types = [ty] } } in
  let source = box boolean and target = box (TDynTrait (owner (body 4))) in
  let place ty : place = { kind = PlaceLocal (LocalId.of_int 1); ty } in
  let classify from_type into_type operand =
    Vtable_injection.classify_carrier ~owner:source_owner ~from_type ~into_type operand in
  require "an actual owned Box move retains its complete carrier and source Self"
    (match classify source target (Move (place source)) with
     | Vtable_injection.OwnedBox (before, after), region, self ->
         TAdt before = source && TAdt after = target && region = body 4 && self = boolean
     | _ -> false);
  require "an owned Box cannot become a copied dynamic carrier"
    (refuses (fun () -> ignore (classify source target (Copy (place source)))));
  require "an erased Box object bound cannot supply liveness evidence"
    (refuses (fun () -> ignore (classify source (box (TDynTrait source_owner)) (Move (place source)))));
  require "the actual owned source operand cannot be relabelled to another pointee type"
    (refuses (fun () -> ignore (classify source target (Move (place (box (TLiteral (Charon.Values.TUInt Charon.Values.U64))))))));
  let mutable_source = TRef (body 1, boolean, RMut) in
  let mutable_target = TRef (body 2, TDynTrait (owner (body 4)), RMut) in
  require "an exclusive borrowed carrier cannot be copied"
    (refuses (fun () -> ignore (classify mutable_source mutable_target (Copy (place mutable_source)))));
  require "borrow shortening is retained as an obligation rather than equating source and target lifetimes"
    (match classify mutable_source mutable_target (Move (place mutable_source)) with
     | Vtable_injection.Borrowed (source, target, RMut), _, _ -> source = body 1 && target = body 2
     | _ -> false);
  require "changing borrow mutability cannot hide behind the source dictionary"
    (refuses (fun () -> ignore (classify mutable_source
      (TRef (body 2, TDynTrait (owner (body 4)), RShared)) (Move (place mutable_source)))))
