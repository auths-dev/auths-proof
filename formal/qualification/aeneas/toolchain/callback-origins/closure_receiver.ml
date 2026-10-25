(* The actual captured-field accessor used by a source callback's Box receiver.
   This keeps the entire conditional prefix as a required effect obligation.
   A shallow reference load is an address access, never another owning Box or
   an independently usable exclusive loan. Creator-value/activation provenance
   and preservation through preceding effects are not inferred from this slice. *)
open Charon
open Types
open Expressions
open LlbcAst

type t = {
  consumer : Source_call.t;
  receiver : Virtual_receiver.t;
  closure_reference : type_decl_ref;
  source_type : type_decl;
  source_field : field;
  actual_field_type : ty;
  closure_argument : place;
  captured_place : place;
  address_load : statement;
  reborrow : statement;
  passed_receiver : operand;
  conditional_prefix : Source_path.step list;
  constraints : Region_equations.predicates;
}

(* Find the last actual definition along the conditional source path. Crossing
   a branch that uses/defines that local would need a joined value invariant;
   it cannot silently select an arm or borrow a definition from another arm. *)
let last_definition prefix id =
  let rec find = function
    | [] -> invalid_arg "the callback receiver local has no dominating actual source definition"
    | Source_path.Execute statement :: rest ->
        (match statement.kind with
         | Assign ({ kind = PlaceLocal actual; _ }, _) when actual = id -> statement, List.rev rest
         | StorageDead actual | StorageLive actual when actual = id ->
             invalid_arg "the callback receiver accessor crosses dead or reallocated source storage"
         | _ when Source_path.mentions_local id statement ->
             invalid_arg "the callback receiver accessor needs an explicit intervening local effect rule"
         | _ -> find rest)
    | Source_path.Branch choice :: rest ->
        let mentions = match choice.selector with
          | Source_path.Value (Copy place | Move place) | Source_path.Discriminant place ->
              let found = ref false in
              let scan = object inherit [_] iter_statement as super
                method! visit_place env place =
                  (match place.kind with PlaceLocal actual when actual = id -> found := true | _ -> ());
                  super#visit_place env place
              end in scan#visit_place () place; !found
          | Source_path.Value (Constant _) -> false in
        if mentions then invalid_arg "a callback receiver local participates in an unresolved branch selector";
        find rest in
  find (List.rev prefix)

let derive crate ~(consumer : Source_call.t) ~(receiver : Virtual_receiver.t) =
  if not (Source_call.replay crate consumer) || not (Virtual_receiver.replay receiver) then
    invalid_arg "a captured callback receiver needs its actual complete source call and virtual receiver";
  if receiver.view <> consumer.callee.view || receiver.frame <> Source_call.frame consumer.callee then
    invalid_arg "the callback receiver accessor and consumer identify different actual callee instances";
  let frame = Source_call.frame consumer.caller in
  let argument_type, closure_reference = match frame.signature.inputs with
    | (TRef (_, TAdt ({ id = TAdtId _; _ } as reference), RMut) as argument) :: _ -> argument, reference
    | _ -> invalid_arg "a captured Box accessor requires the actual exclusive closure receiver parameter" in
  let resolution = Type_view.resolve crate closure_reference in
  if resolution.obligations <> [] || resolution.reference <> closure_reference then
    invalid_arg "the source callback closure type retains unresolved original predicates";
  let source_type = resolution.declaration in
  let fields = match source_type.src, source_type.kind with ClosureItem _, Struct fields -> fields
    | _ -> invalid_arg "a captured Box accessor cannot substitute an ordinary struct for its actual source closure" in
  let index = LocalId.to_int receiver.receiver_origin.argument - 1 in
  let passed_receiver = if index < 0 || index >= List.length consumer.call.args then
      invalid_arg "the source callback lost the actual Box consumer receiver argument"
    else List.nth consumer.call.args index in
  let receiver_local = match passed_receiver with Move { kind = PlaceLocal id; _ } -> id
    | _ -> invalid_arg "the callback must pass its actual local exclusive reborrow by move" in
  let conditional_prefix = Source_path.before frame.body consumer.source_statement.statement_id in
  let reborrow, before_borrow = last_definition conditional_prefix receiver_local in
  let destination, alias, source, metadata = match reborrow.kind with
    | Assign (destination, RvRef (({ kind = PlaceProjection (alias, Deref); _ } as source), (BMut | BTwoPhaseMut), metadata)) ->
        destination, alias, source, metadata
    | _ -> invalid_arg "the callback receiver is not its original exclusive captured-reference reborrow" in
  (match metadata with Constant { kind = CAdt (None, []); ty } when ty = Vtable_shape.unit -> ()
   | _ -> invalid_arg "the sized captured Box reborrow must retain exact original unit metadata");
  let alias_id = match alias.kind with PlaceLocal id -> id
    | _ -> invalid_arg "the callback captured-reference address access lost its actual local identity" in
  let address_load, _ = last_definition before_borrow alias_id in
  let loaded, captured_place = match address_load.kind with
    | Assign (loaded, Use (Copy captured, NoRetag)) -> loaded, captured
    | _ -> invalid_arg "the callback needs its exact original shallow captured-reference address load" in
  let closure_argument, field_index = match captured_place.kind with
    | PlaceProjection ({ kind = PlaceProjection (argument, Deref); ty = TAdt actual }, Field (ProjAdt (id, None), index))
        when actual = closure_reference && closure_reference.id = TAdtId id -> argument, index
    | _ -> invalid_arg "the Box reference must come from the actual nominal closure field through its receiver" in
  (match closure_argument.kind with PlaceLocal id when LocalId.to_int id = 1 -> ()
   | _ -> invalid_arg "the captured Box field comes from another value than the actual closure receiver parameter");
  let source_field = try List.nth fields (FieldId.to_int field_index)
    with Invalid_argument _ | Failure _ -> invalid_arg "the actual captured Box field is absent" in
  let substitution = Type_view.source_substitution source_type closure_reference.generics resolution.self_evidence in
  let normalizer = new Static_targets.normalize crate in
  let actual_field_type = normalizer#visit_ty 0 (Substitute.ty_substitute substitution source_field.field_ty) in
  normalizer#check_requirements;
  if normalizer#obligations <> [] then invalid_arg "the actual captured Box field retains unresolved source predicates";
  let field_box = match actual_field_type with TRef (_, box, RMut) when Option.is_some (Capture_return.predicate box) -> box
    | _ -> invalid_arg "the selected source closure field is not its actual exclusive reference to a dynamic Box" in
  let result_box = match destination.ty with TRef (_, box, RMut) -> box
    | _ -> invalid_arg "the captured Box accessor changed its actual reborrow result ABI" in
  let requirements = [argument_type, closure_argument.ty; actual_field_type, captured_place.ty;
    captured_place.ty, loaded.ty; loaded.ty, alias.ty; field_box, source.ty;
    source.ty, result_box; destination.ty, Vtable_dispatch.operand_type passed_receiver] in
  let constraints = List.fold_left (fun premises (left, right) -> Region_equations.add_type premises left right)
    consumer.constraints requirements in
  if not (Region_equations.replay_predicates constraints) then
    invalid_arg "the actual callback/field/address/reborrow/consumer typing premises did not replay";
  { consumer; receiver; closure_reference; source_type; source_field; actual_field_type; closure_argument;
    captured_place; address_load; reborrow; passed_receiver; conditional_prefix; constraints }

let replay crate witness = try derive crate ~consumer:witness.consumer ~receiver:witness.receiver = witness
  with Invalid_argument _ | Not_found | Source_path.Not_dominating -> false

let create crate ~consumer ~receiver =
  let witness = derive crate ~consumer ~receiver in
  if not (replay crate witness) then invalid_arg "the complete actual closure-field receiver accessor did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["actual_consumer", Source_call.report crate witness.consumer;
    "actual_source_closure_type", `String (show_type_decl_ref witness.closure_reference);
    "actual_captured_reference", `String (show_place witness.captured_place);
    "actual_source_field_type", `String (show_ty witness.actual_field_type);
    "source_address_load", `Int (StatementId.to_int witness.address_load.statement_id);
    "source_exclusive_reborrow", `Int (StatementId.to_int witness.reborrow.statement_id);
    "complete_conditional_prefix_effect_obligations", Source_path.report witness.conditional_prefix;
    "source_typing_premises", region_certificate_json witness.constraints;
    "complete_actual_captured_field_accessor_replays", `Bool (replay crate witness);
    "shallow_access_mints_owner_or_independent_exclusive_loan", `Bool false;
    "creator_value_and_preceding_effect_preservation_proved", `Bool false;
    "native_activation_alias_loan_and_unwind_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
