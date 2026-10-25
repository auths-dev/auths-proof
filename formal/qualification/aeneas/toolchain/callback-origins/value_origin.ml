(* Actual source definition/access tree at a carrier-bearing source point.
   A last local definition is not a proof that aliases/intervening effects kept
   its value. Every full lexical prefix, retag and enclosing iteration survives
   as a required native value/effect invariant. No ordinary result is invented
   and no unique caller is inferred from a function's generic instance/type. *)
open Charon
open Types
open Expressions
open LlbcAst

type context = {
  captures : Closure_capture.t list;
  closure_returns : Closure_return_call.t list;
  box_returns : Capture_callsite.t list;
  reference_accesses : Closure_receiver.t list;
  box_receivers : Virtual_receiver.t list;
}
type expression =
  | ParameterSlot of int * place
  | SourceMove of statement * expression
  | SourceBorrow of statement * expression
  | SourceProjection of place * projection_elem * expression
  | CapturedAggregate of Closure_capture.t
  | ActualClosureResult of Closure_return_call.t
  | ActualBoxResult of Capture_callsite.t
  | ShallowAddressAccess of statement * expression
type t = {
  node : Source_closure.node;
  target : statement;
  operand : operand;
  prefix : Iteration_path.step list;
  expression : expression;
  constraints : Region_equations.predicates;
}

let derive crate ~(context : context) ~(node : Source_closure.node) target_id operand =
  Source_call.actual_view crate node;
  let frame = Source_call.frame node in
  let target = Prepared_injection.unique_statement frame.body target_id in
  let actual_operands = match target.kind with Call (call, _) -> call.args
    | Assign (_, Aggregate (_, operands)) -> operands
    | _ -> invalid_arg "a carrier value origin must bind an actual call argument or aggregate field" in
  if not (List.mem operand actual_operands) then invalid_arg "a source value origin cannot substitute another operand at its actual source point";
  let prefix = Iteration_path.before frame.body target_id in
  let constraints = ref frame.region_certificate in
  let equal left right = constraints := Region_equations.add_type !constraints left right in
  let merge premises = constraints := List.fold_left Region_equations.add_premise !constraints (List.rev premises.Region_equations.originals) in
  let declared id = match List.filter (fun (local : local) -> local.index = id) frame.locals with
    | [local] -> local | _ -> invalid_arg "a source value origin uses an absent or ambiguous local slot" in
  let source_address_load statement =
    List.exists (fun (access : Closure_receiver.t) -> access.consumer.caller = node && access.address_load = statement) context.reference_accesses ||
    List.exists (fun (receiver : Virtual_receiver.t) -> receiver.view = node.view && receiver.frame = frame &&
      List.exists (fun (access : Virtual_receiver.box_access) -> access.statement = statement) receiver.box_accesses) context.box_receivers in
  let flat_local_effect id statement =
    let found = ref false in
    let scan = object inherit [_] iter_statement as super
      method! visit_block _ _ = ()
      method! visit_statement env statement =
        (match statement.kind with
         | Assign ({ kind = PlaceLocal actual; _ }, _) | Call ({ dest = { kind = PlaceLocal actual; _ }; _ }, _)
             when actual = id -> found := true
         | StorageLive actual | StorageDead actual when actual = id -> found := true
         | Drop ({ kind = PlaceLocal actual; _ }, _, _, _) when actual = id -> found := true
         | _ -> ()); super#visit_statement env statement
      method! visit_operand env operand =
        (match operand with Move { kind = PlaceLocal actual; _ } when actual = id -> found := true | _ -> ());
        super#visit_operand env operand
    end in scan#visit_statement () statement; !found in
  let rec continuing_block_effect id (block : block) =
    Iteration_path.falls_through block && List.exists (continuing_statement_effect id) block.statements
  and continuing_statement_effect id (statement : statement) =
    flat_local_effect id statement || match statement.kind with
    | Switch switch -> let _, targets = Source_path.branches switch in List.exists (continuing_block_effect id) targets
    | Call (_, unwind) | Drop (_, _, _, unwind) | Assert (_, _, unwind) -> continuing_block_effect id unwind
    | Loop source ->
        (* An earlier complete loop needs its own joined invariant. Keep this
           conservative; an enclosing current iteration is represented by its
           separate Iteration node and explicit loop-head obligation. *)
        let found = ref false in
        let scan = object inherit [_] iter_statement as super
          method! visit_statement env statement =
            if flat_local_effect id statement then found := true;
            super#visit_statement env statement
        end in scan#visit_block () source; !found
    | _ -> false in
  let rec shared_ancestor (source : place) = match source.kind with
    | PlaceProjection (parent, Deref) ->
        (match parent.ty with TRef (_, _, RShared) -> true | _ -> shared_ancestor parent)
    | PlaceProjection (parent, _) -> shared_ancestor parent
    | _ -> false in
  let steps = ref 0 in
  let rec place depth prefix (source : place) =
    incr steps;
    if depth > 128 || !steps > 100000 then invalid_arg "source value origin exceeds its explicit structural construction bound";
    match source.kind with
    | PlaceLocal id ->
        equal (declared id).local_ty source.ty;
        definition depth prefix source id (List.rev prefix)
    | PlaceProjection (parent, Deref) ->
        let pointee = match parent.ty with TRef (_, pointee, _) -> pointee
          | ty -> (match Virtual_receiver.box_pointee ty with Some pointee -> pointee
              | None -> invalid_arg "a source value dereference needs its actual reference/Box type") in
        equal pointee source.ty;
        SourceProjection (source, Deref, place (depth + 1) prefix parent)
    | PlaceProjection (parent, (Field (ProjAdt (id, None), index) as projection)) ->
        let reference = match parent.ty with TAdt ({ id = TAdtId actual; _ } as reference) when actual = id -> reference
          | _ -> invalid_arg "a captured value field must retain its actual nominal source owner" in
        let resolution = Type_view.resolve crate reference in
        if resolution.obligations <> [] || resolution.reference <> reference then invalid_arg "the actual source value field retains unresolved predicates";
        let fields = match resolution.declaration.kind with Struct fields -> fields
          | _ -> invalid_arg "this value route needs its actual nominal source struct field, not a guessed enum/union/opaque layout" in
        let field = try List.nth fields (FieldId.to_int index) with Failure _ | Invalid_argument _ -> invalid_arg "the actual captured source field is absent" in
        let substitution = Type_view.source_substitution resolution.declaration reference.generics resolution.self_evidence in
        let normalizer = new Static_targets.normalize crate in
        let ty = normalizer#visit_ty 0 (Substitute.ty_substitute substitution field.field_ty) in
        normalizer#check_requirements;
        if normalizer#obligations <> [] then invalid_arg "an actual source captured field retains unresolved type obligations";
        equal ty source.ty;
        SourceProjection (source, projection, place (depth + 1) prefix parent)
    | _ -> invalid_arg "the actual source value needs an explicit global/tuple/index/pointer projection rule"
  and definition depth complete source id = function
    | [] ->
        let parameter_index = LocalId.to_int id - 1 in
        if parameter_index < 0 || parameter_index >= List.length frame.signature.inputs then
          invalid_arg "a source value has no original parameter, aggregate or actual-return definition";
        equal (List.nth frame.signature.inputs parameter_index) source.ty;
        ParameterSlot (parameter_index, source)
    | Iteration_path.Iteration _ :: rest -> definition depth complete source id rest
    | Iteration_path.Source (Source_path.Branch _) :: rest -> definition depth complete source id rest
    | Iteration_path.Source (Source_path.Execute statement) :: rest ->
        let before = List.rev rest in
        (match statement.kind with
         | Assign (({ kind = PlaceLocal actual; _ } as destination), rvalue) when actual = id ->
             equal destination.ty source.ty;
             (match rvalue with
              | Use (Move moved, _) -> SourceMove (statement, place (depth + 1) before moved)
              | Use (Copy copied, NoRetag) when source_address_load statement ->
                  ShallowAddressAccess (statement, place (depth + 1) before copied)
              | RvRef (borrowed, (BMut | BTwoPhaseMut | BShared), metadata) ->
                  let pointee, mutability = match destination.ty with TRef (_, pointee, mutability) -> pointee, mutability
                    | _ -> invalid_arg "a source value borrow lost its complete reference result type" in
                  (match rvalue, mutability with RvRef (_, (BMut | BTwoPhaseMut), _), RMut | RvRef (_, BShared, _), RShared -> ()
                   | _ -> invalid_arg "a source value borrow changes its original mutability");
                  if mutability = RMut && shared_ancestor borrowed then invalid_arg "a source value borrow cannot amplify a shared ancestor into exclusive access";
                  (match metadata with Constant { kind = CAdt (None, []); ty } when ty = Vtable_shape.unit -> ()
                   | _ -> invalid_arg "this source value borrow needs its exact sized carrier metadata");
                  equal pointee borrowed.ty;
                  SourceBorrow (statement, place (depth + 1) before borrowed)
              | Aggregate (AggregatedAdt (_, None, None), _) ->
                  (match List.filter (fun (capture : Closure_capture.t) -> capture.caller = node && capture.statement = statement) context.captures with
                   | [capture] -> if not (Closure_capture.replay crate capture) then invalid_arg "the actual value aggregate lost its complete captured fields";
                       merge capture.constraints; CapturedAggregate capture
                   | _ -> invalid_arg "the actual closure aggregate has no unique complete source capture binding")
              | _ -> invalid_arg "a source carrier value definition needs an exact move/borrow/capture interface")
         | Call (call, _) when call.dest.kind = PlaceLocal id ->
             equal call.dest.ty source.ty;
             let closures = List.filter (fun (returned : Closure_return_call.t) ->
               returned.binding.caller = node && returned.binding.source_statement = statement) context.closure_returns in
             let boxes = List.filter (fun (returned : Capture_callsite.t) ->
               returned.binding.caller = node && returned.binding.source_statement = statement) context.box_returns in
             (match closures, boxes with
              | [returned], [] -> if not (Closure_return_call.replay crate returned) then invalid_arg "the actual returned closure origin did not replay";
                  merge returned.binding.constraints; ActualClosureResult returned
              | [], [returned] -> if not (Capture_callsite.replay crate returned) then invalid_arg "the actual returned Box origin did not replay";
                  merge returned.binding.constraints; ActualBoxResult returned
              | _ -> invalid_arg "a carrier-bearing source result has no unique actual return mapping; no opaque result is supplied")
         | StorageLive actual | StorageDead actual when actual = id ->
             invalid_arg "an actual carrier value origin crosses uninitialized, dead or replaced local storage"
         | Drop ({ kind = PlaceLocal actual; _ }, _, _, _) when actual = id ->
             invalid_arg "the source value origin crosses its actual local destructor"
         | Call (call, _) when List.exists (function Move { kind = PlaceLocal actual; _ } -> actual = id | _ -> false) call.args ->
             invalid_arg "the source value slot was moved into an earlier call without its explicit returned-value route"
         | (Switch _ | Loop _) when continuing_statement_effect id statement ->
             invalid_arg "a source value definition in an earlier branch/loop needs an explicit joined value invariant"
         | _ when (match statement.kind with Call _ -> false | _ -> continuing_statement_effect id statement) ->
             invalid_arg "an actual source value slot was consumed before this read"
         | _ -> definition depth complete source id rest)
  in
  let expression = match operand with
    | Move source -> place 0 prefix source
    | Copy _ -> invalid_arg "a carrier source operand cannot mint an owner/exclusive reference by copy"
    | Constant _ -> invalid_arg "a carrier source value cannot be supplied as an arbitrary constant" in
  if not (Region_equations.replay_predicates !constraints) then invalid_arg "the complete source value definition/access typing premises did not replay";
  { node; target; operand; prefix; expression; constraints = !constraints }

let replay crate ~context witness = try derive crate ~context ~node:witness.node witness.target.statement_id witness.operand = witness
  with Invalid_argument _ | Not_found | Source_path.Not_dominating -> false

let create crate ~context ~(node : Source_closure.node) target_id operand =
  if Function_frame.prepare crate node.view <> Source_call.frame node then
    invalid_arg "a source value origin requires its complete actual source frame";
  let witness = derive crate ~context ~node target_id operand in
  if not (replay crate ~context witness) then invalid_arg "the complete actual source value origin tree did not replay";
  witness

let rec expression_report = function
  | ParameterSlot (index, place) -> `Assoc ["kind", `String "current_parameter_slot"; "zero_based_parameter_index", `Int index;
      "actual_place", `String (Diagnostic.show_place place); "entry_value_and_intervening_effect_preservation_proved", `Bool false]
  | SourceMove (statement, source) -> `Assoc ["kind", `String "original_move"; "statement", `Int (StatementId.to_int statement.statement_id);
      "original_retag", (match statement.kind with Assign (_, Use (_, tag)) -> `String (Expressions.show_with_retag tag) | _ -> `Null);
      "source", expression_report source]
  | SourceBorrow (statement, source) -> `Assoc ["kind", `String "original_borrow"; "statement", `Int (StatementId.to_int statement.statement_id);
      "source", expression_report source; "native_exclusive_loan_and_metadata_simulation_proved", `Bool false]
  | SourceProjection (place, projection, source) -> `Assoc ["kind", `String "original_typed_projection";
      "actual_place", `String (Diagnostic.show_place place); "actual_projection", `String (Expressions.show_projection_elem projection);
      "source", expression_report source]
  | CapturedAggregate capture -> `Assoc ["kind", `String "actual_source_aggregate"; "source_node", `Int capture.caller.index;
      "source_statement", `Int (StatementId.to_int capture.statement.statement_id)]
  | ActualClosureResult returned -> `Assoc ["kind", `String "actual_source_closure_return";
      "caller", `Int returned.binding.caller.index; "callee", `Int returned.binding.callee.index;
      "source_statement", `Int (StatementId.to_int returned.binding.source_statement.statement_id);
      "runtime_activation_return_case_and_field_transport_proved", `Bool false]
  | ActualBoxResult returned -> `Assoc ["kind", `String "actual_source_box_return";
      "caller", `Int returned.binding.caller.index; "callee", `Int returned.binding.callee.index;
      "source_statement", `Int (StatementId.to_int returned.binding.source_statement.statement_id);
      "normal_source_case_count", `Int (List.length returned.cases); "runtime_case_value_and_capture_opening_proved", `Bool false]
  | ShallowAddressAccess (statement, source) -> `Assoc ["kind", `String "actual_nonowning_source_address_access";
      "statement", `Int (StatementId.to_int statement.statement_id); "source", expression_report source;
      "new_owner_or_independent_exclusive_loan_created", `Bool false]

let report crate ~context witness = `Assoc ["source_node", `Int witness.node.index;
  "actual_source_point", `Int (StatementId.to_int witness.target.statement_id);
  "actual_source_operand", `String (Diagnostic.show_operand witness.operand);
  "actual_definition_and_access_tree", expression_report witness.expression;
  "complete_lexical_preceding_effect_obligations", Iteration_path.report witness.prefix;
  "original_typing_premises", Diagnostic.region_certificate_json witness.constraints;
  "complete_source_value_tree_replays", `Bool (replay crate ~context witness);
  "native_value_provenance_effect_alias_loop_and_activation_simulation_proved", `Bool false;
  "qualified", `Bool false; "program_emitted", `Bool false]
