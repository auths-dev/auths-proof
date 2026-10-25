(* Bind an actual indirect call to the vtable field of the very receiver it
   passes. Track its original argument/reborrow/move lineage through the source
   prefix. No alias/value-flow assumption is supplied by the caller. The
   resulting source witness is not a native loan/simulation/exhaustiveness
   proof and does not install a replacement call or method implementation. *)
open Charon
open Types
open Expressions
open LlbcAst

type lookup = {
  receiver : place;
  metadata_place : place;
  table_reference : type_decl_ref;
  field_index : field_id;
  original_function_type : ty;
  shape : Vtable_shape.t;
  field : Vtable_shape.field_view;
  invocation : Signature_instance.t;
}

type lineage = { argument : local_id; reborrows : statement_id list }
type value = { ty : ty; lineage : lineage option }
type cell = { declared : local; live : bool; value : value option }
type reborrow = {
  statement : statement;
  source : place;
  destination : place;
  metadata : operand;
  inherited : lineage;
}
type branch = {
  source_vtable : Vtable_initializer.t;
  source_slot : Vtable_initializer.slot;
  own_call_arguments : region list;
}
type t = {
  caller : fun_decl;
  source_statement : statement;
  source_call : call;
  on_unwind : block;
  lookup : lookup;
  receiver_lineage : lineage;
  reborrows : reborrow list;
  prefix : statement list;
  region_constraints : Region_equations.predicates;
  available_source_branches : branch list;
}

let operand_type = function Move place | Copy place -> place.ty | Constant value -> value.ty

let lookup_path (call : call) =
  let function_place = match call.func with
    | FnOpDynamic (Copy place) -> place
    | _ -> invalid_arg "vtable dispatch requires the actual copied function field operand" in
  (match function_place.ty with TFnPtr _ -> ()
   | _ -> invalid_arg "a source vtable method operand must retain its actual function-pointer type");
  let metadata_place, receiver, table_reference, field_index = match function_place.kind with
    | PlaceProjection (({ kind = PlaceProjection (metadata, Deref); ty = TAdt reference }),
        Field (ProjAdt (id, None), index)) ->
        (match metadata.kind, metadata.ty with
         | PlaceProjection (receiver, PtrMetadata), TRawPtr (TAdt raw, RShared)
             when raw = reference && reference.id = TAdtId id -> metadata, receiver, reference, index
         | _ -> invalid_arg "the source method field must come from the original receiver's actual raw vtable metadata")
    | _ -> invalid_arg "the source dynamic function operand is not an actual nominal vtable field" in
  (match call.args with
   | Move argument :: _ | Copy argument :: _ when argument = receiver -> ()
   | _ -> invalid_arg "the vtable function and call receiver must come from the very same complete source place");
  function_place, metadata_place, receiver, table_reference, field_index

let lookup crate (call : call) =
  let function_place, metadata_place, receiver, table_reference, field_index = lookup_path call in
  let declaration = match table_reference.id with
    | TAdtId id -> (match TypeDeclId.Map.find_opt id crate.type_decls with
        | Some declaration -> declaration
        | None -> invalid_arg "the actual dispatch vtable declaration is absent")
    | _ -> invalid_arg "a dynamic dispatch cannot substitute a built-in tuple for its source vtable" in
  let shape = Vtable_shape.create crate declaration in
  Static_targets.require_argument_arity declaration.generics table_reference.generics;
  let field = match List.filter (fun (field : Vtable_shape.field_view) -> field.index = field_index) shape.fields with
    | [field] -> field
    | _ -> invalid_arg "the source dynamic call selects an absent or ambiguous vtable field" in
  (match field.role with VTableMethod _ -> ()
   | _ -> invalid_arg "ordinary method dispatch cannot reinterpret a layout/drop/supertrait field as its method");
  let family = match field.function_field with Some field -> field
    | None -> invalid_arg "the source dispatch field has no exact function signature family" in
  let substitution = Substitute.make_subst_from_generics declaration.generics table_reference.generics Self in
  let substitute = Substitute.st_substitute_visitor#visit_region_binder Substitute.st_substitute_visitor#visit_fun_sig substitution in
  let original = substitute family.original in
  if function_place.ty <> TFnPtr original then
    invalid_arg "the source dynamic function operand changed the complete original field signature";
  let predicate = match receiver.ty with
    | TRef (_, TDynTrait predicate, _) -> predicate
    | _ -> invalid_arg "method dispatch needs its actual borrowed dynamic receiver" in
  let object_region = Vtable_shape.object_annotation shape.source_predicate predicate in
  if object_region = RErased then invalid_arg "the actual dynamic call receiver has no source object provenance";
  let actual = { original.binder_value with inputs = List.map operand_type call.args; output = call.dest.ty } in
  let invocation = Signature_instance.create (substitute family.parameterized) actual in
  (match List.rev invocation.arguments with
   | actual :: _ when actual = object_region -> ()
   | _ -> invalid_arg "the actual method invocation did not retain the receiver's exact object annotation");
  { receiver; metadata_place; table_reference; field_index; original_function_type = function_place.ty;
    shape; field; invocation }

let derive crate ~(caller : fun_decl) (source_statement : statement) =
  (match FunDeclId.Map.find_opt caller.def_id crate.fun_decls with
   | Some actual when actual = caller -> ()
   | _ -> invalid_arg "dispatch lineage requires the complete actual caller declaration");
  let body = match caller.body with StructuredBody body -> body
    | _ -> invalid_arg "dispatch lineage requires the actual structured caller body" in
  let matches = ref 0 in
  let find = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if statement.statement_id = source_statement.statement_id then (
        if statement <> source_statement then invalid_arg "the dispatch source statement ID was substituted";
        incr matches);
      super#visit_statement env statement
  end in
  find#visit_block () body.body;
  if !matches <> 1 then invalid_arg "dispatch lineage requires one exact source statement";
  let source_call, on_unwind = match source_statement.kind with
    | Call (({ func = FnOpDynamic _; _ } as call), on_unwind) -> call, on_unwind
    | _ -> invalid_arg "the dispatch source statement is not an actual indirect call" in
  let lookup = lookup crate source_call in
  let rec before result = function
    | [] -> invalid_arg "a nested dispatch requires its explicit control-flow lineage before construction"
    | first :: _ when first = source_statement -> List.rev result
    | first :: rest -> before (first :: result) rest in
  let prefix = before [] body.body.statements in
  if body.locals.arg_count <> List.length caller.signature.inputs then
    invalid_arg "source dispatch argument locals disagree with its complete source signature";
  let cells = ref LocalId.Map.empty in
  List.iter (fun (local : local) ->
    if LocalId.Map.mem local.index !cells then invalid_arg "source dispatch locals have duplicate IDs";
    cells := LocalId.Map.add local.index { declared = local; live = false; value = None } !cells) body.locals.locals;
  let constraints = ref Region_equations.empty_predicates in
  let equal expected actual = constraints := Region_equations.add_type !constraints expected actual in
  let cell id = match LocalId.Map.find_opt id !cells with Some cell -> cell
    | None -> invalid_arg "dispatch lineage uses an undeclared source local" in
  List.iteri (fun index input ->
    let id = LocalId.of_int (index + 1) in
    let original = cell id in
    equal input original.declared.local_ty;
    let lineage = match input with TRef (_, TDynTrait _, _) -> Some { argument = id; reborrows = [] }
      | _ -> None in
    cells := LocalId.Map.add id { original with live = true;
      value = Some { ty = original.declared.local_ty; lineage } } !cells) caller.signature.inputs;
  let read (place : place) = match place.kind with
    | PlaceLocal id ->
        let original = cell id in
        (match original.live, original.value with
         | true, Some value -> equal value.ty place.ty; value
         | _ -> invalid_arg "dispatch lineage reads a dead, uninitialized or moved source local")
    | _ -> invalid_arg "dispatch lineage needs explicit projected-place value flow" in
  let read_operand = function
    | Move place ->
        let value = read place in
        (match place.kind with PlaceLocal id ->
          let original = cell id in cells := LocalId.Map.add id { original with value = None } !cells
         | _ -> invalid_arg "a moved dispatch operand lost its source local identity");
        value
    | Copy place ->
        (match place.ty with
         | TRef (_, _, RMut) | TAdt { id = TBuiltin TBox; _ } ->
             invalid_arg "dispatch lineage cannot copy an exclusive borrow or owned box"
         | _ -> ());
        read place
    | Constant constant -> { ty = constant.ty; lineage = None } in
  let reborrows = ref [] in
  let scope = new Region_scope.statement_check ~body_regions:body.bound_body_regions caller.generics.regions in
  List.iter (fun (statement : statement) ->
    scope#visit_statement [] statement;
    match statement.kind with
    | StorageLive id ->
        let original = cell id in
        if LocalId.to_int id > 0 && LocalId.to_int id <= body.locals.arg_count then
          invalid_arg "dispatch lineage cannot silently replace an original argument allocation";
        cells := LocalId.Map.add id { original with live = true; value = None } !cells
    | StorageDead id ->
        let original = cell id in cells := LocalId.Map.add id { original with live = false; value = None } !cells
    | Assign (({ kind = PlaceLocal id; _ } as destination), rvalue) ->
        let target = cell id in
        if not target.live then invalid_arg "dispatch lineage assigns into an unallocated source local";
        equal target.declared.local_ty destination.ty;
        let value = match rvalue with
          | Use (operand, _) ->
              let value = read_operand operand in equal value.ty destination.ty; value
          | RvRef (({ kind = PlaceProjection (parent, Deref); _ } as source), kind, metadata) ->
              let inherited = read parent in
              (match parent.ty, destination.ty with
               | TRef (_, TDynTrait parent_predicate, parent_mutability), TRef (_, TDynTrait predicate, mutability) ->
                   (match kind, parent_mutability, mutability with
                    | BShared, _, RShared | BMut, RMut, RMut | BTwoPhaseMut, RMut, RMut -> ()
                    | _ -> invalid_arg "the actual dynamic reborrow changed its source borrow classification");
                   ignore (Vtable_shape.object_annotation lookup.shape.source_predicate parent_predicate);
                   ignore (Vtable_shape.object_annotation lookup.shape.source_predicate predicate);
                   equal (TDynTrait parent_predicate) source.ty;
                   (match metadata with
                    | Copy { kind = PlaceProjection (actual_parent, PtrMetadata);
                        ty = TRef (RStatic, TAdt reference, RShared) }
                        when actual_parent = parent && reference = lookup.table_reference -> ()
                    | _ -> invalid_arg "the dynamic reborrow must copy the metadata of its very same original receiver");
                   let lineage = match inherited.lineage with Some lineage -> lineage
                     | None -> invalid_arg "a dynamic reborrow has no original source receiver argument" in
                   reborrows := { statement; source; destination; metadata; inherited = lineage } :: !reborrows;
                   { ty = destination.ty; lineage = Some { lineage with reborrows = lineage.reborrows @ [statement.statement_id] } }
               | TRef (_, pointee, _), TRef (_, actual, _) when inherited.lineage = None ->
                   equal pointee source.ty; equal source.ty actual;
                   (match metadata with Constant { kind = CAdt (None, []); ty } when ty = Vtable_shape.unit -> ()
                    | _ -> invalid_arg "an ordinary source reborrow requires its exact unit metadata");
                   { ty = destination.ty; lineage = None }
               | _ -> invalid_arg "the source dispatch reborrow needs explicit carrier/alias flow")
          | _ -> invalid_arg "the dispatch prefix has an unsupported source value/effect requiring explicit lineage" in
        cells := LocalId.Map.add id { target with value = Some { value with ty = destination.ty } } !cells
    | Nop -> ()
    | _ -> invalid_arg "the dispatch prefix needs explicit call/control-flow/alias effects before lineage can be constructed") prefix;
  let receiver_value = read lookup.receiver in
  let receiver_lineage = match receiver_value.lineage with Some lineage -> lineage
    | None -> invalid_arg "the actual vtable call receiver has no original argument/reborrow lineage" in
  List.iter (fun operand -> scope#visit_operand [] operand; ignore (read_operand operand)) source_call.args;
  scope#visit_place [] source_call.dest;
  if not (Region_equations.replay_predicates !constraints) then
    invalid_arg "the complete original dispatch prefix type constraints did not replay";
  let own_call_arguments = List.rev (List.tl (List.rev lookup.invocation.arguments)) in
  let available_source_branches = GlobalDeclId.Map.bindings crate.global_decls |> List.filter_map (fun (_, (global : global_decl)) ->
    match global.ty with
    | TAdt reference when reference.id = lookup.table_reference.id ->
        let source_vtable = Vtable_initializer.create crate global in
        let source_slot = match List.filter (fun (slot : Vtable_initializer.slot) -> slot.field.index = lookup.field_index) source_vtable.slots with
          | [slot] when slot.field.role = lookup.field.role -> slot
          | _ -> invalid_arg "the actual source vtable instance changed the selected method slot" in
        let binding = match source_slot.function_binding with Some binding -> binding
          | None -> invalid_arg "the source dispatch branch has no actual generated function binding" in
        if List.length binding.cast_signature_binding.own_source_parameters <> List.length own_call_arguments then
          invalid_arg "the source branch shim's own binder disagrees with the actual invocation";
        Some { source_vtable; source_slot; own_call_arguments }
    | _ -> None) in
  { caller; source_statement; source_call; on_unwind; lookup; receiver_lineage;
    reborrows = List.rev !reborrows; prefix; region_constraints = !constraints; available_source_branches }

let replay crate witness =
  try derive crate ~caller:witness.caller witness.source_statement = witness with Invalid_argument _ -> false

let create crate ~caller statement =
  let witness = derive crate ~caller statement in
  if not (replay crate witness) then invalid_arg "the complete actual vtable dispatch lineage witness did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_function_id", `Int (FunDeclId.to_int witness.caller.def_id);
    "source_statement_id", `Int (StatementId.to_int witness.source_statement.statement_id);
    "original_call", `String (show_call witness.source_call);
    "original_on_unwind", `String (show_block witness.on_unwind);
    "receiver_place", `String (show_place witness.lookup.receiver);
    "metadata_place", `String (show_place witness.lookup.metadata_place);
    "source_vtable_type", `String (show_type_decl_ref witness.lookup.table_reference);
    "source_field", `Int (FieldId.to_int witness.lookup.field_index);
    "original_function_type", `String (show_ty witness.lookup.original_function_type);
    "source_field_invocation", Signature_instance.report witness.lookup.invocation;
    "original_receiver_argument", `Int (LocalId.to_int witness.receiver_lineage.argument);
    "actual_reborrow_statements", `List (List.map (fun id -> `Int (StatementId.to_int id)) witness.receiver_lineage.reborrows);
    "retained_reborrow_obligations", `List (List.map (fun (entry : reborrow) -> `Assoc [
      "statement_id", `Int (StatementId.to_int entry.statement.statement_id);
      "original_source", `String (show_place entry.source);
      "original_destination", `String (show_place entry.destination);
      "original_metadata", `String (show_operand entry.metadata);
      "liveness_aliasing_and_exclusivity_proved", `Bool false]) witness.reborrows);
    "source_prefix_type_constraints", region_certificate_json witness.region_constraints;
    "available_source_template_branches", `List (List.map (fun (branch : branch) -> `Assoc [
      "global", `Int (GlobalDeclId.to_int branch.source_vtable.global.def_id);
      "implementation", `Int (TraitImplId.to_int branch.source_vtable.owner.id);
      "actual_initializer_binding", Vtable_initializer.report branch.source_vtable;
      "own_call_lifetimes_in_caller_scope", `List (List.map (fun region -> `String (show_region region)) branch.own_call_arguments);
      "captured_arguments_instantiated_in_caller_scope", `Bool false]) witness.available_source_branches);
    "complete_source_dispatch_lineage_replays", `Bool (replay crate witness);
    "template_branches_are_exhaustive_native_instances", `Bool false;
    "interprocedural_value_flow_loan_and_execution_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
