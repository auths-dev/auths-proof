(* Source control-flow provenance for returned dynamic Boxes. Branches retain
   their original tests; ordinary calls retain their actual bodies/contracts.
   This enumerates normal source return routes, not native execution/loans or
   an interpretation of an opaque callback. Unsupported flows refuse. *)
open Charon
open Types
open Expressions
open LlbcAst

type step = {
  statement : statement_id;
  from_place : place;
  into_place : place;
  object_regions : (region * region) option;
}
type paired = { producer : Prepared_injection.t; steps : step list; constraints : Region_equations.predicates }
type value = Ordinary | Unknown | Paired of paired
type cell = { declared : local; live : bool; value : value option }
type path = { cells : cell LocalId.Map.t; branches : (statement_id * int) list }
type returned = { statement : statement_id; branches : (statement_id * int) list; paired : paired }
type t = { view : Instance_view.t; frame : Function_frame.t; producers : Prepared_injection.t list;
  returns : returned list; deferred_unwind_blocks : block list }

let predicate ty = match Virtual_receiver.box_pointee ty with Some (TDynTrait predicate) -> Some predicate | _ -> None

let derive crate ~(view : Instance_view.t) ~(frame : Function_frame.t) ~producers =
  if frame.original_function_id <> view.original_id || Option.is_none (predicate frame.signature.output) then
    invalid_arg "capture return construction requires its actual dynamic Box result signature";
  if producers = [] || List.exists (fun (producer : Prepared_injection.t) ->
    producer.view <> view || producer.frame <> frame || not (Prepared_injection.replay crate producer) ||
    (match producer.carrier with Vtable_injection.OwnedBox _ -> false | _ -> true)) producers then
    invalid_arg "a returned Box needs the complete actual owned source injection set";
  let expected_producers = ref [] in
  let source_ids = ref StatementId.Set.empty in
  let scan = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if StatementId.Set.mem statement.statement_id !source_ids then invalid_arg "capture return source statement IDs are ambiguous";
      source_ids := StatementId.Set.add statement.statement_id !source_ids;
      (match statement.kind with
       | Assign (_, UnaryOp (Cast (CastUnsize (_, into, MetaVTable _)), _)) when Option.is_some (predicate into) ->
           expected_producers := statement.statement_id :: !expected_producers
       | _ -> ()); super#visit_statement env statement
  end in scan#visit_block () frame.body;
  if List.sort StatementId.compare_id !expected_producers <>
     List.sort StatementId.compare_id (List.map (fun (producer : Prepared_injection.t) -> producer.statement.statement_id) producers) then
    invalid_arg "capture return construction cannot omit or duplicate an actual source Box injection";
  let cells = List.fold_left (fun cells (declared : local) ->
    if LocalId.Map.mem declared.index cells then invalid_arg "capture return locals have duplicate IDs";
    let argument = LocalId.to_int declared.index > 0 && LocalId.to_int declared.index <= frame.source_body.locals.arg_count in
    LocalId.Map.add declared.index { declared; live = argument; value = if argument then Some (
      if Option.is_some (predicate declared.local_ty) then Unknown else Ordinary) else None } cells) LocalId.Map.empty frame.locals in
  let get path id = match LocalId.Map.find_opt id path.cells with Some cell -> cell
    | None -> invalid_arg "a returned capture uses an undeclared source local" in
  let set path id cell = { path with cells = LocalId.Map.add id cell path.cells } in
  let rec root (place : place) = match place.kind with PlaceLocal id -> id
    | PlaceProjection (parent, _) -> root parent
    | PlaceGlobal _ -> invalid_arg "a returned Box global requires its actual value/ownership source binding" in
  let read path (place : place) =
    let cell = get path (root place) in
    match cell.live, cell.value with
    | true, Some (Paired paired) when place.kind = PlaceLocal cell.declared.index ->
        let constraints = Region_equations.add_type paired.constraints cell.declared.local_ty place.ty in
        Paired { paired with constraints }
    | true, Some (Paired _) -> invalid_arg "a projected paired Box requires explicit alias/field semantics"
    | true, Some value -> value
    | _ -> invalid_arg "capture return provenance reads dead, moved or uninitialized storage" in
  let operand path = function
    | Constant value -> if Option.is_some (predicate value.ty) then path, Unknown else path, Ordinary
    | Copy place ->
        let value = read path place in
        (match value with Paired _ -> invalid_arg "a returned dynamic Box cannot be copied as another owner" | _ -> ());
        if Option.is_some (predicate place.ty) then invalid_arg "a returned Box copy has no unique source owner";
        path, value
    | Move place ->
        let value = read path place in
        (match place.kind with PlaceLocal id -> let cell = get path id in set path id { cell with value = None }, value
         | _ -> path, value) in
  let store path (destination : place) value = match destination.kind with
    | PlaceLocal id ->
        let cell = get path id in
        if not cell.live || Option.is_some cell.value then invalid_arg "capture return must initialize allocated empty local storage";
        let value = match value with Paired paired -> Paired { paired with constraints =
          Region_equations.add_type paired.constraints destination.ty cell.declared.local_ty } | value -> value in
        set path id { cell with value = Some value }
    | _ -> invalid_arg "capture return assignment needs explicit projected destination semantics" in
  let no_paired value = match value with Paired _ -> invalid_arg "a paired Box escapes into an unmodeled source effect" | _ -> () in
  let returns = ref [] and deferred_unwind_blocks = ref [] in
  let visits = ref 0 in
  let rec block (paths : path list) (source : block) = List.fold_left (fun paths statement ->
    List.concat_map (fun path -> execute path statement) paths) paths source.statements
  and execute (path : path) (statement : statement) =
    incr visits;
    if !visits > 100000 then invalid_arg "capture return path construction exceeds its explicit resource bound";
    match statement.kind with
    | StorageLive id -> let cell = get path id in
        if cell.live then invalid_arg "capture return cannot silently replace a live local allocation";
        [set path id { cell with live = true; value = None }]
    | StorageDead id -> let cell = get path id in
        Option.iter no_paired cell.value;
        [set path id { cell with live = false; value = None }]
    | Assign (destination, (UnaryOp (Cast (CastUnsize (from, into, MetaVTable _)), source))) ->
        let producer = match List.filter (fun (producer : Prepared_injection.t) -> producer.statement = statement) producers with
          | [producer] -> producer | _ -> invalid_arg "the actual Box injection is absent from its exact source producer set" in
        let source_regions = Function_frame.region_mapper producer.constraints.solution in
        if source_regions#visit_ty () from <> source_regions#visit_ty () producer.from_type ||
           source_regions#visit_ty () into <> source_regions#visit_ty () destination.ty then
          invalid_arg "capture return changed an actual source cast type outside its recorded source equations";
        let path, previous = operand path source in no_paired previous;
        let from_place = match source with Move place -> place
          | _ -> invalid_arg "an actual Box injection must move its complete source owner" in
        let paired = { producer; constraints = producer.constraints;
          steps = [{ statement = statement.statement_id; from_place; into_place = destination; object_regions = None }] } in
        [store path destination (Paired paired)]
    | Assign (destination, UnaryOp (Cast (CastUnsize (from, into, MetaVTableUpcast [])), source)) ->
        let path, value = operand path source in
        let paired = match value with Paired paired -> paired
          | _ -> invalid_arg "a source Box object-bound cast lost its actual paired producer" in
        (* These are full original cast/operand and cast/destination source
           typing premises, accumulated with the producer certificate. The
           from/into object bounds are deliberately NOT equated: narrowing
           remains an explicit semantic obligation below. *)
        let constraints = Region_equations.add_type paired.constraints from (Vtable_dispatch.operand_type source) in
        let constraints = Region_equations.add_type constraints into destination.ty in
        if not (Region_equations.replay_predicates constraints) then
          invalid_arg "a source Box cast failed its complete accumulated operand/destination typing premises";
        let from_predicate, into_predicate = match predicate from, predicate into with Some first, Some second -> first, second
          | _ -> invalid_arg "an empty source vtable upcast needs its exact original Box carrier" in
        let owner = paired.producer.original.source_vtable.shape.source_predicate in
        let before = Vtable_shape.object_annotation owner from_predicate and after = Vtable_shape.object_annotation owner into_predicate in
        if before = RErased || after = RErased then invalid_arg "a source object-bound cast cannot guess an erased lifetime";
        let from_place = match source with Move place -> place | _ -> invalid_arg "an object-bound Box cast cannot copy ownership" in
        let step = { statement = statement.statement_id; from_place; into_place = destination; object_regions = Some (before, after) } in
        [store path destination (Paired { paired with constraints; steps = paired.steps @ [step] })]
    | Assign (destination, Use (source, _)) ->
        let path, value = operand path source in
        let value = match value with Paired paired ->
          if destination.ty <> Vtable_dispatch.operand_type source then
            invalid_arg "a paired Box move needs an explicit source object-bound cast for a changed type";
          let from_place = match source with Move place -> place | _ -> invalid_arg "a paired Box must move" in
          Paired { paired with steps = paired.steps @ [{ statement = statement.statement_id; from_place; into_place = destination; object_regions = None }] }
          | _ -> if Option.is_some (predicate destination.ty) then Unknown else value in
        [store path destination value]
    | Assign (destination, rvalue) ->
        let current = ref path in
        let inspect = object inherit [_] iter_statement as super
          method! visit_operand _ source = let path, value = operand !current source in no_paired value; current := path
          method! visit_place env place = no_paired (read !current place); super#visit_place env place
        end in inspect#visit_rvalue () rvalue;
        [store !current destination (if Option.is_some (predicate destination.ty) then Unknown else Ordinary)]
    | Call (call, unwind) ->
        let path = List.fold_left (fun path source -> let path, value = operand path source in no_paired value; path) path call.args in
        deferred_unwind_blocks := unwind :: !deferred_unwind_blocks;
        [store path call.dest (if Option.is_some (predicate call.dest.ty) then Unknown else Ordinary)]
    | Switch switch ->
        let branch (path : path) index source = block [{ path with branches = path.branches @ [statement.statement_id, index] }] source in
        (match switch with
         | If (condition, yes, no) -> let path, value = operand path condition in no_paired value;
             branch path 0 yes @ branch path 1 no
         | SwitchInt (condition, _, branches, otherwise) -> let path, value = operand path condition in no_paired value;
             let literals = List.concat_map fst branches in
             if List.length (List.sort_uniq compare literals) <> List.length literals then invalid_arg "a source integer switch has duplicate branch literals";
             List.concat (List.mapi (fun index (_, source) -> branch path index source) branches) @ branch path (List.length branches) otherwise
         | Match (place, branches, otherwise) ->
             no_paired (read path place);
             let supplied = List.concat_map fst branches |> List.sort VariantId.compare_id in
             if List.sort_uniq VariantId.compare_id supplied <> supplied then invalid_arg "a source enum match has duplicate variants";
             let variants = match place.ty with TAdt { id = TAdtId id; _ } ->
                 (match TypeDeclId.Map.find_opt id crate.type_decls with Some { kind = Enum variants; _ } ->
                   List.map (fun (variant : variant) -> variant.id) variants |> List.sort VariantId.compare_id
                  | _ -> invalid_arg "capture return match needs its actual source enum definition")
               | _ -> invalid_arg "capture return match lost its original nominal enum type" in
             if List.exists (fun id -> not (List.mem id variants)) supplied || (otherwise = None && supplied <> variants) then
               invalid_arg "the exact source enum branches are not exhaustive";
             List.concat (List.mapi (fun index (_, source) -> branch path index source) branches) @
               (match otherwise with Some source -> branch path (List.length branches) source | None -> []))
    | Return ->
        let result = get path (LocalId.of_int 0) in
        let paired = match result.live, result.value with true, Some (Paired paired) -> paired
          | _ -> invalid_arg "a normal dynamic Box return has no exact source producer" in
        let paired = { paired with constraints = Region_equations.add_type paired.constraints
          result.declared.local_ty frame.signature.output } in
        if not (Region_equations.replay_predicates paired.constraints) then
          invalid_arg "the complete normal source return type premises did not replay";
        LocalId.Map.iter (fun id cell -> if LocalId.to_int id <> 0 then Option.iter no_paired cell.value) path.cells;
        returns := { statement = statement.statement_id; branches = path.branches; paired } :: !returns; []
    | Abort _ | UnwindResume -> []
    | Nop -> [path]
    | PlaceMention place -> no_paired (read path place); [path]
    | _ -> invalid_arg "capture return control flow needs an additional explicit source rule" in
  let remaining = block [{ cells; branches = [] }] frame.body in
  if remaining <> [] || !returns = [] then invalid_arg "capture return construction needs every normal path to reach an explicit paired return";
  { view; frame; producers; returns = List.rev !returns; deferred_unwind_blocks = List.rev !deferred_unwind_blocks }

let replay crate witness = try derive crate ~view:witness.view ~frame:witness.frame ~producers:witness.producers = witness
  with Invalid_argument _ -> false

let create crate ~view ~frame ~producers =
  if Function_frame.prepare crate view <> frame then invalid_arg "capture return requires its actual complete source frame replay";
  let witness = derive crate ~view ~frame ~producers in
  if not (replay crate witness) then invalid_arg "the complete normal source Box return routes did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_function", `Int (FunDeclId.to_int witness.view.original_id);
    "normal_return_routes", `List (List.map (fun (returned : returned) -> `Assoc [
      "return_statement", `Int (StatementId.to_int returned.statement);
      "source_branches", `List (List.map (fun (statement, index) -> `Assoc [
        "statement", `Int (StatementId.to_int statement); "branch_index", `Int index]) returned.branches);
      "producer_statement", `Int (StatementId.to_int returned.paired.producer.statement.statement_id);
      "accumulated_original_source_type_premises", region_certificate_json returned.paired.constraints;
      "paired_move_and_object_bound_steps", `List (List.map (fun (step : step) -> `Assoc [
        "statement", `Int (StatementId.to_int step.statement);
        "source", `String (show_place step.from_place); "destination", `String (show_place step.into_place);
        "required_object_lifetime_narrowing", (match step.object_regions with None -> `Null | Some (before, after) ->
          `List [`String (show_region before); `String (show_region after)])]) returned.paired.steps)]) witness.returns);
    "deferred_original_unwind_blocks", `Int (List.length witness.deferred_unwind_blocks);
    "complete_normal_source_return_routes_replay", `Bool (replay crate witness);
    "ordinary_calls_evaluated_or_results_supplied", `Bool false;
    "native_control_flow_allocation_loan_drop_and_unwind_simulation_proved", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
