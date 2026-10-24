(* Exact receiver/argument provenance in an actual prepared source frame.
   A shallow Box pointer access is recorded as a non-owning alias; it cannot
   escape, be copied/moved as an owner, or acquire a second destructor. This
   syntax witness does not establish native loan/ownership simulation. *)
open Charon
open Types
open Expressions
open LlbcAst

type origin = { argument : local_id; dereferences : int; reborrows : statement_id list }
type value = { ty : ty; origin : origin; box_access : bool }
type cell = { declared : local; live : bool; value : value option }
type borrow = {
  statement : statement;
  source : place;
  destination : place;
  metadata : operand;
  origin : origin;
  implicit_box_metadata : bool;
}
type box_access = { statement : statement; source : place; destination : place; origin : origin }
type t = {
  view : Instance_view.t;
  frame : Function_frame.t;
  call : Function_frame.dynamic_call;
  source_statement : statement;
  receiver : place;
  receiver_origin : origin;
  argument_origins : origin list;
  prefix : statement list;
  borrows : borrow list;
  box_accesses : box_access list;
  constraints : Region_equations.predicates;
}

let box_pointee = function
  | TAdt { id = TBuiltin TBox; generics } when generics.regions = [] &&
      generics.const_generics = [] && generics.trait_refs = [] ->
      (match generics.types with [ty] -> Some ty | _ -> None)
  | _ -> None

let derive ~(view : Instance_view.t) ~(frame : Function_frame.t) ~(call : Function_frame.dynamic_call) =
  if frame.original_function_id <> view.original_id || not (List.mem call frame.dynamic_calls) then
    invalid_arg "virtual receiver flow requires its actual prepared source call and function instance";
  let source_statement = ref None in
  let statement_ids = ref StatementId.Set.empty in
  let find = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      if StatementId.Set.mem statement.statement_id !statement_ids then
        invalid_arg "virtual receiver flow cannot identify duplicate source statement IDs";
      statement_ids := StatementId.Set.add statement.statement_id !statement_ids;
      if statement.statement_id = call.dynamic_statement_id then source_statement := Some statement;
      super#visit_statement env statement
  end in find#visit_block () frame.body;
  let source_statement = match !source_statement with Some statement -> statement
    | None -> invalid_arg "the virtual receiver call is absent from its actual source frame" in
  let actual_call = match source_statement.kind with
    | Call (actual, _) when actual = { call.dynamic_source_call with func = FnOpRegular call.dynamic_plan.pointer } -> actual
    | _ -> invalid_arg "the complete prepared virtual source call changed outside its exact normalization" in
  if not (List.for_all (fun (left, right) -> left = right) (Dynamic_method.call_requirements call.dynamic_plan actual_call)) then
    invalid_arg "virtual receiver flow changed the complete actual source call ABI";
  let rec split before = function
    | first :: rest when first = source_statement -> List.rev before, rest
    | first :: rest -> split (first :: before) rest
    | [] -> invalid_arg "nested virtual dispatch needs explicit control-flow provenance" in
  let prefix, suffix = split [] frame.body.statements in
  if frame.source_body.locals.arg_count <> List.length frame.signature.inputs then
    invalid_arg "virtual receiver source arguments disagree with their complete signature";
  let cells = ref LocalId.Map.empty in
  List.iter (fun (declared : local) ->
    if LocalId.Map.mem declared.index !cells then invalid_arg "virtual receiver locals have duplicate IDs";
    cells := LocalId.Map.add declared.index { declared; live = false; value = None } !cells) frame.locals;
  let get id = match LocalId.Map.find_opt id !cells with Some cell -> cell
    | None -> invalid_arg "virtual receiver flow uses an undeclared source local" in
  let constraints = ref Region_equations.empty_predicates in
  let equal left right = constraints := Region_equations.add_type !constraints left right in
  List.iteri (fun index ty ->
    let id = LocalId.of_int (index + 1) in let cell = get id in
    equal cell.declared.local_ty ty;
    cells := LocalId.Map.add id { cell with live = true;
      value = Some { ty = cell.declared.local_ty; origin = { argument = id; dereferences = 0; reborrows = [] }; box_access = false } } !cells)
    frame.signature.inputs;
  let rec read (place : place) = match place.kind with
    | PlaceLocal id ->
        let cell = get id in
        (match cell.live, cell.value with true, Some value -> equal value.ty place.ty; value
         | _ -> invalid_arg "virtual receiver flow reads dead, moved or uninitialized storage")
    | PlaceProjection (parent, Deref) ->
        let value = read parent in
        let pointee = match parent.ty with TRef (_, ty, _) -> ty
          | ty -> (match box_pointee ty with Some ty -> ty
              | None -> invalid_arg "virtual receiver projection needs its actual reference or Box carrier") in
        equal pointee place.ty;
        { ty = place.ty; origin = { value.origin with dereferences = value.origin.dereferences + 1 }; box_access = value.box_access }
    | _ -> invalid_arg "virtual receiver flow requires an explicit source projection rule" in
  let operand = function
    | Move ({ kind = PlaceLocal id; _ } as place) ->
        let value = read place in
        if value.box_access then invalid_arg "a shallow Box access cannot move as a new owner";
        let cell = get id in cells := LocalId.Map.add id { cell with value = None } !cells; value
    | Copy place ->
        let value = read place in
        if value.box_access || Option.is_some (box_pointee place.ty) then
          invalid_arg "a shallow Box access requires its exact non-owning source route";
        (match place.ty with TRef (_, _, RMut) -> invalid_arg "virtual receiver flow cannot copy an exclusive reference" | _ -> ());
        value
    | Move _ -> invalid_arg "a projected virtual move requires its explicit ownership interpretation"
    | Constant _ -> invalid_arg "a virtual argument cannot obtain provenance from an arbitrary constant" in
  let borrows = ref [] and box_accesses = ref [] in
  let scope = new Region_scope.statement_check ~body_regions:frame.source_body.bound_body_regions view.arguments.parameters in
  List.iter (fun (statement : statement) ->
    scope#visit_statement [] statement;
    match statement.kind with
    | StorageLive id ->
        let cell = get id in
        if cell.live then invalid_arg "virtual receiver flow cannot overwrite live storage with StorageLive";
        cells := LocalId.Map.add id { cell with live = true; value = None } !cells
    | StorageDead id -> let cell = get id in cells := LocalId.Map.add id { cell with live = false; value = None } !cells
    | Assign (({ kind = PlaceLocal id; _ } as destination), rvalue) ->
        let cell = get id in
        if not cell.live || Option.is_some cell.value then
          invalid_arg "virtual receiver flow must initialize allocated empty storage";
        equal cell.declared.local_ty destination.ty;
        let value = match rvalue with
          | Use (Copy ({ kind = PlaceProjection (parent, Deref); _ } as source), NoRetag)
              when Option.is_some (box_pointee source.ty) ->
              (match parent.ty with TRef (_, ty, RMut) when ty = source.ty -> ()
               | _ -> invalid_arg "a shallow Box access requires its actual exclusive parent reference");
              let value = read source in equal source.ty destination.ty;
              box_accesses := { statement; source; destination; origin = value.origin } :: !box_accesses;
              { value with ty = destination.ty; box_access = true }
          | Use (source, NoRetag) -> let value = operand source in equal value.ty destination.ty; { value with ty = destination.ty }
          | RvRef (({ kind = PlaceProjection (parent, Deref); _ } as source), kind, metadata) ->
              let value = read source in
              let borrow, pointee, mutability = match destination.ty with TRef (borrow, pointee, mutability) -> borrow, pointee, mutability
                | _ -> invalid_arg "a virtual source reborrow must retain its actual reference type" in
              ignore borrow; equal pointee source.ty;
              let exclusive = match parent.ty with TRef (_, _, RMut) -> true
                | ty -> Option.is_some (box_pointee ty) in
              (match kind, mutability with BShared, RShared -> ()
               | (BMut | BTwoPhaseMut), RMut when exclusive -> ()
               | _ -> invalid_arg "a virtual source reborrow cannot acquire stronger mutability than its actual carrier");
              let implicit_box_metadata = Option.is_some (box_pointee parent.ty) in
              (match source.ty, metadata with
               | TDynTrait predicate, Constant { kind = CAdt (None, []); ty }
                   when implicit_box_metadata && ty = Vtable_shape.unit ->
                   ignore (Vtable_shape.object_annotation call.dynamic_plan.vtable_shape.source_predicate predicate)
               | TDynTrait predicate, Copy { kind = PlaceProjection (actual, PtrMetadata);
                   ty = TRef (RStatic, TAdt table, RShared) }
                   when not implicit_box_metadata && actual = parent && table = call.dynamic_plan.vtable_reference ->
                   ignore (Vtable_shape.object_annotation call.dynamic_plan.vtable_shape.source_predicate predicate)
               | TSlice _, Copy { kind = PlaceProjection (actual, PtrMetadata); ty }
                   when actual = parent && ty = Vtable_shape.usize -> ()
               | _, Constant { kind = CAdt (None, []); ty } when ty = Vtable_shape.unit &&
                   (match source.ty with TDynTrait _ | TSlice _ -> false | _ -> true) -> ()
               | _ -> invalid_arg "a virtual reborrow must preserve the metadata route of its exact original carrier");
              let origin = { value.origin with reborrows = value.origin.reborrows @ [statement.statement_id] } in
              borrows := { statement; source; destination; metadata; origin; implicit_box_metadata } :: !borrows;
              { ty = destination.ty; origin; box_access = false }
          | _ -> invalid_arg "the virtual prefix requires an additional explicit value/effect rule" in
        cells := LocalId.Map.add id { cell with value = Some value } !cells
    | Nop -> ()
    | _ -> invalid_arg "the virtual receiver prefix requires explicit control-flow/call/alias semantics") prefix;
  let receiver = match actual_call.args with Move place :: _ -> place
    | Copy ({ ty = TRef (_, _, RShared); _ } as place) :: _ -> place
    | _ -> invalid_arg "virtual dispatch must pass its actual receiver with the original ownership class" in
  let receiver_value = read receiver in
  (match receiver.ty with TRef (_, self, _) when self = call.dynamic_plan.self_type -> ()
   | _ -> invalid_arg "the virtual receiver flow ends at a different dynamic Self");
  let argument_origins = List.map (fun argument -> (operand argument).origin) actual_call.args in
  let destination = match actual_call.dest.kind with PlaceLocal id -> get id
    | _ -> invalid_arg "the virtual call result needs explicit projected destination semantics" in
  if not destination.live || Option.is_some destination.value then
    invalid_arg "the actual virtual call destination is not allocated empty storage";
  equal destination.declared.local_ty actual_call.dest.ty;
  let alias_ids = List.map (fun (access : box_access) -> match access.destination.kind with PlaceLocal id -> id
    | _ -> invalid_arg "a shallow Box access lost its local identity") !box_accesses in
  let no_escape = object inherit [_] iter_statement as super
    method! visit_place env place =
      (match place.kind with PlaceLocal id when List.mem id alias_ids ->
        invalid_arg "a shallow Box access escapes after the virtual reborrow or reaches a destructor" | _ -> ());
      super#visit_place env place
  end in
  (match source_statement.kind with Call (_, unwind) -> no_escape#visit_block () unwind | _ -> ());
  List.iter (no_escape#visit_statement ()) suffix;
  if not (Region_equations.replay_predicates !constraints) then
    invalid_arg "the full original virtual receiver type equations did not replay";
  { view; frame; call; source_statement; receiver; receiver_origin = receiver_value.origin;
    argument_origins; prefix; borrows = List.rev !borrows; box_accesses = List.rev !box_accesses; constraints = !constraints }

let replay witness = try derive ~view:witness.view ~frame:witness.frame ~call:witness.call = witness
  with Invalid_argument _ -> false

let create crate ~view ~frame ~call =
  if Function_frame.prepare crate view <> frame then invalid_arg "virtual provenance requires the exact replayed source frame";
  let witness = derive ~view ~frame ~call in
  if not (replay witness) then invalid_arg "the complete virtual receiver provenance did not replay";
  witness

let origin_json origin = `Assoc ["source_argument", `Int (LocalId.to_int origin.argument);
  "dereferences", `Int origin.dereferences;
  "reborrow_statements", `List (List.map (fun id -> `Int (StatementId.to_int id)) origin.reborrows)]

let report witness =
  let open Diagnostic in
  `Assoc ["source_function", `Int (FunDeclId.to_int witness.view.original_id);
    "source_statement", `Int (StatementId.to_int witness.source_statement.statement_id);
    "receiver", `String (show_place witness.receiver); "receiver_origin", origin_json witness.receiver_origin;
    "argument_origins", `List (List.map origin_json witness.argument_origins);
    "borrows", `List (List.map (fun (borrow : borrow) -> `Assoc [
      "source_statement", `Int (StatementId.to_int borrow.statement.statement_id);
      "source_place", `String (show_place borrow.source); "destination", `String (show_place borrow.destination);
      "actual_metadata", `String (show_operand borrow.metadata); "origin", origin_json borrow.origin;
      "implicit_box_metadata", `Bool borrow.implicit_box_metadata]) witness.borrows);
    "nonowning_box_accesses", `List (List.map (fun (access : box_access) -> `Assoc [
      "source_statement", `Int (StatementId.to_int access.statement.statement_id);
      "source_place", `String (show_place access.source); "destination", `String (show_place access.destination);
      "origin", origin_json access.origin]) witness.box_accesses);
    "source_type_constraints", region_certificate_json witness.constraints;
    "complete_source_receiver_provenance_replays", `Bool (replay witness);
    "native_box_metadata_loan_ownership_and_source_simulation_proved", `Bool false;
    "runtime_capture_selected", `Bool false; "qualified", `Bool false; "program_emitted", `Bool false]
