(* Reconstruction candidate for one source-only shape: a straight-line helper
   moves every declared input exactly once into its returned closure aggregate.
   An erased output capture slot may be filled only by the declared type of
   that very moved input, through the original nominal source field schema.
   Known regions, all type/const/dictionary structure and binders stay rigid.
   The original erased signature is retained; native source/opaque-interface
   refinement and loan/retag semantics remain a separate required proof. *)
open Charon
open Types
open Expressions
open LlbcAst

type capture = {
  field_index : int;
  source_field : field;
  source_operand : operand;
  parameter_index : int;
  declared_parameter_type : ty;
  field_pattern : ty;
}
type completion = { output_region_index : int; marker : region; actual : region }
type t = {
  view : Instance_view.t;
  original : fun_sig;
  reconstructed : fun_sig;
  source_type : type_decl;
  original_output : type_decl_ref;
  source_aggregate : statement;
  source_return : statement;
  captures : capture list;
  completions : completion list;
  constraints : Region_equations.predicates;
}

let erased ty =
  let found = ref false in
  let scan = object inherit [_] iter_ty method! visit_region _ region = if region = RErased then found := true end in
  scan#visit_ty () ty; !found

let region_shape ty =
  let erase = object inherit [_] map_ty method! visit_region _ _ = RErased end in
  erase#visit_ty () ty

let regions ty =
  let result = ref [] in
  let scan = object inherit [_] Region_shape.binder_map
    method! visit_region depth region = result := (depth, region) :: !result; region
  end in ignore (scan#visit_ty 0 ty); List.rev !result

let derive crate (view : Instance_view.t) =
  let original = view.signature in
  if not (erased original.output) then None else (
    let definition = match FunDeclId.Map.find_opt view.original_id crate.fun_decls with Some definition -> definition
      | None -> invalid_arg "a source return signature requires its original function declaration" in
    if not (Instance_view.replay definition view) then invalid_arg "the complete original return-signature source view did not replay";
    let locals, body = match view.locals_and_body with Some source -> source
      | None -> invalid_arg "an erased public return requires its actual structured source constructor, not an opaque result" in
    ignore (Source_path.unique_ids body);
    let source_body = match view.source_body with Some body -> body | None -> invalid_arg "the original source body metadata is absent" in
    let output = match original.output with TAdt ({ id = TAdtId _; _ } as reference) -> reference
      | _ -> invalid_arg "only an actual nominal source closure return supports this capture reconstruction" in
    let source_type = match output.id with TAdtId id ->
        (match TypeDeclId.Map.find_opt id crate.type_decls with Some source -> source
         | None -> invalid_arg "the returned source closure declaration is absent")
      | _ -> invalid_arg "a reconstructed source return cannot substitute a tuple or builtin" in
    let fields = match source_type.src, source_type.kind with ClosureItem _, Struct fields -> fields
      | _ -> invalid_arg "an erased source return cannot use a guessed ordinary struct representation" in
    Static_targets.require_argument_arity source_type.generics output.generics;
    let public_scope = new Region_scope.check view.arguments.parameters in
    List.iter (public_scope#visit_ty []) original.inputs;
    if source_body.locals.arg_count <> List.length original.inputs then invalid_arg "the source return helper lost a complete declared input";
    let largest = List.fold_left (fun largest (parameter : region_param) -> max largest (RegionId.to_int parameter.index)) (-1) view.arguments.parameters in
    if largest >= Int.max_int - List.length output.generics.regions - 1 then invalid_arg "source return capture markers exceed construction identifier space";
    let missing = ref [] in
    let marked_regions = List.mapi (fun index region -> if region <> RErased then region else (
      let marker = RVar (Free (RegionId.of_int (largest + index + 1))) in
      missing := (index, marker) :: !missing; marker)) output.generics.regions in
    if !missing = [] then invalid_arg "this return reconstruction cannot recover erased nested type/const/dictionary or unopened binder provenance";
    let pattern = { output with generics = { output.generics with regions = marked_regions } } in
    if erased (TAdt pattern) then invalid_arg "source return reconstruction cannot hide an erased region outside its original capture slots";
    let aggregate = ref None and returned = ref None and live_return = ref false and dead = ref LocalId.Set.empty in
    List.iter (fun (statement : statement) ->
      if Option.is_some !returned then invalid_arg "the exact source closure helper continues after its return";
      match statement.kind with
      | StorageLive id when LocalId.to_int id = 0 && not !live_return && Option.is_none !aggregate -> live_return := true
      | Assign (({ kind = PlaceLocal id; _ } as destination), Aggregate (AggregatedAdt (reference, None, None), operands))
          when LocalId.to_int id = 0 && !live_return && Option.is_none !aggregate && reference.id = output.id ->
          aggregate := Some (statement, destination, reference, operands)
      | StorageDead id when Option.is_some !aggregate && LocalId.to_int id > 0 &&
          LocalId.to_int id <= List.length original.inputs && not (LocalId.Set.mem id !dead) ->
          dead := LocalId.Set.add id !dead
      | Return when Option.is_some !aggregate -> returned := Some statement
      | Nop -> ()
      | _ -> invalid_arg "an erased source return needs a complete straight-line input-move/aggregate/return body") body.statements;
    let source_aggregate, destination, actual_reference, operands = match !aggregate with Some source -> source
      | None -> invalid_arg "the erased source return has no actual nominal aggregate" in
    let source_return = match !returned with Some statement -> statement | None -> invalid_arg "the actual source closure helper has no explicit return" in
    if List.length operands <> List.length fields || List.length operands <> List.length original.inputs then
      invalid_arg "a source return reconstruction must account for every input and captured field exactly once";
    let declaration id = match List.filter (fun (local : local) -> local.index = id) locals with
      | [source] -> source | _ -> invalid_arg "the source return helper's local declarations are missing or ambiguous" in
    let substitution = Type_view.source_substitution source_type pattern.generics None in
    let actual_substitution = Type_view.source_substitution source_type actual_reference.generics None in
    let inferred = ref [] and used = ref LocalId.Set.empty in
    let constraints = ref Region_equations.empty_predicates in
    let equal left right = constraints := Region_equations.add_type !constraints left right in
    let captures = List.mapi (fun field_index ((source_field : field), source_operand) ->
      let place, id = match source_operand with Move ({ kind = PlaceLocal id; _ } as place)
          when LocalId.to_int id > 0 && LocalId.to_int id <= List.length original.inputs -> place, id
        | _ -> invalid_arg "a source output capture must be the actual moved whole input, never a copy, reborrow, projection or fabricated value" in
      if LocalId.Set.mem id !used then invalid_arg "a source helper cannot duplicate an input into two captures";
      used := LocalId.Set.add id !used;
      let parameter_index = LocalId.to_int id - 1 in
      let declared_parameter_type = List.nth original.inputs parameter_index in
      let field_pattern = Substitute.ty_substitute substitution source_field.field_ty in
      if region_shape field_pattern <> region_shape declared_parameter_type then
        invalid_arg "the complete source closure field and declared moved parameter differ outside lifetime slots";
      List.iter2 (fun (_, expected) (_, actual) ->
        if List.exists (fun (_, marker) -> marker = expected) !missing then (
          (match actual with RStatic | RVar (Free _) -> public_scope#visit_region [] actual
           | _ -> invalid_arg "an output capture cannot guess a private, erased or unopened argument lifetime");
          match List.assoc_opt expected !inferred with
          | None -> inferred := (expected, actual) :: !inferred
          | Some previous when previous = actual -> ()
          | Some _ -> invalid_arg "one original output capture lifetime has inconsistent source parameter provenance")
        else if expected <> actual then invalid_arg "source return reconstruction changed a known captured lifetime or binder")
        (regions field_pattern) (regions declared_parameter_type);
      equal (declaration id).local_ty place.ty;
      equal declared_parameter_type place.ty;
      equal (Substitute.ty_substitute actual_substitution source_field.field_ty) place.ty;
      { field_index; source_field; source_operand; parameter_index; declared_parameter_type; field_pattern }
    ) (List.combine fields operands) in
    let completions = List.rev !missing |> List.map (fun (output_region_index, marker) ->
      let actual = match List.assoc_opt marker !inferred with Some actual -> actual
        | None -> invalid_arg "an erased output capture slot lacks actual moved-parameter provenance" in
      { output_region_index; marker; actual }) in
    let completed_regions = List.mapi (fun index region -> match List.find_opt (fun completion -> completion.output_region_index = index) completions with
      | Some completion when region = RErased -> completion.actual
      | Some _ -> invalid_arg "source return reconstruction attempted to replace a known output lifetime"
      | None -> region) output.generics.regions in
    let reconstructed = { original with output = TAdt { output with generics = { output.generics with regions = completed_regions } } } in
    public_scope#visit_fun_sig [] reconstructed;
    equal (declaration (LocalId.of_int 0)).local_ty destination.ty;
    equal destination.ty (TAdt actual_reference);
    equal destination.ty reconstructed.output;
    if not (Region_equations.replay_predicates !constraints) then invalid_arg "the complete original parameter/capture/return typing premises did not replay";
    if LocalId.Set.cardinal !used <> List.length original.inputs || LocalId.Set.cardinal !dead <> List.length original.inputs then
      invalid_arg "the source helper did not consume and end every moved input's original storage";
    Some { view; original; reconstructed; source_type; original_output = output; source_aggregate; source_return;
      captures; completions; constraints = !constraints })

let replay crate witness = try derive crate witness.view = Some witness with Invalid_argument _ | Not_found -> false

let create crate view = match derive crate view with
  | None -> None
  | Some witness -> if not (replay crate witness) then invalid_arg "the complete original source return capture reconstruction did not replay";
      Some witness

let report crate witness =
  let open Diagnostic in
  `Assoc ["source_function", `Int (FunDeclId.to_int witness.view.original_id);
    "original_erased_source_signature", `String (show_fun_sig witness.original);
    "source_parameter_derived_signature_candidate", `String (show_fun_sig witness.reconstructed);
    "actual_source_aggregate", `Int (StatementId.to_int witness.source_aggregate.statement_id);
    "actual_source_return", `Int (StatementId.to_int witness.source_return.statement_id);
    "source_captures", `List (List.map (fun capture -> `Assoc ["field_index", `Int capture.field_index;
      "actual_source_operand", `String (show_operand capture.source_operand);
      "actual_parameter_index", `Int capture.parameter_index;
      "declared_parameter_type", `String (show_ty capture.declared_parameter_type);
      "original_nominal_field_pattern", `String (show_ty capture.field_pattern)]) witness.captures);
    "output_capture_completions", `List (List.map (fun completion -> `Assoc ["output_region_index", `Int completion.output_region_index;
      "temporary_source_slot_matching_marker_not_emitted", `String (show_region completion.marker);
      "actual_declared_input_lifetime", `String (show_region completion.actual)]) witness.completions);
    "complete_original_source_typing_premises", region_certificate_json witness.constraints;
    "complete_source_reconstruction_replays", `Bool (replay crate witness);
    "native_original_opaque_signature_refinement_and_loan_simulation_proved", `Bool false;
    "ordinary_return_value_or_guessed_static_lifetime_supplied", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false]
