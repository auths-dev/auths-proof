(* Bind an actual stored function-pointer signature to the generated source
   field's explicit object-lifetime family. Only that one field-local object
   parameter may vary. All other regions and every non-region/binder/ABI node
   must reconstruct exactly. Native cast, loan and method semantics remain
   separate obligations; this module never relaxes Type_view's source gate. *)
open Charon
open Types

type t = {
  template_parameters : generic_params;
  template_arguments : generic_args;
  free_parameters : region_param list;
  body_regions : int;
  owner : dyn_predicate;
  source_field : Vtable_shape.function_field;
  original : fun_sig region_binder;
  exposed : fun_sig region_binder;
  actual : fun_sig region_binder;
  object_argument : region;
  reconstructed : fun_sig region_binder;
}

let signature_shape (signature : fun_sig region_binder) =
  let erase = object inherit [_] map_ty method! visit_region _ _ = RErased end in
  erase#visit_region_binder erase#visit_fun_sig () signature

let scoped_regions (signature : fun_sig region_binder) =
  let result = ref [] in
  let scan = object (self)
    inherit [_] iter_ty
    method! visit_binder visit depth binder =
      let depth = depth + 1 in
      self#visit_generic_params depth binder.binder_params;
      visit depth binder.binder_value
    method! visit_region_binder visit depth binder = visit (depth + 1) binder.binder_value
    method! visit_region depth region = result := (depth, region) :: !result
  end in
  (* The field's outer function binder remains in place during instantiation.
     Start inside it; only nested binders increase this relative depth. *)
  scan#visit_fun_sig 0 signature.binder_value;
  List.rev !result

let map_object (parameter : region_param) replacement (signature : fun_sig region_binder) =
  let instantiate = object
    inherit [_] Region_shape.binder_map
    method! visit_region depth = function
      | RVar (Bound (binder, id)) when binder = depth && id = parameter.index ->
          Region_shape.under depth replacement
      | region -> region
  end in
  { signature with binder_value = instantiate#visit_fun_sig 0 signature.binder_value }

let derive ~parameters ~arguments ~free_parameters ~body_regions ~owner source_field actual =
  if not (Vtable_shape.replay_function owner source_field) then
    invalid_arg "a stored vtable field needs its exact source object-annotation family";
  Static_targets.require_argument_arity parameters arguments;
  let substitution = Substitute.make_subst_from_generics parameters arguments Self in
  let substitute = Substitute.st_substitute_visitor#visit_region_binder
    Substitute.st_substitute_visitor#visit_fun_sig substitution in
  let original = substitute source_field.original in
  let exposed = substitute source_field.parameterized in
  if exposed.binder_regions <> original.binder_regions @ [source_field.object_parameter] ||
     actual.binder_regions <> original.binder_regions then
    invalid_arg "a stored vtable field changed the complete original function binder";
  let pattern = { exposed with binder_regions = original.binder_regions } in
  if map_object source_field.object_parameter RErased pattern <> original then
    invalid_arg "source template substitution did not preserve exact object-marker erasure";
  if signature_shape pattern <> signature_shape actual then
    invalid_arg "a stored vtable signature differs in complete type/const/dictionary/quantifier/ABI structure";
  let left, right = scoped_regions pattern, scoped_regions actual in
  if List.length left <> List.length right then invalid_arg "stored vtable signature region traversal arities disagree";
  let inferred = ref None in
  List.iter2 (fun (depth, expected) (actual_depth, supplied) ->
    if depth <> actual_depth then invalid_arg "stored vtable signature binder depths disagree";
    if expected = RVar (Bound (depth, source_field.object_parameter.index)) then (
      let argument = match supplied with
        | RStatic -> RStatic
        | RBody id when RegionId.to_int id >= 0 && RegionId.to_int id < body_regions -> supplied
        | RVar (Free id) when List.exists (fun (parameter : region_param) -> parameter.index = id) free_parameters -> supplied
        | RVar (Bound (binder, id)) when binder = depth &&
            List.exists (fun (parameter : region_param) -> parameter.index = id) original.binder_regions ->
            RVar (Bound (0, id))
        | _ -> invalid_arg "a stored vtable object annotation lacks exact body/free/own-binder provenance" in
      match !inferred with
      | None -> inferred := Some argument
      | Some previous when previous = argument -> ()
      | Some _ -> invalid_arg "one source vtable object parameter has incompatible actual annotations"
    )) left right;
  let object_argument = match !inferred with
    | Some argument -> argument
    | None -> invalid_arg "the stored vtable signature does not determine the source object annotation" in
  let reconstructed = map_object source_field.object_parameter object_argument pattern in
  if reconstructed <> actual then
    invalid_arg "stored vtable field reconstruction changed a fixed region or complete signature node";
  let scope = new Region_scope.check ~body_regions free_parameters in
  scope#visit_ty [] (TFnPtr actual);
  { template_parameters = parameters; template_arguments = arguments; free_parameters;
    body_regions; owner; source_field; original; exposed; actual; object_argument; reconstructed }

let replay witness =
  try derive ~parameters:witness.template_parameters ~arguments:witness.template_arguments
    ~free_parameters:witness.free_parameters ~body_regions:witness.body_regions ~owner:witness.owner
    witness.source_field witness.actual = witness
  with Invalid_argument _ -> false

let create ~parameters ~arguments ~free_parameters ~body_regions ~owner source_field actual =
  let witness = derive ~parameters ~arguments ~free_parameters ~body_regions ~owner source_field actual in
  if not (replay witness) then invalid_arg "the complete stored source vtable signature did not replay";
  witness

let report witness =
  let open Diagnostic in
  let signature value = show_ty (TFnPtr value) in
  `Assoc ["source_template_parameters", `String (show_generic_params witness.template_parameters);
    "source_template_arguments", `String (show_generic_args witness.template_arguments);
    "source_free_parameters", `List (List.map (fun value -> `String (show_region_param value)) witness.free_parameters);
    "source_body_region_bound", `Int witness.body_regions;
    "instantiated_original_field", `String (signature witness.original);
    "instantiated_object_family", `String (signature witness.exposed);
    "actual_stored_signature", `String (signature witness.actual);
    "actual_source_object_argument", `String (show_region witness.object_argument);
    "complete_reconstructed_signature", `String (signature witness.reconstructed);
    "complete_stored_field_signature_replays", `Bool (replay witness);
    "native_cast_loan_aliasing_and_method_semantics_discharged", `Bool false]
