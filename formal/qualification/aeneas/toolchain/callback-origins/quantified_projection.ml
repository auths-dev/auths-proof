(* Project the actual source associated type of a universally quantified
   dictionary. Its representative implementation arguments are not that
   universal instance. Open the complete predicate, instantiate the source,
   then close the result under exactly the original lifetime binder. *)
open Charon
open Types
open LlbcAst

type origin =
  | Implementation of trait_impl_ref * Quantified_dictionary.witness
  | FunctionItem of Callable_instance.t

type t = {
  reference : trait_ref;
  type_id : assoc_type_id;
  fresh_arguments : region list;
  origin : origin;
  representative_value : trait_assoc_ty_impl;
  output : ty region_binder;
  input_requirement : (ty region_binder * ty region_binder) option;
  associated_requirements : generic_params list;
  function_requirements : generic_params option;
}

let close_type parameters fresh opened =
  if List.length parameters <> List.length fresh then
    invalid_arg "a quantified output has inconsistent lifetime binder arity";
  let pairs = List.combine fresh (List.map (fun (parameter : region_param) ->
    RVar (Bound (0, parameter.index))) parameters) in
  let under = Substitute.ty_substitute Substitute.move_under_binder_subst opened in
  let substitution = { Substitute.empty_subst with r_subst = (fun variable ->
    let region = RVar variable in
    match List.assoc_opt region pairs with Some bound -> bound | None -> region) } in
  let closed = { binder_regions = parameters; binder_value = Substitute.ty_substitute substitution under } in
  let reopened = Callable_instance.open_binder Substitute.st_substitute_visitor#visit_ty fresh closed in
  if reopened <> opened then
    invalid_arg "closing a universal output did not reconstruct its complete opened source type";
  closed

let source_value (impl : trait_impl) (target : trait_impl_ref) type_id =
  let body = match AssocTypeId.Map.find_opt type_id impl.types with
    | Some body -> body
    | None -> invalid_arg "a quantified projection has no actual source associated type" in
  let parameters = body.binder_params in
  if parameters.regions <> [] || parameters.types <> [] || parameters.const_generics <> [] ||
     parameters.trait_clauses <> [] then
    invalid_arg "a quantified associated projection needs explicit associated generic arguments";
  let substitution = Substitute.make_subst_from_generics impl.generics target.generics (TraitImpl target) in
  let requirements = Substitute.predicates_substitute
    (Substitute.subst_remove_binder_zero Substitute.error_sb_subst)
    (Substitute.predicates_substitute substitution parameters) in
  let body = Substitute.st_substitute_visitor#visit_binder
    Substitute.st_substitute_visitor#visit_trait_assoc_ty_impl substitution body in
  Substitute.apply_args_to_binder TypesUtils.empty_generic_args
    Substitute.st_substitute_visitor#visit_trait_assoc_ty_impl body, requirements

let require_invariant fresh visit value =
  let visitor = object
    inherit [_] iter_ty
    method! visit_region _ region =
      if List.mem region fresh then
        invalid_arg "quantified projection prerequisites need an explicit varying-condition proof"
  end in
  visit visitor value

let derive crate (reference : trait_ref) type_id =
  let predicate = reference.trait_decl_ref in
  if predicate.binder_regions = [] then
    invalid_arg "a universal associated projection requires its original nonempty source binder";
  match reference.kind with
  | TraitImpl target ->
      let impl = match TraitImplId.Map.find_opt target.id crate.trait_impls with
        | Some impl -> impl | None -> invalid_arg "a projected source implementation is absent" in
      let family = Quantified_dictionary.recover impl.generics impl.impl_trait target.generics predicate in
      let generalized = { target with generics = family.family.reconstructed_arguments } in
      let value, requirements = source_value impl generalized type_id in
      require_invariant family.fresh_arguments (fun visitor value -> visitor#visit_generic_params () value) requirements;
      let representative_value, _ = source_value impl target type_id in
      { reference; type_id; fresh_arguments = family.fresh_arguments;
        origin = Implementation (target, family); representative_value;
        output = close_type predicate.binder_regions family.fresh_arguments value.value;
        input_requirement = None; associated_requirements = [requirements]; function_requirements = None }
  | BuiltinOrAuto (BuiltinFnOnce, _, types) ->
      let trait = match TraitDeclId.Map.find_opt predicate.binder_value.id crate.trait_decls with
        | Some trait -> trait | None -> invalid_arg "a projected source callable trait is absent" in
      let labels = List.filter_map (function PeIdent (name, _) -> Some name | _ -> None) trait.item_meta.name in
      if labels <> ["core"; "ops"; "function"; "FnOnce"] ||
         GAstUtils.get_assoc_type_name crate trait.def_id type_id <> "Output" then
        invalid_arg "a source function output is attached to an unexpected trait/item identity";
      let fresh = Quantified_dictionary.fresh_regions predicate.binder_value
        TypesUtils.empty_generic_args predicate in
      let opened = Quantified_dictionary.open_predicate fresh predicate in
      let definition, actual_tuple = match opened.generics.types with
        | [TFnDef definition; actual_tuple] -> definition, actual_tuple
        | _ -> invalid_arg "a universal builtin callable projection needs an actual source function item" in
      let plan = Callable_instance.create crate definition actual_tuple in
      let requirements = Callable_instance.requirements crate plan in
      require_invariant fresh (fun visitor value -> visitor#visit_generic_params () value) requirements;
      List.iter (require_invariant fresh (fun visitor value -> visitor#visit_trait_ref () value))
        plan.target.generics.trait_refs;
      let representative_value = match AssocTypeId.Map.find_opt type_id types with
        | Some value -> value | None -> invalid_arg "the original callable output metadata is absent" in
      let close = close_type predicate.binder_regions fresh in
      { reference; type_id; fresh_arguments = fresh; origin = FunctionItem plan; representative_value;
        output = close plan.output;
        input_requirement = Some (close plan.input_tuple, close plan.actual_tuple);
        associated_requirements = []; function_requirements = Some requirements }
  | _ -> invalid_arg "a universal projection lacks a concrete source implementation or function item"

let replay crate witness =
  try derive crate witness.reference witness.type_id = witness
  with Invalid_argument _ | Not_found -> false

let create crate reference type_id =
  let witness = derive crate reference type_id in
  if not (replay crate witness) then invalid_arg "a universal source projection did not replay";
  witness

let report crate witness =
  let open Diagnostic in
  let text value = `String value in
  `Assoc ["source_reference", text (show_trait_ref witness.reference);
    "associated_type_id", `Int (AssocTypeId.to_int witness.type_id);
    "fresh_lifetime_arguments", `List (List.map (fun value -> text (show_region value)) witness.fresh_arguments);
    "representative_associated_value", text (show_trait_assoc_ty_impl witness.representative_value);
    "derived_output", text (show_ty witness.output.binder_value);
    "original_output_binder", `List (List.map (fun value -> text (show_region_param value)) witness.output.binder_regions);
    "source_input_requirement", (match witness.input_requirement with
      | None -> `Null
      | Some (expected, actual) -> `Assoc [
          "binder", `List (List.map (fun parameter -> text (show_region_param parameter)) expected.binder_regions);
          "expected", text (show_ty expected.binder_value);
          "actual", text (show_ty actual.binder_value);
          "equal", `Bool (expected = actual)]);
    "source_derivation_replays", `Bool (replay crate witness);
    "declared_function_requirements", (match witness.function_requirements with
      | None -> `Null | Some requirements -> text (show_generic_params requirements));
    "associated_requirements", `List (List.map (fun value -> text (show_generic_params value)) witness.associated_requirements);
    "origin", (match witness.origin with
      | FunctionItem plan -> Callable_instance.report crate plan
      | Implementation (target, family) -> `Assoc [
          "implementation", `Int (TraitImplId.to_int target.id);
          "representative_arguments", text (show_generic_args target.generics);
          "universal_arguments", text (show_generic_args family.family.reconstructed_arguments);
          "fixed_actual", text (show_trait_decl_ref family.fixed_actual.binder_value)]);
    "source_adequacy_discharged", `Bool false ]
