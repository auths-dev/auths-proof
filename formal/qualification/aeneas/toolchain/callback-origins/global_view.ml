(* Source global instantiation. This preserves the actual constant expression,
   kind and source metadata; it never supplies a replacement value. Global
   initializer function references must enter the ordinary source closure. *)
open Charon
open Types
open LlbcAst

type t = {
  declaration : global_decl;
  arguments : Region_shape.factorization;
  call_arguments : generic_args;
  ty : ty;
  value : constant_expr;
  inherited_requirements : generic_params;
  opaque_values : string list;
  source_resolution : Static_targets.global_resolution;
  self_evidence : trait_ref option;
}

let factored_self (original : generic_args) (pattern : generic_args) evidence =
  if List.length original.trait_refs <> List.length pattern.trait_refs then
    invalid_arg "factored global dictionary arity changed";
  let candidates = List.combine original.trait_refs pattern.trait_refs
    |> List.filter_map (fun (before, after) -> if before = evidence then Some after else None)
    |> List.sort_uniq compare_trait_ref in
  match candidates with
  | [actual] -> actual
  | _ -> invalid_arg "factored global Self no longer identifies its exact provided source dictionary"

let create crate (source_resolution : Static_targets.global_resolution) =
  let reference = source_resolution.global_reference in
  if source_resolution.global_obligations <> [] then
    invalid_arg "a source global view requires strictly checked declared predicates";
  let declaration = match GlobalDeclId.Map.find_opt reference.id crate.global_decls with
    | Some declaration -> declaration
    | None -> invalid_arg "a referenced source global declaration is absent" in
  let arguments = Region_shape.factor reference.generics in
  let call_arguments = arguments.pattern in
  let self_evidence = Option.map (factored_self reference.generics call_arguments)
    source_resolution.global_self_evidence in
  Static_targets.require_argument_arity declaration.generics call_arguments;
  let preliminary = Substitute.make_subst_from_generics declaration.generics call_arguments Self in
  let tr_self = match self_evidence, declaration.src with
    | Some reference, _ -> reference.kind
    | None, TraitImplItem (owner, _, _, _) -> TraitImpl
        (Substitute.st_substitute_visitor#visit_trait_impl_ref preliminary owner)
    | None, TraitDeclItem _ ->
        invalid_arg "a trait-default global needs its actual source Self dictionary"
    | _ -> Self in
  let substitution = { preliminary with tr_self } in
  let ty = Substitute.ty_substitute substitution declaration.ty in
  let value = Substitute.st_substitute_visitor#visit_constant_expr substitution declaration.value in
  let inherited_requirements = Substitute.predicates_substitute substitution declaration.generics in
  let opaque_values = ref [] in
  let scope = object
    inherit [_] iter_statement
    method! visit_region _ = function
      | RBody _ -> invalid_arg "a source global value has no existential body-region binder"
      | _ -> ()
    method! visit_COpaque _ reason =
      if Instance_view.is_auths declaration.item_meta.name then
        invalid_arg "an Auths source global requires its actual constant expression";
      opaque_values := reason :: !opaque_values
  end in
  scope#visit_ty () ty;
  scope#visit_constant_expr () value;
  let closed_scope = new Region_scope.statement_check arguments.parameters in
  closed_scope#visit_ty [] ty;
  closed_scope#visit_constant_expr [] value;
  closed_scope#visit_generic_params [] inherited_requirements;
  { declaration; arguments; call_arguments; ty; value; inherited_requirements;
    opaque_values = List.rev !opaque_values; source_resolution; self_evidence }
