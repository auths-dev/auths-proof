(* Source ADT instantiation for the next whole-program closure stage. Declared
   dictionary/type requirements must hold before body regions become rigid
   instance parameters. Layouts remain source metadata, not a proved layout of
   the instantiated type. This module does not emit a type declaration. *)
open Charon
open Types
open LlbcAst

type resolution = {
  original_reference : type_decl_ref;
  reference : type_decl_ref;
  declaration : type_decl;
  requirements : generic_params;
  self_evidence : trait_ref option;
  obligations : Static_targets.predicate_obligation list;
  type_requirements : Static_targets.type_requirement list;
  associated_requirements : generic_params list;
  impl_reconstructions : Static_targets.impl_reconstruction list;
  metadata_reconstructions : Static_targets.metadata_reconstruction list;
  implementation_requirements : Static_targets.implementation_requirement list;
  quantified_families : Static_targets.quantified_family list;
  quantified_instances : Static_targets.quantified_instance list;
  parent_quantifications : Static_targets.parent_quantification list;
  quantified_projections : Quantified_projection.t list;
  outlives_evidence : Static_targets.outlives_evidence list;
}

type field_requirements = {
  associated : generic_params list;
  type_equalities : Static_targets.type_requirement list;
  implementations : Static_targets.implementation_requirement list;
  impl_reconstructions : Static_targets.impl_reconstruction list;
  metadata_reconstructions : Static_targets.metadata_reconstruction list;
  quantified_families : Static_targets.quantified_family list;
  quantified_instances : Static_targets.quantified_instance list;
  parent_quantifications : Static_targets.parent_quantification list;
  quantified_projections : Quantified_projection.t list;
  outlives_evidence : Static_targets.outlives_evidence list;
}

type t = {
  source_resolution : resolution;
  arguments : Region_shape.factorization;
  call_arguments : generic_args;
  self_evidence : trait_ref option;
  kind : type_decl_kind;
  ptr_metadata : ptr_metadata;
  inherited_requirements : generic_params;
  field_requirements : field_requirements;
  ordinary_opaque_contract_required : bool;
  union_representation_contract_required : bool;
}

let source_substitution (declaration : type_decl) (arguments : generic_args) (self_evidence : trait_ref option) =
  Static_targets.require_argument_arity declaration.generics arguments;
  let preliminary = Substitute.make_subst_from_generics declaration.generics arguments Self in
  let tr_self = match self_evidence, declaration.src with
    | Some evidence, _ -> evidence.kind
    | None, TraitImplItem (owner, _, _, _) -> TraitImpl
        (Substitute.st_substitute_visitor#visit_trait_impl_ref preliminary owner)
    | None, TraitDeclItem _ ->
        invalid_arg "a source type in a trait default needs its explicit actual Self dictionary"
    | _ -> Self in
  { preliminary with tr_self }

let resolve ?(candidate_only = false) crate (reference : type_decl_ref) =
  let original_reference = reference in
  let visitor = new Static_targets.normalize ~candidate_only crate in
  let reference = visitor#visit_type_decl_ref 0 reference in
  let id = match reference.id with
    | TAdtId id -> id
    | _ -> invalid_arg "a source type view requires an actual ADT declaration" in
  let declaration = match TypeDeclId.Map.find_opt id crate.type_decls with
    | Some declaration -> declaration
    | None -> invalid_arg "a source ADT declaration is absent" in
  Static_targets.require_argument_arity declaration.generics reference.generics;
  let preliminary = Substitute.make_subst_from_generics declaration.generics reference.generics Self in
  let self_evidence = match declaration.src with
    | TraitDeclItem (owner, _) ->
        let expected = visitor#visit_trait_decl_ref 0
          (Substitute.trait_decl_ref_substitute preliminary owner) in
        Some (Static_targets.source_self_evidence
          (Substitute.trait_decl_ref_to_poly_trait_decl_ref expected) reference.generics.trait_refs)
    | _ -> None in
  let substitution = source_substitution declaration reference.generics self_evidence in
  let requirements = Substitute.predicates_substitute substitution declaration.generics in
  List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
    let expected = visitor#visit_region_binder visitor#visit_trait_decl_ref 0 clause.trait in
    visitor#require_predicate "selected type declared trait bound" expected evidence.trait_decl_ref)
    requirements.trait_clauses reference.generics.trait_refs;
  visitor#check_type_requirements requirements.trait_type_constraints;
  visitor#check_requirements;
  { original_reference; reference; declaration; requirements; self_evidence;
    obligations = visitor#obligations; type_requirements = visitor#type_requirements;
    associated_requirements = visitor#associated_requirements;
    impl_reconstructions = visitor#impl_reconstructions;
    metadata_reconstructions = visitor#metadata_reconstructions;
    implementation_requirements = visitor#implementation_requirements;
    quantified_families = visitor#quantified_families;
    quantified_instances = visitor#quantified_instances;
    parent_quantifications = visitor#parent_quantifications;
    quantified_projections = visitor#quantified_projections;
    outlives_evidence = visitor#outlives_evidence }

let create crate (source_resolution : resolution) =
  (* Candidate-only traversal is insufficient evidence for a declaration view.
     Re-resolve the original complete reference strictly before factorization. *)
  let strict = resolve crate source_resolution.original_reference in
  if strict <> source_resolution || strict.obligations <> [] then
    invalid_arg "a source ADT view requires its complete strictly replayed declared bounds";
  let arguments, call_arguments, self_evidence =
    Instance_view.factor_context strict.reference.generics strict.self_evidence in
  let substitution = source_substitution strict.declaration call_arguments self_evidence in
  let normalizer = new Static_targets.normalize crate in
  let mapper = object
    inherit [_] map_type_decl
    method! visit_ty _ ty = normalizer#visit_ty 0 (Substitute.ty_substitute substitution ty)
  end in
  let kind = mapper#visit_type_decl_kind () strict.declaration.kind in
  let ptr_metadata = match strict.declaration.ptr_metadata with
    | NoMetadata -> NoMetadata
    | Length -> Length
    | VTable reference -> VTable
        (normalizer#visit_type_decl_ref 0
          (Substitute.st_substitute_visitor#visit_type_decl_ref substitution reference))
    | InheritFrom ty -> InheritFrom (normalizer#visit_ty 0 (Substitute.ty_substitute substitution ty)) in
  normalizer#check_requirements;
  if normalizer#obligations <> [] then
    invalid_arg "a source type field retained an unresolved declared predicate";
  let field_requirements = {
    associated = normalizer#associated_requirements;
    type_equalities = normalizer#type_requirements;
    implementations = normalizer#implementation_requirements;
    impl_reconstructions = normalizer#impl_reconstructions;
    metadata_reconstructions = normalizer#metadata_reconstructions;
    quantified_families = normalizer#quantified_families;
    quantified_instances = normalizer#quantified_instances;
    parent_quantifications = normalizer#parent_quantifications;
    quantified_projections = normalizer#quantified_projections;
    outlives_evidence = normalizer#outlives_evidence } in
  let ordinary_opaque_contract_required = match kind with
    | TDeclError message -> invalid_arg ("source type extraction failed: " ^ message)
    | Opaque when Instance_view.is_auths strict.declaration.item_meta.name ->
        invalid_arg "an Auths source type cannot be replaced by an opaque carrier"
    | Opaque -> true
    | _ -> false in
  let scope = new Region_scope.declaration_check arguments.parameters in
  scope#visit_type_decl_kind [] kind;
  scope#visit_ptr_metadata [] ptr_metadata;
  let inherited_requirements = Substitute.predicates_substitute substitution strict.declaration.generics in
  scope#visit_generic_params [] inherited_requirements;
  { source_resolution; arguments; call_arguments; self_evidence; kind; ptr_metadata;
    inherited_requirements; field_requirements; ordinary_opaque_contract_required;
    union_representation_contract_required = (match kind with Union _ -> true | _ -> false) }

let resolution_report crate (resolution : resolution) =
  let open Diagnostic in
  let text value = `String value in
  `Assoc ["source_type_id", `Int (TypeDeclId.to_int resolution.declaration.def_id);
    "source_name", text (Print.name_to_string (Print.crate_to_fmt_env crate) resolution.declaration.item_meta.name);
    "original_arguments", text (show_generic_args resolution.original_reference.generics);
    "resolved_arguments", text (show_generic_args resolution.reference.generics);
    "declared_requirements", text (show_generic_params resolution.requirements);
    "associated_outlives_evidence", `List (List.map Static_targets.outlives_report resolution.outlives_evidence);
    "self_evidence", (match resolution.self_evidence with None -> `Null | Some value -> text (show_trait_ref value));
    "quantified_output_projections", `List (List.map (Quantified_projection.report crate) resolution.quantified_projections);
    "source_type_closure_emitted", `Bool false;
    "source_type_borrow_adequacy_discharged", `Bool false ]

let field_report crate (requirements : field_requirements) =
  let open Diagnostic in
  let text value = `String value in
  `Assoc [
    "associated_outlives_evidence", `List (List.map Static_targets.outlives_report requirements.outlives_evidence);
    "implementation_reconstructions", `List (List.map (fun (entry : Static_targets.impl_reconstruction) ->
      let impl = TraitImplId.Map.find entry.implementation crate.trait_impls in
      `Assoc ["implementation", `Int (TraitImplId.to_int entry.implementation);
        "original_arguments", text (show_generic_args entry.witness.original_arguments);
        "reconstructed_arguments", text (show_generic_args entry.witness.reconstructed_arguments);
        "declared_predicate", text (show_trait_decl_ref entry.witness.source_predicate);
        "replays", `Bool (Impl_regions.replay_predicate impl.generics impl.impl_trait entry.witness)]) requirements.impl_reconstructions);
    "metadata_reconstructions", `List (List.map (fun (entry : Static_targets.metadata_reconstruction) ->
      `Assoc ["implementation", `Int (TraitImplId.to_int entry.implementation);
        "original", text (show_trait_decl_ref entry.witness.original.binder_value);
        "source", text (show_trait_decl_ref entry.witness.source.binder_value);
        "completed", text (show_trait_decl_ref entry.witness.completed.binder_value);
        "replays", `Bool (Predicate_metadata.replay entry.witness)]) requirements.metadata_reconstructions);
    "quantified_families", `List (List.map (fun (entry : Static_targets.quantified_family) ->
      let impl = TraitImplId.Map.find entry.implementation crate.trait_impls in
      `Assoc ["implementation", `Int (TraitImplId.to_int entry.implementation);
        "representative_arguments", text (show_generic_args entry.witness.representative_arguments);
        "universal_arguments", text (show_generic_args entry.witness.family.reconstructed_arguments);
        "binder", `List (List.map (fun value -> text (show_region_param value)) entry.witness.expected.binder_regions);
        "expected", text (show_trait_decl_ref entry.witness.expected.binder_value);
        "fixed_actual", text (show_trait_decl_ref entry.witness.fixed_actual.binder_value);
        "replays", `Bool (Quantified_dictionary.replay impl.generics impl.impl_trait entry.witness)]) requirements.quantified_families);
    "quantified_instances", `List (List.map (fun (entry : Static_targets.quantified_instance) ->
      `Assoc ["implementation", `Int (TraitImplId.to_int entry.family.implementation);
        "arguments", text (show_generic_args entry.instance.reconstructed_arguments);
        "predicate", text (show_trait_decl_ref entry.instance.reconstructed_predicate)]) requirements.quantified_instances);
    "parent_derivations", `List (List.map (fun (entry : Static_targets.parent_quantification) ->
      `Assoc ["parent", text (show_trait_ref entry.parent);
        "clause_id", `Int (TraitClauseId.to_int entry.clause_id);
        "original_selected", text (show_trait_ref entry.original_selected);
        "binder", `List (List.map (fun value -> text (show_region_param value)) entry.declared_parent.binder_regions);
        "declared_parent", text (show_trait_decl_ref entry.declared_parent.binder_value)]) requirements.parent_quantifications) ]
