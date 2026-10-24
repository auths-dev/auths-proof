(* Resolve statically supplied trait dictionaries in the original LLBC. Missing
   region arguments require complete source evidence; dynamic targets are never guessed. This
   module returns source references; it does not emit new declarations. *)
open Charon
open Types
open LlbcAst
open Diagnostic

module Subst = Substitute
module References = Map.Make (struct
  type t = trait_ref
  let compare = compare_trait_ref
end)

type dispatch = Direct | Implementation | Default | NoopDestruct | FnDefCall of Callable_instance.t
  | DynamicMethod of Dynamic_method.t
type predicate_obligation = {
  boundary : string;
  expected : trait_decl_ref region_binder;
  actual : trait_decl_ref region_binder;
}
type type_requirement = {
  source : trait_type_constraint region_binder;
  left : ty;
  right : ty;
}
type impl_reconstruction = {
  implementation : trait_impl_id;
  witness : Impl_regions.predicate_witness;
  previous_predicate : trait_decl_ref region_binder;
  source_predicate : trait_decl_ref region_binder;
}
type metadata_reconstruction = {
  implementation : trait_impl_id;
  witness : Predicate_metadata.witness;
}
type quantified_family = {
  implementation : trait_impl_id;
  witness : Quantified_dictionary.witness;
}
type quantified_instance = {
  family : quantified_family;
  instance : Impl_regions.predicate_witness;
}
type implementation_requirement = {
  source_implementation : trait_impl_id;
  implementation_arguments : generic_args;
  requirements : generic_params;
}
type parent_quantification = {
  parent : trait_ref;
  clause_id : trait_clause_id;
  original_selected : trait_ref;
  declared_parent : trait_decl_ref region_binder;
}
type outlives_evidence =
  | ReflexiveRegion of (region * region) region_binder
  | StaticRegion of (region * region) region_binder
  | ClosedSourceType of (ty * region) region_binder * Closed_type.t

let known_outlives_region binder = function
  | RStatic -> true
  | RVar (Free id) -> RegionId.to_int id >= 0
  | RVar (Bound (0, id)) -> List.exists (fun (parameter : region_param) ->
      parameter.index = id) binder
  | RVar (Bound _) | RErased | RBody _ -> false

let replay_outlives ~declarations ~normalize = function
  | ReflexiveRegion source ->
      let left, right = source.binder_value in
      known_outlives_region source.binder_regions left && left = right
  | StaticRegion source ->
      let left, right = source.binder_value in
      left = RStatic && known_outlives_region source.binder_regions right
  | ClosedSourceType (source, witness) ->
      let original, target = source.binder_value in
      known_outlives_region source.binder_regions target && original = witness.original &&
      Closed_type.replay ~declarations ~normalize witness
(* A source type may contain a projection outside a function reference, or in
   a destructor pointer whose dispatch is still pending. Retain the complete
   normalization ledger without pretending that selecting a type's dictionary
   establishes the destructor's behavior. *)
type normalization_evidence = {
  predicate_obligations : predicate_obligation list;
  associated_conditions : generic_params list;
  type_equalities : type_requirement list;
  implementation_conditions : implementation_requirement list;
  implementation_reconstructions : impl_reconstruction list;
  metadata_completions : metadata_reconstruction list;
  universal_families : quantified_family list;
  universal_instances : quantified_instance list;
  parent_derivations : parent_quantification list;
  output_projections : Quantified_projection.t list;
  lifetime_evidence : outlives_evidence list;
}
type resolved = {
  pointer : fn_ptr;
  dispatch : dispatch;
  self_evidence : trait_ref option;
  obligations : predicate_obligation list;
  associated_requirements : generic_params list;
  type_requirements : type_requirement list;
  impl_reconstructions : impl_reconstruction list;
  metadata_reconstructions : metadata_reconstruction list;
  function_requirements : generic_params option;
  quantified_families : quantified_family list;
  quantified_instances : quantified_instance list;
  implementation_requirements : implementation_requirement list;
  parent_quantifications : parent_quantification list;
  argument_requirements : (ty * ty) list;
  quantified_projections : Quantified_projection.t list;
  outlives_evidence : outlives_evidence list;
}
type global_resolution = {
  global_reference : global_decl_ref;
  global_requirements : generic_params;
  global_obligations : predicate_obligation list;
  global_type_requirements : type_requirement list;
  global_associated_requirements : generic_params list;
  global_impl_reconstructions : impl_reconstruction list;
  global_metadata_reconstructions : metadata_reconstruction list;
  global_quantified_families : quantified_family list;
  global_quantified_instances : quantified_instance list;
  global_implementation_requirements : implementation_requirement list;
  global_self_evidence : trait_ref option;
  global_parent_quantifications : parent_quantification list;
  global_quantified_projections : Quantified_projection.t list;
  global_outlives_evidence : outlives_evidence list;
}

let compare_predicates ~candidate_only boundary expected actual =
  if expected = actual then None else (
    (* Diagnostic candidate traversal never counts this as agreement. A shape
       comparison can identify a regional discrepancy, but cannot discharge
       aliasing, outlives, erasure or higher-ranked instantiation obligations. *)
    let shape (predicate : trait_decl_ref region_binder) =
      let value = predicate.binder_value in
      (* Pinned substitution erasure only replaces RVar; this diagnostic must
         classify RBody and RStatic as well. The visitor is local to shape
         comparison and its result never becomes an instantiation argument. *)
      let visitor = object
        inherit [_] map_ty
        method! visit_region _ _ = RErased
      end in
      value.id, visitor#visit_generic_args () value.generics in
    if not candidate_only || shape expected <> shape actual then
      invalid_arg (boundary ^ ": complete trait predicates differ\nexpected=" ^
        show_trait_decl_ref expected.binder_value ^ "\nactual=" ^ show_trait_decl_ref actual.binder_value);
    Some { boundary; expected; actual }
  )

let without_region_binder visit (binder : 'a region_binder) : 'a =
  if binder.binder_regions <> [] then
    invalid_arg "a higher-ranked trait reference requires explicit instantiation";
  visit (Subst.subst_remove_binder_zero Subst.error_sb_subst) binder.binder_value

let implementation crate (reference : trait_impl_ref) =
  match TraitImplId.Map.find_opt reference.id crate.trait_impls with
  | Some declaration -> declaration
  | None -> invalid_arg "static trait implementation declaration is absent"

let declaration crate id =
  match TraitDeclId.Map.find_opt id crate.trait_decls with
  | Some declaration -> declaration
  | None -> invalid_arg "static trait declaration is absent"

let require_argument_arity (parameters : generic_params) (arguments : generic_args) =
  List.iter (fun (label, expected, actual) ->
    if expected <> actual then invalid_arg (Printf.sprintf
      "selected source %s argument count: expected %d, got %d" label expected actual)) [
    "region", List.length parameters.regions, List.length arguments.regions;
    "type", List.length parameters.types, List.length arguments.types;
    "const", List.length parameters.const_generics, List.length arguments.const_generics;
    "trait", List.length parameters.trait_clauses, List.length arguments.trait_refs ]

let source_self_evidence expected references =
  let candidates = List.filter (fun (reference : trait_ref) ->
    reference.trait_decl_ref = expected &&
    (match reference.kind with TraitImpl _ -> true | _ -> false)) references
    |> List.sort_uniq compare_trait_ref in
  match candidates with
  | [reference] -> reference
  | [] -> invalid_arg "source Self requires an explicit matching concrete dictionary"
  | _ -> invalid_arg "source Self has ambiguous concrete implementation evidence"

let substitution (impl : trait_impl) (reference : trait_impl_ref) =
  require_argument_arity impl.generics reference.generics;
  Subst.make_subst_from_generics impl.generics reference.generics (TraitImpl reference)

let select_parent (clauses : trait_param list) references clause_id : trait_ref =
  if List.length clauses <> List.length references then
    invalid_arg "parent clause declarations and implementation evidence disagree";
  let indexed = List.combine clauses references in
  match List.filter (fun ((clause : trait_param), _) -> clause.clause_id = clause_id) indexed with
  | [(_, reference)] -> reference
  | [] -> invalid_arg "parent clause identifier has no implementation evidence"
  | _ -> invalid_arg "parent clause identifier is ambiguous"

let parent_reference crate (parent : trait_ref) clause_id : trait_ref =
  let trait = declaration crate parent.trait_decl_ref.binder_value.id in
  let references = match parent.kind with
    | TraitImpl reference ->
        let impl = implementation crate reference in
        List.map (Subst.trait_ref_substitute (substitution impl reference)) impl.implied_trait_refs
    | BuiltinOrAuto (_, parents, _) -> parents
    | _ -> invalid_arg "a parent clause has no statically resolved dictionary"
  in
  select_parent trait.implied_clauses references clause_id

let quantified_parent_predicate parameters (parent : trait_decl_ref region_binder) (clause : trait_param) =
  let no_self = object
    inherit [_] iter_ty
    method! visit_Self _ = invalid_arg "a quantified parent projection requires explicit source Self-family substitution"
  end in
  no_self#visit_region_binder no_self#visit_trait_decl_ref () clause.trait;
  let substitution = Subst.make_subst_from_generics parameters parent.binder_value.generics Self in
  let declared = Subst.st_substitute_visitor#visit_region_binder
    Subst.st_substitute_visitor#visit_trait_decl_ref substitution clause.trait in
  let value = without_region_binder Subst.st_substitute_visitor#visit_trait_decl_ref declared in
  { binder_regions = parent.binder_regions; binder_value = value }

let require_no_associated_arguments (parameters : generic_params) =
  if parameters.regions <> [] || parameters.types <> [] || parameters.const_generics <> [] ||
     parameters.trait_clauses <> [] then
    invalid_arg "associated-item generic arguments require explicit source instantiation"

let unbind_associated_requirements substitution (parameters : generic_params) =
  require_no_associated_arguments parameters;
  let parameters = Subst.predicates_substitute substitution parameters in
  Subst.predicates_substitute
    (Subst.subst_remove_binder_zero Subst.error_sb_subst) parameters

let associated_reference crate (parent : trait_ref) type_id clause_id :
    trait_ref * generic_params list * trait_decl_ref region_binder =
  let trait = declaration crate parent.trait_decl_ref.binder_value.id in
  let source_type = match AssocTypeId.Map.find_opt type_id trait.types with
    | Some declaration -> declaration
    | None -> invalid_arg "associated-item clause has no declared source type" in
  let parent_predicate = without_region_binder
    Subst.st_substitute_visitor#visit_trait_decl_ref parent.trait_decl_ref in
  let source_substitution = Subst.make_subst_from_generics trait.generics
    parent_predicate.generics parent.kind in
  let source_requirements = unbind_associated_requirements source_substitution source_type.binder_params in
  let value, implementation_requirements = match parent.kind with
    | TraitImpl reference ->
        let impl = implementation crate reference in
        let body = match AssocTypeId.Map.find_opt type_id impl.types with
          | Some body -> body
          | None -> invalid_arg "associated-item clause has no source implementation" in
        let requirements = unbind_associated_requirements
          (substitution impl reference) body.binder_params in
        let bound = Subst.st_substitute_visitor#visit_binder
          Subst.st_substitute_visitor#visit_trait_assoc_ty_impl
          (substitution impl reference) body in
        Subst.apply_args_to_binder TypesUtils.empty_generic_args
          Subst.st_substitute_visitor#visit_trait_assoc_ty_impl bound, requirements
    | BuiltinOrAuto (_, _, types) ->
        (match AssocTypeId.Map.find_opt type_id types with
         | Some body -> body, TypesUtils.empty_generic_params
         | None -> invalid_arg "builtin associated-item evidence is absent")
    | _ -> invalid_arg "associated-item clause has no statically resolved source dictionary" in
  let selected = select_parent source_type.binder_value.implied_clauses value.implied_trait_refs clause_id in
  let clause = match List.filter (fun (clause : trait_param) -> clause.clause_id = clause_id)
      source_type.binder_value.implied_clauses with
    | [clause] -> clause
    | _ -> invalid_arg "associated bound has no unique declared predicate" in
  let declared = Subst.st_substitute_visitor#visit_region_binder
    Subst.st_substitute_visitor#visit_trait_decl_ref source_substitution clause.trait in
  let declared = Subst.st_substitute_visitor#visit_region_binder
    Subst.st_substitute_visitor#visit_trait_decl_ref
    (Subst.subst_remove_binder_zero Subst.error_sb_subst) declared in
  selected, [source_requirements; implementation_requirements], declared

let method_self_evidence ~default_lookup owner_id trait_id method_id reference = function
  | TraitImplItem (owner, declared, AssocIdMethod item, _)
      when not default_lookup && owner.id = owner_id && declared.id = trait_id && item = method_id ->
      (* Self is reconstructed from this source implementation and its full
         function arguments, rather than a separately scoped call predicate. *)
      None
  | TraitDeclItem (declared, AssocIdMethod item)
      when declared.id = trait_id && item = method_id -> Some reference
  | _ -> invalid_arg "selected method source owner, trait or associated-item identity disagrees with dispatch"

(* Associated-type and parent-clause normalization uses actual declarations.
   Retaining ordinary ADTs and their region arguments avoids Hax's whole-type
   lifetime erasure. The depth limit refuses malformed cyclic metadata; it is
   a construction resource limit, never a proof or a shipping input bound. *)
class ['self] normalize ?(candidate_only = false) crate = object (self : 'self)
  inherit [_] map_ty as super
  val mutable obligations : predicate_obligation list = []
  method obligations = List.rev obligations
  val mutable pending_requirements : generic_params list = []
  val mutable associated_requirements : generic_params list = []
  val mutable type_requirements : type_requirement list = []
  val mutable impl_reconstructions : impl_reconstruction list = []
  val mutable metadata_reconstructions : metadata_reconstruction list = []
  (* This cache belongs to one resolution, one immutable crate and one fixed
     strict/candidate mode. Keys are the complete reference AST, including
     regions, binders and nested evidence. A hit reuses facts already retained
     by this visitor; it never assumes an in-progress recursive fact. *)
  val mutable normalized_references : trait_ref References.t = References.empty
  val mutable active_references : trait_ref list = []
  val mutable quantified_families : quantified_family list = []
  val mutable quantified_instances : quantified_instance list = []
  val mutable implementation_requirements : implementation_requirement list = []
  val mutable parent_quantifications : parent_quantification list = []
  val mutable quantified_projections : Quantified_projection.t list = []
  val mutable outlives_evidence : outlives_evidence list = []
  method associated_requirements = List.rev associated_requirements
  method type_requirements = List.rev type_requirements
  method impl_reconstructions = List.rev impl_reconstructions
  method metadata_reconstructions = List.rev metadata_reconstructions
  method quantified_families = List.rev quantified_families
  method quantified_instances = List.rev quantified_instances
  method implementation_requirements = List.rev implementation_requirements
  method parent_quantifications = List.rev parent_quantifications
  method quantified_projections = List.rev quantified_projections
  method outlives_evidence = List.rev outlives_evidence

  method private check_implementation_requirements (impl : trait_impl) (target : trait_impl_ref) =
    let requirements = Subst.predicates_substitute (substitution impl target) impl.generics in
    List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
      let expected = self#visit_region_binder self#visit_trait_decl_ref 0 clause.trait in
      self#require_predicate "selected implementation declared trait bound" expected evidence.trait_decl_ref)
      requirements.trait_clauses target.generics.trait_refs;
    self#check_type_requirements requirements.trait_type_constraints;
    implementation_requirements <- { source_implementation = target.id;
      implementation_arguments = target.generics; requirements } :: implementation_requirements

  method private source_family (target : trait_impl_ref) expected =
    let impl = implementation crate target in
    let witness = try Quantified_dictionary.recover impl.generics impl.impl_trait target.generics expected
      with Invalid_argument message -> invalid_arg (message ^
        "\nsource_implementation=" ^ Print.name_to_string (Print.crate_to_fmt_env crate) impl.item_meta.name ^
        "\nimplementation_parameters=" ^ show_generic_params impl.generics ^
        "\nrepresentative_arguments=" ^ show_generic_args target.generics ^
        "\nexpected_predicate=" ^ show_trait_decl_ref expected.binder_value) in
    let family = { implementation = target.id; witness } in
    self#require_predicate "universal dictionary fixed representative arguments"
      witness.expected witness.fixed_actual;
    quantified_families <- family :: quantified_families;
    family

  method private instantiate_family expected (reference : trait_ref) =
    match reference.kind with
    | TraitImpl target when reference.trait_decl_ref.binder_regions <> [] && expected.binder_regions = [] ->
        let impl = implementation crate target in
        let family = self#source_family target reference.trait_decl_ref in
        let instance = Quantified_dictionary.instantiate ~candidate_only impl.generics impl.impl_trait family.witness expected in
        quantified_instances <- { family; instance } :: quantified_instances;
        { kind = TraitImpl { target with generics = instance.reconstructed_arguments };
          trait_decl_ref = Subst.trait_decl_ref_to_poly_trait_decl_ref instance.reconstructed_predicate }
    | _ -> reference

  method private reconstruct_source_dictionary depth (reference : trait_ref) declared =
    match reference.kind with
    | TraitImpl target when List.mem RErased target.generics.regions ->
        if reference.trait_decl_ref.binder_regions <> [] || declared.binder_regions <> [] then
          invalid_arg "quantified source dictionary reconstruction needs explicit source instantiation";
        let impl = implementation crate target in
        let declared = self#visit_region_binder self#visit_trait_decl_ref depth declared in
        let expected = without_region_binder Subst.st_substitute_visitor#visit_trait_decl_ref declared in
        let witness = try Impl_regions.recover_predicate impl.generics impl.impl_trait target.generics expected
          with Invalid_argument message -> invalid_arg (message ^
            "\ndeclared_bound=" ^ show_trait_decl_ref expected ^
            "\nimplementation_template=" ^ show_trait_decl_ref impl.impl_trait) in
        let reconstructed = { target with generics = witness.reconstructed_arguments } in
        let source_predicate = Subst.trait_decl_ref_to_poly_trait_decl_ref witness.reconstructed_predicate in
        impl_reconstructions <- { implementation = target.id; witness;
          previous_predicate = reference.trait_decl_ref; source_predicate } :: impl_reconstructions;
        let predicate = if List.mem RErased (Region_equations.occurrences reference.trait_decl_ref) then (
          let metadata = Predicate_metadata.recover reference.trait_decl_ref source_predicate in
          metadata_reconstructions <- { implementation = target.id; witness = metadata } :: metadata_reconstructions;
          metadata.completed
        ) else reference.trait_decl_ref in
        (* Missing implementation arguments come only from the complete actual
           declared bound. Known informative labels remain original and must
           still agree in the ordinary whole-predicate replay. *)
        { kind = TraitImpl reconstructed; trait_decl_ref = predicate }
    | _ -> reference

  method private require_associated (parameters : generic_params) =
    if not (List.mem parameters associated_requirements) then (
      associated_requirements <- parameters :: associated_requirements;
      pending_requirements <- parameters :: pending_requirements
    )

  method check_type_requirements sources =
      List.iter (fun source ->
        (* Normalize under the original binder, including an empty one.
           Removing it before comparison loses the universal requirement or
           changes captured de Bruijn depths. Body-region replay preserves
           the complete binder and cannot bind a body lifetime to its locals. *)
        let constraint_ = source.binder_value in
        let left = if source.binder_regions <> [] &&
            source.binder_regions = constraint_.trait_ref.trait_decl_ref.binder_regions then (
          let reference = self#visit_trait_ref 0 constraint_.trait_ref in
          let projection = Quantified_projection.create crate reference constraint_.type_id in
          if projection.output.binder_regions <> source.binder_regions then
            invalid_arg "associated output projection changed the original universal binder";
          quantified_projections <- projection :: quantified_projections;
          List.iter self#require_associated projection.associated_requirements;
          (match projection.function_requirements, projection.origin with
           | Some requirements, Quantified_projection.FunctionItem plan ->
               List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
                 let expected = self#visit_region_binder self#visit_trait_decl_ref 0 clause.trait in
                 let actual = self#visit_trait_ref 0 evidence in
                 self#require_predicate "quantified output source function declared trait bound"
                   expected actual.trait_decl_ref)
                 requirements.trait_clauses plan.target.generics.trait_refs;
               self#check_type_requirements requirements.trait_type_constraints
           | None, Quantified_projection.Implementation _ -> ()
           | _ -> invalid_arg "quantified output source requirement identity disagrees");
          (match projection.input_requirement with
           | Some (expected, actual) ->
               if expected.binder_regions <> source.binder_regions || actual.binder_regions <> source.binder_regions then
                 invalid_arg "quantified function inputs changed their source binder";
               self#retain_type_requirement { source; left = expected.binder_value; right = actual.binder_value }
           | None -> ());
          self#visit_ty 0 projection.output.binder_value
        ) else self#visit_ty 0 (TTraitType (constraint_.trait_ref,
          constraint_.type_id, TypesUtils.empty_generic_args)) in
        let right = self#visit_ty 0 constraint_.ty in
        self#retain_type_requirement { source; left; right }) sources

  method private retain_type_requirement (requirement : type_requirement) =
        type_requirements <- requirement :: type_requirements;
        if requirement.left <> requirement.right then (
          let eraser = object
            inherit [_] map_ty
            method! visit_region _ _ = RErased
          end in
          if not candidate_only || eraser#visit_ty () requirement.left <> eraser#visit_ty () requirement.right then
            invalid_arg "selected source type equality is not established"
        )

  method check_requirements =
    let visited = ref 0 in
    while pending_requirements <> [] do
      incr visited;
      if !visited > 512 then invalid_arg "associated requirements exceed their construction resource limit";
      let parameters = List.hd pending_requirements in
      pending_requirements <- List.tl pending_requirements;
      require_no_associated_arguments parameters;
      let retain evidence =
        if not (replay_outlives ~declarations:crate.type_decls ~normalize:(self#visit_ty 0) evidence) then
          invalid_arg "associated outlives evidence did not reconstruct its complete source requirement";
        outlives_evidence <- evidence :: outlives_evidence in
      List.iter (fun source ->
        let left, right = source.binder_value in
        if not (known_outlives_region source.binder_regions left && known_outlives_region source.binder_regions right) then
          invalid_arg "associated region outlives evidence cannot recover erased or body lifetime provenance";
        let evidence = if left = right then ReflexiveRegion source
          else if left = RStatic then StaticRegion source
          else invalid_arg "associated region outlives requirements need an explicit source relation" in
        retain evidence) parameters.regions_outlive;
      List.iter (fun source ->
        let ty, region = source.binder_value in
        if not (known_outlives_region source.binder_regions region) then
          invalid_arg "associated type outlives evidence needs the exact source target lifetime";
        let witness = Closed_type.create ~declarations:crate.type_decls
          ~normalize:(self#visit_ty 0) ty in
        retain (ClosedSourceType (source, witness))) parameters.types_outlive;
      self#check_type_requirements parameters.trait_type_constraints
    done

  method require_predicate boundary expected actual =
    match compare_predicates ~candidate_only boundary expected actual with
    | None -> ()
    | Some obligation -> obligations <- obligation :: obligations

  method private descend depth =
    if depth >= 512 then invalid_arg "cyclic or excessively deep static trait metadata";
    depth + 1

  method! visit_trait_ref depth reference =
    match References.find_opt reference normalized_references with
    | Some result -> result
    | None ->
        if List.mem reference active_references then
          invalid_arg "cyclic implementation metadata cannot establish its own dictionary predicate";
        active_references <- reference :: active_references;
        (try
          let result = self#normalize_trait_ref depth reference in
          active_references <- List.tl active_references;
          normalized_references <- References.add reference result normalized_references;
          result
        with error ->
          active_references <- List.tl active_references;
          raise error)

  method private normalize_trait_ref depth reference =
    let depth = self#descend depth in
    let reference = super#visit_trait_ref depth reference in
    match reference.kind with
    | TraitImpl target ->
        let impl = implementation crate target in
        self#check_implementation_requirements impl target;
        if reference.trait_decl_ref.binder_regions <> [] then (
          ignore (self#source_family target reference.trait_decl_ref);
          reference
        ) else (
        let actual = self#visit_trait_decl_ref depth
          (Subst.trait_decl_ref_substitute (substitution impl target) impl.impl_trait) in
        let actual = Subst.trait_decl_ref_to_poly_trait_decl_ref actual in
        let reference = if List.mem RErased (Region_equations.occurrences reference.trait_decl_ref) then (
          let witness = Predicate_metadata.recover reference.trait_decl_ref actual in
          metadata_reconstructions <- { implementation = target.id; witness } :: metadata_reconstructions;
          { reference with trait_decl_ref = witness.completed }
        ) else reference in
        self#require_predicate "selected implementation dictionary" reference.trait_decl_ref actual;
        reference)
    | ParentClause (parent, id) ->
        let selected = parent_reference crate parent id in
        let selected = match selected.kind with
          | TraitImpl target when List.mem RErased target.generics.regions ->
              let trait = declaration crate parent.trait_decl_ref.binder_value.id in
              let clause = match List.filter (fun (clause : trait_param) -> clause.clause_id = id) trait.implied_clauses with
                | [clause] -> clause
                | _ -> invalid_arg "a reconstructed parent has no unique actual declared source clause" in
              let declared = quantified_parent_predicate trait.generics parent.trait_decl_ref clause in
              self#reconstruct_source_dictionary depth selected declared
          | _ -> selected in
        let resolved = self#visit_trait_ref depth selected in
        let resolved = if parent.trait_decl_ref.binder_regions = [] then resolved else (
          let trait = declaration crate parent.trait_decl_ref.binder_value.id in
          let clause = match List.filter (fun (clause : trait_param) -> clause.clause_id = id) trait.implied_clauses with
            | [clause] -> clause
            | _ -> invalid_arg "quantified parent has no unique declared source clause" in
          let declared_parent = quantified_parent_predicate trait.generics parent.trait_decl_ref clause in
          parent_quantifications <- { parent; clause_id = id; original_selected = resolved; declared_parent } :: parent_quantifications;
          (* A universal family inherits the declared parent for every bound
             lifetime. Keep the original selected dictionary in the ledger,
             then validate its source implementation as that full family. *)
          self#visit_trait_ref depth { resolved with trait_decl_ref = declared_parent }
        ) in
        let resolved = self#instantiate_family reference.trait_decl_ref resolved in
        (* Keep the caller's complete expected predicate, including binders.
           Its identity must match the actual selected parent predicate. *)
        self#require_predicate "parent dictionary" reference.trait_decl_ref resolved.trait_decl_ref;
        (* The caller's predicate remains unchanged. A candidate with a
           mismatched dictionary is never an emitted, typed specialization. *)
        { reference with kind = resolved.kind }
    | ItemClause (parent, type_id, id) ->
        let resolved, requirements, declared = associated_reference crate parent type_id id in
        List.iter self#require_associated requirements;
        let resolved = self#reconstruct_source_dictionary depth resolved declared in
        let resolved = self#visit_trait_ref depth resolved in
        let resolved = self#instantiate_family reference.trait_decl_ref resolved in
        self#require_predicate "associated-item dictionary" reference.trait_decl_ref resolved.trait_decl_ref;
        { reference with kind = resolved.kind }
    | _ -> reference

  method! visit_ty depth ty =
    let depth = self#descend depth in
    let ty = super#visit_ty depth ty in
    match ty with
    | TTraitType (reference, id, arguments) ->
        let value = match reference.kind with
          | TraitImpl target ->
              let impl = implementation crate target in
              let body = match AssocTypeId.Map.find_opt id impl.types with
                | Some body -> body
                | None -> invalid_arg "associated type implementation is absent" in
              let bound = Subst.st_substitute_visitor#visit_binder
                Subst.st_substitute_visitor#visit_trait_assoc_ty_impl
                (substitution impl target) body in
              Subst.apply_args_to_binder arguments
                Subst.st_substitute_visitor#visit_trait_assoc_ty_impl bound
          | BuiltinOrAuto (_, _, types) ->
              if arguments.regions <> [] || arguments.types <> [] ||
                 arguments.const_generics <> [] || arguments.trait_refs <> [] then
                invalid_arg "builtin associated types do not provide a generic binder";
              (match AssocTypeId.Map.find_opt id types with
               | Some value -> value
               | None -> invalid_arg "builtin associated type is absent")
          | _ -> invalid_arg "associated type has no statically resolved dictionary"
        in
        self#visit_ty depth value.value
    | _ -> ty
end

let normalization_evidence visitor = {
  predicate_obligations = visitor#obligations;
  associated_conditions = visitor#associated_requirements;
  type_equalities = visitor#type_requirements;
  implementation_conditions = visitor#implementation_requirements;
  implementation_reconstructions = visitor#impl_reconstructions;
  metadata_completions = visitor#metadata_reconstructions;
  universal_families = visitor#quantified_families;
  universal_instances = visitor#quantified_instances;
  parent_derivations = visitor#parent_quantifications;
  output_projections = visitor#quantified_projections;
  lifetime_evidence = visitor#outlives_evidence;
}

let outlives_report = function
  | ReflexiveRegion source | StaticRegion source as evidence ->
      let left, right = source.binder_value in
      `Assoc ["rule", `String (match evidence with ReflexiveRegion _ -> "reflexive region" | _ -> "static region");
        "binder", `List (List.map (fun value -> `String (show_region_param value)) source.binder_regions);
        "left", `String (show_region left); "right", `String (show_region right);
        "full_source_borrow_adequacy_discharged", `Bool false]
  | ClosedSourceType (source, witness) ->
      let original, region = source.binder_value in
      `Assoc ["rule", `String "actual closed source type";
        "binder", `List (List.map (fun value -> `String (show_region_param value)) source.binder_regions);
        "original_type", `String (show_ty original); "target_region", `String (show_region region);
        "closed_source_witness", Closed_type.report witness;
        "full_source_borrow_adequacy_discharged", `Bool false]

let resolve_global ?(candidate_only = false) crate (reference : global_decl_ref) : global_resolution =
  let visitor = new normalize ~candidate_only crate in
  let reference = visitor#visit_global_decl_ref 0 reference in
  let declaration = match GlobalDeclId.Map.find_opt reference.id crate.global_decls with
    | Some declaration -> declaration
    | None -> invalid_arg "referenced source global declaration is absent" in
  require_argument_arity declaration.generics reference.generics;
  let preliminary = Subst.make_subst_from_generics declaration.generics reference.generics Self in
  let self_evidence = match declaration.src with
    | TraitDeclItem (owner, _) ->
        let expected = visitor#visit_trait_decl_ref 0
          (Subst.trait_decl_ref_substitute preliminary owner) in
        Some (source_self_evidence (Subst.trait_decl_ref_to_poly_trait_decl_ref expected)
          reference.generics.trait_refs)
    | _ -> None in
  let tr_self = match self_evidence, declaration.src with
    | Some evidence, _ -> evidence.kind
    | None, TraitImplItem (owner, _, _, _) -> TraitImpl
        (Subst.st_substitute_visitor#visit_trait_impl_ref preliminary owner)
    | _ -> Self in
  let requirements = Subst.predicates_substitute { preliminary with tr_self } declaration.generics in
  List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
    let expected = visitor#visit_region_binder visitor#visit_trait_decl_ref 0 clause.trait in
    visitor#require_predicate "selected global declared trait bound" expected evidence.trait_decl_ref)
    requirements.trait_clauses reference.generics.trait_refs;
  visitor#check_type_requirements requirements.trait_type_constraints;
  visitor#check_requirements;
  { global_reference = reference; global_requirements = requirements;
    global_obligations = visitor#obligations; global_type_requirements = visitor#type_requirements;
    global_associated_requirements = visitor#associated_requirements;
    global_impl_reconstructions = visitor#impl_reconstructions;
    global_metadata_reconstructions = visitor#metadata_reconstructions;
    global_quantified_families = visitor#quantified_families;
    global_quantified_instances = visitor#quantified_instances;
    global_implementation_requirements = visitor#implementation_requirements;
    global_self_evidence = self_evidence;
    global_parent_quantifications = visitor#parent_quantifications;
    global_quantified_projections = visitor#quantified_projections;
    global_outlives_evidence = visitor#outlives_evidence }

let rec resolve ?(candidate_only = false) crate (pointer : fn_ptr) : resolved =
  let visitor = new normalize ~candidate_only crate in
  let pointer = visitor#visit_fn_ptr 0 pointer in
  let finish (pointer : fn_ptr) dispatch (self_evidence : trait_ref option) =
    let self_evidence = match self_evidence, pointer.kind with
      | Some _, _ -> self_evidence
      | None, FunId (FRegular id) ->
          let f = match FunDeclId.Map.find_opt id crate.fun_decls with
            | Some f -> f | None -> invalid_arg "source initializer function is absent" in
          (match f.is_global_initializer, f.src with
           | Some global_id, TraitDeclItem (owner, item) ->
               let global = match GlobalDeclId.Map.find_opt global_id crate.global_decls with
                 | Some global -> global | None -> invalid_arg "source initializer's global is absent" in
               (match global.src with
                | TraitDeclItem (global_owner, global_item)
                    when owner.id = global_owner.id && item = global_item -> ()
                | _ -> invalid_arg "source initializer and global trait/item ownership disagree");
               require_argument_arity f.generics pointer.generics;
               let substitution = Subst.make_subst_from_generics f.generics pointer.generics Self in
               let expected = visitor#visit_trait_decl_ref 0
                 (Subst.trait_decl_ref_substitute substitution owner) in
               Some (source_self_evidence (Subst.trait_decl_ref_to_poly_trait_decl_ref expected)
                 pointer.generics.trait_refs)
           | _ -> None)
      | _ -> None in
    (* Validate the selected function's declared dictionary preconditions in
       the caller's scope, before Instance_view factors any region. Otherwise
       an equality imposed by R: Read<'de> can become two unrelated rigid
       parameters in the callee. All remaining where predicates are retained
       as requirements, not counted as discharged borrow/outlives evidence. *)
    let function_requirements = match pointer.kind with
      | FunId (FRegular id) ->
          let f = match FunDeclId.Map.find_opt id crate.fun_decls with
            | Some f -> f | None -> invalid_arg "selected function declaration is absent" in
          require_argument_arity f.generics pointer.generics;
          let preliminary = Subst.make_subst_from_generics f.generics pointer.generics Self in
          let tr_self = match self_evidence with
            | Some reference -> reference.kind
            | None -> (match f.src with
                | TraitImplItem (owner, _, _, _) -> TraitImpl
                    (Subst.st_substitute_visitor#visit_trait_impl_ref preliminary owner)
                | _ -> Self) in
          let requirements = Subst.predicates_substitute
            { preliminary with tr_self } f.generics in
          List.iter2 (fun (clause : trait_param) (reference : trait_ref) ->
            let expected = visitor#visit_region_binder visitor#visit_trait_decl_ref 0 clause.trait in
            visitor#require_predicate "selected function declared trait bound"
              expected reference.trait_decl_ref)
            requirements.trait_clauses pointer.generics.trait_refs;
          visitor#check_type_requirements requirements.trait_type_constraints;
          Some requirements
      | _ -> None in
    visitor#check_requirements;
    { pointer; dispatch; self_evidence; obligations = visitor#obligations;
      associated_requirements = visitor#associated_requirements;
      type_requirements = visitor#type_requirements;
      impl_reconstructions = visitor#impl_reconstructions;
      metadata_reconstructions = visitor#metadata_reconstructions;
      function_requirements;
      quantified_families = visitor#quantified_families;
      quantified_instances = visitor#quantified_instances;
      implementation_requirements = visitor#implementation_requirements;
      parent_quantifications = visitor#parent_quantifications;
      argument_requirements = []; quantified_projections = visitor#quantified_projections;
      outlives_evidence = visitor#outlives_evidence } in
  match pointer.kind with
  | FunId _ -> finish pointer Direct None
  | TraitMethod ({ kind = BuiltinOrAuto (BuiltinNoopDestruct, [], _); _ } as reference, method_id) ->
      let trait = declaration crate reference.trait_decl_ref.binder_value.id in
      let labels = List.filter_map (function PeIdent (name, _) -> Some name | _ -> None) trait.item_meta.name in
      if labels <> ["core"; "marker"; "Destruct"] ||
         GAstUtils.get_method_name crate trait.def_id method_id <> "drop_glue" then
        invalid_arg "a no-op destructor dictionary is attached to an unexpected trait method";
      finish pointer NoopDestruct None
  | TraitMethod ({ kind = BuiltinOrAuto ((BuiltinFnOnce | BuiltinFnMut | BuiltinFn), _, _); _ } as reference, method_id) ->
      let trait = declaration crate reference.trait_decl_ref.binder_value.id in
      let labels = List.filter_map (function PeIdent (name, _) -> Some name | _ -> None) trait.item_meta.name in
      let expected_trait, expected_method, region_arity = match reference.kind with
        | BuiltinOrAuto (BuiltinFnOnce, _, _) -> "FnOnce", "call_once", 0
        | BuiltinOrAuto (BuiltinFnMut, _, _) -> "FnMut", "call_mut", 1
        | BuiltinOrAuto (BuiltinFn, _, _) -> "Fn", "call", 1
        | _ -> invalid_arg "callable builtin classification changed" in
      if labels <> ["core"; "ops"; "function"; expected_trait] ||
         GAstUtils.get_method_name crate trait.def_id method_id <> expected_method then
        invalid_arg "a function-item callable dictionary has unexpected source trait/method identity";
      if List.length pointer.generics.regions <> region_arity || pointer.generics.types <> [] ||
         pointer.generics.const_generics <> [] || pointer.generics.trait_refs <> [] then
        invalid_arg "a callable method has unexpected receiver generic arguments";
      let predicate = without_region_binder Subst.st_substitute_visitor#visit_trait_decl_ref reference.trait_decl_ref in
      let definition, actual_tuple = match predicate.generics.types with
        | [TFnDef definition; actual_tuple] -> definition, actual_tuple
        | _ -> invalid_arg "a callable builtin without a concrete source function item needs explicit target evidence" in
      let plan = Callable_instance.create crate definition actual_tuple in
      if not candidate_only && plan.input_tuple <> plan.actual_tuple then
        invalid_arg "strict callable resolution requires exact complete source input types";
      let target = resolve ~candidate_only crate plan.target in
      let outer = finish pointer (FnDefCall plan) None in
      { outer with obligations = outer.obligations @ target.obligations;
        associated_requirements = outer.associated_requirements @ target.associated_requirements;
        type_requirements = outer.type_requirements @ target.type_requirements;
        impl_reconstructions = outer.impl_reconstructions @ target.impl_reconstructions;
        metadata_reconstructions = outer.metadata_reconstructions @ target.metadata_reconstructions;
        function_requirements = target.function_requirements;
        quantified_families = outer.quantified_families @ target.quantified_families;
        quantified_instances = outer.quantified_instances @ target.quantified_instances;
        implementation_requirements = outer.implementation_requirements @ target.implementation_requirements;
        parent_quantifications = outer.parent_quantifications @ target.parent_quantifications;
        quantified_projections = outer.quantified_projections @ target.quantified_projections;
        outlives_evidence = outer.outlives_evidence @ target.outlives_evidence;
        argument_requirements = (plan.input_tuple, plan.actual_tuple) :: target.argument_requirements }
  | TraitMethod (({ kind = Dyn; _ } as reference), _) ->
      let plan = Dynamic_method.create crate pointer in
      let owner = without_region_binder Subst.st_substitute_visitor#visit_trait_decl_ref reference.trait_decl_ref in
      List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
        visitor#require_predicate "dynamic owner declared trait bound" clause.trait evidence.trait_decl_ref)
        plan.owner_requirements.trait_clauses owner.generics.trait_refs;
      List.iter2 (fun (clause : trait_param) (evidence : trait_ref) ->
        visitor#require_predicate "dynamic method declared trait bound" clause.trait evidence.trait_decl_ref)
        plan.method_requirements.trait_clauses pointer.generics.trait_refs;
      visitor#check_type_requirements plan.owner_requirements.trait_type_constraints;
      visitor#check_type_requirements plan.method_requirements.trait_type_constraints;
      let outer = finish pointer (DynamicMethod plan) None in
      { outer with associated_requirements = plan.owner_requirements :: plan.method_requirements :: outer.associated_requirements }
  | TraitMethod (reference, method_id) ->
      let target = match reference.kind with
        | TraitImpl target -> target
        | _ -> invalid_arg ("trait method has no concrete implementation dictionary\nreference=" ^
            show_trait_ref reference ^ "\nmethod=" ^ string_of_int (TraitMethodId.to_int method_id) ^
            "\nmethod_arguments=" ^ show_generic_args pointer.generics) in
      let impl = implementation crate target in
      let actual = visitor#visit_trait_decl_ref 0
        (Subst.trait_decl_ref_substitute (substitution impl target) impl.impl_trait) in
      visitor#require_predicate "method implementation" reference.trait_decl_ref
        (Subst.trait_decl_ref_to_poly_trait_decl_ref actual);
      let method_, dispatch =
        match Subst.lookup_and_subst_trait_impl_method impl method_id target.generics pointer.generics with
        | Some method_ -> method_, Implementation
        | None ->
            let trait = declaration crate reference.trait_decl_ref.binder_value.id in
            (match Subst.lookup_and_subst_trait_decl_method trait method_id reference pointer.generics with
             | Some method_ -> method_, Default
             | None -> invalid_arg "neither an actual implementation nor a default method body exists")
      in
      let pointer = visitor#visit_fn_ptr 0
        { kind = FunId (FRegular method_.id); generics = method_.generics } in
      let f = match FunDeclId.Map.find_opt method_.id crate.fun_decls with
        | Some f -> f | None -> invalid_arg "selected actual method declaration is absent" in
      let self_evidence = method_self_evidence ~default_lookup:(dispatch = Default)
        target.id impl.impl_trait.id method_id reference f.src in
      finish pointer dispatch self_evidence
