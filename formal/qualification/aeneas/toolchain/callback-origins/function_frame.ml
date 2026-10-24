(* Source-body preparation for lifetime-preserving specialization. This returns
   an in-memory frame, not a new declaration or a qualified program. All
   ordinary references must resolve strictly after one shared body-region
   solution. Drops remain explicit source statements and unresolved boundaries.
   Globals, type declarations, callee cloning and whole-program closure are
   deliberately required before any frame could be emitted. *)
open Charon
open Types
open LlbcAst
open Diagnostic

module TypeReferences = Map.Make (struct
  type t = type_decl_ref
  let compare = compare_type_decl_ref
end)

type call_binding = {
  original : fn_ptr;
  direct : fn_ptr;
  dispatch : Static_targets.dispatch;
  self_evidence : trait_ref option;
  associated_requirements : generic_params list;
  type_requirements : Static_targets.type_requirement list;
  impl_reconstructions : Static_targets.impl_reconstruction list;
  metadata_reconstructions : Static_targets.metadata_reconstruction list;
  function_requirements : generic_params option;
  quantified_families : Static_targets.quantified_family list;
  quantified_instances : Static_targets.quantified_instance list;
  implementation_requirements : Static_targets.implementation_requirement list;
  parent_quantifications : Static_targets.parent_quantification list;
  argument_requirements : (ty * ty) list;
  quantified_projections : Quantified_projection.t list;
  outlives_evidence : Static_targets.outlives_evidence list;
}
type global_binding = {
  original_global : global_decl_ref;
  resolution : Static_targets.global_resolution;
}

type type_binding = {
  original_type : type_decl_ref;
  type_resolution : Type_view.resolution;
}

type callable_call = {
  statement_id : statement_id;
  pointer : fn_ptr;
  source_call : call;
  plan : Callable_instance.t;
  requirements : (ty * ty) list;
}

type drop_binding = {
  drop_statement_id : statement_id;
  original_drop : fn_ptr;
  replayed_drop : fn_ptr;
  normalized_drop : fn_ptr;
}

type dynamic_call = {
  dynamic_statement_id : statement_id;
  dynamic_source_call : call;
  dynamic_plan : Dynamic_method.t;
  dynamic_requirements : (ty * ty) list;
}

type t = {
  original_function_id : fun_decl_id;
  signature : fun_sig;
  return_signature : Return_signature.t option;
  locals : local list;
  body : block;
  source_body : expr_body;
  inherited_requirements : generic_params;
  region_certificate : Region_equations.predicates;
  bindings : call_binding list;
  global_bindings : global_binding list;
  type_bindings : type_binding list;
  preserved_drops : (statement_id * fn_ptr) list;
  primitive_contracts : fn_ptr list;
  callable_calls : callable_call list;
  dynamic_calls : dynamic_call list;
  drop_bindings : drop_binding list;
  source_metadata : Static_targets.normalization_evidence;
}

let region_mapper solution = object
  inherit [_] map_statement
  method! visit_region _ region = Region_equations.resolve solution region
end

let require_body_region count = function
  | RBody id when count < 0 || RegionId.to_int id < 0 || RegionId.to_int id >= count ->
      invalid_arg "a source frame references a region outside its original body scope"
  | _ when count < 0 -> invalid_arg "a source frame has a negative body-region count"
  | _ -> ()

let prepare crate (view : Instance_view.t) : t =
  let source_body = match view.source_body with
    | Some body -> body
    | None -> invalid_arg "a prepared frame requires the original source body metadata" in
  let locals, body = match view.locals_and_body with
    | Some value -> value
    | None -> invalid_arg "an ordinary foreign leaf has no source frame to specialize" in
  let return_signature = Return_signature.create crate view in
  let source_signature = match return_signature with Some candidate -> candidate.reconstructed | None -> view.signature in
  let scope = object
    inherit [_] iter_statement
    method! visit_region _ region = require_body_region source_body.bound_body_regions region
  end in
  scope#visit_fun_sig () source_signature;
  scope#visit_generic_params () view.inherited_requirements;
  List.iter (scope#visit_local ()) locals;
  scope#visit_block () body;
  let certificate = ref (match return_signature with Some candidate -> candidate.constraints | None -> Region_equations.empty_predicates) in
  let candidate_metadata = new Static_targets.normalize ~candidate_only:true crate in
  let strict_metadata = new Static_targets.normalize crate in
  let original_drops = ref StatementId.Map.empty in
  (* Each table belongs to one immutable source frame and one resolution mode.
     The full reference AST, including every region/binder/dictionary, is the
     key. Reuse never assumes an in-progress predicate or crosses replay. *)
  let candidate_types = ref TypeReferences.empty in
  let strict_types = ref TypeReferences.empty in
  let resolve_type ~candidate_only reference =
    let table = if candidate_only then candidate_types else strict_types in
    match TypeReferences.find_opt reference !table with
    | Some resolution -> resolution
    | None ->
        let resolution = Type_view.resolve ~candidate_only crate reference in
        table := TypeReferences.add reference resolution !table;
        resolution in
  let require_facts context obligations type_requirements =
    List.iter (fun (obligation : Static_targets.predicate_obligation) ->
      try certificate := Region_equations.add_predicate !certificate
        obligation.expected obligation.actual
      with Invalid_argument message -> invalid_arg (message ^
        "\nreference=" ^ context ^ "\nboundary=" ^ obligation.boundary ^
        "\nexpected=" ^ show_trait_decl_ref obligation.expected.binder_value ^
        "\nexpected_binders=" ^ String.concat "," (List.map show_region_param obligation.expected.binder_regions) ^
        "\nactual=" ^ show_trait_decl_ref obligation.actual.binder_value ^
        "\nactual_binders=" ^ String.concat "," (List.map show_region_param obligation.actual.binder_regions))) obligations;
    List.iter (fun (requirement : Static_targets.type_requirement) ->
      try certificate := Region_equations.add_quantified_type !certificate
        { binder_regions = requirement.source.binder_regions; binder_value = requirement.left }
        { binder_regions = requirement.source.binder_regions; binder_value = requirement.right }
      with Invalid_argument message -> invalid_arg (message ^
        "\nreference=" ^ context ^ "\nboundary=selected source type equality" ^
        "\nsource=" ^ show_trait_type_constraint requirement.source.binder_value ^
        "\nbinders=" ^ String.concat "," (List.map show_region_param requirement.source.binder_regions) ^
        "\nleft=" ^ show_ty requirement.left ^ "\nright=" ^ show_ty requirement.right)) type_requirements in
  let collect = object (self)
    inherit [_] iter_statement as super
    method! visit_statement env statement =
      match statement.kind with
      | Call ({ func = FnOpRegular pointer; _ } as call, _) ->
          let resolved = Static_targets.resolve ~candidate_only:true crate pointer in
          (match resolved.dispatch with
           | Static_targets.FnDefCall plan ->
               List.iter (fun (expected, actual) ->
                 certificate := Region_equations.add_type !certificate expected actual)
                 (Callable_instance.call_requirements resolved.pointer plan call)
           | Static_targets.DynamicMethod plan ->
               List.iter (fun (expected, actual) ->
                 certificate := Region_equations.add_type !certificate expected actual)
                 (Dynamic_method.call_requirements plan { call with func = FnOpRegular resolved.pointer })
           | _ -> ());
          super#visit_statement env statement
      | Drop (place, pointer, _, unwind) ->
          (* Never treat an unknown destructor as a no-op. The actual pointer
             and statement remain in the returned frame, with a separate
             pending drop boundary. Its embedded source types must nonetheless
             participate in the same caller-region solution as every use.
             Normalizing these types does not select or certify a destructor. *)
          original_drops := StatementId.Map.add statement.statement_id pointer !original_drops;
          ignore (candidate_metadata#visit_fn_ptr 0 pointer);
          super#visit_fn_ptr env pointer;
          self#visit_place env place;
          self#visit_block env unwind
      | _ -> super#visit_statement env statement
    method! visit_ty env ty =
      ignore (candidate_metadata#visit_ty 0 ty);
      super#visit_ty env ty
    method! visit_fn_operand env operand =
      (match operand with
       | FnOpDynamic _ -> invalid_arg "a source frame cannot guess a dynamic call target"
       | FnOpRegular _ -> ());
      super#visit_fn_operand env operand
    method! visit_fn_ptr env pointer =
      let resolved = Static_targets.resolve ~candidate_only:true crate pointer in
      require_facts (Print.fn_ptr_to_string (Print.crate_to_fmt_env crate) pointer)
        resolved.obligations resolved.type_requirements;
      List.iter (fun (expected, actual) ->
        certificate := Region_equations.add_type !certificate expected actual) resolved.argument_requirements;
      super#visit_fn_ptr env pointer
    method! visit_global_decl_ref env reference =
      let resolved = Static_targets.resolve_global ~candidate_only:true crate reference in
      require_facts ("global " ^ string_of_int (GlobalDeclId.to_int reference.id) ^
        " " ^ show_generic_args reference.generics)
        resolved.global_obligations resolved.global_type_requirements;
      super#visit_global_decl_ref env reference
    method! visit_type_decl_ref env reference =
      (match reference.id with
       | TAdtId id ->
           let resolved = resolve_type ~candidate_only:true reference in
           require_facts ("source type " ^ string_of_int (TypeDeclId.to_int id))
             resolved.obligations resolved.type_requirements
       | _ -> ());
      super#visit_type_decl_ref env reference
  end in
  collect#visit_fun_sig () source_signature;
  collect#visit_generic_params () view.inherited_requirements;
  List.iter (collect#visit_local ()) locals;
  collect#visit_block () body;
  candidate_metadata#check_requirements;
  require_facts "complete source frame types and pending destructor metadata"
    candidate_metadata#obligations candidate_metadata#type_requirements;
  if not (Region_equations.replay_predicates !certificate) then
    invalid_arg "source-frame body-region certificate did not reconstruct its original predicates";
  let regions = region_mapper (!certificate).solution in
  let signature = regions#visit_fun_sig () source_signature in
  let locals = List.map (regions#visit_local ()) locals in
  let body = regions#visit_block () body in
  let inherited_requirements = regions#visit_generic_params () view.inherited_requirements in
  let bindings = ref [] in
  let global_bindings = ref [] in
  let type_bindings = ref [] in
  let preserved_drops = ref [] in
  let primitive_contracts = ref [] in
  let callable_calls = ref [] in
  let dynamic_calls = ref [] in
  let drop_bindings = ref [] in
  let rewrite = object (self)
    inherit [_] map_statement as super
    method! visit_statement env statement =
      match statement.kind with
      | Call ({ func = FnOpRegular pointer; _ } as call, _) ->
          let resolved = Static_targets.resolve crate pointer in
          (match resolved.dispatch with
           | Static_targets.FnDefCall plan ->
               let requirements = Callable_instance.call_requirements resolved.pointer plan call in
               if not (List.for_all (fun (expected, actual) -> expected = actual) requirements) then
                 invalid_arg "strict callable statement ABI did not replay against its source signature";
               callable_calls := { statement_id = statement.statement_id;
                 pointer = resolved.pointer; source_call = call; plan; requirements } :: !callable_calls
           | Static_targets.DynamicMethod plan ->
               let requirements = Dynamic_method.call_requirements plan { call with func = FnOpRegular resolved.pointer } in
               if not (List.for_all (fun (expected, actual) -> expected = actual) requirements) then
                 invalid_arg "strict virtual method call ABI did not replay against its actual source interface";
               dynamic_calls := { dynamic_statement_id = statement.statement_id;
                 dynamic_source_call = call; dynamic_plan = plan; dynamic_requirements = requirements } :: !dynamic_calls
           | _ -> ());
          super#visit_statement env statement
      | Drop (place, pointer, kind, unwind) ->
          preserved_drops := (statement.statement_id, pointer) :: !preserved_drops;
          let original_drop = match StatementId.Map.find_opt statement.statement_id !original_drops with
            | Some original -> original
            | None -> invalid_arg "a staged destructor has no original source statement" in
          let replayed_original = regions#visit_fn_ptr () original_drop in
          if replayed_original <> pointer then
            invalid_arg "a pending destructor pointer changed outside common source-region replay";
          let normalized_drop = strict_metadata#visit_fn_ptr 0 pointer in
          (* Traverse type/function-valued arguments without dispatching this
             destructor through visit_fn_ptr. Its own semantics stay pending. *)
          let normalized_drop = super#visit_fn_ptr env normalized_drop in
          drop_bindings := { drop_statement_id = statement.statement_id;
            original_drop; replayed_drop = pointer; normalized_drop } :: !drop_bindings;
          { statement with kind = Drop (self#visit_place env place, normalized_drop, kind,
              self#visit_block env unwind) }
      | _ -> super#visit_statement env statement
    method! visit_ty env ty =
      super#visit_ty env (strict_metadata#visit_ty 0 ty)
    method! visit_fn_operand env operand =
      (match operand with
       | FnOpDynamic _ -> invalid_arg "a staged source frame contains a dynamic call target"
       | FnOpRegular _ -> ());
      super#visit_fn_operand env operand
    method! visit_fn_ptr env pointer =
      let resolved = Static_targets.resolve crate pointer in
      if resolved.obligations <> [] then
        invalid_arg "strict source-frame resolution retained an unsatisfied predicate";
      (* Retain all explicit type/trait/const/lifetime arguments. Factoring is
         an exact reconstruction guard here, not argument erasure. *)
      (try ignore (Region_shape.factor resolved.pointer.generics) with Invalid_argument message ->
        invalid_arg (Print.fn_ptr_to_string (Print.crate_to_fmt_env crate) resolved.pointer ^ ": " ^ message));
      (match resolved.dispatch with
       | Static_targets.NoopDestruct | Static_targets.FnDefCall _ ->
           primitive_contracts := resolved.pointer :: !primitive_contracts
       | _ -> ());
      bindings := { original = pointer; direct = resolved.pointer;
        dispatch = resolved.dispatch; self_evidence = resolved.self_evidence;
        associated_requirements = resolved.associated_requirements;
        type_requirements = resolved.type_requirements;
        impl_reconstructions = resolved.impl_reconstructions;
        metadata_reconstructions = resolved.metadata_reconstructions;
        function_requirements = resolved.function_requirements;
        quantified_families = resolved.quantified_families;
        quantified_instances = resolved.quantified_instances;
        implementation_requirements = resolved.implementation_requirements;
        parent_quantifications = resolved.parent_quantifications;
        quantified_projections = resolved.quantified_projections;
        outlives_evidence = resolved.outlives_evidence;
        argument_requirements = resolved.argument_requirements } :: !bindings;
      super#visit_fn_ptr env resolved.pointer
    method! visit_global_decl_ref env reference =
      let resolved = Static_targets.resolve_global crate reference in
      if resolved.global_obligations <> [] then
        invalid_arg "strict source-global resolution retained an unsatisfied predicate";
      ignore (Region_shape.factor resolved.global_reference.generics);
      global_bindings := { original_global = reference; resolution = resolved } :: !global_bindings;
      super#visit_global_decl_ref env resolved.global_reference
    method! visit_type_decl_ref env reference =
      let reference = match reference.id with
        | TAdtId _ ->
            let type_resolution = resolve_type ~candidate_only:false reference in
            if type_resolution.obligations <> [] then
              invalid_arg "strict source type resolution retained an unsatisfied declared predicate";
            type_bindings := { original_type = reference; type_resolution } :: !type_bindings;
            type_resolution.reference
        | _ -> reference in
      super#visit_type_decl_ref env reference
  end in
  let signature = rewrite#visit_fun_sig () signature in
  let inherited_requirements = rewrite#visit_generic_params ()
    (strict_metadata#visit_generic_params 0 inherited_requirements) in
  let locals = List.map (rewrite#visit_local ()) locals in
  let body = rewrite#visit_block () body in
  strict_metadata#check_requirements;
  if strict_metadata#obligations <> [] then
    invalid_arg "strict whole-frame type normalization retained an unsatisfied predicate";
  let closed_scope = new Region_scope.statement_check
    ~body_regions:source_body.bound_body_regions view.arguments.parameters in
  closed_scope#visit_fun_sig [] signature;
  closed_scope#visit_generic_params [] inherited_requirements;
  List.iter (closed_scope#visit_local []) locals;
  closed_scope#visit_block [] body;
  { original_function_id = view.original_id; signature; return_signature; locals; body;
    source_body; inherited_requirements;
    region_certificate = !certificate; bindings = List.rev !bindings;
    global_bindings = List.rev !global_bindings;
    type_bindings = List.rev !type_bindings;
    preserved_drops = List.rev !preserved_drops;
    primitive_contracts = List.rev !primitive_contracts;
    callable_calls = List.rev !callable_calls;
    dynamic_calls = List.rev !dynamic_calls;
    drop_bindings = List.rev !drop_bindings;
    source_metadata = Static_targets.normalization_evidence strict_metadata }

let metadata_report crate (evidence : Static_targets.normalization_evidence) =
  let text value = `String value in
  let binder value show = `Assoc [
    "binder", `List (List.map (fun parameter -> text (Types.show_region_param parameter)) value.binder_regions);
    "value", text (show value.binder_value)] in
  let field_evidence : Type_view.field_requirements = {
    associated = evidence.associated_conditions;
    type_equalities = evidence.type_equalities;
    implementations = evidence.implementation_conditions;
    impl_reconstructions = evidence.implementation_reconstructions;
    metadata_reconstructions = evidence.metadata_completions;
    quantified_families = evidence.universal_families;
    quantified_instances = evidence.universal_instances;
    parent_quantifications = evidence.parent_derivations;
    quantified_projections = evidence.output_projections;
    outlives_evidence = evidence.lifetime_evidence } in
  `Assoc [
    "source_derivations", Type_view.field_report crate field_evidence;
    "predicate_obligations", `List (List.map (fun (obligation : Static_targets.predicate_obligation) ->
      `Assoc ["boundary", text obligation.boundary;
        "expected", binder obligation.expected show_trait_decl_ref;
        "actual", binder obligation.actual show_trait_decl_ref]) evidence.predicate_obligations);
    "associated_conditions", `List (List.map (fun value -> text (show_generic_params value)) evidence.associated_conditions);
    "type_equalities", `List (List.map (fun (requirement : Static_targets.type_requirement) ->
      `Assoc ["source", binder requirement.source show_trait_type_constraint;
        "left", text (show_ty requirement.left); "right", text (show_ty requirement.right)]) evidence.type_equalities);
    "implementation_conditions", `List (List.map (fun (requirement : Static_targets.implementation_requirement) ->
      `Assoc ["implementation", `Int (TraitImplId.to_int requirement.source_implementation);
        "arguments", text (show_generic_args requirement.implementation_arguments);
        "conditions", text (show_generic_params requirement.requirements)]) evidence.implementation_conditions);
    "quantified_output_projections", `List (List.map (Quantified_projection.report crate) evidence.output_projections);
    "type_and_borrow_adequacy_discharged", `Bool false;
    "destructor_semantics_discharged", `Bool false ]

let drop_report (binding : drop_binding) =
  `Assoc ["statement_id", `Int (StatementId.to_int binding.drop_statement_id);
    "original_source_pointer", `String (show_fn_ptr binding.original_drop);
    "pointer_after_common_region_replay", `String (show_fn_ptr binding.replayed_drop);
    "pointer_after_source_type_normalization", `String (show_fn_ptr binding.normalized_drop);
    "destructor_selection_and_semantics_discharged", `Bool false]
