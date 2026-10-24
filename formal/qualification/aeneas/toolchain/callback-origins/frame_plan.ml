(* Construct actual source-body frames for the exact native recipe roots.
   This is an interface constructor, never a qualification or whole-program
   emitter. Preserved drops and unresolved callees remain explicit barriers. *)
open Charon
open Types
open LlbcAst
open Diagnostic

let labels name = List.filter_map (function PeIdent (label, _) -> Some label | _ -> None) name
let text value = `String value
let number value = `Int value
let flag value = `Bool value

let () =
  if Array.length Sys.argv <> 4 then failwith "usage: frame_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "source frames require the shipping gateway library";
  let roots = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  if List.length roots <> 21 || List.length (List.sort_uniq String.compare roots) <> 21 ||
     not (List.mem "auths_gateway::recipe::compile_source_bytes" roots) then
    failwith "all twenty-one distinct native roots, including the actual public byte entry, are required";
  let fmt = Print.crate_to_fmt_env crate in
  let failures = ref 0 in
  let pending_drops = ref 0 in
  let primitives = ref 0 in
  let encode_frame name =
    let candidates = FunDeclId.Map.bindings crate.fun_decls |> List.filter (fun (_, declaration) ->
      String.concat "::" (labels declaration.item_meta.name) = name) in
    try
      let declaration = match candidates with
        | [(_, declaration)] -> declaration
        | [] -> invalid_arg "requested original source declaration is absent"
        | _ -> invalid_arg "requested original source declaration is ambiguous" in
      if declaration.generics.types <> [] || declaration.generics.const_generics <> [] ||
         declaration.generics.trait_clauses <> [] then
        invalid_arg "root needs an explicit closed type/const/dictionary instantiation";
      let arguments = { TypesUtils.empty_generic_args with regions = List.map
        (fun (region : region_param) -> RVar (Free region.index)) declaration.generics.regions } in
      let view = Instance_view.create declaration arguments in
      let frame = Function_frame.prepare crate view in
      pending_drops := !pending_drops + List.length frame.preserved_drops;
      primitives := !primitives + List.length frame.primitive_contracts;
      `Assoc ["source", text name;
        "original_function_id", number (FunDeclId.to_int declaration.def_id);
        "frame_prepared", flag true; "declaration_emitted", flag false;
        "region_equations", `List (List.map (fun (left, right) -> `List [text (show_region left); text (show_region right)])
          (List.rev frame.region_certificate.solution.equations));
        "region_certificate_replays", flag (Region_equations.replay_predicates frame.region_certificate);
        "complete_region_certificate", region_certificate_json frame.region_certificate;
        "source_type_bindings", `List (List.map (fun (binding : Function_frame.type_binding) ->
          Type_view.resolution_report crate binding.type_resolution) frame.type_bindings);
        "signature", text (show_fun_sig frame.signature);
        "locals", `List (List.map (fun local -> text (show_local local)) frame.locals);
        "staged_body", text (show_block frame.body);
        "bound_body_regions", number frame.source_body.bound_body_regions;
        "inherited_requirements", text (show_generic_params frame.inherited_requirements);
        "complete_source_type_normalization", Function_frame.metadata_report crate frame.source_metadata;
        "pending_destructor_type_normalization", `List (List.map Function_frame.drop_report frame.drop_bindings);
        "callable_statement_abi", `List (List.map (fun (call : Function_frame.callable_call) ->
          `Assoc ["statement_id", number (StatementId.to_int call.statement_id);
            "source_call", text (show_call call.source_call);
            "instantiation", Callable_instance.report crate call.plan;
            "complete_type_equalities", `List (List.map (fun (expected, actual) ->
              `Assoc ["expected", text (show_ty expected); "actual", text (show_ty actual);
                "equal", flag (expected = actual)]) call.requirements)]) frame.callable_calls);
        "global_bindings", `List (List.map (fun (binding : Function_frame.global_binding) ->
          let resolved = binding.resolution in
          `Assoc ["source_global_id", number (GlobalDeclId.to_int binding.original_global.id);
            "original_arguments", text (show_generic_args binding.original_global.generics);
            "resolved_arguments", text (show_generic_args resolved.global_reference.generics);
            "declared_requirements", text (show_generic_params resolved.global_requirements);
            "quantified_output_projections", `List (List.map (Quantified_projection.report crate)
              resolved.global_quantified_projections);
            "associated_requirements", `List (List.map (fun parameters -> text (show_generic_params parameters)) resolved.global_associated_requirements);
            "type_equalities", `List (List.map (fun (requirement : Static_targets.type_requirement) ->
              `Assoc ["binder", `List (List.map (fun parameter -> text (show_region_param parameter)) requirement.source.binder_regions);
                "left", text (show_ty requirement.left); "right", text (show_ty requirement.right)]) resolved.global_type_requirements)]) frame.global_bindings);
        "call_bindings", `List (List.map (fun (binding : Function_frame.call_binding) ->
          `Assoc ["original", text (Print.fn_ptr_to_string fmt binding.original);
            "direct", text (Print.fn_ptr_to_string fmt binding.direct);
            "callable_adapter", (match binding.dispatch with
              | Static_targets.FnDefCall plan -> Callable_instance.report crate plan
              | _ -> `Null);
            "argument_requirements", `List (List.map (fun (expected, actual) ->
              `Assoc ["expected", text (show_ty expected); "actual", text (show_ty actual);
                "equal", flag (expected = actual)]) binding.argument_requirements);
            "quantified_output_projections", `List (List.map (Quantified_projection.report crate)
              binding.quantified_projections);
            "self_evidence", (match binding.self_evidence with
              | None -> `Null | Some evidence -> text (show_trait_ref evidence));
            "declared_function_requirements", (match binding.function_requirements with
              | None -> `Null | Some requirements -> text (show_generic_params requirements));
            "source_implementation_requirements", `List (List.map (fun (requirement : Static_targets.implementation_requirement) ->
              `Assoc ["implementation", number (TraitImplId.to_int requirement.source_implementation);
                "arguments", text (show_generic_args requirement.implementation_arguments);
                "requirements", text (show_generic_params requirement.requirements)]) binding.implementation_requirements);
            "quantified_parent_derivations", `List (List.map (fun (derivation : Static_targets.parent_quantification) ->
              `Assoc ["parent", text (show_trait_ref derivation.parent);
                "clause_id", number (TraitClauseId.to_int derivation.clause_id);
                "original_selected", text (show_trait_ref derivation.original_selected);
                "declared_binder", `List (List.map (fun parameter -> text (show_region_param parameter)) derivation.declared_parent.binder_regions);
                "declared_parent", text (show_trait_decl_ref derivation.declared_parent.binder_value)]) binding.parent_quantifications);
            "quantified_source_families", `List (List.map (fun (family : Static_targets.quantified_family) ->
              let impl = TraitImplId.Map.find family.implementation crate.trait_impls in
              `Assoc ["implementation", number (TraitImplId.to_int family.implementation);
                "representative_arguments_unchanged", text (show_generic_args family.witness.representative_arguments);
                "universal_binder", `List (List.map (fun parameter -> text (show_region_param parameter)) family.witness.expected.binder_regions);
                "universal_predicate", text (show_trait_decl_ref family.witness.expected.binder_value);
                "fixed_argument_actual_predicate", text (show_trait_decl_ref family.witness.fixed_actual.binder_value);
                "fixed_arguments_match", flag (family.witness.expected = family.witness.fixed_actual);
                "invariant_prerequisites", `List (List.map (fun ((clause : trait_param), (evidence : trait_ref)) ->
                  `Assoc ["clause_id", number (TraitClauseId.to_int clause.clause_id);
                    "declared", text (show_trait_decl_ref clause.trait.binder_value);
                    "source_evidence", text (show_trait_ref evidence)]) family.witness.invariant_prerequisites);
                "family_arguments", text (show_generic_args family.witness.family.reconstructed_arguments);
                "replays", flag (Quantified_dictionary.replay impl.generics impl.impl_trait family.witness)]) binding.quantified_families);
            "quantified_source_instances", `List (List.map (fun (instance : Static_targets.quantified_instance) ->
              `Assoc ["implementation", number (TraitImplId.to_int instance.family.implementation);
                "instance_arguments", text (show_generic_args instance.instance.reconstructed_arguments);
                "full_instance_predicate", text (show_trait_decl_ref instance.instance.reconstructed_predicate)]) binding.quantified_instances);
            "metadata_reconstructions", `List (List.map (fun (reconstruction : Static_targets.metadata_reconstruction) ->
              `Assoc ["implementation", number (TraitImplId.to_int reconstruction.implementation);
                "original", text (show_trait_decl_ref reconstruction.witness.original.binder_value);
                "selected_source", text (show_trait_decl_ref reconstruction.witness.source.binder_value);
                "completed", text (show_trait_decl_ref reconstruction.witness.completed.binder_value);
                "replays", flag (Predicate_metadata.replay reconstruction.witness)]) binding.metadata_reconstructions);
            "associated_requirements", `List (List.map (fun requirements ->
              text (show_generic_params requirements)) binding.associated_requirements);
            "associated_outlives_evidence", `List (List.map Static_targets.outlives_report binding.outlives_evidence);
            "implementation_reconstructions", `List (List.map (fun (reconstruction : Static_targets.impl_reconstruction) ->
              `Assoc ["implementation", number (TraitImplId.to_int reconstruction.implementation);
                "original_arguments", text (show_generic_args reconstruction.witness.original_arguments);
                "reconstructed_arguments", text (show_generic_args reconstruction.witness.reconstructed_arguments);
                "declared_source_predicate", text (show_trait_decl_ref reconstruction.witness.source_predicate);
                "reconstructed_predicate", text (show_trait_decl_ref reconstruction.witness.reconstructed_predicate)]) binding.impl_reconstructions);
            "type_requirements", `List (List.map (fun (requirement : Static_targets.type_requirement) ->
              `Assoc ["source", text (show_trait_type_constraint requirement.source.binder_value);
                "left", text (show_ty requirement.left); "right", text (show_ty requirement.right);
                "satisfied", flag (requirement.left = requirement.right)]) binding.type_requirements)]) frame.bindings);
        "preserved_drop_boundaries", `List (List.map (fun (id, pointer) ->
          `Assoc ["statement_id", number (StatementId.to_int id);
            "source_reference", text (Print.fn_ptr_to_string fmt pointer);
            "contract_discharged", flag false]) frame.preserved_drops);
        "primitive_contracts_required", number (List.length frame.primitive_contracts) ]
    with Invalid_argument message ->
      incr failures;
      `Assoc ["source", text name; "frame_prepared", flag false;
        "declaration_emitted", flag false; "error", text message] in
  Json_stream.write Sys.argv.(3) ~array_name:"frames" ~values:roots ~encode:encode_frame ~metadata:(fun () -> [
    "schema", text "auths-proof-source-function-frames/v2";
    "qualified", flag false; "program_emitted", flag false;
    "scope", text "root source-body frames only; callee cloning, default Self, drops, globals, type closure, full typing/borrow/source preservation and qualification remain";
    "input", text Sys.argv.(1); "roots", number (List.length roots);
    "failed_frames", number !failures; "preserved_drop_boundaries", number !pending_drops;
    "primitive_contracts_required", number !primitives;
    "source_text_encoding", text "inline file contents are interned by exact file-name/crate in source_file_table; spans and checked ASTs are unchanged";
    "source_file_table", Diagnostic.source_files_json () ]);
  Printf.printf "Source frames: roots=%d prepared=%d failed=%d pending-drops=%d primitives=%d; no program emitted, unqualified\n%!"
    (List.length roots) (List.length roots - !failures) !failures !pending_drops !primitives;
  if !failures <> 0 || !pending_drops <> 0 || !primitives <> 0 then exit 2
