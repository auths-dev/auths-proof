open Charon
open Types
open LlbcAst
open Diagnostic

let text value = `String value
let number value = `Int value
let flag value = `Bool value
let rec target crate = function
  | Source_closure.VirtualMethod plan -> `Assoc ["virtual_method_interface", Dynamic_method.report crate plan;
      "runtime_selection_and_execution_binding_required", flag true]
  | Source_closure.Instance index -> `Assoc ["instance", number index]
  | Source_closure.Builtin id -> `Assoc ["builtin_contract_required", text (show_builtin_fun_id id)]
  | Source_closure.NoopDestruct pointer -> `Assoc ["noop_destructor_contract_required", text (show_fn_ptr pointer)]
  | Source_closure.CallableAdapter (plan, source) -> `Assoc [
      "callable_adapter", Callable_instance.report crate plan;
      "source_target", target crate source]

let () =
  if Array.length Sys.argv <> 4 then
    failwith "usage: prepared_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "prepared closure requires the shipping gateway library";
  let roots = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let pointers = Source_roots.pointers crate roots in
  let graph, vtable_adapters, adapter_iterations = Vtable_graph.close_source_dependencies crate pointers in
  Printf.printf "Source graph constructed: scheduled=%d nodes=%d failures=%d; writing interface\n%!"
    graph.scheduled (List.length graph.nodes) (List.length graph.failures);
  let fmt = Print.crate_to_fmt_env crate in
  let prepared = ref 0 in
  let leaves = ref 0 in
  let drops = ref 0 in
  let primitives = ref 0 in
  let virtual_methods = ref 0 in
  let return_signatures = ref 0 in
  let encode_node (node : Source_closure.node) =
    if node.index mod 128 = 0 then Printf.printf "Writing source frame %d\n%!" node.index;
    let body = match node.frame with
      | None -> incr leaves; `Null
      | Some frame ->
          incr prepared;
          if Option.is_some frame.return_signature then incr return_signatures;
          drops := !drops + List.length frame.preserved_drops;
          `Assoc [
            "bound_body_regions", number frame.source_body.bound_body_regions;
            "source_span", text (show_span frame.source_body.span);
            "signature", text (show_fun_sig frame.signature);
            "original_opaque_return_signature_refinement_required", (match frame.return_signature with Some candidate -> Return_signature.report crate candidate | None -> `Null);
            "locals", `List (List.map (fun local -> text (show_local local)) frame.locals);
            "staged_body", text (show_block frame.body);
            "region_equations", `List (List.map (fun (left, right) ->
              `List [text (show_region left); text (show_region right)])
              (List.rev frame.region_certificate.solution.equations));
            "region_certificate_replays", flag (Region_equations.replay_predicates frame.region_certificate);
            "complete_region_certificate", region_certificate_json frame.region_certificate;
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
            "virtual_statement_abi", `List (List.map (fun (call : Function_frame.dynamic_call) -> `Assoc [
              "statement_id", number (StatementId.to_int call.dynamic_statement_id);
              "original_source_call", text (show_call call.dynamic_source_call);
              "original_virtual_interface", Dynamic_method.report crate call.dynamic_plan;
              "complete_type_equalities", `List (List.map (fun (expected, actual) -> `Assoc [
                "expected", text (show_ty expected); "actual", text (show_ty actual);
                "equal", flag (expected = actual)]) call.dynamic_requirements);
              "runtime_receiver_selection_and_native_execution_proved", flag false]) frame.dynamic_calls);
            "global_bindings", `List (List.map (fun (binding : Function_frame.global_binding) ->
              `Assoc ["source_global_id", number (GlobalDeclId.to_int binding.original_global.id);
                "original_arguments", text (show_generic_args binding.original_global.generics);
                "resolved_arguments", text (show_generic_args binding.resolution.global_reference.generics);
                "associated_outlives_evidence", `List (List.map Static_targets.outlives_report binding.resolution.global_outlives_evidence);
                "quantified_output_projections", `List (List.map (Quantified_projection.report crate)
                  binding.resolution.global_quantified_projections);
                "declared_requirements", text (show_generic_params binding.resolution.global_requirements)]) frame.global_bindings);
            "source_type_bindings", `List (List.map (fun (binding : Function_frame.type_binding) ->
              Type_view.resolution_report crate binding.type_resolution) frame.type_bindings);
            "preserved_drop_boundaries", `List (List.map (fun (id, pointer) ->
              `Assoc ["statement_id", number (StatementId.to_int id);
                "pointer", text (Print.fn_ptr_to_string fmt pointer);
                "discharged", flag false]) frame.preserved_drops) ] in
    `Assoc ["instance", number node.index;
      "original_function_id", number (FunDeclId.to_int node.declaration.def_id);
      "source_name", text (Print.name_to_string fmt node.declaration.item_meta.name);
      "auths", flag (Instance_view.is_auths node.declaration.item_meta.name);
      "pattern", text (show_generic_args node.view.arguments.pattern);
      "self_evidence", (match node.view.self_evidence with None -> `Null | Some evidence -> text (show_trait_ref evidence));
      "frame", body; "ordinary_leaf_contract_required", flag (Option.is_none node.frame);
      "global_dependencies", `List (List.map number node.globals);
      "source_type_dependencies", `List (List.map number node.types);
      "callees", `List (List.map (fun (edge : Source_closure.edge) ->
        (match edge.target with Source_closure.Instance _ -> ()
         | Source_closure.VirtualMethod _ -> incr virtual_methods
         | _ -> incr primitives);
        `Assoc ["source_reference", text (Print.fn_ptr_to_string fmt edge.binding.original);
          "source_reference_ast", text (show_fn_ptr edge.binding.original);
          "selected_reference", text (Print.fn_ptr_to_string fmt edge.binding.direct);
          "argument_requirements", `List (List.map (fun (expected, actual) ->
            `Assoc ["expected", text (show_ty expected); "actual", text (show_ty actual);
              "equal", flag (expected = actual)]) edge.binding.argument_requirements);
          "associated_outlives_evidence", `List (List.map Static_targets.outlives_report edge.binding.outlives_evidence);
          "quantified_output_projections", `List (List.map (Quantified_projection.report crate)
            edge.binding.quantified_projections);
          "declared_type_equalities", `List (List.map (fun (requirement : Static_targets.type_requirement) ->
            `Assoc ["source", text (show_trait_type_constraint requirement.source.binder_value);
              "binder", `List (List.map (fun parameter -> text (show_region_param parameter)) requirement.source.binder_regions);
              "left", text (show_ty requirement.left); "right", text (show_ty requirement.right);
              "equal", flag (requirement.left = requirement.right)]) edge.binding.type_requirements);
          "self_evidence", (match edge.binding.self_evidence with None -> `Null | Some evidence -> text (show_trait_ref evidence));
          "declared_function_requirements", (match edge.binding.function_requirements with
            | None -> `Null | Some requirements -> text (show_generic_params requirements));
          "source_implementation_requirements", `List (List.map (fun (requirement : Static_targets.implementation_requirement) ->
            `Assoc ["implementation", number (TraitImplId.to_int requirement.source_implementation);
              "arguments", text (show_generic_args requirement.implementation_arguments);
              "requirements", text (show_generic_params requirement.requirements)]) edge.binding.implementation_requirements);
          "quantified_parent_derivations", `List (List.map (fun (derivation : Static_targets.parent_quantification) ->
            `Assoc ["parent", text (show_trait_ref derivation.parent);
              "clause_id", number (TraitClauseId.to_int derivation.clause_id);
              "original_selected", text (show_trait_ref derivation.original_selected);
              "declared_binder", `List (List.map (fun parameter -> text (show_region_param parameter)) derivation.declared_parent.binder_regions);
              "declared_parent", text (show_trait_decl_ref derivation.declared_parent.binder_value)]) edge.binding.parent_quantifications);
          "quantified_families", `List (List.map (fun (family : Static_targets.quantified_family) ->
            let impl = TraitImplId.Map.find family.implementation crate.trait_impls in
            `Assoc ["implementation", number (TraitImplId.to_int family.implementation);
              "representative_arguments", text (show_generic_args family.witness.representative_arguments);
              "universal_binder", `List (List.map (fun parameter -> text (show_region_param parameter)) family.witness.expected.binder_regions);
              "universal_predicate", text (show_trait_decl_ref family.witness.expected.binder_value);
              "fixed_argument_actual_predicate", text (show_trait_decl_ref family.witness.fixed_actual.binder_value);
              "fixed_arguments_match", flag (family.witness.expected = family.witness.fixed_actual);
              "invariant_prerequisites", `List (List.map (fun ((clause : trait_param), (evidence : trait_ref)) ->
                `Assoc ["clause_id", number (TraitClauseId.to_int clause.clause_id);
                  "declared", text (show_trait_decl_ref clause.trait.binder_value);
                  "source_evidence", text (show_trait_ref evidence)]) family.witness.invariant_prerequisites);
              "family_arguments", text (show_generic_args family.witness.family.reconstructed_arguments);
              "replays", flag (Quantified_dictionary.replay impl.generics impl.impl_trait family.witness)]) edge.binding.quantified_families);
          "quantified_instances", `List (List.map (fun (instance : Static_targets.quantified_instance) ->
            `Assoc ["implementation", number (TraitImplId.to_int instance.family.implementation);
              "instance_arguments", text (show_generic_args instance.instance.reconstructed_arguments);
              "instance_predicate", text (show_trait_decl_ref instance.instance.reconstructed_predicate)]) edge.binding.quantified_instances);
          "target", target crate edge.target]) node.callees) ] in
  Json_stream.write Sys.argv.(3) ~array_name:"nodes" ~values:graph.nodes ~encode:encode_node ~metadata:(fun () ->
    let fields = [
    "schema", text "auths-proof-prepared-source-closure/v3";
    "qualified", flag false; "program_emitted", flag false;
    "scope", text "prepared source frames; drops, ordinary primitive contracts, globals/types, full source/type/borrow adequacy and emission remain";
    "input", text Sys.argv.(1); "root_count", number (List.length roots);
    "vtable_adapter_dependency_iterations", number adapter_iterations;
    "vtable_adapter_source_dependencies", `List (List.map (target crate) graph.adapter_dependencies);
    "vtable_adapter_candidates", Vtable_graph.report crate vtable_adapters;
    "scheduled_instances", number graph.scheduled; "prepared_frames", number !prepared;
    "ordinary_leaves", number !leaves; "preserved_drop_boundaries", number !drops;
    "primitive_contracts_required", number !primitives;
    "virtual_method_execution_bindings_required", number !virtual_methods;
    "source_opaque_return_signature_refinements_required", number !return_signatures;
    "source_return_call_execution_bindings_required", number (List.length vtable_adapters.return_calls);
    "source_box_receiver_execution_bindings_required", number (List.length vtable_adapters.box_receiver_calls);
    "source_closure_execution_bindings_required", number (List.length vtable_adapters.closure_captures);
    "source_closure_invocation_simulations_required", number (List.length vtable_adapters.closure_invocations);
    "source_captured_field_receiver_effects_required", number (List.length vtable_adapters.closure_receivers);
    "source_closure_argument_activation_bindings_required", number (List.length vtable_adapters.closure_arguments);
    "source_callback_carrier_effect_simulations_required", number (List.length vtable_adapters.carrier_effects.nodes);
    "source_callback_carrier_effect_failures", number (List.length vtable_adapters.carrier_effects.failures);
    "source_closure_return_simulations_required", number (List.length vtable_adapters.closure_returns);
    "source_closure_return_call_simulations_required", number (List.length vtable_adapters.closure_return_calls);
    "source_carrier_value_flow_simulations_required", number (List.length vtable_adapters.value_flow.edges);
    "source_carrier_value_flow_failures", number (List.length vtable_adapters.value_flow.failures);
    "scheduled_globals", number graph.scheduled_globals;
    "scheduled_source_types", number graph.scheduled_types;
    "source_types", `List (List.map (fun (node : Source_closure.type_node) ->
      let view = node.view in
      `Assoc ["type", number node.type_index;
        "source_resolution", Type_view.resolution_report crate view.source_resolution;
        "source_kind_instantiated", text (show_type_decl_kind view.kind);
        "pointer_metadata_instantiated", text (show_ptr_metadata view.ptr_metadata);
        "arguments", text (show_generic_args view.arguments.pattern);
        "inherited_requirements", text (show_generic_params view.inherited_requirements);
        "field_associated_requirements", `List (List.map (fun requirements ->
          text (show_generic_params requirements)) view.field_requirements.associated);
        "field_type_equalities", `List (List.map (fun (requirement : Static_targets.type_requirement) ->
          `Assoc ["source", text (show_trait_type_constraint requirement.source.binder_value);
            "binder", `List (List.map (fun parameter -> text (show_region_param parameter)) requirement.source.binder_regions);
            "left", text (show_ty requirement.left); "right", text (show_ty requirement.right)]) view.field_requirements.type_equalities);
        "field_implementation_requirements", `List (List.map (fun (requirement : Static_targets.implementation_requirement) ->
          `Assoc ["implementation", number (TraitImplId.to_int requirement.source_implementation);
            "arguments", text (show_generic_args requirement.implementation_arguments);
            "requirements", text (show_generic_params requirement.requirements)]) view.field_requirements.implementations);
        "field_quantified_output_projections", `List (List.map (Quantified_projection.report crate)
          view.field_requirements.quantified_projections);
        "field_source_derivations", Type_view.field_report crate view.field_requirements;
        "type_dependencies", `List (List.map number node.types);
        "global_dependencies", `List (List.map number node.globals);
        "function_references", `List (List.map (fun ((resolved : Static_targets.resolved), destination) ->
          `Assoc ["reference", text (show_fn_ptr resolved.pointer); "target", target crate destination]) node.function_references);
        "ordinary_opaque_contract_required", flag view.ordinary_opaque_contract_required;
        "union_representation_contract_required", flag view.union_representation_contract_required;
        "source_layout_metadata", `List (List.map (fun (target, layout) ->
          `Assoc ["target", text target; "layout", text (Types.show_layout layout)]) view.source_resolution.declaration.layout);
        "layout_instantiation_discharged", flag false;
        "source_type_borrow_adequacy_discharged", flag false ]) graph.type_nodes);
    "source_type_failures", `List (List.map (fun (failure : Source_closure.type_failure) ->
      `Assoc ["owner", text failure.owner;
        "source_reference", text (show_type_decl_ref failure.reference);
        "error", text failure.message]) graph.type_failures);
    "globals", `List (List.map (fun (global : Source_closure.global_node) ->
      `Assoc ["global", number global.global_index;
        "source_global_id", number (GlobalDeclId.to_int global.view.declaration.def_id);
        "source_name", text (Print.name_to_string fmt global.view.declaration.item_meta.name);
        "kind", text (show_global_kind global.view.declaration.global_kind);
        "type", text (show_ty global.view.ty);
        "source_value", text (show_constant_expr global.view.value);
        "inherited_requirements", text (show_generic_params global.view.inherited_requirements);
        "arguments", text (show_generic_args global.view.arguments.pattern);
        "source_self_evidence", (match global.view.self_evidence with None -> `Null | Some evidence -> text (show_trait_ref evidence));
        "global_dependencies", `List (List.map number global.globals);
        "source_type_dependencies", `List (List.map number global.types);
        "opaque_value_contracts_required", `List (List.map text global.view.opaque_values);
        "global_initialization_semantics_discharged", flag false;
        "initializer_references", `List (List.map (fun ((resolved : Static_targets.resolved), destination) ->
          `Assoc ["reference", text (show_fn_ptr resolved.pointer);
            "self_evidence", (match resolved.self_evidence with None -> `Null | Some evidence -> text (show_trait_ref evidence));
            "target", target crate destination]) global.initializer_references) ]) graph.global_nodes);
    "global_failures", `List (List.map (fun (failure : Source_closure.global_failure) ->
      `Assoc ["owner", text failure.owner;
        "source_global_id", number (GlobalDeclId.to_int failure.reference.id);
        "arguments", text (show_generic_args failure.reference.generics);
        "error", text failure.message]) graph.global_failures);
    "failures", `List (List.map (fun (failure : Source_closure.failure) ->
      `Assoc ["instance", (match failure.instance with None -> `Null | Some index -> number index);
        "source_reference", text (Print.fn_ptr_to_string fmt failure.pointer);
        "error", text failure.message]) graph.failures);
    "roots", `List (List.map (target crate) graph.roots);
    "source_text_encoding", text "inline file contents are interned by exact file-name/crate in source_file_table; spans and checked ASTs are unchanged" ] in
    fields @ ["source_file_table", Diagnostic.source_files_json ()]);
  Printf.printf "Prepared source closure: scheduled=%d frames=%d leaves=%d failures=%d drops=%d; unqualified, no program emitted\n%!"
    graph.scheduled !prepared !leaves (List.length graph.failures) !drops;
  (* A successful construction is not a qualification. All model/drop/global/
     type obligations must be closed before an emitter can claim a program. *)
  if graph.failures <> [] || graph.global_failures <> [] || graph.scheduled_globals <> 0 ||
     graph.type_failures <> [] || graph.scheduled_types <> 0 ||
     !leaves <> 0 || !drops <> 0 || !primitives <> 0 || !virtual_methods <> 0 || !return_signatures <> 0 ||
     vtable_adapters.failures <> [] || vtable_adapters.unmatched_globals <> [] ||
     vtable_adapters.instances <> [] || vtable_adapters.virtual_instances <> [] ||
     vtable_adapters.return_calls <> [] || vtable_adapters.box_receiver_calls <> [] ||
     vtable_adapters.closure_captures <> [] || vtable_adapters.closure_invocations <> [] ||
     vtable_adapters.closure_receivers <> [] || vtable_adapters.closure_arguments <> [] ||
     vtable_adapters.carrier_effects.nodes <> [] || vtable_adapters.carrier_effects.failures <> [] ||
     vtable_adapters.closure_returns <> [] || vtable_adapters.closure_return_calls <> [] ||
     vtable_adapters.value_flow.edges <> [] || vtable_adapters.value_flow.failures <> [] then exit 2
