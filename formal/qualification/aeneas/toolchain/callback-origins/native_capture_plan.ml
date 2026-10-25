(* Native Aeneas component construction for actual source return constructors.
   No public root is rewritten, no ordinary function result is supplied, and
   this tool never emits/adopts a whole-program qualification result. *)
open Charon
open Types
open LlbcAst

let write_json_exclusive path value =
  let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
  try Yojson.Basic.pretty_to_channel channel value; output_char channel '\n'; close_out channel
  with error -> close_out_noerr channel; (try Sys.remove path with Sys_error _ -> ()); raise error

(* Preserve the actual final abstraction environments before a later scope or
   ABI refusal. Absence is recorded as absence, not replaced by a made-up final
   EndAbs event or treated as a proof of all source heap/loan obligations. *)
let terminal_abstractions symbolic =
  let module V = Aeneas.Values in
  let module S = Aeneas.SymbolicAst in
  let rec delimiter = function
    | S.Meta (_, next) | S.Expansion (_, _, S.ExpandNoBranch (_, next)) -> delimiter next
    | S.Expansion (_, _, S.ExpandAdt [None, _, next]) -> delimiter next
    | S.ForwardEnd (_, _, _, branches) -> branches
    | _ -> invalid_arg "terminal abstraction receipt cannot omit an intervening symbolic effect" in
  let rec endpoint endings = function
    | S.Meta (_, next) -> endpoint endings next
    | S.EndAbs (_, abs, level, next) -> endpoint ((abs.V.abs_id, abs.kind, level) :: endings) next
    | S.Return (context, None) -> List.rev endings, context
    | _ -> invalid_arg "terminal abstraction receipt requires every actual ending and its original void-return context" in
  let id identity = `Int (V.AbsId.to_int identity) in
  let levels values = `List (List.map (fun value -> `Int value) values) in
  let describe (abs : V.abs) =
    let abstract, continuation = Native_borrow_protocol.active_levels abs in
    `Assoc ["identity", id abs.abs_id; "kind", `String (V.show_abs_kind abs.kind);
      "complete_original_abs_ast", `String (V.show_abs abs);
      "active_abstract_levels", levels abstract; "active_continuation_levels", levels continuation;
      "actual_native_has_live_borrows", `Bool (Aeneas.InterpBorrowsCore.abs_has_non_ended_eborrows abs 0);
      "actual_native_has_live_loans", `Bool (Aeneas.InterpBorrowsCore.abs_has_non_ended_eloans abs 0)] in
  let branches = RegionGroupId.Map.bindings (delimiter symbolic) |> List.map (fun (target, body) ->
    let endings, context = endpoint [] body in
    let remaining = Aeneas.Contexts.ctx_get_abs context in
    `Assoc ["target", `Int (RegionGroupId.to_int target);
      "actual_ending_sequence", `List (List.map (fun (identity, kind, level) ->
        `Assoc ["identity", id identity; "kind", `String (V.show_abs_kind kind); "level", `Int level;
          "actual_terminal_entry", (match V.AbsId.Map.find_opt identity remaining with None -> `Null | Some abs -> describe abs)]) endings);
      "all_remaining_abstractions", `List (List.map (fun (_, abs) -> describe abs) (V.AbsId.Map.bindings remaining))]) in
  `Assoc ["schema", `String "actual-native-backward-terminal-abstraction-contexts/v1";
    "branches", `List branches; "all_original_branch_endings_and_terminal_abstractions_retained", `Bool true;
    "missing_endings_or_ordinary_results_supplied", `Bool false;
    "native_context_absence_is_whole_source_loan_proof", `Bool false;
    "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]

let () =
  if Array.length Sys.argv <> 4 && Array.length Sys.argv <> 5 then
    invalid_arg "usage: native_capture_plan SOURCE.llbc ROOT-ARGUMENTS.json [WRITER-OWNER-TYPE-ID] OUTPUT.json";
  let output_path = Sys.argv.(Array.length Sys.argv - 1) in
  Aeneas.Config.set_backend "lean";
  Aeneas.Config.fail_hard := true;
  Aeneas.Config.warnings_as_errors := true;
  Aeneas.Config.sanity_checks := true;
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> invalid_arg message in
  let roots = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let graph, adapters, _ = Vtable_graph.close_source_dependencies crate (Source_roots.pointers crate roots) in
  let writer_runtime = if Array.length Sys.argv = 4 then None else (
    let owner_id = TypeDeclId.of_int (int_of_string Sys.argv.(3)) in
    let largest = match TypeDeclId.Map.max_binding_opt crate.type_decls with Some (id, _) -> TypeDeclId.to_int id | None -> -1 in
    if largest >= Int.max_int then invalid_arg "native writer type identities exceed the identifier space";
    Some (Writer_runtime.create crate ~source:graph ~adapters ~owner_id ~enum_id:(TypeDeclId.of_int (largest + 1)))) in
  Option.iter (fun witness -> Writer_runtime.write_lean (output_path ^ ".writer.lean") witness) writer_runtime;
  Option.iter (fun runtime ->
    let witness = Writer_input_bound.create crate runtime in
    Writer_input_bound.write_lean (output_path ^ ".writer-input-bound.lean") witness;
    write_json_exclusive (output_path ^ ".writer-input-bound.json") (Writer_input_bound.report crate witness)
  ) writer_runtime;
  let candidates = List.filter (fun (node : Source_closure.node) -> match node.frame with
    | Some frame -> Option.is_some frame.return_signature | None -> false) graph.nodes in
  if candidates = [] then invalid_arg "the complete actual source graph has no closure-return constructor";
  let next = ref (match FunDeclId.Map.max_binding_opt crate.fun_decls with
    | Some (id, _) -> FunDeclId.to_int id | None -> -1) in
  let values = List.map (fun (node : Source_closure.node) ->
    if !next >= Int.max_int then invalid_arg "native constructor identities exceed the identifier space";
    incr next;
    let witness = Native_capture_candidate.create ?writer_runtime crate ~node ~candidate_id:(FunDeclId.of_int !next) in
    let source_component = Native_capture_candidate.component_crate crate witness in
    (* The pinned interpreter distinguishes region-bearing signature types
       from erased executable local/place types. Use its original prepass at
       that API boundary; keep the complete reconstructed frame in [witness].
       This is not an inference of missing source lifetimes or permission to
       weaken the original source/loan refinement obligation. *)
    let native_candidate = Aeneas.PrePasses.erase_body_regions source_component witness.candidate in
    if { native_candidate with body = witness.candidate.body } <> witness.candidate then
      invalid_arg "native executable annotation erasure changed a source signature or declaration";
    let component = { source_component with fun_decls = FunDeclId.Map.add
      native_candidate.def_id native_candidate source_component.fun_decls } in
    Printf.eprintf "Native capture source_node=%d source_function=%d candidate=%d: hierarchy/context/symbolic construction\n%!"
      node.index (FunDeclId.to_int node.declaration.def_id) (FunDeclId.to_int native_candidate.def_id);
    let bound : Aeneas.LlbcAst.bound_fun_sig = { item_binder_params = native_candidate.generics;
      item_binder_value = native_candidate.signature } in
    let hierarchy = Aeneas.RegionsHierarchy.compute_regions_hierarchy_for_sig
      (Some witness.candidate.item_meta.span) component bound in
    let context = Aeneas.Interp.compute_contexts component in
    if !Aeneas.Errors.error_list <> [] then invalid_arg "the pinned native constructor context has unresolved errors";
    let symbolic_inputs, symbolic = match Aeneas.Translate.translate_function_to_symbolics context
        Aeneas.ContextsBase.empty_marked_ids native_candidate with
      | Some (inputs, expression) -> inputs, expression
      | None -> invalid_arg "the actual native constructor lost its transparent body" in
    if !Aeneas.Errors.error_list <> [] then invalid_arg "the pinned native constructor produced a failed symbolic body";
    let returns = ref 0 in
    let complete = object inherit [_] Aeneas.SymbolicAst.iter_expr as super
      method! visit_expr env expression =
        (match expression with
         | Aeneas.SymbolicAst.Error _ -> invalid_arg "a native error node cannot stand in for the actual source constructor"
         | Aeneas.SymbolicAst.Panic -> invalid_arg "a native panic cannot stand in for the actual move-only source constructor"
         | Aeneas.SymbolicAst.Return (_, Some _) -> incr returns
         | _ -> ());
        super#visit_expr env expression
    end in
    complete#visit_expr () symbolic;
    if !returns = 0 then invalid_arg "the actual native constructor has no value-returning path";
    let fmt = Aeneas.Print.crate_to_fmt_env component in
    (* Seal this completed phase before attempting a later translation stage.
       A later refusal must not erase the actual symbolic body, and this
       artifact must never imply pure translation or source qualification. *)
    let symbolic_path = output_path ^ ".symbolic-source-node-" ^ string_of_int node.index ^ ".json" in
    write_json_exclusive symbolic_path (`Assoc [
      "schema", `String "actual-source-native-capture-symbolic-component/v1";
      "source_node", `Int node.index;
      "source_function", `Int (FunDeclId.to_int node.declaration.def_id);
      "isolated_candidate", `Int (FunDeclId.to_int native_candidate.def_id);
      "complete_public_roots", `List (List.map (fun name -> `String name) roots);
      "candidate_signature", `String (show_fun_sig native_candidate.signature);
      "candidate_complete_requirements", `String (show_generic_params native_candidate.generics);
      "complete_source_generic_arguments", `String (show_generic_args witness.source_generic_arguments);
      "candidate_scoped_generic_arguments", `String (show_generic_args witness.candidate_generic_arguments);
      "native_executable_prepass", `String "pinned PrePasses.erase_body_regions";
      "source_region_bearing_frame_retained", `Bool true;
      "conditional_writer_runtime_overlay", (match writer_runtime with None -> `Null | Some runtime -> Writer_runtime.report crate runtime);
      "required_native_value_type_analysis", `List (List.map (fun id ->
        let declaration = TypeDeclId.Map.find id component.type_decls in
        `Assoc ["source_type", `Int (TypeDeclId.to_int id);
          "source_name", `String (Print.name_to_string fmt declaration.item_meta.name);
          "native_value_kind", `String (show_type_decl_kind declaration.kind);
          "contains_nested_mutable_borrows", `Bool (Aeneas.TypesUtils.type_decl_has_nested_mut_borrows
            (Some declaration.item_meta.span) context.type_ctx.type_infos declaration)])
        (TypeDeclId.Set.elements witness.required_types));
      "physical_pointer_metadata_obligations", `List (List.map (fun (id, metadata) ->
        `Assoc ["source_type", `Int (TypeDeclId.to_int id);
          "original_pointer_metadata", `String (show_ptr_metadata metadata);
          "source_and_native_layout_refinement_proved", `Bool false]) witness.metadata_obligations);
      "pinned_native_region_hierarchy", `String (Aeneas.RegionsHierarchy.show_regions_hierarchy hierarchy);
      "pinned_native_symbolic_body", `String (Aeneas.PrintSymbolicAst.expr_to_string fmt "" "  " symbolic);
      "native_symbolic_component_constructed", `Bool true;
      "native_value_return_nodes", `Int !returns;
      "native_error_or_panic_nodes", `Int 0;
      "native_pure_component_constructed", `Bool false;
      "native_lean_component_constructed", `Bool false;
      "source_to_native_value_loan_and_opaque_interface_refinement_proved", `Bool false;
      "whole_program_emitted", `Bool false;
      "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]);
    Printf.eprintf "Native symbolic capture sealed at %s; attempting pure translation\n%!" symbolic_path;
    let terminal_path = output_path ^ ".terminal-abstractions-source-node-" ^ string_of_int node.index ^ ".json" in
    write_json_exclusive terminal_path (terminal_abstractions symbolic);
    let projection = Borrow_projection.create component native_candidate in
    let projection_path = output_path ^ ".projection-source-node-" ^ string_of_int node.index in
    Borrow_projection.write_lean (projection_path ^ ".lean") projection;
    write_json_exclusive (projection_path ^ ".json") (Borrow_projection.report component projection);
    let forward_value = Native_capture_value.create component projection symbolic_inputs symbolic in
    let forward_path = output_path ^ ".forward-value-source-node-" ^ string_of_int node.index in
    Native_capture_value.write_lean (forward_path ^ ".lean") projection forward_value;
    write_json_exclusive (forward_path ^ ".json")
      (Native_capture_value.report component projection symbolic_inputs symbolic forward_value);
    let protocol = Native_borrow_protocol.create component projection symbolic_inputs symbolic forward_value in
    let protocol_path = output_path ^ ".backward-protocol-source-node-" ^ string_of_int node.index in
    Native_borrow_protocol.write_lean (protocol_path ^ ".lean") protocol;
    write_json_exclusive (protocol_path ^ ".json")
      (Native_borrow_protocol.report component projection symbolic_inputs symbolic forward_value protocol);
    let wiring = Native_borrow_wiring.create component projection symbolic_inputs symbolic forward_value protocol in
    let wiring_path = output_path ^ ".backward-wiring-source-node-" ^ string_of_int node.index in
    Native_borrow_wiring.write_lean (wiring_path ^ ".lean") wiring;
    write_json_exclusive (wiring_path ^ ".json")
      (Native_borrow_wiring.report component projection symbolic_inputs symbolic forward_value protocol wiring);
    let borrow_levels = Native_borrow_levels.create component projection symbolic_inputs symbolic forward_value protocol wiring in
    let borrow_levels_path = output_path ^ ".borrow-levels-source-node-" ^ string_of_int node.index in
    Native_borrow_levels.write_lean (borrow_levels_path ^ ".lean") borrow_levels;
    write_json_exclusive (borrow_levels_path ^ ".json")
      (Native_borrow_levels.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels);
    let backward_types = Native_backward_types.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels in
    let backward_types_path = output_path ^ ".backward-types-source-node-" ^ string_of_int node.index in
    (* Preserve the complete actual native signature before a stricter reflected
       type fragment can refuse an unsupported dictionary/constant/binder. *)
    write_json_exclusive (backward_types_path ^ ".json")
      (Native_backward_types.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types);
    Native_backward_types.write_lean (backward_types_path ^ ".lean") backward_types;
    let root_origins = Native_root_origins.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types in
    let root_origins_path = output_path ^ ".root-origins-source-node-" ^ string_of_int node.index in
    write_json_exclusive (root_origins_path ^ ".json")
      (Native_root_origins.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins);
    Native_root_origins.write_lean (root_origins_path ^ ".lean") projection root_origins;
    let root_payload = Native_root_payload.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins in
    let root_payload_path = output_path ^ ".root-payload-source-node-" ^ string_of_int node.index in
    write_json_exclusive (root_payload_path ^ ".json")
      (Native_root_payload.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload);
    Native_root_payload.write_lean (root_payload_path ^ ".lean") root_payload;
    let views = Native_borrow_view.create component projection symbolic_inputs symbolic forward_value protocol wiring in
    let views_path = output_path ^ ".backward-views-source-node-" ^ string_of_int node.index in
    Native_borrow_view.write_lean (views_path ^ ".lean") views;
    write_json_exclusive (views_path ^ ".json")
      (Native_borrow_view.report component projection symbolic_inputs symbolic forward_value protocol wiring views);
    let transport = Native_borrow_transport.create component projection symbolic_inputs symbolic forward_value protocol wiring views in
    let transport_path = output_path ^ ".backward-transport-source-node-" ^ string_of_int node.index in
    Native_borrow_transport.write_lean (transport_path ^ ".lean") transport;
    write_json_exclusive (transport_path ^ ".json")
      (Native_borrow_transport.report component projection symbolic_inputs symbolic forward_value protocol wiring views transport);
    let current_carrier = Current_borrow_carrier.create component projection symbolic_inputs symbolic forward_value protocol wiring views transport in
    let current_path = output_path ^ ".current-carrier-source-node-" ^ string_of_int node.index in
    Current_borrow_carrier.write_lean (current_path ^ ".lean") current_carrier;
    write_json_exclusive (current_path ^ ".json")
      (Current_borrow_carrier.report component projection symbolic_inputs symbolic forward_value protocol wiring views transport current_carrier);
    let defaults = Native_borrow_defaults.create component projection symbolic_inputs symbolic forward_value protocol wiring in
    let defaults_path = output_path ^ ".backward-defaults-source-node-" ^ string_of_int node.index in
    Native_borrow_defaults.write_lean (defaults_path ^ ".lean") defaults;
    write_json_exclusive (defaults_path ^ ".json")
      (Native_borrow_defaults.report component projection symbolic_inputs symbolic forward_value protocol wiring defaults);
    let root_bindings = Native_root_bindings.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults in
    let root_bindings_path = output_path ^ ".root-bindings-source-node-" ^ string_of_int node.index in
    write_json_exclusive (root_bindings_path ^ ".json")
      (Native_root_bindings.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings);
    Native_root_bindings.write_lean (root_bindings_path ^ ".lean") root_bindings;
    let reconstruction = Native_nested_reconstruction.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings in
    let reconstruction_path = output_path ^ ".nested-reconstruction-source-node-" ^ string_of_int node.index in
    write_json_exclusive (reconstruction_path ^ ".json")
      (Native_nested_reconstruction.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction);
    Native_nested_reconstruction.write_lean (reconstruction_path ^ ".lean") root_payload reconstruction;
    let scoped_defaults = Native_scoped_defaults.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction in
    let scoped_defaults_path = output_path ^ ".scoped-defaults-source-node-" ^ string_of_int node.index in
    write_json_exclusive (scoped_defaults_path ^ ".json")
      (Native_scoped_defaults.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults);
    Native_scoped_defaults.write_lean (scoped_defaults_path ^ ".lean") root_payload scoped_defaults;
    let foreign_defaults = Native_foreign_defaults.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults in
    let foreign_defaults_path = output_path ^ ".foreign-defaults-source-node-" ^ string_of_int node.index in
    write_json_exclusive (foreign_defaults_path ^ ".json")
      (Native_foreign_defaults.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults foreign_defaults);
    Native_foreign_defaults.write_lean (foreign_defaults_path ^ ".lean") root_payload foreign_defaults;
    let owned_bindings = Native_owned_bindings.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults in
    let owned_bindings_path = output_path ^ ".owned-bindings-source-node-" ^ string_of_int node.index in
    write_json_exclusive (owned_bindings_path ^ ".json")
      (Native_owned_bindings.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults owned_bindings);
    Native_owned_bindings.write_lean (owned_bindings_path ^ ".lean") root_payload owned_bindings;
    let projector_kinds = Native_projector_kinds.analyze component projection symbolic_inputs symbolic forward_value protocol wiring in
    let projector_kinds_path = output_path ^ ".projector-kinds-source-node-" ^ string_of_int node.index in
    write_json_exclusive (projector_kinds_path ^ ".json") (Native_projector_kinds.report projector_kinds);
    Native_projector_kinds.require_admitted projector_kinds;
    Native_projector_kinds.write_lean (projector_kinds_path ^ ".lean") projector_kinds;
    let consumed_coverage = Native_consumed_coverage.analyze component projection symbolic_inputs symbolic forward_value protocol wiring in
    let consumed_coverage_path = output_path ^ ".consumed-coverage-source-node-" ^ string_of_int node.index in
    write_json_exclusive (consumed_coverage_path ^ ".json") (Native_consumed_coverage.report consumed_coverage);
    Native_consumed_coverage.require_admitted consumed_coverage;
    Native_consumed_coverage.write_lean (consumed_coverage_path ^ ".lean") consumed_coverage;
    let consumed_reconstruction = Native_consumed_reconstruction.analyze component projection consumed_coverage in
    let consumed_reconstruction_path = output_path ^ ".consumed-reconstruction-source-node-" ^ string_of_int node.index in
    write_json_exclusive (consumed_reconstruction_path ^ ".json") (Native_consumed_reconstruction.report consumed_reconstruction);
    Native_consumed_reconstruction.write_lean (consumed_reconstruction_path ^ ".lean") consumed_reconstruction;
    let root_programs = Native_root_programs.create component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults foreign_defaults owned_bindings in
    let root_programs_path = output_path ^ ".root-programs-source-node-" ^ string_of_int node.index in
    write_json_exclusive (root_programs_path ^ ".json")
      (Native_root_programs.report component projection symbolic_inputs symbolic forward_value protocol wiring borrow_levels backward_types root_origins root_payload defaults root_bindings reconstruction scoped_defaults foreign_defaults owned_bindings root_programs);
    Native_root_programs.write_lean (root_programs_path ^ ".lean") root_payload root_programs;
    let forward_context = Aeneas.Interp.compute_contexts component in
    let nested_declarations = TypeDeclId.Map.bindings forward_context.type_ctx.to_extract |>
      List.filter (fun (_, (declaration : type_decl)) ->
        Aeneas.TypesUtils.type_decl_has_nested_mut_borrows
          (Some declaration.item_meta.span) forward_context.type_ctx.type_infos declaration) in
    let forward_declarations = List.map (fun (identity, (declaration : type_decl)) ->
      let native = Aeneas.SymbolicToPureTypes.translate_type_decl forward_context declaration in
      let parameters, predicates = Aeneas.SymbolicToPureTypes.translate_generic_params
        (Some declaration.item_meta.span) declaration.generics in
      if native.def_id <> identity || native.llbc_generics <> declaration.generics ||
          native.generics <> parameters || native.preds <> predicates ||
          not (Aeneas.SymbolicToPureTypes.complete_nested_forward_kind forward_context
            declaration.item_meta.span declaration.kind native.kind) then
        invalid_arg "a nested forward declaration lost original fields or complete generic requirements";
      `Assoc ["identity", `Int (TypeDeclId.to_int identity);
        "complete_original_declaration", `String (show_type_decl declaration);
        "complete_native_declaration", `String (Aeneas.Pure.show_type_decl native);
        "complete_forward_field_certificate", `Bool true;
        "source_heap_loan_backward_continuation_adequacy_proved", `Bool false]
    ) nested_declarations in
    if !Aeneas.Errors.error_list <> [] then
      invalid_arg "nested forward declaration construction has unresolved original diagnostics";
    write_json_exclusive (output_path ^ ".forward-declarations-source-node-" ^ string_of_int node.index ^ ".json")
      (`Assoc ["schema", `String "checked-complete-native-nested-forward-declarations/v1";
        "declarations", `List forward_declarations;
        "original_native_to_extract_declaration_count", `Int (TypeDeclId.Map.cardinal forward_context.type_ctx.to_extract);
        "retained_source_lookup_declaration_count", `Int (TypeDeclId.Map.cardinal forward_context.type_ctx.type_decls);
        "original_backward_ending_environment_and_loan_guards_retained", `Bool true;
        "tests_run", `Bool false; "lean_elaboration_run", `Bool false; "qualified", `Bool false]);
    (* Continue through the pinned pure translation and Lean extractor. A
       successful symbolic trace alone is not an emitted native definition.
       Only the selected component declaration groups are translated; the
       complete original maps remain available for name/type lookup. *)
    let pure_context, pure_component = Aeneas.Translate.translate_crate_to_pure
      component Aeneas.ContextsBase.empty_marked_ids in
    if !Aeneas.Errors.error_list <> [] then
      invalid_arg "the native constructor pure translation contains unresolved errors";
    let pure_complete = object inherit [_] Aeneas.Pure.iter_expr as super
      method! visit_expr env expression =
        (match expression with
         | Aeneas.Pure.EError _ -> invalid_arg "a pure error placeholder cannot replace the source constructor"
         | Aeneas.Pure.Loop _ -> invalid_arg "the pure move-only constructor cannot acquire a loop"
         | _ -> ());
        super#visit_expr env expression
      method! visit_pure_builtin_fun_id _ = function
        | Aeneas.Pure.Fail | Aeneas.Pure.Assert ->
            invalid_arg "the pure move-only constructor cannot acquire a failure or assertion path"
        | _ -> ()
    end in
    (match pure_component.fun_decls with
     | [translation] when translation.f.def_id = native_candidate.def_id &&
         Option.is_some translation.f.body && translation.loops = [] ->
         List.iter (fun (definition : Aeneas.Pure.fun_decl) -> match definition.body with
           | Some body -> pure_complete#visit_texpr () body.body
           | None -> invalid_arg "a native constructor decomposition introduced an opaque body")
           (translation.f :: translation.bodies)
     | _ -> invalid_arg "the pure native constructor lost its sole transparent source function or introduced a loop");
    if pure_component.global_decls <> [] || pure_component.trait_decls <> [] || pure_component.trait_impls <> [] then
      invalid_arg "the isolated native constructor has undeclared global or trait emission dependencies";
    let native_directory = output_path ^ ".native-source-node-" ^ string_of_int node.index in
    Sys.mkdir native_directory 0o700;
    let notice = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600
      (Filename.concat native_directory "UNQUALIFIED.txt") in
    Fun.protect ~finally:(fun () -> close_out notice) (fun () ->
      output_string notice "Conditional native component construction only. No source/loan/layout refinement, Lean elaboration, whole-program emission, or qualification is established.\n");
    let extracted_opaque = ref false in
    Aeneas.Translate.extract_translated_crate Sys.argv.(1) native_directory None
      component pure_context pure_component extracted_opaque;
    if !extracted_opaque || !Aeneas.Errors.error_list <> [] then
      invalid_arg "the native constructor extraction introduced an opaque declaration or unresolved error";
    let native_files = Sys.readdir native_directory |> Array.to_list |> List.sort String.compare in
    if not (List.exists (fun name -> Filename.check_suffix name ".lean") native_files) then
      invalid_arg "the pinned native constructor extractor emitted no Lean source";
    `Assoc ["source_node", `Int node.index;
      "source_function", `Int (FunDeclId.to_int node.declaration.def_id);
      "isolated_candidate", `Int (FunDeclId.to_int witness.candidate.def_id);
      "complete_actual_source_candidate_replays", `Bool (Native_capture_candidate.replay crate witness);
      "candidate_signature", `String (show_fun_sig witness.candidate.signature);
      "candidate_complete_requirements", `String (show_generic_params witness.candidate.generics);
      "native_executable_prepass", `String "pinned PrePasses.erase_body_regions";
      "source_region_bearing_frame_retained", `Bool true;
      "source_to_native_annotation_and_loan_refinement_proved", `Bool false;
      "complete_source_generic_arguments", `String (show_generic_args witness.source_generic_arguments);
      "candidate_scoped_generic_arguments", `String (show_generic_args witness.candidate_generic_arguments);
      "specialized_original_region_parameters", `List (List.map (fun parameter -> `String (show_region_param parameter)) witness.specialized_region_parameters);
      "specialized_original_type_parameters", `List (List.map (fun parameter -> `String (show_type_param parameter)) witness.specialized_type_parameters);
      "specialized_original_const_parameters", `List (List.map (fun parameter -> `String (show_const_generic_param parameter)) witness.specialized_const_parameters);
      "required_type_count", `Int (TypeDeclId.Set.cardinal witness.required_types);
      "required_types", `List (List.map (fun id -> `Int (TypeDeclId.to_int id)) (TypeDeclId.Set.elements witness.required_types));
      "physical_pointer_metadata_obligations", `List (List.map (fun (id, metadata) ->
        `Assoc ["source_type", `Int (TypeDeclId.to_int id);
          "original_pointer_metadata", `String (show_ptr_metadata metadata);
          "native_layout_and_source_representation_refinement_proved", `Bool false]) witness.metadata_obligations);
      "pinned_native_region_hierarchy", `String (Aeneas.RegionsHierarchy.show_regions_hierarchy hierarchy);
      "pinned_native_symbolic_body", `String (Aeneas.PrintSymbolicAst.expr_to_string fmt "" "  " symbolic);
      "native_symbolic_component_constructed", `Bool true;
      "native_pure_component_constructed", `Bool true;
      "native_lean_component_directory", `String native_directory;
      "native_lean_component_files", `List (List.map (fun name -> `String name) native_files);
      "native_extracted_opaque_declarations", `Bool false;
      "native_value_return_nodes", `Int !returns;
      "native_error_or_panic_nodes", `Int 0;
      "original_opaque_interface_and_source_loan_refinement_proved", `Bool false;
      "whole_program_emitted", `Bool false; "qualified", `Bool false]
  ) candidates in
  let report = `Assoc ["schema", `String "actual-source-native-capture-component/v1";
    "complete_public_root_count", `Int (List.length roots);
    "complete_source_worklist_attempted", `Bool true;
    "original_public_roots_or_bodies_rewritten", `Bool false;
    "native_component_declarations_are_a_whole_program", `Bool false;
    "conditional_writer_runtime_overlay", (match writer_runtime with None -> `Null | Some witness -> Writer_runtime.report crate witness);
    "source_to_lifted_runtime_input_relation_proved", `Bool false;
    "components", `List values; "program_emitted", `Bool false;
    "tests_run", `Bool false; "qualified", `Bool false] in
  write_json_exclusive output_path report;
  Printf.printf "Pinned native symbolic constructor components written: %d; unqualified/no whole program\n%!" (List.length values)
