(* Construction-only, source-backed function-instance closure. This follows
   calls and function-value references in actual structured bodies; it emits
   no transformed program and cannot qualify a proof or a library model. *)
open Charon
open Types
open LlbcAst
open Diagnostic

module Key = Map.Make (struct
  type t = fun_decl_id * generic_args
  let compare (left_id, left_args) (right_id, right_args) =
    let ids = FunDeclId.compare_id left_id right_id in
    if ids <> 0 then ids else compare_generic_args left_args right_args
end)

let labels name = List.filter_map (function PeIdent (text, _) -> Some text | _ -> None) name
let text value = `String value
let bool value = `Bool value
let count value = `Int value
let empty_args : generic_args = { regions = []; types = []; const_generics = []; trait_refs = [] }

let dispatch_name = function
  | Static_targets.Direct -> "direct"
  | Static_targets.Implementation -> "actual-implementation"
  | Static_targets.Default -> "actual-default-method"
  | Static_targets.NoopDestruct -> "pinned-noop-destructor"
  | Static_targets.FnDefCall _ -> "source-function-item-callable-adapter"
  | Static_targets.DynamicMethod _ -> "actual-virtual-interface-adapter-required"

let () =
  if Array.length Sys.argv <> 4 then
    failwith "usage: closure_plan ORIGINAL.llbc CONSTRUCTION-ARGUMENTS.json OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with
    | Ok crate -> crate | Error error -> failwith error in
  if crate.name <> "auths_gateway" then failwith "closure construction requires the shipping library";
  let requested = match Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots" with
    | `List roots -> List.map Yojson.Basic.Util.to_string roots
    | _ -> failwith "the exact construction root list is absent" in
  if List.length requested <> 21 || List.length (List.sort_uniq String.compare requested) <> 21 then
    failwith "closure construction requires all twenty-one distinct native recipe roots";
  if not (List.mem "auths_gateway::recipe::compile_source_bytes" requested) then
    failwith "the actual public byte-entry root is absent";
  let fmt = Print.crate_to_fmt_env crate in
  let pending = Queue.create () in
  let known = ref Key.empty in
  let nodes = ref [] in
  let edges = ref [] in
  let errors = ref [] in
  let obligations = ref [] in
  let type_requirements = ref [] in
  let unsatisfied_types = ref 0 in
  let impl_reconstructions = ref [] in
  let metadata_reconstructions = ref [] in
  let quantified_families = ref [] in
  let next = ref 0 in
  let add_error ?(arguments = `Null) caller target message =
    errors := `Assoc ["caller", caller; "target", text target; "error", text message;
      "argument_evidence", arguments] :: !errors in
  let rec schedule (resolved : Static_targets.resolved) =
    match resolved.dispatch, resolved.pointer.kind with
    | Static_targets.DynamicMethod plan, _ -> `Assoc [
        "virtual_interface", Dynamic_method.report crate plan;
        "runtime_selection_and_execution_binding_required", bool true]
    | Static_targets.FnDefCall plan, _ ->
        `Assoc ["callable_adapter", Callable_instance.report crate plan;
          "source_target", schedule (Static_targets.resolve ~candidate_only:true crate plan.target)]
    | Static_targets.NoopDestruct, TraitMethod _ ->
        `Assoc ["builtin_noop_destructor", text (Print.fn_ptr_to_string fmt resolved.pointer);
          "reviewed_contract_required", bool true]
    | _, TraitMethod _ -> invalid_arg "static resolver left an indirect trait method"
    | _, FunId (FBuiltin id) -> `Assoc ["builtin", text (show_builtin_fun_id id)]
    | _, FunId (FRegular id) ->
        let factor, _, _ = Instance_view.factor_context resolved.pointer.generics resolved.self_evidence in
        let key = id, factor.pattern in
        let index = match Key.find_opt key !known with
          | Some index -> index
          | None ->
              if !next >= 50000 then invalid_arg "instance closure exceeds its construction-only resource limit";
              let index = !next in
              incr next;
              known := Key.add key index !known;
              Queue.add (index, resolved) pending;
              index in
        `Assoc ["instance", count index]
  in
  let roots = List.map (fun name ->
    let candidates = FunDeclId.Map.bindings crate.fun_decls |> List.filter (fun (_, f) ->
      String.concat "::" (labels f.item_meta.name) = name) in
    match candidates with
    | [(_, f)] ->
        if f.generics.types <> [] || f.generics.const_generics <> [] || f.generics.trait_clauses <> [] then
          failwith ("root needs an explicit closed non-region instantiation: " ^ name);
        let generics = { empty_args with regions = List.map
          (fun (region : region_param) -> RVar (Free region.index)) f.generics.regions } in
        let pointer : fn_ptr = { kind = FunId (FRegular f.def_id); generics } in
        let resolved = Static_targets.resolve crate pointer in
        `Assoc ["name", text name; "target", schedule resolved]
    | [] -> failwith ("requested source root absent: " ^ name)
    | _ -> failwith ("requested source root ambiguous: " ^ name)) requested in
  while not (Queue.is_empty pending) do
    let index, resolved = Queue.take pending in
    let id = match resolved.pointer.kind with
      | FunId (FRegular id) -> id
      | _ -> failwith "scheduled target is not a regular source function" in
    let f = match FunDeclId.Map.find_opt id crate.fun_decls with
      | Some f -> f | None -> failwith "scheduled original function declaration is absent" in
    let name = Print.name_to_string fmt f.item_meta.name in
    try
      let view = Instance_view.create ?self_evidence:resolved.self_evidence f resolved.pointer.generics in
      nodes := `Assoc [
        "instance", count index; "original_function_id", count (FunDeclId.to_int id);
        "source_name", text name; "local", bool f.item_meta.is_local;
        "auths", bool (Instance_view.is_auths f.item_meta.name);
        "region_parameter_count", count (List.length view.arguments.parameters);
        "pattern", text (show_generic_args view.arguments.pattern);
        "original_signature_instantiated", text (show_fun_sig view.signature);
        "requirements_retained", text (show_generic_params view.inherited_requirements);
        "structured_body_preserved", bool (Option.is_some view.locals_and_body);
        "ordinary_leaf_model_required", bool (Option.is_none view.locals_and_body);
        "declaration_emitted", bool false ] :: !nodes;
      (match view.locals_and_body with
       | None -> ()
       | Some (locals, body) ->
           let occurrence = ref 0 in
           let visitor = object
             inherit [_] iter_statement as super
             method! visit_fn_operand env operand =
               (match operand with
                | FnOpDynamic _ -> add_error (count index) "dynamic function operand"
                    "dynamic dispatch needs explicit sound target resolution"
                | FnOpRegular _ -> ());
               super#visit_fn_operand env operand
             method! visit_fn_ptr env pointer =
               let at = !occurrence in
               incr occurrence;
               let target = Print.fn_ptr_to_string fmt pointer in
               let resolved_arguments = ref None in
               (try
                  let resolved = Static_targets.resolve ~candidate_only:true crate pointer in
                  resolved_arguments := Some resolved.pointer.generics;
                  List.iter (fun (family : Static_targets.quantified_family) ->
                    let impl = TraitImplId.Map.find family.implementation crate.trait_impls in
                    quantified_families := `Assoc ["caller", count index; "occurrence", count at;
                      "implementation", count (TraitImplId.to_int family.implementation);
                      "representative_arguments", text (show_generic_args family.witness.representative_arguments);
                      "universal_binder", `List (List.map (fun parameter -> text (show_region_param parameter)) family.witness.expected.binder_regions);
                      "universal_predicate", text (show_trait_decl_ref family.witness.expected.binder_value);
                      "family_arguments", text (show_generic_args family.witness.family.reconstructed_arguments);
                      "replays", bool (Quantified_dictionary.replay impl.generics impl.impl_trait family.witness)] :: !quantified_families)
                    resolved.quantified_families;
                  List.iter (fun (reconstruction : Static_targets.metadata_reconstruction) ->
                    let witness = reconstruction.witness in
                    metadata_reconstructions := `Assoc ["caller", count index; "occurrence", count at;
                      "implementation", count (TraitImplId.to_int reconstruction.implementation);
                      "original", text (show_trait_decl_ref witness.original.binder_value);
                      "selected_source", text (show_trait_decl_ref witness.source.binder_value);
                      "completed", text (show_trait_decl_ref witness.completed.binder_value);
                      "replays", bool (Predicate_metadata.replay witness)] :: !metadata_reconstructions)
                    resolved.metadata_reconstructions;
                  List.iter (fun (reconstruction : Static_targets.impl_reconstruction) ->
                    let witness = reconstruction.witness in
                    impl_reconstructions := `Assoc [
                      "caller", count index; "occurrence", count at;
                      "implementation", count (TraitImplId.to_int reconstruction.implementation);
                      "original_arguments", text (show_generic_args witness.original_arguments);
                      "reconstructed_arguments", text (show_generic_args witness.reconstructed_arguments);
                      "declared_source_predicate", text (show_trait_decl_ref witness.source_predicate);
                      "reconstructed_predicate", text (show_trait_decl_ref witness.reconstructed_predicate);
                      "previous_informative_predicate", text (show_trait_decl_ref reconstruction.previous_predicate.binder_value);
                      "source_predicate", text (show_trait_decl_ref reconstruction.source_predicate.binder_value);
                      "complete_predicate_match", bool (witness.source_predicate = witness.reconstructed_predicate) ] :: !impl_reconstructions)
                    resolved.impl_reconstructions;
                  List.iter (fun (obligation : Static_targets.predicate_obligation) ->
                    obligations := `Assoc [
                      "caller", count index; "occurrence", count at;
                      "original_reference", text target; "boundary", text obligation.boundary;
                      "expected", text (show_trait_decl_ref obligation.expected.binder_value);
                      "expected_binders", `List (List.map (fun parameter -> text (show_region_param parameter)) obligation.expected.binder_regions);
                      "actual", text (show_trait_decl_ref obligation.actual.binder_value);
                      "actual_binders", `List (List.map (fun parameter -> text (show_region_param parameter)) obligation.actual.binder_regions);
                      "satisfied", bool false ] :: !obligations) resolved.obligations;
                  List.iter (fun (requirement : Static_targets.type_requirement) ->
                    let satisfied = requirement.left = requirement.right in
                    if not satisfied then incr unsatisfied_types;
                    type_requirements := `Assoc [
                      "caller", count index; "occurrence", count at;
                      "original_reference", text target;
                      "source_requirement", text (show_trait_type_constraint requirement.source.binder_value);
                      "left", text (show_ty requirement.left);
                      "right", text (show_ty requirement.right);
                      "satisfied", bool satisfied ] :: !type_requirements) resolved.type_requirements;
                  let destination = schedule resolved in
                  edges := `Assoc [
                    "caller", count index; "occurrence", count at;
                    "original_reference", text target;
                    "dispatch", text (dispatch_name resolved.dispatch);
                    "declared_function_requirements", (match resolved.function_requirements with
                      | None -> `Null | Some requirements -> text (show_generic_params requirements));
                    "target", destination ] :: !edges
                with Invalid_argument message ->
                  let arguments = `Assoc [
                    "original", text (show_generic_args pointer.generics);
                    "selected_target", (match !resolved_arguments with
                      | Some arguments -> text (show_generic_args arguments)
                      | None -> `Null) ] in
                  add_error ~arguments (count index) target message);
               (* Function values can occur inside generic arguments as
                  FnDef types. Retain those references even when resolving
                  the enclosing ordinary call is unsupported. *)
               super#visit_fn_ptr env pointer
           end in
           List.iter (visitor#visit_local ()) locals;
           visitor#visit_block () body)
    with Invalid_argument message -> add_error
      ~arguments:(text (show_generic_args resolved.pointer.generics)) (count index) name message
  done;
  let complete = !errors = [] && !obligations = [] && !unsatisfied_types = 0 && List.length !nodes = !next in
  Yojson.Basic.to_file Sys.argv.(3) (`Assoc [
    "schema", text "auths-proof-source-instance-closure/v2";
    "qualified", bool false; "program_transformed", bool false;
    "scope", text "read-only source-target candidates; region predicate mismatches remain unsatisfied; ordinary leaves, globals, type declarations, adequacy and emitted specialization remain separate";
    "input", text Sys.argv.(1); "root_count", count (List.length roots);
    "instance_count", count !next; "edge_count", count (List.length !edges);
    "unsupported_count", count (List.length !errors);
    "unsatisfied_predicate_count", count (List.length !obligations);
    "associated_type_requirement_count", count (List.length !type_requirements);
    "unsatisfied_type_equality_count", count !unsatisfied_types;
    "source_impl_reconstruction_count", count (List.length !impl_reconstructions);
    "metadata_reconstruction_count", count (List.length !metadata_reconstructions);
    "quantified_source_family_count", count (List.length !quantified_families);
    "function_reference_closure_resolved", bool complete;
    "roots", `List roots; "instances", `List (List.rev !nodes);
    "edges", `List (List.rev !edges); "unsupported", `List (List.rev !errors);
    "unsatisfied_predicates", `List (List.rev !obligations);
    "associated_type_requirements", `List (List.rev !type_requirements);
    "source_impl_reconstructions", `List (List.rev !impl_reconstructions);
    "metadata_reconstructions", `List (List.rev !metadata_reconstructions);
    "quantified_source_families", `List (List.rev !quantified_families);
    "source_text_encoding", text "inline file text uses source_file_table references; original optional presence and spans remain";
    "source_file_table", Diagnostic.source_files_json () ]);
  Printf.printf "Source target candidates: roots=%d instances=%d edges=%d unsupported=%d unsatisfied=%d; unqualified\n%!"
    (List.length roots) !next (List.length !edges) (List.length !errors) (List.length !obligations);
  if not complete then exit 2
