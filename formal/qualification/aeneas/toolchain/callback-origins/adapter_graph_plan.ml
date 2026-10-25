(* Complete prepared source/adaptor construction, with an explicit index-only
   diagnostic output. Every source frame is constructed; unrelated frame text
   is not rendered. This is never an emitted program or qualification gate. *)
open Charon
open Types
open LlbcAst
open Diagnostic

let () =
  if Array.length Sys.argv <> 4 then failwith "usage: adapter_graph_plan SOURCE.llbc ROOT-ARGUMENTS.json OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> failwith message in
  let roots = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let graph, adapters, iterations = Vtable_graph.close_source_dependencies crate (Source_roots.pointers crate roots) in
  let frames = List.filter_map (fun (node : Source_closure.node) -> Option.map (fun frame -> node, frame) node.frame) graph.nodes in
  let fmt = Print.crate_to_fmt_env crate in
  let report = `Assoc ["schema", `String "auths-proof-prepared-adapter-index/v1";
    "input", `String Sys.argv.(1); "public_roots", `List (List.map (fun name -> `String name) roots);
    "qualified", `Bool false; "program_emitted", `Bool false; "tests_run", `Bool false;
    "complete_source_worklist_attempted", `Bool true;
    "source_frame_bodies_omitted_from_diagnostic_index", `Bool true;
    "scheduled_instances", `Int graph.scheduled; "source_nodes", `Int (List.length graph.nodes);
    "prepared_frames", `Int (List.length frames); "ordinary_leaves", `Int (List.length graph.nodes - List.length frames);
    "source_globals", `Int (List.length graph.global_nodes); "scheduled_source_types", `Int graph.scheduled_types;
    "source_type_nodes", `Int (List.length graph.type_nodes);
    "preserved_drops", `Int (List.fold_left (fun total (_, (frame : Function_frame.t)) -> total + List.length frame.preserved_drops) 0 frames);
    "original_opaque_return_signature_refinements_required", `List (List.filter_map (fun ((node : Source_closure.node), (frame : Function_frame.t)) ->
      Option.map (fun candidate -> `Assoc ["source_node", `Int node.index; "source_derivation", Return_signature.report crate candidate]) frame.return_signature) frames);
    "adapter_dependency_iterations", `Int iterations;
    "virtual_calls", `List (List.concat_map (fun ((node : Source_closure.node), (frame : Function_frame.t)) ->
      List.map (fun (call : Function_frame.dynamic_call) -> `Assoc ["source_node", `Int node.index;
        "source_function", `Int (FunDeclId.to_int node.declaration.def_id);
        "statement", `Int (StatementId.to_int call.dynamic_statement_id);
        "actual_source_call", `String (show_call call.dynamic_source_call);
        "source_interface", Dynamic_method.report crate call.dynamic_plan;
        "full_abi_equalities", `List (List.map (fun (expected, actual) -> `Assoc [
          "expected", `String (show_ty expected); "actual", `String (show_ty actual);
          "equal", `Bool (expected = actual)]) call.dynamic_requirements);
        "runtime_selection_and_execution_proved", `Bool false]) frame.dynamic_calls) frames);
    "adapters", Vtable_graph.report crate adapters;
    "function_failures", `List (List.map (fun (failure : Source_closure.failure) -> `Assoc [
      "instance", (match failure.instance with Some index -> `Int index | None -> `Null);
      "source_pointer", `String (show_fn_ptr failure.pointer);
      "source_name", `String (Print.fn_ptr_to_string fmt failure.pointer);
      "error", `String failure.message]) graph.failures);
    "global_failures", `List (List.map (fun (failure : Source_closure.global_failure) -> `Assoc [
      "owner", `String failure.owner; "source_global", `Int (GlobalDeclId.to_int failure.reference.id);
      "arguments", `String (show_generic_args failure.reference.generics); "error", `String failure.message]) graph.global_failures);
    "type_failures", `List (List.map (fun (failure : Source_closure.type_failure) -> `Assoc [
      "owner", `String failure.owner; "source_type", `String (show_type_decl_ref failure.reference);
      "error", `String failure.message]) graph.type_failures);
    "source_file_table", source_files_json ()] in
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(3) in
  Fun.protect ~finally:(fun () -> close_out output) (fun () -> Yojson.Basic.pretty_to_channel output report);
  Printf.printf "Complete source adapter index: functions=%d frames=%d failures=%d adapters=%d virtual=%d adapter_failures=%d; unqualified/no program\n%!"
    graph.scheduled (List.length frames) (List.length graph.failures) (List.length adapters.instances)
    (List.length adapters.virtual_instances) (List.length adapters.failures)
