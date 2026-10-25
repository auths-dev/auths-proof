(* Discover an actual instantiated source frame through all 21 public roots,
   then construct its pending virtual interface without rendering unrelated
   frames. Early discovery is explicitly not whole-program closure evidence. *)
open Charon
open Types
open LlbcAst
open Diagnostic

exception Selected of fun_decl * Instance_view.t

let contains text part =
  let rec at index = index + String.length part <= String.length text &&
    (String.sub text index (String.length part) = part || at (index + 1)) in at 0

let () =
  if Array.length Sys.argv <> 5 then
    failwith "usage: virtual_frame_plan SOURCE.llbc ROOT-ARGUMENTS.json SOURCE-NAME-SUBSTRING OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "virtual source construction requires the actual gateway crate";
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let pointers = Source_roots.pointers crate names in
  let fmt = Print.crate_to_fmt_env crate in
  let declaration, view =
    try ignore (Source_closure.build crate pointers ~on_view:(fun declaration view ->
      if contains (Print.name_to_string fmt declaration.item_meta.name) Sys.argv.(3) then raise (Selected (declaration, view))));
      invalid_arg "the actual selected source instantiation is not in the discovered dependency prefix"
    with Selected (declaration, view) -> declaration, view in
  let frame = Function_frame.prepare crate view in
  let result = `Assoc ["schema", `String "auths-proof-virtual-source-frame-construction/v1";
    "input", `String Sys.argv.(1); "public_root_count", `Int (List.length names);
    "qualified", `Bool false; "program_emitted", `Bool false; "tests_run", `Bool false;
    "whole_source_graph_constructed", `Bool false;
    "source_function", `Int (FunDeclId.to_int declaration.def_id);
    "source_name", `String (Print.name_to_string fmt declaration.item_meta.name);
    "source_parameters", `String (show_generic_params declaration.generics);
    "actual_capture_arguments", `String (show_generic_args view.call_arguments);
    "signature", `String (show_fun_sig frame.signature);
    "locals", `List (List.map (fun value -> `String (show_local value)) frame.locals);
    "staged_original_body", `String (show_block frame.body);
    "complete_region_certificate", region_certificate_json frame.region_certificate;
    "virtual_calls", `List (List.map (fun (call : Function_frame.dynamic_call) ->
      let receiver = Virtual_receiver.create crate ~view ~frame ~call in `Assoc [
      "statement", `Int (StatementId.to_int call.dynamic_statement_id);
      "actual_source_call", `String (show_call call.dynamic_source_call);
      "original_virtual_interface", Dynamic_method.report crate call.dynamic_plan;
      "source_receiver_provenance", Virtual_receiver.report receiver;
      "full_actual_abi_equalities", `List (List.map (fun (expected, actual) -> `Assoc [
        "expected", `String (show_ty expected); "actual", `String (show_ty actual);
        "equal", `Bool (expected = actual)]) call.dynamic_requirements);
      "runtime_receiver_selection_and_native_execution_proved", `Bool false]) frame.dynamic_calls);
    "source_file_table", source_files_json ()] in
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(4) in
  Fun.protect ~finally:(fun () -> close_out output) (fun () -> Yojson.Basic.pretty_to_channel output result);
  Printf.printf "Actual virtual frame constructed: function=%d interfaces=%d; source/loan/execution unqualified\n%!"
    (FunDeclId.to_int declaration.def_id) (List.length frame.dynamic_calls)
