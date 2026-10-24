(* Focused source interface construction, never whole-program qualification. *)
open Charon
open Types
open LlbcAst
exception Selected of fun_decl * Instance_view.t
let contains text part =
  let rec at index = index + String.length part <= String.length text &&
    (String.sub text index (String.length part) = part || at (index + 1)) in at 0

let () =
  if Array.length Sys.argv <> 5 then failwith "usage: box_return_plan SOURCE.llbc ROOT-ARGUMENTS.json SOURCE-NAME-SUBSTRING OUTPUT.json";
  let crate = match OfJson.crate_of_json_file Sys.argv.(1) with Ok crate -> crate | Error message -> failwith message in
  let names = Yojson.Basic.from_file Sys.argv.(2) |> Yojson.Basic.Util.member "roots"
    |> Yojson.Basic.Util.to_list |> List.map Yojson.Basic.Util.to_string in
  let fmt = Print.crate_to_fmt_env crate in
  let declaration, view = try
    ignore (Source_closure.build crate (Source_roots.pointers crate names) ~on_view:(fun declaration view ->
      if contains (Print.name_to_string fmt declaration.item_meta.name) Sys.argv.(3) then raise (Selected (declaration, view))));
    invalid_arg "the actual selected dynamic Box producer function is absent from the source dependency prefix"
    with Selected (declaration, view) -> declaration, view in
  let frame = Function_frame.prepare crate view in
  let producers = ref [] in
  let collect = object inherit [_] iter_statement as super
    method! visit_statement env statement =
      (match statement.kind with Assign (_, Charon.Expressions.UnaryOp (Cast (CastUnsize (_, into, MetaVTable _)), _))
          when Option.is_some (Capture_return.predicate into) ->
            producers := Prepared_injection.create crate ~view ~frame statement.statement_id :: !producers
       | _ -> ()); super#visit_statement env statement
  end in collect#visit_block () frame.body;
  let routes = Capture_return.create crate ~view ~frame ~producers:(List.rev !producers) in
  let result = `Assoc ["schema", `String "auths-proof-source-box-return-construction/v1";
    "input", `String Sys.argv.(1); "public_roots", `List (List.map (fun name -> `String name) names);
    "source_function", `Int (FunDeclId.to_int declaration.def_id);
    "source_name", `String (Print.name_to_string fmt declaration.item_meta.name);
    "source_signature", `String (Diagnostic.show_fun_sig frame.signature);
    "actual_source_body", `String (Diagnostic.show_block frame.body);
    "source_producers", `List (List.map (Prepared_injection.report crate) routes.producers);
    "normal_source_return_routes", Capture_return.report crate routes;
    "whole_source_graph_constructed", `Bool false;
    "qualified", `Bool false; "program_emitted", `Bool false; "tests_run", `Bool false;
    "source_file_table", Diagnostic.source_files_json ()] in
  let output = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 Sys.argv.(4) in
  Fun.protect ~finally:(fun () -> close_out output) (fun () -> Yojson.Basic.pretty_to_channel output result);
  Printf.printf "Actual source Box return routes constructed: producers=%d normal_routes=%d; native source/loan/execution unqualified\n%!"
    (List.length routes.producers) (List.length routes.returns)
