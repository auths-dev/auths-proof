(* Diagnostic publication regressions, deferred to the final validation batch. *)
let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true
let own_output ?(compressed = false) action =
  let seed = Filename.temp_file "auths-source-interface-" (if compressed then ".json.gz" else ".json") in
  Sys.remove seed;
  let partial = seed ^ ".partial-" ^ string_of_int (Unix.getpid ()) in
  Fun.protect ~finally:(fun () -> List.iter (fun path ->
    if Sys.file_exists path then Sys.remove path) [seed; partial]) (fun () -> action seed)

let () =
  own_output (fun path ->
    let encoded = ref 0 in
    let original = ["first\n\"quoted\""; "second"; "third"] in
    Json_stream.write path ~array_name:"frames" ~values:original
      ~encode:(fun value -> incr encoded; `String value)
      ~metadata:(fun () -> ["encoded", `Int !encoded; "qualified", `Bool false]);
    let object_ = Yojson.Basic.from_file path in
    let open Yojson.Basic.Util in
    require "streamed strings must preserve exact escaped data"
      (object_ |> member "frames" |> to_list |> List.map to_string = original);
    require "final metadata must observe all constructed frames"
      (object_ |> member "encoded" |> to_int = 3);
    require "a diagnostic must retain its unqualified status"
      (object_ |> member "qualified" |> to_bool = false);
    require "an existing construction artifact must not be overwritten"
      (refuses (fun () -> Json_stream.write path ~array_name:"frames" ~values:[]
        ~encode:(fun _ -> `Null) ~metadata:(fun () -> [])));
    require "refusal must preserve the previously published object"
      (Yojson.Basic.from_file path = object_));
  own_output (fun path ->
    require "a frame encoding failure must abort publication"
      (refuses (fun () -> Json_stream.write path ~array_name:"frames" ~values:[1; 2]
        ~encode:(fun value -> if value = 2 then invalid_arg "intentional fixture refusal" else `Int value)
        ~metadata:(fun () -> [])));
    require "a failed interface must not appear at the authoritative output path"
      (not (Sys.file_exists path)));
  own_output (fun path ->
    require "a duplicate streamed-array field must refuse publication"
      (refuses (fun () -> Json_stream.write path ~array_name:"frames" ~values:[]
        ~encode:(fun _ -> `Null) ~metadata:(fun () -> ["frames", `List []])));
    require "duplicate metadata must not publish an ambiguous JSON object"
      (not (Sys.file_exists path)));
  own_output ~compressed:true (fun path ->
    let values = [`String "full source\n\"unchanged\""; `Int 7] in
    Json_stream.write path ~array_name:"frames" ~values ~encode:Fun.id
      ~metadata:(fun () -> ["qualified", `Bool false]);
    let input = Unix.open_process_args_in "/usr/bin/gzip" [|"gzip"; "-dc"; path|] in
    let object_ = Yojson.Basic.from_channel input in
    let status = Unix.close_process_in input in
    require "the compressed interface must complete its external encoder" (status = Unix.WEXITED 0);
    require "compression must preserve all complete JSON source values"
      (Yojson.Basic.Util.member "frames" object_ = `List values);
    require "compression must retain the unqualified status"
      (Yojson.Basic.Util.member "qualified" object_ = `Bool false));
  own_output ~compressed:true (fun path ->
    require "compressed encoding failure must abort publication"
      (refuses (fun () -> Json_stream.write path ~array_name:"frames" ~values:[1; 2]
        ~encode:(fun value -> if value = 2 then invalid_arg "intentional fixture refusal" else `Int value)
        ~metadata:(fun () -> [])));
    require "a failed compressed interface must not publish a partial authoritative result"
      (not (Sys.file_exists path)))
