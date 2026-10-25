(* Construction diagnostics retain complete source facts. Stream one frame at
   a time instead of keeping every expanded pretty-printed AST alive. This
   changes neither the checking computation nor the JSON value. Publication
   happens only after the complete array and final metadata are written. *)
type sink = { channel : out_channel; finish : unit -> unit; abort : unit -> unit }

let open_sink path compressed =
  if not compressed then (
    let channel = open_out_gen [Open_wronly; Open_creat; Open_excl; Open_binary] 0o600 path in
    { channel; finish = (fun () -> close_out channel);
      abort = (fun () -> close_out_noerr channel) }
  ) else (
    let output = Unix.openfile path [Unix.O_WRONLY; Unix.O_CREAT; Unix.O_EXCL; Unix.O_CLOEXEC] 0o600 in
    let reader, writer = Unix.pipe ~cloexec:true () in
    let pid = try Unix.create_process "/usr/bin/gzip" [|"gzip"; "-c"|]
        reader output Unix.stderr
      with error -> Unix.close reader; Unix.close writer; Unix.close output; raise error in
    Unix.close reader;
    Unix.close output;
    let channel = Unix.out_channel_of_descr writer in
    let wait () = match snd (Unix.waitpid [] pid) with
      | Unix.WEXITED 0 -> ()
      | _ -> failwith "construction interface compression did not complete" in
    { channel;
      finish = (fun () -> close_out channel; wait ());
      abort = (fun () -> close_out_noerr channel; try wait () with _ -> ()) }
  )

let write path ~array_name ~values ~encode ~metadata =
  if Sys.file_exists path then invalid_arg "construction output already exists";
  let partial = path ^ ".partial-" ^ string_of_int (Unix.getpid ()) in
  let sink = open_sink partial (Filename.check_suffix path ".gz") in
  let channel = sink.channel in
  try
    output_char channel '{';
    Yojson.Basic.to_channel channel (`String array_name);
    output_string channel ":[";
    List.iteri (fun index value ->
      if index <> 0 then output_char channel ',';
      Yojson.Basic.to_channel channel (encode value);
      flush channel) values;
    output_char channel ']';
    List.iter (fun (name, value) ->
      if name = array_name then invalid_arg "construction metadata duplicates its streamed array";
      output_char channel ',';
      Yojson.Basic.to_channel channel (`String name);
      output_char channel ':';
      Yojson.Basic.to_channel channel value) (metadata ());
    output_string channel "}\n";
    sink.finish ();
    Sys.rename partial path
  with error -> sink.abort (); raise error
