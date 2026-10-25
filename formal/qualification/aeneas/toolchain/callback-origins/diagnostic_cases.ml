(* Source display interning regressions. Deferred to final validation. *)
open Charon

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true

let () =
  let original : Meta.file = { name = Meta.Local "source-interning-fixture.rs";
    crate_name = "construction_fixture"; contents = Some "pub fn source() {}\n" } in
  let shown = Diagnostic.file original in
  require "display interning must not mutate checked source contents"
    (original.contents = Some "pub fn source() {}\n");
  require "file identity and original presence must remain in the display"
    (shown.name = original.name && shown.crate_name = original.crate_name &&
      shown.contents = Some "[source_file_table contents]");
  let absent = Diagnostic.file { original with contents = None } in
  require "a missing original source text must remain distinguishable from an interned present text"
    (absent.contents = None);
  require "repeated identical source texts must use the same display reference"
    (Diagnostic.file original = shown);
  let files = Diagnostic.source_files_json () |> Yojson.Basic.Util.to_list in
  let rows = List.filter (fun row -> Yojson.Basic.Util.member "crate" row =
    `String original.crate_name) files in
  require "the complete original text must be stored exactly once"
    (match rows with [row] -> Yojson.Basic.Util.member "contents" row =
      `String "pub fn source() {}\n" | _ -> false);
  require "the same source identity with different text must be refused"
    (refuses (fun () -> ignore (Diagnostic.file
      { original with contents = Some "pub fn changed() {}\n" })))
