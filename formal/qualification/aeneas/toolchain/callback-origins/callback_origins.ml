(* Construction-only source-origin comparison through the pinned Charon parser.
   It never mutates either program, rewrites names for extraction, or emits
   qualification evidence. Concrete instantiation names remain in the report. *)
open Charon
open Types
open LlbcAst

module Names = Map.Make (String)

let filename (span : Meta.span) =
  match span.data.file.name with
  | Meta.Local name | Meta.Virtual name | Meta.NotReal name -> name

let rec origin_name (crate : crate) depth name =
  if depth > 64 then failwith "recursive source-origin name";
  let element = function
    | PeIdent (text, disambiguator) ->
        Some (text ^ "#" ^ string_of_int (Disambiguator.to_int disambiguator))
    | PeTarget target -> Some ("target:" ^ target)
    | PeInstantiated _ -> None
    | PeImpl (ImplElemTy binder) ->
        Some ("impl-type:" ^ origin_type crate (depth + 1) binder.binder_value)
    | PeImpl (ImplElemTrait id) ->
        let implementation = TraitImplId.Map.find id crate.trait_impls in
        let declaration = TraitDeclId.Map.find implementation.impl_trait.id crate.trait_decls in
        let self = match implementation.impl_trait.generics.types with
          | self :: _ -> origin_type crate (depth + 1) self
          | [] -> failwith "trait implementation has no self type"
        in
        Some ("impl-trait:" ^ origin_name crate (depth + 1) declaration.item_meta.name ^ ":self:" ^ self)
  in
  String.concat "/" (List.filter_map element name)

and origin_type (crate : crate) depth = function
  | TAdt { id = TAdtId id; generics } ->
      (* Source callback implementers are closed record/visitor carriers. Do
         not merge a genuinely generic Self with a concrete specialization.
         Lifetimes carry no declaration identity; bindings are retained in the
         unmodified instance name and this is not lifetime/model adequacy. *)
      if generics.types <> [] || generics.const_generics <> [] then
        failwith "generic callback self type requires an explicit origin rule";
      let declaration = TypeDeclId.Map.find id crate.type_decls in
      origin_name crate (depth + 1) declaration.item_meta.name
  | _ -> failwith "non-record callback self type requires an explicit origin rule"

let labels name = List.filter_map (function PeIdent (text, _) -> Some text | _ -> None) name

let callback (crate : crate) (f : fun_decl) =
  match labels f.item_meta.name, f.src with
  | "auths_gateway" :: "recipe" :: _, TraitImplItem (_, trait_ref, _, _) ->
      let declaration = TraitDeclId.Map.find trait_ref.id crate.trait_decls in
      let method_name = List.hd (List.rev (labels f.item_meta.name)) in
      let selected = method_name = "serialize" || method_name = "deserialize"
        || method_name = "expecting"
        || (String.length method_name >= 6 && String.sub method_name 0 6 = "visit_") in
      selected && (match labels declaration.item_meta.name with "serde_core" :: _ -> true | _ -> false)
  | _ -> false

let inspect path =
  let crate = match OfJson.crate_of_json_file path with
    | Ok crate -> crate | Error message -> failwith message in
  if crate.name <> "auths_gateway" then failwith "source-origin comparison requires the shipping auths_gateway crate";
  let root_present = FunDeclId.Map.exists (fun _ f ->
    labels f.item_meta.name = ["auths_gateway"; "recipe"; "compile_source_bytes"]
      && f.item_meta.is_local && (match f.body with StructuredBody _ -> true | _ -> false)) crate.fun_decls in
  if not root_present then failwith "source-origin comparison requires the actual public compiler body";
  let fmt = Print.crate_to_fmt_env crate in
  let origins, errors = FunDeclId.Map.fold (fun id f (origins, errors) ->
    if not (callback crate f) then origins, errors else
    let instance = Print.name_to_string fmt f.item_meta.name in
    try
      let key = Printf.sprintf "%s:%d:%d:%s" (filename f.item_meta.span)
        f.item_meta.span.data.beg_loc.line f.item_meta.span.data.end_loc.line
        (origin_name crate 0 f.item_meta.name) in
      let body = match f.body with StructuredBody _ -> true | _ -> false in
      let entry = `Assoc [
        "function_id", `Int (FunDeclId.to_int id);
        "instance", `String instance;
        "local", `Bool f.item_meta.is_local;
        "structured_body", `Bool body;
        "source_file", `String (filename f.item_meta.span);
        "begin_line", `Int f.item_meta.span.data.beg_loc.line;
        "end_line", `Int f.item_meta.span.data.end_loc.line ] in
      let earlier = Option.value ~default:[] (Names.find_opt key origins) in
      Names.add key (entry :: earlier) origins, errors
    with Failure message ->
      origins, (`Assoc ["instance", `String instance; "error", `String message]) :: errors
  ) crate.fun_decls (Names.empty, []) in
  origins, List.rev errors

let () =
  if Array.length Sys.argv <> 4 then
    failwith "usage: callback_origins BASELINE.llbc CANDIDATE.llbc OUTPUT.json";
  let baseline, baseline_errors = inspect Sys.argv.(1) in
  let candidate, candidate_errors = inspect Sys.argv.(2) in
  let baseline_duplicates = Names.bindings baseline
    |> List.filter_map (fun (key, entries) -> if List.length entries = 1 then None else Some (`String key)) in
  let retained, missing = Names.fold (fun key original (retained, missing) ->
    match Names.find_opt key candidate with
    | None -> retained, (`Assoc ["origin", `String key; "baseline", `List original]) :: missing
    | Some instances ->
        let usable = List.exists (function
          | `Assoc fields -> List.assoc_opt "local" fields = Some (`Bool true)
              && List.assoc_opt "structured_body" fields = Some (`Bool true)
          | _ -> false) instances in
        if usable then
          (`Assoc ["origin", `String key; "baseline", `List original;
            "candidate", `List instances]) :: retained, missing
        else retained, (`Assoc ["origin", `String key; "baseline", `List original;
          "candidate", `List instances; "reason", `String "no local structured body"]) :: missing
  ) baseline ([], []) in
  let report = `Assoc [
    "schema", `String "auths-proof-callback-origin-construction/v1";
    "qualified", `Bool false;
    "scope", `String "declaration-origin comparison only; not reachability, lifetime, model or proof adequacy";
    "baseline", `String Sys.argv.(1); "candidate", `String Sys.argv.(2);
    "baseline_origins", `Int (Names.cardinal baseline);
    "baseline_empty", `Bool (Names.is_empty baseline);
    "baseline_duplicate_origins", `List baseline_duplicates;
    "candidate_origins", `Int (Names.cardinal candidate);
    "retained", `List (List.rev retained); "missing", `List (List.rev missing);
    "baseline_errors", `List baseline_errors; "candidate_errors", `List candidate_errors ] in
  Yojson.Basic.to_file Sys.argv.(3) report;
  Printf.printf "Callback origins: baseline=%d candidate=%d retained=%d missing=%d unsupported=%d; unqualified\n%!"
    (Names.cardinal baseline) (Names.cardinal candidate) (List.length retained) (List.length missing)
    (List.length baseline_errors + List.length candidate_errors);
  if Names.is_empty baseline || baseline_duplicates <> [] || missing <> []
      || baseline_errors <> [] || candidate_errors <> [] then exit 2
