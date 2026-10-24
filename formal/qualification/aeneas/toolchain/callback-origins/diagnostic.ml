(* Display-only source-text interning. Actual checked ASTs are untouched.
   Every displayed span retains its complete name/crate/range/provenance; file
   contents are stored once in the report table instead of inside every type,
   predicate and body pretty-print. Conflicting source texts are refused. *)
open Charon
open LlbcAst

module Files = Map.Make (struct
  type t = Meta.file_name * string
  let compare (name, crate) (other, other_crate) =
    let names = Meta.compare_file_name name other in
    if names <> 0 then names else String.compare crate other_crate
end)

let files : string option Files.t ref = ref Files.empty

let file (original : Meta.file) =
  let key = original.name, original.crate_name in
  (match Files.find_opt key !files with
   | None -> files := Files.add key original.contents !files
   | Some None -> files := Files.add key original.contents !files
   | Some (Some previous) -> (match original.contents with
       | None -> ()
       | Some current when previous = current -> ()
       | Some _ -> invalid_arg "construction source-file table contains conflicting text"));
  { original with contents = Option.map (fun _ -> "[source_file_table contents]") original.contents }

let display = object
  inherit [_] map_statement
  method! visit_span _ (original : Meta.span) =
    let data (value : Meta.span_data) = { value with file = file value.file } in
    { data = data original.data;
      generated_from_span = Option.map data original.generated_from_span }
end

let show_generic_args value = Types.show_generic_args (display#visit_generic_args () value)
let show_generic_params value = Types.show_generic_params (display#visit_generic_params () value)
let show_trait_decl_ref value = Types.show_trait_decl_ref (display#visit_trait_decl_ref () value)
let show_trait_ref value = Types.show_trait_ref (display#visit_trait_ref () value)
let show_trait_type_constraint value = Types.show_trait_type_constraint (display#visit_trait_type_constraint () value)
let show_ty value = Types.show_ty (display#visit_ty () value)
let show_fn_ptr value = Types.show_fn_ptr (display#visit_fn_ptr () value)
let show_type_decl_ref value = Types.show_type_decl_ref (display#visit_type_decl_ref () value)
let show_fun_sig value = Types.show_fun_sig (display#visit_fun_sig () value)
let show_local value = LlbcAst.show_local (display#visit_local () value)
let show_block value = LlbcAst.show_block (display#visit_block () value)
let show_call value = LlbcAst.show_call (display#visit_call () value)
let show_place value = Expressions.show_place (display#visit_place () value)
let show_operand value = Expressions.show_operand (display#visit_operand () value)
let show_rvalue value = Expressions.show_rvalue (display#visit_rvalue () value)
let show_trait_assoc_ty_impl value = Types.show_trait_assoc_ty_impl (display#visit_trait_assoc_ty_impl () value)
let type_display = object
  inherit [_] Types.map_type_decl
  method! visit_span env value = display#visit_span env value
end
let show_type_decl_kind value = Types.show_type_decl_kind (type_display#visit_type_decl_kind () value)
let show_ptr_metadata value = Types.show_ptr_metadata (type_display#visit_ptr_metadata () value)
let show_item_source value = Types.show_item_source (type_display#visit_item_source () value)
let show_span value = Meta.show_span (display#visit_span () value)
let show_constant_expr value = Types.show_constant_expr (display#visit_constant_expr () value)

let region_certificate_json (certificate : Region_equations.predicates) =
  let text value = `String value in
  let binder value body = `Assoc [
    "binder", `List (List.map (fun parameter -> text (Types.show_region_param parameter)) value.Types.binder_regions);
    "value", text (body value.Types.binder_value)] in
  `Assoc [
    "original_premises", `List (List.map (function
      | Region_equations.Predicate (left, right) -> `Assoc [
          "kind", text "predicate"; "left", binder left show_trait_decl_ref; "right", binder right show_trait_decl_ref]
      | Region_equations.Type (left, right) -> `Assoc [
          "kind", text "type"; "left", text (show_ty left); "right", text (show_ty right)]
      | Region_equations.QuantifiedType (left, right) -> `Assoc [
          "kind", text "quantified_type"; "left", binder left show_ty; "right", binder right show_ty]
      | Region_equations.Arguments (left, right) -> `Assoc [
          "kind", text "arguments"; "left", text (show_generic_args left); "right", text (show_generic_args right)])
      (List.rev certificate.originals));
    "replays", `Bool (Region_equations.replay_predicates certificate);
    "source_type_borrow_adequacy_discharged", `Bool false ]

let source_files_json () = `List (List.map (fun ((name, crate), contents) ->
  `Assoc ["name", `String (Meta.show_file_name name); "crate", `String crate;
    "contents", (match contents with None -> `Null | Some text -> `String text)]) (Files.bindings !files))
