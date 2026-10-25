(* Exact public ABI for native recipe source construction. Additional adapter
   dependencies are not public roots and must never replace any of these. *)
open Charon
open Types
open LlbcAst

let names = [
  "auths_gateway_kernel::recipe_binding::source_lengths_bounded";
  "auths_gateway::recipe::strict_json::insert_member_name";
  "auths_gateway::recipe::profile::schema_value";
  "auths_gateway::recipe::profile::schema_array";
  "auths_gateway::recipe::profile::schema_members";
  "auths_gateway::recipe::profile::parse_root";
  "auths_gateway::recipe::profile::rule_fields";
  "auths_gateway::recipe::lower::source_value";
  "auths_gateway::recipe::lower::source_values";
  "auths_gateway::recipe::lower::source_members";
  "auths_gateway::recipe::lower::source_form_value";
  "auths_gateway::recipe::lower::source_form_members";
  "auths_gateway::recipe::lower::source_body";
  "auths_gateway::recipe::lower::source_echo";
  "auths_gateway::recipe::lower::method";
  "auths_gateway::recipe::lower::named_path";
  "auths_gateway::recipe::lower::header_source";
  "auths_gateway::recipe::lower::plans";
  "auths_gateway::recipe::validate::validate_source";
  "auths_gateway::recipe::compile_decoded";
  "auths_gateway::recipe::compile_source_bytes" ]

let require supplied =
  if List.length supplied <> List.length names ||
     List.sort String.compare supplied <> List.sort String.compare names then
    invalid_arg "native source construction requires the exact complete 21-root recipe ABI"

let pointers crate supplied =
  require supplied;
  if crate.name <> "auths_gateway" then invalid_arg "native source roots require the actual shipping gateway crate";
  let labels name = List.filter_map (function PeIdent (text, _) -> Some text | _ -> None) name in
  List.map (fun name ->
    match FunDeclId.Map.bindings crate.fun_decls |> List.filter (fun (_, (value : fun_decl)) ->
      String.concat "::" (labels value.item_meta.name) = name) with
    | [(_, declaration)] when declaration.generics.types = [] && declaration.generics.const_generics = [] &&
        declaration.generics.trait_clauses = [] ->
        { kind = FunId (FRegular declaration.def_id); generics = { TypesUtils.empty_generic_args with regions =
          List.map (fun (parameter : region_param) -> RVar (Free parameter.index)) declaration.generics.regions } }
    | _ -> invalid_arg "a native recipe root is absent, ambiguous or has an unbound non-region parameter") supplied
