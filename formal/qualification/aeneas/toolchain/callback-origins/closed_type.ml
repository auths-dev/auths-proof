(* Conservative evidence that a fully instantiated source type contains only
   static lifetimes. This is not a borrow checker: source well-formedness,
   layout, execution and allocation contracts remain separate obligations.
   No nominal name, dictionary alone, erased label or recursive assumption
   establishes this property. Every nominal representation is inspected. *)
open Charon
open Types

module TyMap = Map.Make (struct type t = ty let compare = compare_ty end)

type nominal = {
  reference : type_decl_ref;
  source_kind : type_decl_kind;
  source_pointer_metadata : ptr_metadata;
}

type t = {
  original : ty;
  normalized : ty;
  rule : string;
  nominal : nominal option;
  children : t list;
}

let create ~declarations ~normalize original =
  let known = ref TyMap.empty in
  let rec derive depth active original =
    if depth >= 512 then invalid_arg "closed source type exceeds its construction depth limit";
    match TyMap.find_opt original !known with
    | Some proof -> proof
    | None ->
        if List.mem original active then
          invalid_arg "recursive source lifetime evidence needs a separate induction";
        let active = original :: active in
        let normalized = normalize original in
        let descend ty = derive (depth + 1) active ty in
        let complete rule nominal children =
          let proof = { original; normalized; rule; nominal; children } in
          known := TyMap.add original proof !known;
          proof in
        let args (arguments : generic_args) =
          let scope = object
            inherit [_] iter_ty
            method! visit_region _ = function
              | RStatic -> ()
              | _ -> invalid_arg "closed source type arguments require explicit static lifetime provenance"
            method! visit_TVar _ _ =
              invalid_arg "a type parameter cannot establish closed source lifetime evidence"
            method! visit_CVar _ _ =
              invalid_arg "a const parameter cannot establish a closed source instantiation"
          end in
          scope#visit_generic_args () arguments;
          List.iter (fun (value : constant_expr) -> match value.kind with
            | CLiteral _ -> ()
            | _ -> invalid_arg "closed source type const arguments need actual literal values") arguments.const_generics;
          List.map descend arguments.types in
        match normalized with
        | TLiteral _ -> complete "literal" None []
        | TNever -> complete "never" None []
        | TRef (RStatic, inner, _) -> complete "explicit static reference" None [descend inner]
        | TRef _ -> invalid_arg "a non-static borrow cannot establish a closed static source type"
        | TRawPtr (inner, _) -> complete "raw pointer with closed pointee" None [descend inner]
        | TSlice inner -> complete "slice with closed element" None [descend inner]
        | TArray (inner, length) ->
            (match length.kind with
             | CLiteral _ -> complete "literal array with closed element" None [descend inner]
             | _ -> invalid_arg "closed array lifetime evidence needs its actual literal length")
        | TAdt reference ->
            let argument_proofs = args reference.generics in
            (match reference.id with
             | TTuple ->
                 if reference.generics.regions <> [] || reference.generics.const_generics <> [] ||
                    reference.generics.trait_refs <> [] then
                   invalid_arg "a closed tuple has unexpected non-type arguments";
                 complete "tuple with closed elements" None argument_proofs
             | TBuiltin TStr when reference.generics = TypesUtils.empty_generic_args ->
                 complete "string slice" None []
             | TBuiltin TBox when reference.generics.regions = [] &&
                 reference.generics.const_generics = [] && reference.generics.trait_refs = [] &&
                 List.length argument_proofs = 1 ->
                 complete "box with closed element" None argument_proofs
             | TBuiltin _ -> invalid_arg "a closed builtin has unexpected source arguments"
             | TAdtId id ->
                 let source = match TypeDeclId.Map.find_opt id declarations with
                   | Some source -> source
                   | None -> invalid_arg "closed lifetime evidence requires the actual source type declaration" in
                 (match source.src with
                  | TopLevelItem -> ()
                  | _ -> invalid_arg "closed associated or generated source types need explicit owner evidence");
                 let arity label expected actual = if expected <> actual then
                   invalid_arg ("closed source type " ^ label ^ " argument arity disagrees") in
                 arity "region" (List.length source.generics.regions) (List.length reference.generics.regions);
                 arity "type" (List.length source.generics.types) (List.length reference.generics.types);
                 arity "const" (List.length source.generics.const_generics) (List.length reference.generics.const_generics);
                 arity "dictionary" (List.length source.generics.trait_clauses) (List.length reference.generics.trait_refs);
                 let substitution = Substitute.make_subst_from_generics source.generics reference.generics Self in
                 let mapper = object
                   inherit [_] map_type_decl
                   method! visit_ty _ ty = Substitute.ty_substitute substitution ty
                 end in
                 let source_kind = mapper#visit_type_decl_kind () source.kind in
                 let field_types = match source_kind with
                   | Struct fields | Union fields -> List.map (fun field -> field.field_ty) fields
                   | Enum variants -> List.concat_map (fun variant ->
                       List.map (fun field -> field.field_ty) variant.fields) variants
                   | Alias ty -> [ty]
                   | Opaque | TDeclError _ ->
                       invalid_arg "an opaque or failed source type cannot establish closed lifetime evidence" in
                 let source_pointer_metadata, metadata_types = match source.ptr_metadata with
                   | NoMetadata -> NoMetadata, []
                   | Length -> Length, []
                   | InheritFrom ty ->
                       let ty = Substitute.ty_substitute substitution ty in
                       InheritFrom ty, [ty]
                   | VTable _ -> invalid_arg "closed dynamic pointer metadata needs an explicit source representation proof" in
                 let children = argument_proofs @ List.map descend (field_types @ metadata_types) in
                 complete "actual closed source representation"
                   (Some { reference; source_kind; source_pointer_metadata }) children)
        | TVar _ | TTraitType _ | TDynTrait _ | TFnPtr _ | TFnDef _ | TPtrMetadata _ | TPattern _ | TError _ ->
            invalid_arg "source lifetime evidence does not cover this unresolved or binder-bearing type"
  in
  derive 0 [] original

let replay ~declarations ~normalize proof =
  try create ~declarations ~normalize proof.original = proof with Invalid_argument _ -> false

let rec report proof =
  let open Diagnostic in
  `Assoc ["original_type", `String (show_ty proof.original);
    "normalized_type", `String (show_ty proof.normalized);
    "rule", `String proof.rule;
    "nominal_source", (match proof.nominal with
      | None -> `Null
      | Some nominal -> `Assoc ["reference", `String (show_type_decl_ref nominal.reference);
          "instantiated_source_kind", `String (show_type_decl_kind nominal.source_kind);
          "instantiated_pointer_metadata", `String (show_ptr_metadata nominal.source_pointer_metadata)]);
    "children", `List (List.map report proof.children);
    "source_well_formedness_and_borrow_adequacy_discharged", `Bool false]
