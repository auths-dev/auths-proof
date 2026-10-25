(* Shared complete field-layout/codec construction. The caller chooses a
   faithful type reflection; this module never drops a generic argument,
   predicate, field, variant or source wrapper to fit that reflection. *)
open Charon
open Types
module Q = Aeneas.Pure
module U = Aeneas.PureUtils
module S = Aeneas.SymbolicToPureTypes
module P = Borrow_projection

type label = NativeNominal of Q.ty | NativeVariant of int | NativeField of int * string option
type layout = Atom of Q.ty | Empty | Unit | Product of layout * layout | Sum of layout * layout | Named of label * layout
type codec = CAtom of ty * Q.ty | CEmpty | CUnit | CProduct of codec * codec | CSum of codec * codec
  | CNominal of type_decl_ref * Q.ty * codec | CVariant of variant_id * codec
  | CField of int * string option * codec | CBoxed of codec | CBorrow of ref_kind * region * codec
type schema = { source : P.nominal; native_type : Q.ty; native_kind : Q.type_decl_kind }
type constraints = { source : P.nominal; parameters : Q.generic_params; declared : Q.predicates;
  instantiated : Q.predicates; source_first : Q.predicates }
type t = { atoms : (ty * Q.ty) list; schemas : schema list; constraints : constraints list }

let rec source_atoms = function
  | P.Atom ty -> [ty]
  | P.Product (left, right) | P.Sum (left, right) -> source_atoms left @ source_atoms right
  | P.Named (_, body) | P.Borrow (_, _, body) -> source_atoms body
  | P.Empty | P.Unit -> []

let instantiate_native_kind (parameters : Q.generic_params) (arguments : Q.generic_args) kind =
  if List.length parameters.Q.types <> List.length arguments.Q.types ||
      List.length parameters.const_generics <> List.length arguments.const_generics ||
      List.length parameters.trait_clauses <> List.length arguments.trait_refs then
    invalid_arg "native field instantiation lost a complete generic argument";
  let substitution = U.make_subst_from_generics parameters arguments in
  let field (source : Q.field) = { source with field_ty = U.ty_substitute substitution source.field_ty } in
  match kind with
  | Q.Struct fields -> Q.Struct (List.map field fields)
  | Q.Enum variants -> Q.Enum (List.map (fun (variant : Q.variant) -> { variant with fields = List.map field variant.fields }) variants)
  | Q.Opaque -> invalid_arg "an opaque native declaration cannot supply a complete borrowed field schema"

let create context span ~validate shapes nominals =
  let translate = S.translate_fwd_ty (Some span) context in
  let atoms = List.concat_map source_atoms shapes |> List.sort_uniq Types.compare_ty |>
    List.map (fun source -> let native = translate source in validate native; source, native) in
  let constraints = ref [] in
  let schemas = List.map (fun (source : P.nominal) ->
    let native_type = translate (TAdt source.reference) in validate native_type;
    let arguments = match native_type with Q.TAdt (Q.TAdtId _, arguments) -> arguments
      | _ -> invalid_arg "the actual native nominal lost its complete identity/generic arguments" in
    let parameters, declared = S.translate_generic_params (Some source.declaration.item_meta.span) source.declaration.generics in
    let template = S.translate_type_decl_kind source.declaration.item_meta.span source.declaration.kind in
    let native_kind = instantiate_native_kind parameters arguments template in
    let source_first = S.translate_type_decl_kind source.declaration.item_meta.span source.instantiated_kind in
    if native_kind <> source_first then
      invalid_arg "native complete field instantiation does not commute with actual source instantiation";
    let substitution = U.make_subst_from_generics parameters arguments in
    let visitor = object inherit [_] U.subst_visitor end in
    let instantiated = visitor#visit_predicates substitution declared in
    let _, source_first = S.translate_generic_params (Some source.declaration.item_meta.span) source.inherited_requirements in
    if instantiated <> source_first then
      invalid_arg "native complete predicate instantiation does not commute with actual source requirements";
    constraints := !constraints @ [{ source; parameters; declared; instantiated; source_first }];
    (match source.instantiated_kind with Enum variants -> List.iteri (fun index (variant : variant) ->
      if VariantId.to_int variant.id <> index then invalid_arg "native variant rows changed original source identities") variants | _ -> ());
    { source; native_type; native_kind }) (List.sort_uniq compare nominals) in
  { atoms; schemas; constraints = !constraints }

let rec expand environment stack ty =
  if List.mem ty (List.map snd environment.atoms) then Atom ty else match ty with
  | Q.TNever -> Empty
  | Q.TAdt (Q.TTuple, { types = []; const_generics = []; trait_refs = [] }) -> Unit
  | _ -> (
    if List.mem ty stack then invalid_arg "recursive native borrowed fields require an inductive value codec";
    let schema = match List.filter (fun schema -> schema.native_type = ty) environment.schemas with
      | first :: rest when List.for_all (fun other -> other.native_kind = first.native_kind) rest -> first
      | _ -> invalid_arg "a native value has no unique complete instantiated field schema" in
    let rec fields index = function [] -> Unit | (field : Q.field) :: rest ->
      Product (Named (NativeField (index, field.field_name), expand environment (ty :: stack) field.field_ty), fields (index + 1) rest) in
    let rec variants index = function [] -> Empty | (variant : Q.variant) :: rest ->
      Sum (Named (NativeVariant index, fields 0 variant.fields), variants (index + 1) rest) in
    let body = match schema.native_kind with Q.Struct values -> fields 0 values
      | Q.Enum values -> variants 0 values | Q.Opaque -> invalid_arg "opaque native fields cannot enter a codec" in
    Named (NativeNominal ty, body))

let rec codec context span environment source native = match source, native with
  | P.Borrow (kind, region, body), native -> CBorrow (kind, region, codec context span environment body native)
  | P.Named (P.Boxed, body), native -> CBoxed (codec context span environment body native)
  | P.Atom source, Atom native when List.assoc_opt source environment.atoms = Some native -> CAtom (source, native)
  | P.Empty, Empty -> CEmpty | P.Unit, Unit -> CUnit
  | P.Product (left, right), Product (first, second) ->
      CProduct (codec context span environment left first, codec context span environment right second)
  | P.Sum (left, right), Sum (first, second) -> CSum (codec context span environment left first, codec context span environment right second)
  | P.Named (P.Nominal reference, body), Named (NativeNominal ty, fields)
      when S.translate_fwd_ty (Some span) context (TAdt reference) = ty -> CNominal (reference, ty, codec context span environment body fields)
  | P.Named (P.Variant id, body), Named (NativeVariant index, fields) when VariantId.to_int id = index ->
      CVariant (id, codec context span environment body fields)
  | P.Named (P.Field (index, name), body), Named (NativeField (actual, native_name), fields) when index = actual && name = native_name ->
      CField (index, name, codec context span environment body fields)
  | _ -> invalid_arg "native complete layout differs from its actual source shape; no field/tag/atom may be omitted"
