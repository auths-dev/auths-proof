(* Typed interfaces to the mechanical region matcher. Source values remain
   complete ASTs; neither entry point weakens the full-subject replay guard. *)
open Charon.Types

type witness = {
  original_arguments : generic_args;
  reconstructed_arguments : generic_args;
  source_self : ty;
  reconstructed_self : ty;
  inferred : (region_id * region) list;
}

type predicate_witness = {
  original_arguments : generic_args;
  reconstructed_arguments : generic_args;
  source_predicate : trait_decl_ref;
  reconstructed_predicate : trait_decl_ref;
  inferred : (region_id * region) list;
}

let replay parameters self_template (witness : witness) =
  Region_match.replay parameters (Region_match.Self_type self_template) {
    original_arguments = witness.original_arguments;
    reconstructed_arguments = witness.reconstructed_arguments;
    source = Region_match.Self_type witness.source_self;
    reconstructed = Region_match.Self_type witness.reconstructed_self;
    inferred = witness.inferred }

let recover parameters self_template arguments source_self : witness =
  let result = Region_match.recover parameters (Region_match.Self_type self_template)
    arguments (Region_match.Self_type source_self) in
  let reconstructed_self = match result.reconstructed with
    | Region_match.Self_type ty -> ty
    | _ -> invalid_arg "Self reconstruction changed its subject kind" in
  { original_arguments = result.original_arguments; reconstructed_arguments = result.reconstructed_arguments;
    source_self; reconstructed_self; inferred = result.inferred }

let replay_predicate parameters template (witness : predicate_witness) =
  Region_match.replay parameters (Region_match.Trait_predicate template) {
    original_arguments = witness.original_arguments;
    reconstructed_arguments = witness.reconstructed_arguments;
    source = Region_match.Trait_predicate witness.source_predicate;
    reconstructed = Region_match.Trait_predicate witness.reconstructed_predicate;
    inferred = witness.inferred }

let recover_predicate parameters template arguments source_predicate : predicate_witness =
  let result = Region_match.recover parameters (Region_match.Trait_predicate template)
    arguments (Region_match.Trait_predicate source_predicate) in
  let reconstructed_predicate = match result.reconstructed with
    | Region_match.Trait_predicate predicate -> predicate
    | _ -> invalid_arg "predicate reconstruction changed its subject kind" in
  { original_arguments = result.original_arguments; reconstructed_arguments = result.reconstructed_arguments;
    source_predicate; reconstructed_predicate; inferred = result.inferred }
