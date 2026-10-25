(* Loop-entry provenance is an explicit obligation, not normal dominance.
   These source-boundary cases are authored for the final verification batch. *)
open Charon
open Types
open Expressions
open LlbcAst

let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ | Source_path.Not_dominating -> true
let location : Meta.loc = { line = 1; col = 0 }
let span : Meta.span = { data = { file = { name = Meta.NotReal "iteration-path-fixture";
  crate_name = "construction_fixture"; contents = None }; beg_loc = location; end_loc = location }; generated_from_span = None }
let statement index kind : statement = { span; statement_id = StatementId.of_int index; kind; comments_before = [] }
let block statements : block = { span; statements }
let condition = Copy { kind = PlaceLocal (LocalId.of_int 1); ty = TLiteral Charon.Values.TBool }

let () =
  let first = statement 1 Nop and target = statement 4 Nop in
  let loop = statement 2 (Loop (block [statement 3 Nop; target; statement 5 (Continue 0)])) in
  let body = block [first; loop; statement 6 Return] in
  let path = Iteration_path.before body target.statement_id in
  require "the actual enclosing loop must retain its iteration-value invariant obligation"
    (Iteration_path.loops path = [loop]);
  require "a lexical iteration trace cannot weaken the normal source dominance interface"
    (refuses (fun () -> ignore (Source_path.before body target.statement_id)));
  let skip = statement 7 (Switch (If (condition, block [statement 8 (Continue 0)], block [statement 9 Nop]))) in
  let current = statement 10 (Loop (block [skip; target])) in
  let continued = Iteration_path.before (block [current]) target.statement_id in
  require "a continue arm cannot silently reach a later source point in the same iteration"
    (List.exists (function Iteration_path.Source (Source_path.Branch choice) ->
      choice.statement = skip && choice.index = 1 | _ -> false) continued);
  let duplicate = block [statement 11 Nop; statement 11 Nop; current] in
  require "even non-target duplicate source identities invalidate an iteration trace"
    (refuses (fun () -> ignore (Iteration_path.before duplicate target.statement_id)));
  require "a current-iteration return cannot be ignored before the source point"
    (refuses (fun () -> ignore (Iteration_path.before (block [statement 12 (Loop (block [statement 13 Return; target]))]) target.statement_id)))
