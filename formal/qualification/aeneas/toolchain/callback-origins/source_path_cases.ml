(* Original conditional-path regressions, authored for the final batch. *)
open Charon
open Types
open Expressions
open LlbcAst
let require message condition = if not condition then failwith message
let refuses action = try action (); false with Invalid_argument _ -> true | Source_path.Not_dominating -> true
let location : Meta.loc = { line = 1; col = 0 }
let span : Meta.span = { data = { file = { name = Meta.NotReal "source-path-fixture";
  crate_name = "construction_fixture"; contents = None }; beg_loc = location; end_loc = location }; generated_from_span = None }
let statement index kind : statement = { span; statement_id = StatementId.of_int index; kind; comments_before = [] }
let block statements : block = { span; statements }
let condition = Copy { kind = PlaceLocal (LocalId.of_int 1); ty = TLiteral Charon.Values.TBool }
let id = StatementId.of_int

let () =
  let first = statement 1 Nop and middle = statement 2 Nop and last = statement 4 Nop in
  let switch = statement 3 (Switch (If (condition, block [last], block [statement 5 Return]))) in
  let path = Source_path.between (block [first; middle; switch]) (id 1) (id 4) in
  require "a nested target retains its exact original conditional selector and branch index"
    (match path with [Source_path.Execute actual; Source_path.Branch choice] ->
       actual = middle && choice.statement = switch && choice.index = 0 && choice.selector = Source_path.Value condition
     | _ -> false);
  let fork = statement 6 (Switch (If (condition, block [statement 7 Return], block [middle]))) in
  let continued = Source_path.between (block [first; fork; last]) (id 1) (id 4) in
  require "only the original continuing branch can precede a later target"
    (match continued with [Source_path.Branch choice; Source_path.Execute actual] ->
      choice.statement = fork && choice.index = 1 && actual = middle | _ -> false);
  let separate = block [statement 8 (Switch (If (condition, block [first], block [last])))] in
  require "a producer in another branch does not dominate the receiver"
    (refuses (fun () -> ignore (Source_path.between separate (id 1) (id 4))));
  require "duplicate original statement IDs cannot manufacture a source path"
    (refuses (fun () -> ignore (Source_path.between (block [first; first; last]) (id 1) (id 4))));
  require "an explicit source return cannot be ignored before the target"
    (refuses (fun () -> ignore (Source_path.between (block [first; statement 9 Return; last]) (id 1) (id 4))));
  require "loop paths require their explicit source loop semantics"
    (refuses (fun () -> ignore (Source_path.between (block [first; statement 10 (Loop (block [last]))]) (id 1) (id 4))));
  let tracked = LocalId.of_int 6 in
  let nested_dead = statement 11 (Switch (If (condition,
    block [statement 12 (StorageDead tracked)], block []))) in
  require "a nested storage death must be visible to source value preservation guards"
    (Source_path.mentions_local tracked nested_dead);
  require "nested storage replacement must be visible without a Place operand"
    (Source_path.mentions_local tracked (statement 13 (Loop (block [statement 14 (StorageLive tracked)]))));
  require "another local's storage lifetime does not fabricate a tracked-value use"
    (not (Source_path.mentions_local (LocalId.of_int 7) nested_dead))
