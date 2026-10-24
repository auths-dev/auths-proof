import Auths.Product.TemplateAstRefinement
import Auths.Product.TemplateAstMeaning

open Aeneas Aeneas.Std Result
open auths_gateway_kernel
open Auths.Product.Refinement.Gateway

namespace Auths.Product.TemplateAst.Refinement
set_option maxRecDepth 4096

/- Exact recursive views retain every child and original name/value pair.
There is no depth truncation or validity/success bit in the view. The compiler
separately enforces its own depth/node/resource domains. -/
mutual
  def valueOf : template_ast.Value → Value
    | .String text => .text (vecBytes text)
    | .Integer value => .integer value.val
    | .Boolean value => .boolean value
    | .Field name => .field (vecBytes name)
    | .AuthorEcho => .authorEcho
    | .Object fields => .object (jsonMembersOf fields.val)
    | .Array items => .array (valuesOf items.val)
  termination_by value => sizeOf value
  decreasing_by all_goals simp_wf [alloc.vec.Vec]

  def jsonMembersOf : List template_ast.JsonMember → List (Bytes × Value)
    | [] => []
    | .mk name value :: rest => (vecBytes name, valueOf value) :: jsonMembersOf rest
  termination_by fields => sizeOf fields
  decreasing_by all_goals simp_wf

  def valuesOf : List template_ast.Value → List Value
    | [] => []
    | value :: rest => valueOf value :: valuesOf rest
  termination_by items => sizeOf items
  decreasing_by all_goals simp_wf
end

def formValueOf : template_ast.FormValue → FormValue
  | .String bytes => .text (vecBytes bytes)
  | .Field name => .field (vecBytes name)
  | .Json value => .json (valueOf value)
  | .AuthorEcho => .authorEcho

def formMembersOf (fields : List template_ast.FormMember) : List (Bytes × FormValue) :=
  fields.map (fun member => (vecBytes member.name, formValueOf member.value))

def bodyOf : template_ast.Body → Body
  | .Json value => .json (valueOf value)
  | .Form fields => .form (formMembersOf fields.val)

def echoOf : template_ast.Echo → Echo
  | .Json tokens => .json (tokens.val.map vecBytes)
  | .Form name => .form (vecBytes name)

def jsonFieldNames (fields : List template_ast.JsonMember) : List Bytes := fields.map (fun member => vecBytes member.name)
def formFieldNames (fields : List template_ast.FormMember) : List Bytes := fields.map (fun member => vecBytes member.name)

theorem json_member_names_preserve_pairs (fields : List template_ast.JsonMember) :
    (jsonMembersOf fields).map Prod.fst = jsonFieldNames fields := by
  induction fields with
  | nil => rfl
  | cons member rest ih => cases member <;> simp [jsonMembersOf, jsonFieldNames, ih]

theorem form_member_names_preserve_pairs (fields : List template_ast.FormMember) :
    (formMembersOf fields).map Prod.fst = formFieldNames fields := by simp [formMembersOf, formFieldNames, List.map_map]

theorem json_member_count_preserved (fields : List template_ast.JsonMember) :
    (jsonMembersOf fields).length = fields.length := by
  induction fields with
  | nil => rfl
  | cons member rest ih => cases member <;> simp [jsonMembersOf, ih]

theorem array_source_order_preserved (items : List template_ast.Value) : valuesOf items = items.map valueOf := by
  induction items with
  | nil => rfl
  | cons value rest ih => simp [valuesOf, ih]

end Auths.Product.TemplateAst.Refinement
