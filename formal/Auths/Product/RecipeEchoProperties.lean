import Auths.Product.RecipeRuleAdmission
import Auths.Product.TemplateMemberDomains

namespace Auths.Product.RecipeRuleAdmission
open NativeCompiler RecipeConsumption

theorem json_echo_bad_count (members : List (Bytes × TemplateAst.Value)) (tokens : List Bytes)
    (invalid : members = [] ∨ 32 < members.length) :
    jsonEchoTokens (.object members) tokens = .error .echoConflict := by
  unfold jsonEchoTokens
  split
  · have bad : ¬TemplateMembers.KeyColumn (members.map Prod.fst) .json := by
      rcases invalid with empty | large
      · simp [empty, TemplateMembers.KeyColumn]
      · simp only [TemplateMembers.KeyColumn, List.length_map, TemplateMembers.maximum]
        omega
    simp [TemplateMembers.jsonEchoTarget, bad]
  · rfl

theorem json_echo_bad_names (members : List (Bytes × TemplateAst.Value)) (tokens : List Bytes)
    (invalid : ¬∀ member ∈ members, OperationIdentity.validToken member.1 64 = true) :
    jsonEchoTokens (.object members) tokens = .error .echoConflict := by
  simp [jsonEchoTokens, List.all_eq_true, invalid]

theorem form_echo_bad_count (members : List (Bytes × TemplateAst.FormValue)) (name : Bytes)
    (invalid : members = [] ∨ 16 < members.length) :
    (if members.all (fun member => OperationIdentity.validToken member.1 64) then
      match TemplateMembers.canonicalMembers (members.map Prod.fst) (some name) .form with
      | .ok _ => .ok ()
      | .error _ => .error Error.echoConflict
    else .error .echoConflict) = .error .echoConflict := by
  split
  · have bad : ¬TemplateMembers.KeyColumn (members.map Prod.fst) .form := by
      rcases invalid with empty | large
      · simp [empty, TemplateMembers.KeyColumn]
      · simp only [TemplateMembers.KeyColumn, List.length_map, TemplateMembers.maximum]
        omega
    simp [TemplateMembers.canonicalMembers, bad]
  · rfl

theorem echo_observation_invalid (source : Echo) (body : TemplateAst.Body) (read : Observation)
    (invalid : ¬RecipeAdmissionAtoms.ResponsePointer source.observe) :
    echo source body read = .error .unsafeTemplate := by simp [echo, invalid]

theorem echo_overlap_refuses (source : Echo) (body : TemplateAst.Body) (read : Observation)
    (valid : RecipeAdmissionAtoms.ResponsePointer source.observe)
    (overlap : RecipeAdmissionAtoms.pointersOverlap source.observe read.pointer = true) :
    echo source body read = .error .echoConflict := by simp [echo, valid, overlap]

theorem echo_success_earns_separate_observation (source : Echo) (body : TemplateAst.Body) (read : Observation)
    (accepted : echo source body read = .ok ()) :
    RecipeAdmissionAtoms.ResponsePointer source.observe ∧
      RecipeAdmissionAtoms.pointersOverlap source.observe read.pointer = false := by
  unfold echo at accepted
  split at accepted
  · rename_i valid
    split at accepted
    · contradiction
    · exact ⟨valid, by simpa using ‹¬RecipeAdmissionAtoms.pointersOverlap source.observe read.pointer = true›⟩
  · contradiction

end Auths.Product.RecipeRuleAdmission
