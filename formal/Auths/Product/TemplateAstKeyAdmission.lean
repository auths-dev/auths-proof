import Auths.Product.TemplateAst

namespace Auths.Product.TemplateAst

def LexicalKeys (keys : List RequestConstruction.Bytes) : Prop :=
  ∀ key ∈ keys, OperationIdentity.validToken key 64 = true
instance (keys : List RequestConstruction.Bytes) : Decidable (LexicalKeys keys) := by
  unfold LexicalKeys
  infer_instance

/-- Preallocation admission for an owned key column. Sorting, uniqueness,
echo capacity/collision and child selection are checked by the member compiler. -/
def keyNames (maximum : Nat) (keys : List RequestConstruction.Bytes) :
    Except Error (List RequestConstruction.Bytes) :=
  if 0 < keys.length ∧ keys.length ≤ maximum ∧ LexicalKeys keys then .ok keys else .error .shape

theorem key_names_success_earns_admission (maximum : Nat) (keys output : List RequestConstruction.Bytes)
    (compiled : keyNames maximum keys = .ok output) :
    output = keys ∧ 0 < keys.length ∧ keys.length ≤ maximum ∧ LexicalKeys keys := by
  unfold keyNames at compiled
  split at compiled
  · rename_i admitted
    exact ⟨by simpa using compiled.symm, admitted⟩
  · contradiction

theorem member_column_earns_lexical (keys : List RequestConstruction.Bytes) (domain : TemplateMembers.Domain)
    (admitted : TemplateMembers.KeyColumn keys domain) : LexicalKeys keys := admitted.2.2.1

theorem nonlexical_members_refuse (keys : List RequestConstruction.Bytes)
    (echo : Option RequestConstruction.Bytes) (domain : TemplateMembers.Domain)
    (invalid : ¬LexicalKeys keys) :
    TemplateMembers.canonicalMembers keys echo domain = .error .members := by
  have invalidColumn : ¬TemplateMembers.KeyColumn keys domain :=
    fun admitted => invalid (member_column_earns_lexical keys domain admitted)
  simp [TemplateMembers.canonicalMembers, invalidColumn]

theorem nonlexical_target_refuses (keys tokens : List RequestConstruction.Bytes)
    (invalid : ¬LexicalKeys keys) :
    TemplateMembers.jsonEchoTarget keys tokens = .error .members := by
  have invalidColumn : ¬TemplateMembers.KeyColumn keys .json :=
    fun admitted => invalid (member_column_earns_lexical keys .json admitted)
  simp [TemplateMembers.jsonEchoTarget, invalidColumn]

end Auths.Product.TemplateAst
