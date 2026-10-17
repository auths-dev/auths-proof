import Auths.Product.OperationIdentity
import Auths.Product.ConnectionBytes
namespace Auths.Product.ConnectionFrame
abbrev Bytes := List Nat
def domain : Bytes := [97,117,116,104,115,46,103,97,116,101,119,97,121,45,99,111,110,110,101,99,116,105,111,110,47,49,0]
structure Key where
  provider : Bytes
  aliasBytes : Bytes
  deriving DecidableEq

def preimage (key : Key) : Bytes := domain ++ (key.provider ++ 0 :: key.aliasBytes)

theorem preimage_injective (left right : Key)
    (leftNulFree : 0 ∉ left.provider) (rightNulFree : 0 ∉ right.provider)
    (same : preimage left = preimage right) : left = right := by
  have framed : left.provider ++ 0 :: left.aliasBytes = right.provider ++ 0 :: right.aliasBytes := by
    apply List.append_cancel_left (as := domain)
    exact same
  have providers := congrArg (List.takeWhile (fun byte => byte != 0)) framed
  have lf : OperationIdentity.NulFree left.provider := by
    intro byte member zero
    subst byte
    exact leftNulFree member
  have rf : OperationIdentity.NulFree right.provider := by
    intro byte member zero
    subst byte
    exact rightNulFree member
  rw [OperationIdentity.before_separator _ _ lf, OperationIdentity.before_separator _ _ rf] at providers
  obtain ⟨_, tails⟩ := List.append_inj framed (congrArg List.length providers)
  have aliasByteses := (List.cons.inj tails).2
  cases left; cases right
  simp_all

theorem validated_names_bind_both_fields (left right : Key)
    (leftValid : ConnectionBytes.lowerValid left.provider 64)
    (rightValid : ConnectionBytes.lowerValid right.provider 64)
    (same : preimage left = preimage right) : left = right := by
  exact preimage_injective left right
    (ConnectionBytes.lower_has_no_nul _ _ leftValid)
    (ConnectionBytes.lower_has_no_nul _ _ rightValid) same
end Auths.Product.ConnectionFrame
