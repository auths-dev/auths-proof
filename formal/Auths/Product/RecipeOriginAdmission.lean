import Auths.Product.PathCompiler

/-!
Independent original-origin admission. Parsed components retain optional
presence and the complete host kind/payload. The URL library contract supplies
parsing/normalization meaning; these are Auths checks over that result, not a
DNS-resolution, TLS, network-reachability or public-address claim.
-/
namespace Auths.Product.RecipeOriginAdmission
open RequestConstruction PathCompiler

abbrev Bytes := RequestConstruction.Bytes

def EndsWith (value suffix : Bytes) : Prop :=
  suffix.length ≤ value.length ∧ value.drop (value.length - suffix.length) = suffix
instance (value suffix : Bytes) : Decidable (EndsWith value suffix) := by unfold EndsWith; infer_instance

/-- Remove exactly one final DNS root dot, retaining every other byte. -/
def policyName (domain : Bytes) : Bytes :=
  if domain.getLast? = some 46 then domain.take (domain.length - 1) else domain

def localhost : Bytes := [108,111,99,97,108,104,111,115,116]
def local : Bytes := [108,111,99,97,108]
def internalSuffix : Bytes := [46,105,110,116,101,114,110,97,108]

def DomainChecks (policy : Bytes) : Prop :=
  policy ≠ localhost ∧ ¬EndsWith policy (46 :: localhost) ∧
    policy ≠ local ∧ ¬EndsWith policy (46 :: local) ∧
    ¬EndsWith policy internalSuffix ∧ 46 ∈ policy
instance (policy : Bytes) : Decidable (DomainChecks policy) := by unfold DomainChecks; infer_instance

def DomainPolicy (domain : Bytes) : Prop :=
  domain.length ≤ 253 ∧ DomainChecks (policyName domain)
instance (domain : Bytes) : Decidable (DomainPolicy domain) := by unfold DomainPolicy; infer_instance

inductive Host where
  | domain (name : Bytes)
  | ipv4 (octets : Bytes)
  | ipv6 (octets : Bytes)
  deriving DecidableEq

structure Parsed where
  scheme : Bytes
  username : Bytes
  password : Option Bytes
  host : Option Host
  port : Option Nat
  path : Bytes
  query : Option Bytes
  fragment : Option Bytes
  deriving DecidableEq

def https : Bytes := [104,116,116,112,115]

def Attributes (parsed : Parsed) : Prop :=
  parsed.scheme = https ∧ parsed.username = [] ∧ parsed.password = none ∧
    parsed.port = none ∧ parsed.path = [47] ∧ parsed.query = none ∧ parsed.fragment = none
instance (parsed : Parsed) : Decidable (Attributes parsed) := by unfold Attributes; infer_instance

/-- The original input must equal one literal HTTPS prefix followed by the
same complete canonical domain returned by the named URL parser. -/
def ParsedOrigin (original : Bytes) (parsed : Parsed) (domain : Bytes) : Prop :=
  original.length ≤ 261 ∧ Attributes parsed ∧ parsed.host = some (.domain domain) ∧
    OriginMatches original domain ∧ DomainPolicy domain
instance (original : Bytes) (parsed : Parsed) (domain : Bytes) : Decidable (ParsedOrigin original parsed domain) := by
  unfold ParsedOrigin
  infer_instance

def validate {E : Type} (unsafeOrigin : E) (original : Bytes) (parsed : Except Unit Parsed) : Except E Bytes :=
  if original.length ≤ 261 then
    match parsed with
    | .error () => .error unsafeOrigin
    | .ok value =>
        if Attributes value then
          match value.host with
          | some (.domain domain) =>
              if OriginMatches original domain ∧ DomainPolicy domain then .ok domain else .error unsafeOrigin
          | _ => .error unsafeOrigin
        else .error unsafeOrigin
  else .error unsafeOrigin

theorem successful_origin_has_original_components {E : Type} (unsafeOrigin : E)
    (original domain : Bytes) (parsed : Except Unit Parsed)
    (accepted : validate unsafeOrigin original parsed = .ok domain) :
    ∃ value, parsed = .ok value ∧ ParsedOrigin original value domain := by
  unfold validate at accepted
  split at accepted <;> rename_i size
  · cases parsed with
    | error reason => cases reason; contradiction
    | ok value =>
        split at accepted <;> rename_i attributes
        · cases host : value.host with
          | none => simp [host] at accepted
          | some kind =>
              cases kind with
              | ipv4 octets => simp [host] at accepted
              | ipv6 octets => simp [host] at accepted
              | domain name =>
                  simp only [host] at accepted
                  split at accepted <;> rename_i policy
                  · have same : name = domain := by simpa using accepted
                    subst name
                    exact ⟨value, rfl, size, attributes, host, policy⟩
                  · contradiction
        · contradiction
  · contradiction

theorem successful_origin_has_unique_domain {E : Type} (unsafeOrigin : E)
    (original first second : Bytes) (parsed : Except Unit Parsed)
    (one : validate unsafeOrigin original parsed = .ok first)
    (two : validate unsafeOrigin original parsed = .ok second) : first = second := by
  rw [one] at two
  exact Except.ok.inj two

theorem parsed_origin_retains_exact_host (original : Bytes) (parsed : Parsed) (domain : Bytes)
    (admitted : ParsedOrigin original parsed domain) :
    original = httpsPrefix ++ domain ∧ 0 < domain.length ∧ domain.length ≤ 253 :=
  ⟨admitted.2.2.2.1.2.2, admitted.2.2.2.1.1, admitted.2.2.2.1.2.1⟩

end Auths.Product.RecipeOriginAdmission
