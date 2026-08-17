-- REVIEWED TRANSPARENT ADAPTERS FOR AENEAS-GENERATED PRODUCTION AUTHORITY CODE.
--
-- The authority translation emits authority-local copies of the algebra
-- carriers. These adapters rebox them field by field into the carriers the
-- translated `auths_algebra_kernel` owns and delegate to its functions.
--
-- NO axiom, cast, assumed equality, or restated semantics. Every Boolean
-- decision below is computed by the mechanically translated owning crate.
-- Attenuation dimensions bound by formal/algebra-contract-v1.toml: 11.
import Aeneas
import qualification.aeneas.generated.authority.Types
import qualification.aeneas.generated.model.Funs
import qualification.aeneas.generated.algebra.Funs

open Aeneas Aeneas.Std Result ControlFlow Error

set_option linter.dupNamespace false
set_option linter.hashCommand false
set_option linter.unusedVariables false
set_option maxHeartbeats 1000000
set_option maxRecDepth 2048

namespace auths_authority

/-- Reboxes the authority-local root linkage into the owning carrier. -/
def auths_algebra_kernel.toRootLinkage {Identity : Type}
    (value : auths_algebra_kernel.RootLinkage Identity) :
    _root_.auths_algebra_kernel.RootLinkage Identity :=
  { parent_root := value.parent_root,
    parent_subject := value.parent_subject,
    parent_delegated := value.parent_delegated,
    grant_issuer := value.grant_issuer }

/-- Delegates root preservation to the translated algebra kernel. -/
@[rust_fun "auths_algebra_kernel::root_preserved"]
def auths_algebra_kernel.root_preserved {Identity : Type}
    (inst : core.cmp.PartialEq Identity Identity)
    (linkage : auths_algebra_kernel.RootLinkage Identity) : Result Bool :=
  _root_.auths_algebra_kernel.root_preserved inst
    (auths_algebra_kernel.toRootLinkage linkage)

/-- Reboxes the authority-local attenuation checks into the owning carrier. -/
def auths_algebra_kernel.generated.toAttenuationChecks
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    _root_.auths_algebra_kernel.generated.AttenuationChecks :=
  { root_preserved := value.root_preserved,
    depth_decreases := value.depth_decreases,
    profile_attenuates := value.profile_attenuates,
    permissions_attenuate := value.permissions_attenuate,
    validity_attenuates := value.validity_attenuates,
    audiences_attenuate := value.audiences_attenuate,
    action_constraint_attenuates := value.action_constraint_attenuates,
    budget_attenuates := value.budget_attenuates,
    status_attenuates := value.status_attenuates,
    assurance_attenuates := value.assurance_attenuates,
    extensions_attenuate := value.extensions_attenuate }

/-- Delegates the attenuation conjunction to the translated algebra kernel. -/
@[rust_fun "auths_algebra_kernel::generated::attenuation_checks_accept"]
def auths_algebra_kernel.generated.attenuation_checks_accept
    (checks : auths_algebra_kernel.generated.AttenuationChecks) : Result Bool :=
  _root_.auths_algebra_kernel.generated.attenuation_checks_accept
    (auths_algebra_kernel.generated.toAttenuationChecks checks)

-- EXACT BRIDGE PROOFS. Each reboxed field is definitionally its source
-- field, and each adapter is definitionally the owning-crate function
-- applied to the conversion. A rebox that dropped or crossed a field
-- would not close by rfl.

theorem auths_algebra_kernel.toRootLinkage_parent_root {Identity : Type}
    (value : auths_algebra_kernel.RootLinkage Identity) :
    (auths_algebra_kernel.toRootLinkage value).parent_root = value.parent_root := rfl

theorem auths_algebra_kernel.toRootLinkage_parent_subject {Identity : Type}
    (value : auths_algebra_kernel.RootLinkage Identity) :
    (auths_algebra_kernel.toRootLinkage value).parent_subject = value.parent_subject := rfl

theorem auths_algebra_kernel.toRootLinkage_parent_delegated {Identity : Type}
    (value : auths_algebra_kernel.RootLinkage Identity) :
    (auths_algebra_kernel.toRootLinkage value).parent_delegated = value.parent_delegated := rfl

theorem auths_algebra_kernel.toRootLinkage_grant_issuer {Identity : Type}
    (value : auths_algebra_kernel.RootLinkage Identity) :
    (auths_algebra_kernel.toRootLinkage value).grant_issuer = value.grant_issuer := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_root_preserved
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).root_preserved = value.root_preserved := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_depth_decreases
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).depth_decreases = value.depth_decreases := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_profile_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).profile_attenuates = value.profile_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_permissions_attenuate
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).permissions_attenuate = value.permissions_attenuate := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_validity_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).validity_attenuates = value.validity_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_audiences_attenuate
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).audiences_attenuate = value.audiences_attenuate := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_action_constraint_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).action_constraint_attenuates = value.action_constraint_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_budget_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).budget_attenuates = value.budget_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_status_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).status_attenuates = value.status_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_assurance_attenuates
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).assurance_attenuates = value.assurance_attenuates := rfl

theorem auths_algebra_kernel.generated.toAttenuationChecks_extensions_attenuate
    (value : auths_algebra_kernel.generated.AttenuationChecks) :
    (auths_algebra_kernel.generated.toAttenuationChecks value).extensions_attenuate = value.extensions_attenuate := rfl

theorem auths_algebra_kernel.root_preserved_delegates {Identity : Type}
    (inst : core.cmp.PartialEq Identity Identity)
    (linkage : auths_algebra_kernel.RootLinkage Identity) :
    auths_algebra_kernel.root_preserved inst linkage =
      _root_.auths_algebra_kernel.root_preserved inst
        (auths_algebra_kernel.toRootLinkage linkage) := rfl

theorem auths_algebra_kernel.generated.attenuation_checks_accept_delegates
    (checks : auths_algebra_kernel.generated.AttenuationChecks) :
    auths_algebra_kernel.generated.attenuation_checks_accept checks =
      _root_.auths_algebra_kernel.generated.attenuation_checks_accept
        (auths_algebra_kernel.generated.toAttenuationChecks checks) := rfl

end auths_authority
