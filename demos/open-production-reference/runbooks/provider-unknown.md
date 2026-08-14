# Provider-unknown drill

1. Inject a post-call timeout through the selected exact profile test port.
2. Confirm the SDK returns `recoverable`, not success and not a safe automatic
   retry.
3. Confirm the workflow projection says `outcome-unknown` without exposing the
   action or credential.
4. Terminate the serving pod and resume from another replica with the opaque
   reference.
5. Run the profile reconciler. It must observe the exact provider effect before
   committing or releasing lifecycle state.
6. Confirm a second provider call was not issued and the final receipt binds
   the original command and provider observation.

Escalate when reconciliation remains unavailable after the profile's bounded
window. Never convert an unknown outcome to failure merely to permit retry.
