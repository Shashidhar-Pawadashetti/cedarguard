// R2-IAM-WILDCARD-ACTION: IAM Policy Allows Wildcard Actions (*)
//
// Checks: IAM policies that grant Action: "*", effectively giving
// unrestricted administrative permissions across all AWS services.
//
// Why it matters: A compromised principal with Action: "*" can delete
// infrastructure, exfiltrate data, and escalate privileges without limit.
//
// Example violation: An IAM policy with Statement.Action set to "*".
@id("R2-IAM-WILDCARD-ACTION")
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateIamWildcardAction",
  resource
)
when {
  resource.hasWildcardAction == true
};
