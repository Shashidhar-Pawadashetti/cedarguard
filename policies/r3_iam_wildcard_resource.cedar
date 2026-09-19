// R3-IAM-WILDCARD-RESOURCE: IAM Policy Applies to All Resources (*)
//
// Checks: IAM policies that use Resource: "*", granting access to every
// resource of that type in the AWS account.
//
// Why it matters: Even with scoped actions, applying them to all resources
// violates least-privilege and widens the blast radius of a credential leak.
//
// Example violation: An IAM policy with s3:GetObject/PutObject on Resource: "*".
@id("R3-IAM-WILDCARD-RESOURCE")
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateIamWildcardResource",
  resource
)
when {
  resource.hasWildcardResource == true
};
