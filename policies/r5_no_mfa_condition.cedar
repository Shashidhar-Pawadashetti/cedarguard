// R5-NO-MFA-CONDITION: Sensitive IAM Action Without MFA Condition
//
// Checks: IAM policies that permit sensitive actions (iam:CreateUser,
// iam:AttachRolePolicy, etc.) without requiring multi-factor authentication
// via aws:MultiFactorAuthPresent condition.
//
// Why it matters: Privileged IAM operations without MFA are vulnerable to
// credential theft — a stolen access key can escalate to full account takeover.
//
// Example violation: A policy allowing iam:CreateUser without a Condition
// block requiring aws:MultiFactorAuthPresent: true.
@id("R5-NO-MFA-CONDITION")
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateMfaCondition",
  resource
)
when {
  resource.isSensitiveAction == true &&
  resource.hasMfaCondition == false
};
