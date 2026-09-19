// R1-S3-PUBLIC: S3 Bucket Public Access Enabled
//
// Checks: S3 buckets with public ACLs (public-read, public-read-write) or
// with BlockPublicAcls disabled.
//
// Why it matters: Public S3 buckets are the #1 cause of cloud data breaches.
// Any bucket without full PublicAccessBlock is exposed to the internet.
//
// Example violation: A bucket with AccessControl: public-read and no
// PublicAccessBlockConfiguration.
@id("R1-S3-PUBLIC")
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateS3Public",
  resource
)
when {
  resource.acl == "public-read" ||
  resource.acl == "public-read-write" ||
  resource.blockPublicAcls == false
};
