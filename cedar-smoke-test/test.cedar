// Default permit for scanner
permit (
  principal,
  action,
  resource
);

// Smoke test policy: R1 S3 Public Bucket
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
