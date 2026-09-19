// R4-SG-OPEN-INGRESS: Security Group Ingress Open to 0.0.0.0/0 on Sensitive Ports
//
// Checks: Security groups that allow unrestricted inbound traffic (0.0.0.0/0)
// on sensitive ports: SSH (22), RDP (3389), PostgreSQL (5432), MySQL (3306),
// MSSQL (1433), MongoDB (27017), Redis (6379), Elasticsearch (9200).
//
// Why it matters: Open ingress on database or remote-access ports exposes
// production infrastructure to brute-force attacks and data exfiltration.
//
// Example violation: A SecurityGroup allowing 0.0.0.0/0 on port 5432.
@id("R4-SG-OPEN-INGRESS")
forbid (
  principal,
  action == CedarGuard::Action::"EvaluateSgOpenIngress",
  resource
)
when {
  resource.openIngressPorts.contains(22) ||
  resource.openIngressPorts.contains(3389) ||
  resource.openIngressPorts.contains(5432) ||
  resource.openIngressPorts.contains(3306) ||
  resource.openIngressPorts.contains(1433) ||
  resource.openIngressPorts.contains(27017) ||
  resource.openIngressPorts.contains(6379) ||
  resource.openIngressPorts.contains(9200)
};
