# Security policy

Report suspected workflow, action pin, or supply-chain vulnerabilities privately through GitHub Security Advisories for this repository. Do not open a public issue containing exploit details or credentials.

These workflows are intentionally secretless. They request only the permissions declared in each workflow, do not accept caller-provided secret names or action references, and never use inherited secrets. Consumers that need private packages must prepare an exact dependency artifact in a separate trusted job; do not add credentials to this baseline.

All action references and consumer workflow references must use a reviewed full commit SHA. The `Legacy.Maliev.Workflows` repository has a separate compatibility boundary and is not an approved source for current-platform workflow changes.

Repository self-validation is secretless and fork-safe. It grants each job only its explicit permissions, installs external validation tools from checksum-verified artifacts, and exercises the reusable gates against a production-neutral fixture. A workflow commit must not be released to consumers unless all self-validation jobs pass for that exact commit SHA.
