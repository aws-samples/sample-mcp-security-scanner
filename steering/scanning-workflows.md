---
inclusion: auto
---

# Security Scanning Workflows

## Scanner Selection

Always pick the right tool for the file type:

| File Type | Primary Scanner | Secondary Scanner |
|-----------|----------------|-------------------|
| Python (.py) | `scan_with_bandit` | `scan_with_semgrep` |
| JavaScript (.js), TypeScript (.ts) | `scan_with_semgrep` | — |
| Java (.java), Go (.go), Rust (.rs), Kotlin (.kt), C# (.cs) | `scan_with_semgrep` | — |
| Terraform (.tf, .tfvars) | `scan_with_checkov` | — |
| CloudFormation (.yaml, .yml, .json) | `scan_with_checkov` | — |
| Kubernetes manifests (.yaml, .yml) | `scan_with_checkov` | — |
| Dockerfile | `scan_with_checkov` | `scan_with_trivy` |
| Container images | `scan_image_with_trivy` | — |
| Dependency manifests (package.json, requirements.txt, Cargo.lock, etc.) | `scan_directory_with_grype` | — |

For Python files, run both Bandit and Semgrep — they catch different classes of issues.

## Scan-Fix-Rescan Loop

When asked to fix security issues:

1. Read the file and scan it with the appropriate tool
2. Review findings by severity (CRITICAL > HIGH > MEDIUM > LOW)
3. Fix issues starting from highest severity
4. Re-scan the file to verify fixes
5. Repeat until clean or only accepted risks remain
6. Summarize what was fixed and what remains

## Generating SECURITY.md Reports

When generating a security report:

1. Scan all relevant files using the appropriate scanners
2. Collect all scan result JSON objects into an array
3. Call `generate_security_report` with the project name and the JSON array as a string
4. The tool returns a `report` field containing the full Markdown content
5. Save it as SECURITY.md in the project root

The report includes: executive summary, findings by severity, STRIDE threat model inputs, compliance notes (SOC2, PCI-DSS, HIPAA, GDPR), prioritized recommendations, and tool information with links.

## Severity Handling

- **CRITICAL**: Must be fixed before deployment — block the release
- **HIGH**: Fix in the current sprint — these are exploitable vulnerabilities
- **MEDIUM**: Triage and plan — fix in the next sprint or accept with justification
- **LOW**: Backlog — review for risk acceptance or opportunistic fix

## Directory Scanning

For full-project scans, use `scan_directory_with_*` tools. These save results to dedicated output folders (`.semgrep/`, `.bandit/`, `.checkov/`, `.grype/`, `.ash/`, `.trivy/`, `.sbom/`) to avoid flooding the context window. Use `return_output=True` only when you need the full results inline.
