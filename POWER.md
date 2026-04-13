---
name: "security-scanner"
displayName: "Security Scanner"
description: "Scan code and infrastructure for security vulnerabilities with Semgrep, Bandit, Checkov, Trivy, Grype, and ASH — generate SECURITY.md reports with STRIDE classification, risk matrix, and security assessment coverage"
keywords: ["security", "scan", "vulnerability", "sast", "iac", "semgrep", "bandit", "checkov", "trivy", "grype", "ash", "stride", "threat-model", "compliance", "owasp", "cwe", "devsecops"]
author: "AWS Samples"
---

# Security Scanner Power

Comprehensive security scanning for source code and Infrastructure as Code, with automated SECURITY.md report generation including STRIDE classification, risk matrix, security assessment coverage, and compliance notes.

## Overview

This power integrates six industry-standard security scanners into Kiro, enabling real-time vulnerability detection as you write code. It covers source code (Python, JavaScript, TypeScript, Java, Go, Rust, and more), IaC (Terraform, CloudFormation, Kubernetes, Dockerfile), container images, and dependency manifests.

It also generates structured SECURITY.md reports via the `generate_security_report` tool, which aggregates scan results into an executive summary, STRIDE classification, risk matrix, impacted assets, assumptions, and prioritized recommendations. The report is designed as input for threat modeling and security reviews.

All scanning runs locally — no code leaves your machine.

## Features

- Scan source code snippets or entire directories for vulnerabilities
- Scan IaC files for misconfigurations and compliance violations
- Scan container images for known CVEs
- Generate Software Bill of Materials (SBOM)
- Produce SECURITY.md reports with STRIDE classification, risk matrix, and coverage analysis
- Project security context via `.security/config.yaml` (assumptions, resolved findings)
- Delta scanning for code changes (minimal overhead)
- Directory scanning with file-based output to avoid context window overflow

## MCP Server

### security-scanner

The power provides a single MCP server with multiple scanning tools:

| Tool | Purpose |
|------|---------|
| `scan_with_semgrep` | Scan source code snippets (13 languages) |
| `scan_with_bandit` | Scan Python code snippets |
| `scan_with_checkov` | Scan IaC snippets (Terraform, CFN, K8s, Dockerfile, etc.) |
| `scan_with_trivy` | Scan IaC or Dockerfiles with Trivy |
| `scan_with_ash` | Multi-tool scan with ASH (aggregated results) |
| `scan_image_with_trivy` | Scan container images for CVEs |
| `scan_directory_with_semgrep` | Scan full directories with Semgrep |
| `scan_directory_with_bandit` | Scan full directories with Bandit |
| `scan_directory_with_checkov` | Scan full directories with Checkov |
| `scan_directory_with_grype` | Scan dependencies for known vulnerabilities |
| `scan_directory_with_ash` | Comprehensive directory scan with ASH |
| `scan_directory_with_syft` | Generate SBOM for a directory |
| `get_supported_formats` | List supported languages and formats |
| `check_ash_availability` | Check ASH installation status |
| `generate_security_report` | Generate SECURITY.md from scan results |

## Scanning Strategy

Use the right scanner for the job:

- **Python** (.py) → `scan_with_bandit` + `scan_with_semgrep`
- **JavaScript / TypeScript** (.js, .ts) → `scan_with_semgrep`
- **Java / Go / Rust / Kotlin / C#** → `scan_with_semgrep`
- **Terraform** (.tf) → `scan_with_checkov`
- **CloudFormation** (.yaml, .json) → `scan_with_checkov`
- **Kubernetes manifests** → `scan_with_checkov`
- **Dockerfile** → `scan_with_checkov` or `scan_with_trivy`
- **Container images** → `scan_image_with_trivy`
- **Dependency files** → `scan_directory_with_grype`
- **Full project** → use `scan_directory_with_*` variants

## Security Report (SECURITY.md)

The `generate_security_report` tool takes scan results JSON and produces a structured security posture document designed as input for threat modeling and security reviews:

1. **Executive Summary** — risk level (CRITICAL/HIGH/MEDIUM/LOW), total findings, severity breakdown
2. **Security Assessment Coverage** — areas scanned, assets under review, gaps identified
3. **STRIDE Classification** — findings classified by threat category (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with collapsible details
4. **Risk Matrix** — severity × STRIDE category for prioritization
5. **Impacted Assets** — assets inferred from findings with related finding IDs
6. **Assumptions** — project assumptions (from `.security/config.yaml`) + auto-generated assumptions based on scan coverage
7. **Scan Results by Tool** — per-scanner breakdown with clickable anchor links
8. **Resolved Findings** — remediated issues with evidence (from `.security/config.yaml` or parameter)
9. **Compliance Considerations** — SOC2, PCI-DSS, HIPAA, GDPR, NIST 800-53
10. **Recommended Actions** — prioritized in three tiers (Immediate/Short-term/Long-term)
11. **References** — links to MCP Security Scanner, AWS Prescriptive Guidance, AWS threat modeling blog, and Threat Composer

The report includes a disclaimer noting it is a supporting input for threat modeling and security reviews, not a replacement for a formal security assessment.

### Project Security Context

Projects can define assumptions and resolved findings in `.security/config.yaml`:

```yaml
project:
  name: my-project
  description: Brief description

assumptions:
  - assumption: Authentication handled by Amazon Cognito with MFA
    linked_threats: Spoofing
    comments: User pool in us-east-1

resolved_findings:
  - id: B501
    tool: bandit
    severity: HIGH
    action: Changed verify=False to verify=True
```

This file is loaded automatically — no need to pass parameters. See the included `.security/config.yaml` for a complete template.

### Generating a Report

1. (Optional) Create `.security/config.yaml` with project assumptions
2. Scan relevant files using the appropriate scanner tools
3. Collect all scan result JSON objects into an array
4. Call `generate_security_report` with `project_name` and `scan_results` (JSON string)
5. Save the returned `report` field as `SECURITY.md`

## Workflow Examples

### Scan on demand

```
Scan the current file for security vulnerabilities
```

### Scan and fix loop

```
Scan this Terraform config, fix any issues, and re-scan until clean
```

### Generate a report

```
Run security scans on the project and generate a SECURITY.md report
```

### Full project scan

```
Scan the entire project directory and summarize the findings
```

## Directory Scanning Output

Directory scanning tools save results to dedicated folders by default to prevent context window overflow:

| Tool | Output Directory |
|------|-----------------|
| Semgrep | `.semgrep/` |
| Bandit | `.bandit/` |
| Checkov | `.checkov/` |
| Grype | `.grype/` |
| ASH | `.ash/` |
| Trivy | `.trivy/` |
| Syft | `.sbom/` |

Use `return_output=True` parameter to get full results inline instead.

## Requirements

- Python 3.10–3.13
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager (for running the MCP server via uvx)
- Optional: Trivy, Grype, Syft for container/dependency scanning (install separately)

## References

- [MCP Security Scanner on GitHub](https://github.com/aws-samples/sample-mcp-security-scanner)
- [AWS Prescriptive Guidance Pattern](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-real-time-coding-security-validation-by-using-an-mcp-server-with-kiro-and-other-coding-assistants.html)
- [How to approach threat modeling — AWS Security Blog](https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/)
- [Threat Composer — AWS threat modeling tool](https://github.com/awslabs/threat-composer)
