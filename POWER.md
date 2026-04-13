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

## Agent Behavior Rules

These rules apply whenever this power is active, regardless of the user's workspace.

### ASH is opt-in

Do NOT run `scan_with_ash` or `scan_directory_with_ash` by default. Only use ASH when the user explicitly asks for it or requests a "comprehensive scan". When relevant, inform the user: "ASH is also available for multi-tool aggregated scanning — let me know if you'd like to include it."

### Check for `.security/config.yaml` before scanning or reporting

Before running a full project scan OR generating a SECURITY.md report, check if `.security/config.yaml` exists in the project root:

- **If it exists**: proceed — the tool loads it automatically.
- **If it does NOT exist**: ask the user before proceeding:
  > "I don't see a `.security/config.yaml` in this project. This file lets you define project assumptions (e.g., 'authentication is handled by Cognito with MFA') and document resolved findings — both appear in the SECURITY.md report and help with threat modeling. Would you like me to: 1) Create a template you can fill in, or 2) Skip it and continue with only auto-generated assumptions?"
  - Option 1: create the file using the template below, then proceed.
  - Option 2: proceed immediately.

Template for `.security/config.yaml`:
```yaml
# Project Security Context — loaded automatically by generate_security_report
project:
  name: <project-name>
  description: <brief project description>

# STRIDE categories: Spoofing | Tampering | Repudiation |
#   Information Disclosure | Denial of Service | Elevation of Privilege
assumptions:
  # - assumption: <What you assume to be true>
  #   linked_threats: <STRIDE category>
  #   comments: <Evidence or context>

resolved_findings:
  # - id: <Finding ID from scanner>
  #   tool: <scanner name>
  #   severity: <HIGH, MEDIUM, LOW>
  #   action: <What was done to fix it>
```

### Full project scan workflow

When the user asks to scan the whole project or generate a report:

1. Check for `.security/config.yaml` (see above)
2. Run `check_ash_availability` to see which tools are installed — inform the user of any gaps
3. Run applicable directory scanners with `return_output=True`:
   - `scan_directory_with_semgrep` — always
   - `scan_directory_with_bandit` — always
   - `scan_directory_with_checkov` — always
   - `scan_directory_with_grype` — if installed
   - `scan_directory_with_syft` — if installed
   - `scan_image_with_trivy` — if Dockerfiles or images present
   - `scan_directory_with_ash` — only if user explicitly requests it
4. Collect all results and call `generate_security_report`
5. Save the returned `report` field as `SECURITY.md`

### Scan-fix-rescan loop

When asked to fix security issues:
1. Scan the file with the appropriate tool
2. Fix issues by severity order: CRITICAL → HIGH → MEDIUM → LOW
3. Re-scan to verify fixes
4. Repeat until clean or only accepted risks remain
5. Summarize what was fixed and what remains

### Severity handling

- **CRITICAL**: Must fix before deployment
- **HIGH**: Fix in current sprint
- **MEDIUM**: Triage and plan for next sprint
- **LOW**: Backlog — review for risk acceptance

### Secure coding principles (apply proactively when generating code)

- Validate and sanitize all external inputs
- Use parameterized queries — never string concatenation for SQL/NoSQL
- Never hardcode secrets, passwords, or API keys
- Use cryptographically secure random generators
- Use strong hashing (SHA-256+, bcrypt, argon2) — never MD5/SHA-1 for security
- Avoid dangerous functions: `eval()`, `exec()`, `pickle.loads()`, `yaml.load()` without SafeLoader
- Use subprocess with explicit argument lists and `shell=False`
- Containers: run as non-root, read-only root filesystem, drop all capabilities
- IAM: least-privilege policies, no wildcard (`*`) actions or resources



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
