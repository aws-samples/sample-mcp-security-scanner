---
name: "security-scanner"
displayName: "Security Scanner"
description: "Scan code and infrastructure for security vulnerabilities with Semgrep, Bandit, Checkov, Trivy, Grype, and ASH — generate SECURITY.md reports with STRIDE threat model inputs and compliance notes"
keywords: ["security", "scan", "vulnerability", "sast", "iac", "semgrep", "bandit", "checkov", "trivy", "grype", "ash", "stride", "threat-model", "compliance", "owasp", "cwe", "devsecops"]
author: "AWS Samples"
---

# Security Scanner Power

Comprehensive security scanning for source code and Infrastructure as Code, with automated SECURITY.md report generation including STRIDE threat model inputs and compliance notes.

## Overview

This power integrates six industry-standard security scanners into Kiro, enabling real-time vulnerability detection as you write code. It covers source code (Python, JavaScript, TypeScript, Java, Go, Rust, and more), IaC (Terraform, CloudFormation, Kubernetes, Dockerfile), container images, and dependency manifests.

It also generates structured SECURITY.md reports via the `generate_security_report` tool, which aggregates scan results into an executive summary, detailed findings, STRIDE threat model inputs, compliance notes, and prioritized recommendations.

All scanning runs locally — no code leaves your machine.

## Features

- Scan source code snippets or entire directories for vulnerabilities
- Scan IaC files for misconfigurations and compliance violations
- Scan container images for known CVEs
- Generate Software Bill of Materials (SBOM)
- Produce SECURITY.md reports with STRIDE classification and compliance notes
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

The `generate_security_report` tool takes scan results JSON and produces a structured report with:

1. **Executive Summary** — risk level (CRITICAL/HIGH/MEDIUM/LOW) and total finding counts
2. **Scan Results** — breakdown by scanner, format, and severity
3. **Critical & High Severity Findings** — detailed per-finding info (ID, severity, scanner, line, description, resource, guideline)
4. **Medium & Low Severity Findings** — summary table
5. **Threat Model Inputs** — STRIDE classification (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege) with applicability based on finding keywords
6. **Compliance & Regulatory Notes** — reminder to review against SOC2, PCI-DSS, HIPAA, GDPR
7. **Recommendations** — prioritized actions by severity tier
8. **Tool Information** — links to MCP Security Scanner and AWS Prescriptive Guidance pattern

### Generating a Report

1. Scan relevant files using the appropriate scanner tools
2. Collect all scan result JSON objects into an array
3. Call `generate_security_report` with `project_name` and `scan_results` (JSON string)
4. Save the returned `report` field as `SECURITY.md`

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

When calling any `scan_directory_with_*` tool, always pass the absolute path of the project as `directory_path`. Never use `.`, `..`, or relative paths — the MCP server runs in an isolated environment and cannot infer the workspace location.

Output is saved inside the scanned directory under dedicated folders to prevent context window overflow:

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
