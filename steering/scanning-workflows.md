---
inclusion: auto
---

#[[file:steering/secure-coding.md]]
#[[file:steering/security-report.md]]

# Security Scanning Workflows

## Available Tools

All tools provided by the MCP Security Scanner:

### Snippet scanners (scan code passed as string)

| Tool | What it scans | When to use |
|------|--------------|-------------|
| `scan_with_bandit` | Python code | Always for .py files |
| `scan_with_semgrep` | 13+ languages (Python, JS, TS, Java, Go, Rust, etc.) | Always for source code |
| `scan_with_checkov` | IaC (Terraform, CloudFormation, K8s, Dockerfile, etc.) | Always for IaC files |
| `scan_with_trivy` | Dockerfile and IaC | Dockerfile and IaC security |
| `scan_with_ash` | Any file type via multi-tool scanning | Only when user explicitly requests ASH |
| `scan_image_with_trivy` | Container images (e.g., nginx:latest) | When a Dockerfile or image reference is present |

### Directory scanners (scan entire directories)

| Tool | What it scans | When to use |
|------|--------------|-------------|
| `scan_directory_with_semgrep` | Source code in 13+ languages | Full project source code scan |
| `scan_directory_with_bandit` | All Python files | Full project Python scan |
| `scan_directory_with_checkov` | All IaC files | Full project IaC scan |
| `scan_directory_with_grype` | Dependency manifests (package.json, requirements.txt, go.mod, etc.) | Dependency vulnerability scan |
| `scan_directory_with_ash` | All file types via multi-tool scanning | Only when user explicitly requests ASH |
| `scan_directory_with_syft` | All dependency files | Generate Software Bill of Materials (SBOM) |

### Utility tools

| Tool | Purpose |
|------|---------|
| `check_ash_availability` | Verify which scanners are installed before scanning |
| `get_supported_formats` | List all supported languages and IaC formats |
| `generate_security_report` | Generate SECURITY.md from scan results |

## Scanner Selection by File Type

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

## Generating SECURITY.md Reports

When the user asks to generate a SECURITY.md report, determine the scope first.

### Single file report

If the user asks to scan a specific file or the active file:

1. Read the file content
2. Identify the file type and select the appropriate scanner(s) from the table above
3. Run the scanner(s) — for Python, run both `scan_with_bandit` AND `scan_with_semgrep`
4. For Dockerfiles, also run `scan_with_trivy`
5. Collect all scan result JSON objects into an array
6. Call `generate_security_report` with `project_name` and `scan_results`
7. Save the returned `report` field as `SECURITY.md`

### Full project / directory report

If the user asks to scan the whole project, a directory, or just says "generate a security report":

1. First, run `check_ash_availability` to see which scanners are installed. Inform the user of any missing tools before proceeding.
2. Get the absolute project path using `pwd` — never pass `.` or a relative path.
3. Run directory scanners **sequentially** (not in parallel) with `return_output=True`. Always pass the absolute path. Results are capped at 100 findings inline to prevent context overflow — full results are saved to file automatically:
   - `scan_directory_with_semgrep` — always (covers 13+ languages) [Python dependency]
   - `scan_directory_with_bandit` — always (Python-specific deep analysis) [Python dependency]
   - `scan_directory_with_checkov` — always (catches IaC issues) [Python dependency]
   - `scan_directory_with_grype` — if installed [requires separate install: `brew install grype`]
   - `scan_directory_with_syft` — if installed [requires separate install: `brew install syft`]
   - `scan_directory_with_ash` — **only if the user explicitly asks for ASH or a comprehensive scan** — inform the user it's available but do NOT run it by default [Python dependency]
   - `scan_image_with_trivy` — if Dockerfiles or images present [requires separate install: `brew install trivy`]
4. Collect all successful scan result JSON objects into an array (skip failed/unavailable tools)
5. Call `generate_security_report` with `project_name` and the combined results
6. Save the returned `report` field as `SECURITY.md`
7. If any tools were unavailable, note this in the response — the report's Security Assessment Coverage section will show them as GAPs automatically

### What `generate_security_report` needs

The tool requires:
- `project_name` (string) — name of the project
- `scan_results` (string) — JSON string with an array of scan result objects

It automatically loads `.security/config.yaml` for assumptions and resolved findings.

Optional parameters (only if the user provides them in chat):
- `assumptions` — JSON array of additional assumptions
- `resolved_findings` — JSON array of additional resolved findings

## Scan-Fix-Rescan Loop

When asked to fix security issues:

1. Read the file and scan it with the appropriate tool
2. Review findings by severity (CRITICAL > HIGH > MEDIUM > LOW)
3. Fix issues starting from highest severity
4. Re-scan the file to verify fixes
5. Repeat until clean or only accepted risks remain
6. Summarize what was fixed and what remains

## Severity Handling

- **CRITICAL**: Must be fixed before deployment — block the release
- **HIGH**: Fix in the current sprint — these are exploitable vulnerabilities
- **MEDIUM**: Triage and plan — fix in the next sprint or accept with justification
- **LOW**: Backlog — review for risk acceptance or opportunistic fix

## Directory Scanning Output

Directory scanning tools save results to dedicated output folders by default to prevent context window overflow:

| Tool | Output Directory |
|------|-----------------|
| Semgrep | `.semgrep/` |
| Bandit | `.bandit/` |
| Checkov | `.checkov/` |
| Grype | `.grype/` |
| ASH | `.ash/` |
| Trivy | `.trivy/` |
| Syft | `.sbom/` |

Use `return_output=True` when you need the full results inline (required for report generation).
