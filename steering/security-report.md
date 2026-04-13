---
inclusion: auto
---

# Security Report Generation

## Before Generating a Report

When the user asks to generate a SECURITY.md report, check if `.security/config.yaml` exists in the project root:

**If it exists:** The tool loads it automatically. No action needed — proceed with scanning and report generation.

**If it does NOT exist:** Ask the user:

> "I don't see a `.security/config.yaml` in this project. This file lets you define project assumptions (e.g., 'authentication is handled by Cognito with MFA') and document resolved findings. These appear in the SECURITY.md report and help with threat modeling.
>
> Would you like me to:
> 1. **Create a template** with example assumptions you can fill in
> 2. **Skip it** and generate the report with only auto-generated assumptions
>
> You can always add it later."

If the user chooses option 1, create `.security/config.yaml` using this template:

```yaml
# Project Security Context — loaded automatically by generate_security_report
# See: https://github.com/aws-samples/sample-mcp-security-scanner

project:
  name: <project-name>
  description: <brief project description>

# Security assumptions — document what you assume to be true
# STRIDE categories: Spoofing | Tampering | Repudiation |
#   Information Disclosure | Denial of Service | Elevation of Privilege
assumptions:
  # - assumption: <What you assume to be true>
  #   linked_threats: <STRIDE category>
  #   comments: <Evidence or context>

# Resolved findings — document what has been fixed
resolved_findings:
  # - id: <Finding ID from scanner>
  #   tool: <scanner name>
  #   severity: <HIGH, MEDIUM, LOW>
  #   action: <What was done to fix it>
```

Fill in the project name and description from the README or ask the user. Leave assumptions and resolved_findings commented out — the user fills them in.

If the user chooses option 2, proceed normally. The report will have auto-generated assumptions only (based on which scanners ran and which didn't).

## Generating Reports

When generating a security report with `generate_security_report`:

1. The tool automatically loads `.security/config.yaml` — no need to pass assumptions or resolved findings as parameters unless the user wants to add one-off extras.
2. If the user provides additional assumptions in chat, pass them via the `assumptions` parameter. They are appended after the file-based ones.
3. Same for `resolved_findings` — file-based ones load first, parameter ones are appended.
4. Check the `config_loaded` field in the response to know if the config file was found.

## Report Purpose

The SECURITY.md report is a security posture document for the project repository. It serves as input for threat modeling and security reviews — it is not a threat model itself. The disclaimer in the report makes this clear.
