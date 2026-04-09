# Directory Scanning with File-Based Output

## Overview

All directory scanning tools in the MCP Security Scanner automatically save their output to dedicated folders by default. This design prevents large scan results from overwhelming the context window of LLMs while preserving complete scan data for detailed analysis.

**Key Benefits:**
- **Context Window Protection**: Large repositories can generate massive scan outputs that would fill or exceed LLM context limits
- **Complete Data Preservation**: Full scan results are saved to files for thorough review and compliance documentation
- **Quick Feedback**: Lightweight summaries provide immediate insights without overwhelming the conversation
- **Flexible Output**: Users can explicitly request full results when needed via `return_output=True`
- **Scan History**: Timestamped files enable tracking security posture over time

## How It Works

### Default Behavior (Recommended)

When you scan a directory, the tool:
1. Runs the security scanner on subdirectories
2. Saves the complete output to a timestamped file in a dedicated folder
3. Returns a lightweight summary with:
   - File path where full results are saved
   - Total issue count
   - Severity breakdown
   - Key metadata

**Example:**
```python
result = await scan_directory_with_grype(
    directory_path="./my-project",
    severity_threshold="MEDIUM"
)

# Returns summary like:
{
  "success": true,
  "tool": "grype",
  "output_file": ".grype/grype_scan_my-project_20260227_143022.json",
  "timestamp": "20260227_143022",
  "total_vulnerabilities": 245,
  "filtered_issues": 89,
  "severity_counts": {
    "critical": 12,
    "high": 45,
    "medium": 32,
    "low": 156
  }
}
```

### Full Output Mode (Optional)

Set `return_output=True` to receive complete scan results directly:

```python
result = await scan_directory_with_grype(
    directory_path="./my-project",
    severity_threshold="MEDIUM",
    return_output=True
)

# Returns full results with all vulnerability details
# Warning: Can be very large for big projects!
```

## Supported Scanners

All directory scanning tools follow this pattern:

| Tool | Output Directory | Purpose |
|------|-----------------|---------|
| `scan_directory_with_grype` | `.grype/` | Dependency vulnerability scanning |
| `scan_directory_with_checkov` | `.checkov/` | Infrastructure as Code security |
| `scan_directory_with_bandit` | `.bandit/` | Python security analysis |
| `scan_directory_with_semgrep` | `.semgrep/` | Multi-language code security |
| `scan_directory_with_ash` | `.ash/` | Comprehensive multi-tool scanning |
| `scan_directory_with_syft` | `.sbom/` | Software Bill of Materials generation |
| `scan_image_with_trivy` | `.trivy/` | Container image vulnerability scanning |

## File Naming Convention

All scan outputs follow a consistent naming pattern:

```
.{tool}/{tool}_scan_{target}_{timestamp}.json
```

**Components:**
- `{tool}`: Scanner name (grype, checkov, bandit, etc.)
- `{target}`: Directory or image name (sanitized for filesystem)
- `{timestamp}`: Format `YYYYMMDD_HHMMSS`

**Examples:**
- `.grype/grype_scan_typhon-rs_20260227_143022.json`
- `.checkov/checkov_scan_terraform-infra_20260227_143530.json`
- `.trivy/trivy_scan_nginx_latest_20260227_150015.json`

## Implementation Details

### Helper Method

All scanners use a shared `_save_scan_output` method:

```python
def _save_scan_output(self, tool_name: str, directory_path: str, 
                      output_data: str, extension: str = 'json') -> Dict[str, Any]:
    """Save scan output to a dedicated folder and return file path with summary."""
    # Creates .{tool}/ directory in workspace root
    # Generates timestamped filename
    # Saves output and returns metadata
```

### Summary Format Methods

Each scanner has a corresponding summary method that extracts key metrics:

- `_format_grype_summary`: Vulnerability counts by severity
- `_format_checkov_summary`: IaC issue counts and check statistics
- `_format_bandit_summary`: Python security issue counts
- `_format_semgrep_summary`: Code security finding counts
- `_format_ash_summary`: Aggregated multi-scanner results
- `_format_syft_summary`: Package counts by type and language
- `_format_trivy_image_summary`: Container vulnerability counts

## Scanner-Specific Details

### Grype - Dependency Vulnerabilities
**Scans:** Dependency files (Cargo.lock, package.json, requirements.txt, etc.)

**Summary includes:**
- Total vulnerabilities found
- Issues above severity threshold
- Breakdown by severity (critical, high, medium, low)
- Grype version

**Full output includes:**
- CVE IDs and descriptions
- Affected packages and versions
- Fixed versions (if available)
- Reference URLs

### Checkov - Infrastructure as Code
**Scans:** Terraform, CloudFormation, Kubernetes, Dockerfile, etc.

**Summary includes:**
- Total security issues
- Issues above severity threshold
- Breakdown by severity
- Passed/failed/skipped check counts

**Full output includes:**
- Check IDs and names
- File paths and line numbers
- Remediation guidelines
- Compliance framework mappings

### Bandit - Python Security
**Scans:** Python source files

**Summary includes:**
- Total security issues
- Issues above severity threshold
- Breakdown by severity (high, medium, low)
- Files scanned and lines of code

**Full output includes:**
- Test IDs and names
- Confidence levels
- Code snippets
- Detailed descriptions and references

### Semgrep - Multi-Language Code Security
**Scans:** Python, JavaScript, TypeScript, Java, Go, and more

**Summary includes:**
- Total security findings
- Issues above severity threshold
- Breakdown by severity (error, warning, info)
- Scan errors count

**Full output includes:**
- Rule IDs and messages
- File paths and line numbers
- Code snippets
- Metadata and references

### ASH - Automated Security Helper
**Scans:** Runs multiple scanners (Bandit, Checkov, cfn-nag, cdk-nag, detect-secrets, grype, syft, npm-audit)

**Summary includes:**
- Total issues across all scanners
- Breakdown by severity
- Per-scanner summaries
- ASH version

**Full output includes:**
- SARIF-formatted results
- Scanner-specific findings
- Aggregated severity counts
- Detailed metadata

### Syft - Software Bill of Materials
**Scans:** All software components and dependencies

**Summary includes:**
- Total packages cataloged
- Package counts by type (npm, python, rust-crate, etc.)
- Package counts by language
- Syft version and schema version

**Full output includes:**
- Complete package inventory
- Package locations and licenses
- PURLs and CPEs
- Dependency relationships

### Trivy - Container Image Vulnerabilities
**Scans:** Container images (local or remote)

**Summary includes:**
- Total vulnerabilities found
- Issues above severity threshold
- Breakdown by severity
- Image metadata (OS, image ID)

**Full output includes:**
- CVE IDs and titles
- Affected packages and versions
- Fixed versions
- Descriptions and references

## Usage Examples

### Basic Directory Scan
```python
# Scan with default settings (saves to file)
result = await scan_directory_with_grype(
    directory_path="./my-rust-project"
)

print(f"Scan saved to: {result['output_file']}")
print(f"Found {result['filtered_issues']} issues above MEDIUM threshold")
print(f"Severity breakdown: {result['severity_counts']}")
```

### Scan with Custom Threshold
```python
# Only report HIGH and CRITICAL issues
result = await scan_directory_with_checkov(
    directory_path="./terraform",
    severity_threshold="HIGH"
)

print(f"Critical: {result['severity_counts']['critical']}")
print(f"High: {result['severity_counts']['high']}")
```

### Request Full Output
```python
# Get complete results for detailed analysis
result = await scan_directory_with_bandit(
    directory_path="./python-app",
    severity_threshold="MEDIUM",
    return_output=True
)

# Process all findings
for finding in result['findings']:
    print(f"{finding['test_id']}: {finding['description']}")
    print(f"  File: {finding['file_path']}:{finding['line_number']}")
```

### Container Image Scan
```python
# Scan a Docker image
result = await scan_image_with_trivy(
    image_name="nginx:latest",
    severity_threshold="HIGH"
)

print(f"Image: {result['image']}")
print(f"Vulnerabilities: {result['total_vulnerabilities']}")
print(f"High severity: {result['severity_counts']['high']}")
```

### Generate SBOM
```python
# Create Software Bill of Materials
result = await scan_directory_with_syft(
    directory_path="./my-project",
    output_format="cyclonedx-json"
)

print(f"SBOM saved to: {result['sbom_file']}")
print(f"Total packages: {result['total_packages']}")
print(f"By language: {result['language_counts']}")
```

## Best Practices

### When to Use Default Mode (File Output)
- **Large repositories**: Projects with many dependencies or files
- **Regular scans**: Automated security checks in CI/CD pipelines
- **Compliance documentation**: Need to preserve complete scan records
- **Initial assessment**: First-time scanning of unfamiliar codebases

### When to Use Full Output Mode
- **Small projects**: Limited number of findings that won't overflow context
- **Specific investigation**: Need immediate access to all details
- **Interactive remediation**: Working through findings one by one
- **Custom processing**: Integrating results into other tools

### File Management
- Output directories (`.grype/`, `.checkov/`, etc.) are in `.gitignore`
- Scan files are timestamped for easy identification
- Consider periodic cleanup of old scan files
- Archive important scans for compliance or audit purposes

## Troubleshooting

### Output Directory Not Created
**Issue:** Scan fails with directory creation error

**Solution:** Ensure the workspace root is writable and the `WORKSPACE_ROOT` environment variable is set correctly in your MCP configuration.

### Large File Sizes
**Issue:** Scan output files are very large

**Solution:** This is expected for large projects. The file-based approach is specifically designed to handle this. Use the summary for quick insights and refer to the file for detailed analysis.

### Missing Scan Results
**Issue:** Can't find the output file

**Solution:** Check the `output_file` path in the returned summary. The file is saved relative to the workspace root, not the scanned directory.

## Configuration

### Setting Workspace Root

Optionally set the `WORKSPACE_ROOT` environment variable in your MCP configuration to control where scan output is saved:

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "uvx",
      "args": [
        "--from",
        "/path/to/sample-mcp-security-scanner",
        "security_scanner_mcp_server"
      ],
      "env": {
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)",
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "timeout": 120000,
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

Replace `/path/to/sample-mcp-security-scanner` with your actual repository path and `/path/to/your/workspace` with your workspace directory.

If `WORKSPACE_ROOT` is not set, the current working directory is used as the workspace root.

## Summary

The file-based output approach provides the best of both worlds:
- **Immediate feedback** through lightweight summaries
- **Complete data** preserved in timestamped files
- **Flexible access** via the `return_output` parameter
- **Scalable** to projects of any size

This design ensures that security scanning remains practical and useful even for large, complex projects while maintaining the conversational flow with AI assistants.