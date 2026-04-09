# MCP Security Scanner: Real-Time Protection for AI Code Assistants

This pattern describes how to implement a Model Context Protocol (MCP) server that integrates four industry-standard security scanning tools (Checkov, Semgrep, Bandit, and ASH) to provide comprehensive code security analysis. The server enables AI coding assistants to automatically scan code snippets and Infrastructure as Code (IaC) configurations for security vulnerabilities, misconfigurations, and compliance violations.

The solution combines Checkov for scanning IaC files (including Terraform, CloudFormation, and Kubernetes manifests), Semgrep for analyzing multiple programming languages (such as Python, JavaScript, Java, and others), Bandit for specialized Python security scanning, and ASH (Automated Security Helper) for comprehensive multi-tool scanning with aggregated results.

It provides a unified interface for security scanning with standardized response formats, making it easier to integrate security checks into development workflows. The pattern uses Python and the MCP framework to deliver automated security feedback, helping developers identify and address security issues early in the development process while learning about security best practices through detailed findings.

This pattern is particularly valuable for organizations looking to enhance their development security practices through AI-assisted coding tools, providing continuous security scanning capabilities across multiple programming languages and infrastructure definitions.

Key features:
 - Delta scanning of new code segments, reducing computational overhead
 - Isolated security tool environments preventing cross-tool contamination
 - Seamless integration with AI tools (Amazon Q Developer, Kiro, others)
 - Real-time security feedback during code generation
 - Customizable scanning rules for organizational compliance


## Demo

### Code Scanning Demo

Try these sample prompts with your AI assistant:
1. "Scan the current script and tell me the results"
2. "Scan lines 20-60 and tell me the results"
3. "Scan this Amazon DynamoDB table resource and tell me the result"

![Code Scanning Demo](docs/demo_code_scan.gif)

### Code Generation with Security Scanning Demo

Try these sample prompts to generate secure code:
1. "Generate a Terraform configuration to create a DynamoDB table with encryption enabled and scan it for security issues"
2. "Create a Python Lambda function that writes to DynamoDB and scan it for vulnerabilities"
3. "Generate a CloudFormation template for an S3 bucket with proper security settings and verify it passes security checks"
4. "Write a Python script to query DynamoDB with pagination and scan for security best practices"
5. "Create a Kubernetes deployment manifest for a microservice with security hardening and validate it"

![Code Generation Demo](docs/demo_code_generation.gif)



## Architecture
![Architecture Diagram](docs/diagram.png)

## Features

This MCP server enables AI assistants to perform comprehensive security analysis on code snippets using four powerful security scanning tools:

### 🛡️ Checkov - Infrastructure as Code Security
- Scans Infrastructure as Code (IaC) files for security misconfigurations
- Supports: Terraform, CloudFormation, Kubernetes, Dockerfile, ARM, Bicep, and more
- Detects compliance violations and security best practices

### 🔍 Semgrep - Source Code Security  
- Analyzes source code for security vulnerabilities and bugs
- Supports: Python, JavaScript, TypeScript, Java, Go, C/C++, C#, Ruby, PHP, Scala, Kotlin, Rust
- Uses security-focused rulesets for comprehensive analysis

### 🐍 Bandit - Python Security Specialist
- Specialized Python security scanner
- Detects common Python security issues like insecure functions, hardcoded secrets, injection vulnerabilities
- Provides detailed confidence and severity ratings

### 🚀 ASH - Automated Security Helper
- Comprehensive multi-tool security scanner
- Runs multiple scanners in parallel: Bandit, Checkov, cfn-nag, cdk-nag, detect-secrets, grype, syft, npm-audit
- Delta scanning support for analyzing code changes
- Aggregated results from all scanners with unified reporting
- Supports all formats from the above tools plus additional scanners
- **Note:** Semgrep is excluded from ASH scans to avoid duplication with the standalone `scan_with_semgrep` tool

### 📦 Directory Scanning with File Output
- All directory scanning tools save results to dedicated folders by default
- Prevents context window overflow in LLM interactions
- Output directories: `.grype/`, `.checkov/`, `.bandit/`, `.semgrep/`, `.ash/`, `.sbom/`, `.trivy/`
- Returns lightweight summaries with file paths
- Optional `return_output=True` parameter to get full results instead
- Timestamped files for tracking scan history
- See [SCANNER_FILE_OUTPUT.md](docs/SCANNER_FILE_OUTPUT.md) for details

## Installation

> **Note:** The following instructions are for macOS/Linux. For Windows and other code assistants, see the [AWS MCP Repository README](https://github.com/awslabs/mcp) for platform-specific instructions.

### Prerequisites
- Python >=3.10, <=3.13
- uv package manager (install from [Astral](https://docs.astral.sh/uv/getting-started/installation/))
- (Optional) ASH - Automated Security Helper for comprehensive multi-tool scanning

### Local Installation

This MCP server is not available via PyPI for enhanced security and control:

- **Security**: Verify the exact code you're running by inspecting the repository
- **Control**: Pin to specific versions and review changes before updating
- **Performance**: Local caching improves startup speed and reduces network dependencies
- **Trust**: Avoid potential package name confusion or use of unsecure mcp servers

You can install this server using one of two methods:

#### Option 1: Install from Local Path

Clone or download the repository locally:

```bash
git clone git@github.com:aws-samples/sample-mcp-security-scanner.git
cd sample-mcp-security-scanner
```

Then configure your MCP client to use the local path (see configuration examples below).

#### Option 2: Install from GitHub

Configure your MCP client to install directly from GitHub using:
```
git+https://github.com/aws-samples/sample-mcp-security-scanner.git@main
```

This method automatically downloads and installs the server without requiring a local clone (see configuration examples below).
 
### Dependencies
The server automatically installs:
- `checkov>=3.0.0` - IaC security scanner
- `semgrep>=1.45.0` - Source code security scanner  
- `bandit>=1.7.5` - Python security scanner
- `mcp[cli]>=1.11.0` - MCP framework
- `pydantic>=1.10.0` - Data validation
- `loguru>=0.6.0` - Logging

### Optional: ASH Integration

For comprehensive multi-tool scanning with ASH (Automated Security Helper):

```bash
# Install ASH using uvx (recommended)
uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Or install with pip
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Or install with pipx (isolated environment)
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Verify installation
ash --version
```

ASH provides additional scanners beyond the core three:
- **cfn-nag**: CloudFormation security analysis
- **cdk-nag**: AWS CDK security checks
- **detect-secrets**: Secret detection in code
- **grype**: Vulnerability scanning for dependencies
- **syft**: Software Bill of Materials (SBOM) generation
- **npm-audit**: Node.js dependency security

Note: ASH requires Python 3.10+ and uses UV for package management. Some scanners may require additional dependencies (see [ASH documentation](https://github.com/awslabs/automated-security-helper)).

## Usage

### MCP Configuration

Configure your MCP client to use the server. The configuration varies by client and supports both local path and GitHub installation methods.

### Getting Started with Kiro

<details>
<summary>Install in Kiro</summary>

See [Kiro Model Context Protocol Documentation](https://kiro.dev/docs/mcp/configuration/) for details.

1. Navigate `Kiro` > `MCP Servers`
2. Add a new MCP server by clicking the `Open MCP Config` button.
3. Paste one of the configurations below:

#### Option 1: Install from Local Path

Replace `/path/to/sample-mcp-security-scanner` with your actual repository path:

#### `.kiro/settings/mcp.json` (local) or `~/.kiro/settings/mcp.json` (global)

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
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

#### Option 2: Install from GitHub

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/aws-samples/sample-mcp-security-scanner.git@main",
        "security_scanner_mcp_server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

</details>

### Getting Started with Amazon Q Developer

<details>
<summary>Install in Amazon Q Developer</summary>

See [Amazon Q Developer documentation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/qdev-mcp.html) for details.

1. **Manual Configuration**
   - Edit the MCP configuration file at `~/.aws/amazonq/mcp.json` (global) or `.amazonq/mcp.json` (local).
   - Use one of the configurations below:

#### Option 1: Install from Local Path

Replace `/path/to/sample-mcp-security-scanner` with your actual repository path:

#### `~/.aws/amazonq/mcp.json`

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
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      }
    }
  }
}
```

#### Option 2: Install from GitHub

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/aws-samples/sample-mcp-security-scanner.git@main",
        "security_scanner_mcp_server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      }
    }
  }
}
```

</details>

### Getting Started with Cline

<details>
<summary>Install in Cline</summary>

1. Install the [Cline VS Code Extension](https://marketplace.visualstudio.com/items?itemName=saoudrizwan.claude-dev).
2. Click the extension to open it and select **MCP Servers**.
3. Select the **Installed** tab, then click **Configure MCP Servers** to open the `cline_mcp_settings.json` file.
4. Add one of the configurations below:

#### Option 1: Install from Local Path

Replace `/path/to/sample-mcp-security-scanner` with your actual repository path:

#### `cline_mcp_settings.json`

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
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

#### Option 2: Install from GitHub

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "uvx",
      "args": [
        "--from",
        "git+https://github.com/aws-samples/sample-mcp-security-scanner.git@main",
        "security_scanner_mcp_server"
      ],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "/path/to/your/workspace (optional, defaults to current working directory)"
      },
      "disabled": false,
      "autoApprove": []
    }
  }
}
```

</details>

### Other Code Assistants

For configuration instructions for Cursor, Windsurf, VS Code, Claude Desktop, and other MCP clients, see the [AWS MCP Repository README](https://github.com/awslabs/mcp).

### Available Tools

#### 1. `scan_with_checkov`
Scan Infrastructure as Code files for security issues.

**Parameters:**
- `code` (string): IaC content to scan
- `format_type` (string): Format type (terraform, cloudformation, kubernetes, dockerfile, etc.)

#### 2. `scan_with_semgrep`
Scan source code for security vulnerabilities.

**Parameters:**
- `code` (string): Source code content to scan
- `language` (string): Programming language (python, javascript, java, etc.)

#### 3. `scan_with_bandit`
Scan Python code for security issues (Python-specific).

**Parameters:**
- `code` (string): Python code content to scan

#### 4. `scan_with_ash`
Scan code using ASH for comprehensive multi-tool security analysis.

**Parameters:**
- `code` (string): Code content to scan
- `file_extension` (string): File extension (e.g., .py, .tf, .js, Dockerfile)
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM

**Features:**
- Runs multiple security scanners in parallel
- Provides aggregated results from all applicable scanners
- Delta scanning optimized for code snippets
- Unified severity reporting across all tools

#### 5. `scan_with_trivy`
Scan Infrastructure as Code or Dockerfile using Trivy for security issues.

**Parameters:**
- `code` (string): Code content to scan (Dockerfile or IaC config)
- `scan_type` (string, optional): Type of scan (dockerfile, terraform, kubernetes, config). Default: dockerfile

#### 6. `check_ash_availability`
Check if ASH is installed and available, including which individual scanners are available.

**Returns:** Installation status, version information, scanner availability details, and a formatted report

**Example Response:**
```json
{
  "success": true,
  "available": true,
  "version": "3.2.1",
  "message": "ASH is installed and available: 3.2.1",
  "scanner_summary": {
    "available": 6,
    "total": 9,
    "unavailable": 3
  },
  "formatted_report": "ASH Status: ✅ Installed (version 3.2.1)\nScanner Availability: 6 out of 9 scanners available\n\n✅ Available Scanners:\n  • Bandit - Python security linter (python-based)\n  • Semgrep - Multi-language SAST (python-based)\n  • Checkov - IaC security scanner (python-based)\n  • cdk-nag - AWS CDK security scanner (npm-based)\n  • detect-secrets - Secret detection (python-based)\n  • npm-audit - Node.js dependency scanner (npm-based)\n\n❌ Missing Scanners:\n  • cfn-nag - CloudFormation security scanner (ruby-based)\n    Install with: gem install cfn-nag\n  • Grype - Vulnerability scanner (binary)\n    Install with: Install Grype from official source\n  • Syft - SBOM generator (binary)\n    Install with: Install Syft from official source\n\nThe tool successfully shows which scanners are available and which ones need additional OS-level dependencies.",
  "scanners": {
    "bandit": {
      "name": "Bandit",
      "description": "Python security linter",
      "available": true,
      "dependency_type": "python",
      "file_types": [".py"],
      "status": "installed"
    },
    "semgrep": {
      "name": "Semgrep",
      "description": "Multi-language SAST",
      "available": true,
      "dependency_type": "python",
      "file_types": [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"],
      "status": "installed"
    },
    "checkov": {
      "name": "Checkov",
      "description": "IaC security scanner",
      "available": true,
      "dependency_type": "python",
      "file_types": [".tf", ".yaml", ".yml", ".json", "Dockerfile"],
      "status": "installed"
    },
    "cfn-nag": {
      "name": "cfn-nag",
      "description": "CloudFormation security scanner",
      "available": false,
      "dependency_type": "ruby",
      "file_types": [".yaml", ".yml", ".json", ".template"],
      "status": "not installed",
      "install_hint": "gem install cfn-nag"
    },
    "cdk-nag": {
      "name": "cdk-nag",
      "description": "AWS CDK security scanner",
      "available": true,
      "dependency_type": "npm",
      "file_types": [".ts", ".js"],
      "status": "installed"
    },
    "detect-secrets": {
      "name": "detect-secrets",
      "description": "Secret detection",
      "available": true,
      "dependency_type": "python",
      "file_types": ["*"],
      "status": "installed"
    },
    "grype": {
      "name": "Grype",
      "description": "Vulnerability scanner",
      "available": false,
      "dependency_type": "binary",
      "file_types": ["*"],
      "status": "not installed",
      "install_hint": "Install Grype from official source"
    },
    "syft": {
      "name": "Syft",
      "description": "SBOM generator",
      "available": false,
      "dependency_type": "binary",
      "file_types": ["*"],
      "status": "not installed",
      "install_hint": "Install Syft from official source"
    },
    "npm-audit": {
      "name": "npm-audit",
      "description": "Node.js dependency scanner",
      "available": true,
      "dependency_type": "npm",
      "file_types": ["package.json", "package-lock.json"],
      "status": "installed"
    }
  }
}
```

**Formatted Report Output:**
When you call this tool, the AI assistant will display the `formatted_report` field which provides a clean, readable summary:

```
ASH Status: ✅ Installed (version 3.2.1)
Scanner Availability: 6 out of 9 scanners available

✅ Available Scanners:
  • Bandit - Python security linter (python-based)
  • Semgrep - Multi-language SAST (python-based) (disabled in ASH - use standalone scan_with_semgrep tool)
  • Checkov - IaC security scanner (python-based)
  • cdk-nag - AWS CDK security scanner (npm-based)
  • detect-secrets - Secret detection (python-based)
  • npm-audit - Node.js dependency scanner (npm-based)

❌ Missing Scanners:
  • cfn-nag - CloudFormation security scanner (ruby-based)
    Install with: gem install cfn-nag
  • Grype - Vulnerability scanner (binary)
    Install with: Install Grype from official source
  • Syft - SBOM generator (binary)
    Install with: Install Syft from official source

The tool successfully shows which scanners are available and which ones need additional OS-level dependencies.
```

**Note:** Semgrep is excluded from ASH scans to avoid duplication with the standalone `scan_with_semgrep` tool, which provides more focused and faster scanning.

**Use this tool to:**
- Verify ASH installation before running scans
- Check which scanners are available in your environment
- Identify missing dependencies (e.g., cfn-nag requires Ruby, grype/syft are binaries)
- Get installation hints for missing scanners

#### 7. `get_supported_formats`
Get information about supported formats and languages for all tools.

#### 8. `generate_security_report`
Generate a SECURITY.md report from scan results.

**Parameters:**
- `project_name` (string): Name of the project being analyzed
- `scan_results` (string): JSON string with scan results from any scanning tool. Can be a single result object or an array of result objects.

**Workflow:**
1. Scan relevant files using the appropriate scanner tools
2. Collect all scan result JSON objects into an array
3. Call `generate_security_report` with `project_name` and `scan_results` (JSON string)
4. Save the returned `report` field as `SECURITY.md`

**Report includes:**
- Executive Summary — risk level (CRITICAL/HIGH/MEDIUM/LOW) and total finding counts
- Scan Results — breakdown by scanner, format, and severity
- Critical & High Severity Findings — detailed per-finding info
- Medium & Low Severity Findings — summary table
- Threat Model Inputs — STRIDE classification
- Compliance & Regulatory Notes — SOC2, PCI-DSS, HIPAA, GDPR observations
- Recommendations — prioritized actions by severity tier

### Directory Scanning Tools

The following tools scan entire project directories and save results to files by default to prevent context window overflow:

#### 8. `scan_directory_with_grype`
Scan a project directory for dependency vulnerabilities.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.grype/grype_scan_{directory}_{timestamp}.json` and returns summary

#### 9. `scan_directory_with_checkov`
Scan a project directory for IaC security issues.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.checkov/checkov_scan_{directory}_{timestamp}.json` and returns summary

#### 10. `scan_directory_with_bandit`
Scan a project directory for Python security issues.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.bandit/bandit_scan_{directory}_{timestamp}.json` and returns summary

#### 11. `scan_directory_with_semgrep`
Scan a project directory for source code security issues.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.semgrep/semgrep_scan_{directory}_{timestamp}.json` and returns summary

#### 12. `scan_directory_with_ash`
Scan a project directory with ASH for comprehensive multi-tool security analysis.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.ash/ash_scan_{directory}_{timestamp}.json` and returns summary

#### 13. `scan_directory_with_syft`
Generate Software Bill of Materials (SBOM) for a project directory.

**Parameters:**
- `directory_path` (string): Path to the directory to scan
- `output_format` (string, optional): Output format (json, cyclonedx-json, spdx-json, table). Default: json
- `save_sbom` (bool, optional): Save full SBOM to file. Default: False (only returns summary)

**Output:** Saves to `.sbom/sbom_{directory}_{timestamp}.{extension}` and returns summary

#### 14. `scan_image_with_trivy`
Scan a container image for vulnerabilities.

**Parameters:**
- `image_name` (string): Container image to scan (e.g., nginx:latest, python:3.9)
- `severity_threshold` (string, optional): Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL). Default: MEDIUM
- `return_output` (bool, optional): Return full output instead of saving to file. Default: False

**Output:** Saves to `.trivy/trivy_scan_{image}_{timestamp}.json` and returns summary

**Note:** All directory scanning tools automatically save full results to dedicated folders and return lightweight summaries. Use `return_output=True` to get full results in the response instead. See [SCANNER_FILE_OUTPUT.md](docs/SCANNER_FILE_OUTPUT.md) for more details.

## Supported Formats

### Checkov (IaC)
- **terraform**: .tf, .tfvars, .tfstate
- **cloudformation**: .yaml, .yml, .json, .template  
- **kubernetes**: .yaml, .yml
- **dockerfile**: Dockerfile
- **arm**: .json (Azure Resource Manager)
- **bicep**: .bicep
- **serverless**: .yml, .yaml
- **helm**: .yaml, .yml, .tpl
- **github_actions**: .yml, .yaml
- **gitlab_ci**: .yml, .yaml
- **ansible**: .yml, .yaml

### Semgrep (Source Code)
- **python**: .py
- **javascript**: .js
- **typescript**: .ts
- **java**: .java
- **go**: .go
- **c**: .c
- **cpp**: .cpp
- **csharp**: .cs
- **ruby**: .rb
- **php**: .php
- **scala**: .scala
- **kotlin**: .kt
- **rust**: .rs

### Bandit (Python Only)
- **python**: .py files

## Response Format

All scanning tools return a consistent response format:

```json
{
  "success": true,
  "tool": "checkov|semgrep|bandit|ash",
  "format_type": "terraform",
  "language": "python", 
  "total_issues": 3,
  "findings": [
    {
      "check_id": "CKV_AWS_20",
      "severity": "HIGH",
      "description": "S3 Bucket has an ACL defined which allows public access",
      "line_number": 3,
      "resource": "aws_s3_bucket.example"
    }
  ],
  "summary": {
    "high": 1,
    "medium": 2,
    "low": 0
  }
}
```

## Integration with AI Assistants

This MCP server is designed to work with AI coding assistants like Kiro, Amazon Q Developer, Cline and others. The AI can:

1. **Analyze generated code**: Automatically scan code snippets for security issues
2. **Provide context-aware suggestions**: Get language and format-specific security recommendations  
3. **Continuous security feedback**: Integrate security scanning into the development workflow
4. **Educational insights**: Learn about security best practices through detailed findings

## Kiro Power: Security Scanner

This repository is also packaged as a [Kiro Power](https://kiro.dev/docs/powers/) — a plug-and-play capability bundle that includes the MCP server, steering files, and documentation. Installing the power gives Kiro automatic access to all scanning tools without manual MCP configuration.

### What's included

```
sample-mcp-security-scanner/
├── POWER.md                          # Power metadata and documentation (repo root)
├── mcp.json                          # Pre-configured MCP server (auto-approve all tools)
├── steering/
│   ├── scanning-workflows.md         # Auto-included: scanner selection, scan-fix-rescan loop, report generation
│   └── secure-coding.md              # Auto-included: application, infrastructure, and dependency security rules
├── security_scanner_mcp_server/      # MCP server source code
├── agents/                           # Pre-built Kiro agent configs
├── hooks/                            # Kiro hook definitions
├── tests/                            # Test suite
└── docs/                             # Documentation, examples, and assets
```

### How it works

- **`mcp.json`** — Pre-configured MCP server definition with all scanning tools auto-approved. Kiro automatically starts the security scanner server when the power is installed.
- **`scanning-workflows.md`** (auto-included steering) — Guides Kiro to pick the right scanner for each file type, run scan-fix-rescan loops, and generate SECURITY.md reports.
- **`secure-coding.md`** (auto-included steering) — Instructs Kiro to proactively apply secure coding practices when generating or reviewing code (input validation, parameterized queries, no hardcoded secrets, strong crypto, least-privilege IAM, etc.).

### Installing the power

1. Open Kiro and navigate to the **Powers** panel.
2. Click **Add Custom Power**.
3. Select **Import power from GitHub**.
4. Paste the repository URL and press Enter:
   ```
   https://github.com/aws-samples/sample-mcp-security-scanner
   ```

The power auto-configures the MCP server and steering files — no manual setup needed.

### Usage with the power

Once installed, Kiro automatically applies the steering rules in every conversation. You can use prompts like:

- "Scan the current file for security vulnerabilities"
- "Scan this Terraform config, fix any issues, and re-scan until clean"
- "Run security scans on the project and generate a SECURITY.md report"
- "Scan the entire project directory and summarize the findings"

Kiro will automatically select the right scanner based on file type, apply secure coding practices, and follow the scan-fix-rescan workflow.

## Kiro Agent: Sec-Lazio

This repository includes a pre-built [Kiro](https://kiro.dev) agent that uses the MCP Security Scanner to provide security-first coding assistance.

| Feature | Description |
|---------|-------------|
| Auto-scan | Scans every code change with Semgrep, Bandit, or Checkov |
| Fix loop | Finds vulnerabilities → fixes them → re-scans until clean |
| SECURITY.md | Generates structured reports with STRIDE threat model |
| Secure by default | Applies security best practices when generating code |
| Compliance hints | Flags SOC2, PCI-DSS, HIPAA, GDPR relevant patterns |

### Quick install

```bash
# Global (all projects)
cp agents/sec-lazio/sec-lazio.json ~/.kiro/agents/

# Or project-specific
mkdir -p .kiro/agents
cp agents/sec-lazio/sec-lazio.json .kiro/agents/
```

### Activate

```
/agent sec-lazio
```

Or use the keyboard shortcut: `Ctrl+Shift+S`

See [agents/README.md](agents/README.md) for full documentation and example prompts.

## Scanning Strategy

Use the right scanner for the job:

| File type | Primary scanner | Secondary scanner |
|-----------|----------------|-------------------|
| Python (.py) | `scan_with_bandit` | `scan_with_semgrep` |
| JavaScript (.js), TypeScript (.ts) | `scan_with_semgrep` | — |
| Java, Go, Rust, Kotlin, C# | `scan_with_semgrep` | — |
| Terraform (.tf, .tfvars) | `scan_with_checkov` | — |
| CloudFormation (.yaml, .yml, .json) | `scan_with_checkov` | — |
| Kubernetes manifests | `scan_with_checkov` | — |
| Dockerfile | `scan_with_checkov` | `scan_with_trivy` |
| Container images | `scan_image_with_trivy` | — |
| Dependency manifests | `scan_directory_with_grype` | — |
| Full project | `scan_directory_with_*` variants | — |

For Python files, run both Bandit and Semgrep — they catch different classes of issues.

## Severity Handling

| Severity | Action |
|----------|--------|
| CRITICAL | Must be fixed before deployment — block the release |
| HIGH | Fix in the current sprint — these are exploitable vulnerabilities |
| MEDIUM | Triage and plan — fix in the next sprint or accept with justification |
| LOW | Backlog — review for risk acceptance or opportunistic fix |

## Development

### Running Locally
```bash
# Clone and install
git clone git@github.com:aws-samples/sample-mcp-security-scanner.git
cd sample-mcp-security-scanner
uv pip install -e .

# Run the server
python -m security_scanner_mcp_server.server
```

### Testing

The project includes several test scripts to verify functionality:

#### 1. Comprehensive Scanner Tests
```bash
# Test all scanners (Checkov, Semgrep, Bandit, ASH)
python tests/test_scanner.py
```
This script tests:
- Checkov with Terraform code (S3 bucket and security group misconfigurations)
- Semgrep with Python code (SQL injection and hardcoded secrets)
- Bandit with Python code (insecure pickle usage and weak crypto)

#### 2. ASH Integration Tests
```bash
# Test ASH availability and scanning
python tests/test_ash_integration.py
```
This script tests:
- ASH installation and version check
- ASH scanning with Python code containing security issues
- Scanner availability reporting

#### 3. Simple Standalone Tests
```bash
# Test scanners without MCP dependencies
python tests/simple_test.py
```
This script tests:
- Basic Checkov functionality
- Basic Semgrep functionality
- Basic Bandit functionality
- Useful for troubleshooting scanner installations

#### 4. ASH Import Test
```bash
# Verify ASH module can be imported
python test_ash_import.py
```
This script verifies:
- ASH module is properly installed
- ASH version can be retrieved
- Python environment is correctly configured

### Sample Kiro Hooks

The project includes sample Kiro hooks in the `hooks/` directory that demonstrate automated security scanning workflows. These hooks can be installed in your Kiro IDE to enable automatic security scanning.

#### 1. Security Scanner with Auto-Remediation
**File:** `hooks/security-scan-on-save.kiro.hook`

This hook automatically scans files when saved and offers to fix security issues:

**Features:**
- Triggers on file save for source code and IaC files
- Automatically selects the appropriate scanner:
  - Bandit for Python files
  - Semgrep for multi-language source code
  - Checkov for Infrastructure as Code
- Performs initial security scan
- Offers to remediate findings (with approval):
  - Replaces insecure functions with secure alternatives
  - Removes hardcoded secrets
  - Fixes SQL injection vulnerabilities
  - Updates insecure configurations
- Rescans after remediation to verify fixes
- Provides detailed before/after comparison report

**Supported File Types:**
- Source code: `.py`, `.js`, `.ts`, `.java`, `.go`, `.c`, `.cpp`, `.cs`, `.rb`, `.php`, `.scala`, `.kt`, `.rs`
- IaC: `.tf`, `.tfvars`, `.yaml`, `.yml`, `.json`, `.bicep`, `Dockerfile*`

#### 2. Security Scanner Report (Read-Only)
**File:** `hooks/security-scan-report-on-save.kiro.hook`

This hook scans all open editor files and provides a security report without modifying code:

**Features:**
- Triggers on file save
- Scans ALL currently open editor files (not just the active one)
- Automatically selects appropriate scanner per file type
- Reports security issues with severity levels
- Provides remediation recommendations
- Read-only mode - never modifies source code
- Reuses current chat session for continuous feedback

**Use Cases:**
- Security audits of multiple files
- Pre-commit security checks
- Learning about security issues without auto-fixing
- Team code reviews with security focus

#### Installing Hooks in Kiro

1. **Copy hooks to your project:**
   ```bash
   # Copy to workspace-level hooks (project-specific)
   cp hooks/*.kiro.hook .kiro/hooks/
   
   # Or copy to user-level hooks (global)
   cp hooks/*.kiro.hook ~/.kiro/hooks/
   ```

2. **Enable hooks in Kiro:**
   - Open Kiro IDE
   - Navigate to the "Agent Hooks" section in the explorer view
   - Enable the desired hooks
   - Or use Command Palette: "Open Kiro Hook UI"

3. **Customize hooks:**
   - Edit the `.kiro.hook` files to adjust file patterns
   - Modify the prompts to change scanning behavior
   - Enable/disable auto-remediation as needed

**Note:** Hooks require the security-scanner MCP server to be configured and running in Kiro.

## Troubleshooting

| Issue | Solution |
|-------|----------|
| Environment setup issues | Verify Python 3.10+ is installed. Ensure `uv` package manager is installed. |
| Scanner issues | Verify file formats are supported. Check file syntax is valid. Ensure proper file extensions are used. |
| Integration problems | Verify the MCP server is running. Check the configuration file is correct. Validate API endpoints. |
| ASH not available | Install ASH using `uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.5` |
| Trivy not found | macOS: `brew install trivy`. Linux: see [Trivy installation](https://aquasecurity.github.io/trivy/latest/getting-started/installation/). |

To enable debug logging, set `"FASTMCP_LOG_LEVEL"` to `"DEBUG"` in your MCP configuration.

## Related Resources

- [AWS Prescriptive Guidance Pattern](https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/deploy-real-time-coding-security-validation-by-using-an-mcp-server-with-kiro-and-other-coding-assistants.html)
- [MCP Security Scanner on GitHub](https://github.com/aws-samples/sample-mcp-security-scanner)
- [Model Context Protocol (MCP) documentation](https://modelcontextprotocol.io/)
- [Kiro documentation](https://kiro.dev/docs/)
- [Amazon Q Developer documentation](https://docs.aws.amazon.com/amazonq/latest/qdeveloper-ug/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [Bandit documentation](https://bandit.readthedocs.io/)
- [Checkov documentation](https://www.checkov.io/1.Welcome/Quick%20Start.html)
- [Semgrep documentation](https://semgrep.dev/docs/)
- [ASH documentation](https://github.com/awslabs/automated-security-helper)

## Contributing

Contributions welcome! Please read CONTRIBUTING.md for guidelines.

## Authors

Pattern created by Ivan Girardi (AWS) and Iker Reina Fuente (AWS).

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.
