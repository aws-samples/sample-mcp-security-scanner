# Installation Guide - Security Scanner MCP Server

## Quick Start

### 1. Install with uv (Recommended)

```bash
# Install the MCP server using uv
uvx security_scanner_mcp_server

# Or install from local directory
cd sample-mcp-security-scanner
uv pip install -e .
```

### 2. Configure MCP Client

Add to your MCP configuration file:

**Workspace level**: `.kiro/settings/mcp.json`
**User level**: `~/.kiro/settings/mcp.json`

```json
{
  "mcpServers": {
    "security-scanner": {
      "command": "uvx",
      "args": ["security_scanner_mcp_server"],
      "env": {
        "FASTMCP_LOG_LEVEL": "ERROR",
        "WORKSPACE_ROOT": "PATH_TO_YOUR_WORKSPACE (optional, defaults to current working directory)"
      },
      "disabled": false,
      "autoApprove": [
        "scan_with_checkov",
        "scan_with_semgrep", 
        "scan_with_bandit",
        "scan_with_ash",
        "scan_with_trivy",
        "scan_image_with_trivy",
        "scan_directory_with_grype",
        "scan_directory_with_checkov",
        "scan_directory_with_bandit",
        "scan_directory_with_semgrep",
        "scan_directory_with_ash",
        "scan_directory_with_syft",
        "check_ash_availability",
        "get_supported_formats",
        "generate_security_report"
      ]
    }
  }
}
```

### 3. Test Installation

```bash
# Test the security tools
python tests/simple_test.py

# Test the MCP server (requires mcp dependencies)
python tests/test_scanner.py
```

## Manual Installation

### Prerequisites
- Python >=3.10, <=3.13
- pip or uv package manager

### Install Dependencies

```bash
# Using pip
pip install -r requirements.txt

# Using uv
uv pip install -r requirements.txt
```

### Install Security Tools Separately

```bash
# Install Checkov
pip install checkov

# Install Semgrep  
pip install semgrep

# Install Bandit
pip install bandit
```

### Install ASH (Optional - for comprehensive multi-tool scanning)

ASH (Automated Security Helper) provides comprehensive security scanning with multiple tools:

```bash
# Option 1: Using uvx (recommended)
uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Option 2: Using pip
pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Option 3: Using pipx (isolated environment)
pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.2.5

# Verify installation
ash --version
```

ASH includes additional scanners:
- cfn-nag (CloudFormation)
- cdk-nag (AWS CDK)
- detect-secrets (Secret detection)
- grype (Vulnerability scanning)
- syft (SBOM generation)
- npm-audit (Node.js dependencies)

Note: Some ASH scanners may require additional dependencies. See the [ASH documentation](https://github.com/awslabs/automated-security-helper) for details.

### Install Additional Security Tools (Optional)

These tools can be used standalone or with ASH:

```bash
# macOS (using Homebrew)
brew install trivy    # Container and IaC security scanner
brew install grype    # Vulnerability scanner for dependencies
brew install syft     # SBOM (Software Bill of Materials) generator

# Linux - Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Linux - Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Linux - Syft
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

## Verification

After installation, verify the tools work:

```bash
# Check tool availability
which checkov
which semgrep  
which bandit
which ash     # Optional
which trivy   # Optional
which grype   # Optional
which syft    # Optional

# Test basic functionality
python tests/simple_test.py

# Test ASH integration (if installed)
python tests/test_ash_integration.py
```

Expected output:
```
🚀 Testing Security Scanner Tools
🛡️  Testing Checkov...
✅ Checkov found X issues
🔍 Testing Semgrep...
✅ Semgrep found X issues  
🐍 Testing Bandit...
✅ Bandit found X issues
🎉 All security tools are working correctly!
```

## Usage with AI Assistants

Once installed and configured, you can use the security scanner with AI assistants:

```
"Scan this Terraform code for security issues using Checkov"
"Use Semgrep to analyze this Python code for vulnerabilities"  
"Run Bandit on this Python function to check for security problems"
"Scan this code with ASH for comprehensive multi-tool analysis"
"Check if ASH is available for scanning"
```

The AI assistant will automatically:
1. Detect the appropriate tool based on code type
2. Run the security scan
3. Present findings with severity levels
4. Suggest fixes for identified issues

### ASH-Specific Usage

For comprehensive multi-tool scanning with ASH:

```
"Scan this Python code with ASH using HIGH severity threshold"
"Use ASH to analyze this Terraform configuration"
"Check ASH availability before scanning"
"Get the ASH report from the output directory"
```

ASH provides:
- Aggregated results from multiple scanners
- Unified severity reporting
- Comprehensive coverage across different security aspects
- Delta scanning optimized for code snippets

## Troubleshooting

### Common Issues

1. **Tool not found**: Ensure security tools are in PATH
2. **Permission errors**: Check file permissions in temp directories
3. **JSON parsing errors**: Update to latest tool versions
4. **MCP connection issues**: Verify MCP configuration syntax
5. **ASH not available**: Install ASH using one of the methods above

### ASH-Specific Issues

1. **ASH command not found**
   ```bash
   # Verify installation
   ash --version
   
   # Reinstall if needed
   uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.5
   ```

2. **ASH scanner dependencies missing**
   - Most scanners are managed automatically by ASH via UV
   - Some scanners (cfn-nag, grype, syft) may require manual installation
   - On macOS: `brew install grype syft`
   - For cfn-nag: `gem install cfn-nag`
   - See [ASH documentation](https://github.com/awslabs/automated-security-helper) for details

3. **Trivy not found**
   ```bash
   # macOS
   brew install trivy
   
   # Linux
   curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
   ```

4. **ASH scan timeout**
   - Default timeout is 5 minutes
   - For large code snippets, consider using individual scanners
   - Or break the code into smaller pieces

### Debug Mode

Enable debug logging:
```json
{
  "env": {
    "FASTMCP_LOG_LEVEL": "DEBUG"
  }
}
```

### Manual Testing

Test individual tools:
```bash
# Test Checkov
echo 'resource "aws_s3_bucket" "test" { acl = "public-read" }' > test.tf
checkov -f test.tf

# Test Semgrep
echo 'import pickle; pickle.loads(data)' > test.py
semgrep --config=auto test.py

# Test Bandit  
echo 'PASSWORD="secret"' > test.py
bandit test.py
```