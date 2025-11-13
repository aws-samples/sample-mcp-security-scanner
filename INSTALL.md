# Installation Guide - Security Scanner MCP Server

## Quick Start

### 1. Install with uv (Recommended)

```bash
# Install the MCP server using uv
uvx security_scanner_mcp_server

# Or install from local directory
cd security-scanner-mcp
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
        "FASTMCP_LOG_LEVEL": "ERROR"
      },
      "disabled": false,
      "autoApprove": [
        "scan_with_checkov",
        "scan_with_semgrep", 
        "scan_with_bandit",
        "get_supported_formats"
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

## Verification

After installation, verify the tools work:

```bash
# Check tool availability
which checkov
which semgrep  
which bandit

# Test basic functionality
python tests/simple_test.py
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
```

The AI assistant will automatically:
1. Detect the appropriate tool based on code type
2. Run the security scan
3. Present findings with severity levels
4. Suggest fixes for identified issues

## Troubleshooting

### Common Issues

1. **Tool not found**: Ensure security tools are in PATH
2. **Permission errors**: Check file permissions in temp directories
3. **JSON parsing errors**: Update to latest tool versions
4. **MCP connection issues**: Verify MCP configuration syntax

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