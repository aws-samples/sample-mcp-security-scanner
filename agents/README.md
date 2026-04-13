# 🛡️ Kiro Agents for MCP Security Scanner

Pre-built AI agent configurations that use the MCP Security Scanner to provide security-first coding assistance.

## Available Agents

Each agent lives in its own subfolder for easy discovery and independent versioning.

### [sec-lazio](./sec-lazio/) — Secure Code Agent

A security-first coding agent that scans code as you write it, enforces secure patterns, and generates `SECURITY.md` threat model reports.

| Feature | Description |
|---------|-------------|
| 🔍 Auto-scan | Scans every code change with Semgrep, Bandit, or Checkov |
| 🔄 Fix loop | Finds vulnerabilities → fixes them → re-scans until clean |
| 📝 SECURITY.md | Generates structured reports with STRIDE classification, risk matrix, and coverage analysis |
| 🏗️ Secure by default | Applies security best practices when generating code |
| 📋 Compliance hints | Flags SOC2, PCI-DSS, HIPAA, GDPR, NIST 800-53 relevant patterns |

## Installation

### Prerequisites

- [Kiro](https://kiro.dev) or [Kiro CLI](https://kiro.dev/docs/cli/)
- Python 3.10+
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager

### Quick Install

```bash
# Global (all projects)
cp agents/sec-lazio/sec-lazio.json ~/.kiro/agents/

# Or project-specific
mkdir -p .kiro/agents
cp agents/sec-lazio/sec-lazio.json .kiro/agents/
```

The agent includes the MCP Security Scanner configuration — it will auto-install from GitHub on first use.

## Adding a New Agent

1. Create a new subfolder under `agents/` with the agent name
2. Add a JSON spec file following the [Kiro agent configuration format](https://kiro.dev/docs/cli/agents/)
3. Submit a PR

