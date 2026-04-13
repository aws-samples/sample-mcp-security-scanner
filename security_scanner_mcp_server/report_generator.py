"""Security report generator — produces SECURITY.md from scan results.

Generates a structured security posture document for inclusion in the project
repository. Findings are classified using STRIDE and organized following the
core steps of threat modeling as described in the AWS Security Blog:

  1. Identify assets, entry points, and components
  2. Identify threats (using STRIDE)
  3. Identify mitigations
  4. Review risk matrix

This document is intended as an input to — not a replacement for — a formal
security review conducted by a qualified Security Architect.

Reference: https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, List

from loguru import logger
from pydantic import Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCANNER_DISPLAY_NAMES = {
    'bandit': 'Bandit',
    'semgrep': 'Semgrep',
    'checkov': 'Checkov',
    'trivy': 'Trivy',
    'grype': 'Grype',
    'ash': 'ASH',
    'syft': 'Syft',
    'gitleaks': 'Gitleaks',
    'cdknag': 'CDK NAG',
    'cfn-nag': 'cfn-nag',
    'detect-secrets': 'detect-secrets',
    'npm-audit': 'npm-audit',
}

# STRIDE categories — keyword heuristics for automatic classification
STRIDE = {
    'Spoofing': {
        'description': 'Pretending to be something or someone other than yourself',
        'keywords': ['auth', 'credential', 'password', 'token', 'session',
                     'identity', 'login', 'certificate', 'verify'],
        'question': 'Can an attacker impersonate a user, service, or component?',
    },
    'Tampering': {
        'description': 'Modifying data or code without authorization',
        'keywords': ['injection', 'input', 'validation', 'sanitiz', 'xss',
                     'command', 'sql', 'deserializ', 'pickle', 'eval', 'exec'],
        'question': 'Can an attacker modify data in transit, at rest, or in memory?',
    },
    'Repudiation': {
        'description': 'Claiming to have not performed an action',
        'keywords': ['log', 'audit', 'trail', 'monitor', 'trace', 'record'],
        'question': 'Can actions be performed without being logged or traced?',
    },
    'Information Disclosure': {
        'description': 'Exposing information to unauthorized individuals',
        'keywords': ['secret', 'hardcoded', 'password', 'key', 'encrypt',
                     'leak', 'expose', 'sensitive', 'pii', 'credential'],
        'question': 'Can sensitive data be accessed by unauthorized parties?',
    },
    'Denial of Service': {
        'description': 'Denying or degrading service to users',
        'keywords': ['resource', 'limit', 'timeout', 'throttl', 'rate',
                     'memory', 'cpu', 'exhaust', 'flood'],
        'question': 'Can an attacker make the system unavailable?',
    },
    'Elevation of Privilege': {
        'description': 'Gaining capabilities without proper authorization',
        'keywords': ['iam', 'privilege', 'admin', 'wildcard', 'root',
                     'permission', 'role', 'policy', 'sudo', 'shell'],
        'question': 'Can an attacker gain higher privileges than intended?',
    },
}

# Security assessment areas and which scanners address them
ASSESSMENT_AREAS = {
    'IaC Security': {
        'scanners': ['checkov', 'cdknag', 'cfn-nag'],
        'assets': 'Cloud infrastructure resources and configurations',
    },
    'Application Security': {
        'scanners': ['semgrep', 'bandit'],
        'assets': 'Application source code and business logic',
    },
    'Dependency Security': {
        'scanners': ['grype', 'npm-audit', 'ash'],
        'assets': 'Third-party libraries and packages',
    },
    'Container Security': {
        'scanners': ['trivy'],
        'assets': 'Container images and runtime configurations',
    },
    'Secrets Management': {
        'scanners': ['gitleaks', 'detect-secrets', 'ash'],
        'assets': 'Credentials, API keys, tokens, and certificates',
    },
    'Software Inventory': {
        'scanners': ['syft'],
        'assets': 'Complete software bill of materials (SBOM)',
    },
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _display_name(tool: str) -> str:
    return SCANNER_DISPLAY_NAMES.get(tool.lower(), tool.capitalize())


def _anchor(name: str) -> str:
    return '#' + name.lower().replace(' ', '-')


def _extract_id(f: Dict) -> str:
    return f.get('check_id') or f.get('rule_id') or f.get('test_id') or 'N/A'


def _extract_desc(f: Dict) -> str:
    return f.get('description') or f.get('message') or f.get('check_name') or 'N/A'


def _extract_line(f: Dict):
    return (f.get('line_number') or f.get('line')
            or (f.get('line_range', [None])[0]) or 'N/A')


def _classify_stride(finding: Dict) -> List[str]:
    """Classify a finding into STRIDE categories by keyword matching."""
    text = str(finding).lower()
    categories = []
    for category, info in STRIDE.items():
        if any(kw in text for kw in info['keywords']):
            categories.append(category)
    return categories or ['Uncategorized']


def _load_assumptions_file() -> List[Dict]:
    """Load project assumptions from .security/config.yaml or .security/assumptions.json.

    Supported formats (checked in order):
      1. .security/config.yaml  (recommended — human-friendly)
      2. .security/config.yml
      3. .security/assumptions.json (legacy)

    YAML format:
      assumptions:
        - assumption: "Authentication handled by Cognito"
          linked_threats: "Spoofing"
          comments: "MFA enabled"

    JSON format:
      [{"assumption": "...", "linked_threats": "...", "comments": "..."}]

    Looks in WORKSPACE_ROOT first, then CWD.
    """
    import os
    from pathlib import Path

    workspace_root = os.environ.get('WORKSPACE_ROOT', os.getcwd())
    roots = [Path(workspace_root), Path(os.getcwd())]

    # Try YAML first, then JSON
    for root in roots:
        for name in ('config.yaml', 'config.yml'):
            path = root / '.security' / name
            if path.exists():
                try:
                    import yaml
                except ImportError:
                    # PyYAML not available — skip YAML files
                    logger.debug(f"PyYAML not installed, skipping {path}")
                    continue
                try:
                    with open(path, 'r') as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        assumptions = data.get('assumptions', [])
                        if isinstance(assumptions, list):
                            logger.info(f"Loaded {len(assumptions)} assumptions from {path}")
                            return assumptions
                except Exception as e:
                    logger.warning(f"Failed to load assumptions from {path}: {e}")

        # Fallback to JSON
        json_path = root / '.security' / 'assumptions.json'
        if json_path.exists():
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                if isinstance(data, list):
                    logger.info(f"Loaded {len(data)} assumptions from {json_path}")
                    return data
            except (json.JSONDecodeError, OSError) as e:
                logger.warning(f"Failed to load assumptions from {json_path}: {e}")

    return []


def _load_project_context() -> Dict:
    """Load full project context from .security/config.yaml if available.

    Returns a dict with optional keys: project, assumptions, resolved_findings.
    """
    import os
    from pathlib import Path

    workspace_root = os.environ.get('WORKSPACE_ROOT', os.getcwd())
    roots = [Path(workspace_root), Path(os.getcwd())]

    for root in roots:
        for name in ('config.yaml', 'config.yml'):
            path = root / '.security' / name
            if path.exists():
                try:
                    import yaml
                except ImportError:
                    continue
                try:
                    with open(path, 'r') as f:
                        data = yaml.safe_load(f)
                    if isinstance(data, dict):
                        logger.info(f"Loaded project security context from {path}")
                        return data
                except Exception as e:
                    logger.warning(f"Failed to load context from {path}: {e}")

    return {}


def _build_scanner_summaries(results: List[Dict]):
    all_findings: List[Dict] = []
    scanner_summaries: List[Dict] = []
    clean_scanners: List[str] = []

    for r in results:
        tool = r.get('tool', 'unknown')
        findings = r.get('findings', [])
        summary = r.get('summary', {})

        critical = summary.get('critical', 0)
        high = summary.get('high', summary.get('error', 0))
        medium = summary.get('medium', summary.get('warning', 0))
        low = summary.get('low', summary.get('info', 0))
        suppressed = summary.get('suppressed', 0)
        total = r.get('total_issues', len(findings))

        scanner_summaries.append({
            'tool': tool, 'display_name': _display_name(tool),
            'total': total, 'critical': critical, 'high': high,
            'medium': medium, 'low': low, 'suppressed': suppressed,
            'format': r.get('format_type', r.get('language', 'N/A')),
        })

        if total == 0 and len(findings) == 0:
            clean_scanners.append(_display_name(tool))

        for f in findings:
            f['_tool'] = tool
            f['_display_tool'] = _display_name(tool)
            f['_severity'] = (
                f.get('severity') or f.get('issue_severity') or 'MEDIUM'
            ).upper()
            f['_stride'] = _classify_stride(f)
        all_findings.extend(findings)

    return all_findings, scanner_summaries, clean_scanners


def _risk_level(total_critical, total_high, total_findings):
    if total_critical > 0:
        return '\U0001f534 CRITICAL'
    if total_high > 0:
        return '\U0001f7e0 HIGH'
    if total_findings > 0:
        return '\U0001f7e1 MEDIUM'
    return '\U0001f7e2 LOW'


# ---------------------------------------------------------------------------
# Report sections
# ---------------------------------------------------------------------------

def _section_header(now, project_name, scan_id, scanners_used):
    return [
        '# Security Analysis Report', '',
        '> Generated by MCP Security Scanner', '',
        '> \u26a0\ufe0f **Disclaimer:** This report is generated by automated security '
        'scanning tools and is intended as a supporting input for threat modeling '
        'and security reviews. It does not replace a formal security assessment '
        'conducted by a qualified Security Architect. Automated scanners have '
        'inherent limitations \u2014 they may produce false positives, miss '
        'business-logic vulnerabilities, and cannot evaluate architectural design '
        'decisions. A security professional must review this document, validate '
        'the findings, and assess the overall security posture before any '
        'compliance or release decisions are made.', '',
        f'**Date:** {now}  ',
        f'**Project:** {project_name}  ',
        f'**Scan ID:** `{scan_id}`  ',
        f'**Scanners:** {", ".join(scanners_used)}', '',
        '---', '',
    ]


def _section_summary(risk, total, critical, high, medium, low, suppressed):
    lines = [
        '## Executive Summary', '',
        f'**Overall Risk Level:** {risk}  ',
        f'**Total Findings:** {total}  ',
    ]
    if suppressed > 0:
        lines.append(f'**Suppressed:** {suppressed}')
    lines.append('')
    if total > 0:
        lines.append('### Severity Breakdown')
        lines.append('')
        if critical > 0:
            lines.append(f'- **Critical:** {critical} \u2014 require immediate attention')
        if high > 0:
            lines.append(f'- **High:** {high} \u2014 remediate in the current sprint')
        if medium > 0:
            lines.append(f'- **Medium:** {medium} \u2014 evaluate and plan remediation')
        if low > 0:
            lines.append(f'- **Low:** {low} \u2014 accept or address opportunistically')
        lines.append('')
    return lines


def _section_coverage(scanner_summaries):
    """Security assessment coverage — assets, entry points, and components."""
    lines = [
        '## Security Assessment Coverage', '',
        'Maps security assessment areas to the scanners used and current status. '
        'Gaps indicate areas not covered by this scan that should be evaluated '
        'during a formal security review.', '',
        '| Area | Assets Under Review | Scanners | Findings | Status |',
        '|------|-------------------|----------|----------|--------|',
    ]
    tools_used = {s['tool'].lower() for s in scanner_summaries}

    for area, info in ASSESSMENT_AREAS.items():
        relevant = [s for s in info['scanners'] if s in tools_used]
        if not relevant:
            lines.append(
                f'| {area} | {info["assets"]} | *Not scanned* '
                f'| \u2014 | \u26a0\ufe0f GAP |'
            )
        else:
            names = ', '.join(_display_name(s) for s in relevant)
            count = sum(s['total'] for s in scanner_summaries
                        if s['tool'].lower() in relevant)
            if count == 0:
                status = '\u2705 Clear'
            else:
                cc = sum(s['critical'] for s in scanner_summaries if s['tool'].lower() in relevant)
                ch = sum(s['high'] for s in scanner_summaries if s['tool'].lower() in relevant)
                if cc > 0 or ch > 0:
                    status = f'\u274c {cc} critical, {ch} high'
                else:
                    status = f'\u26a0\ufe0f {count} medium/low'
            lines.append(f'| {area} | {info["assets"]} | {names} | {count} | {status} |')
    lines.append('')
    return lines


def _section_stride(all_findings):
    """STRIDE classification — threats identified and their mitigation status."""
    lines = [
        '## STRIDE Classification', '',
        'Findings classified using '
        '[STRIDE](https://learn.microsoft.com/en-us/azure/security/develop/'
        'threat-modeling-tool-threats) to support threat modeling. '
        'See [How to approach threat modeling]'
        '(https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/) '
        'for guidance on using these inputs.', '',
    ]
    findings_str = str(all_findings).lower()

    for category, info in STRIDE.items():
        applicable = any(kw in findings_str for kw in info['keywords'])
        cat_findings = [f for f in all_findings if category in f.get('_stride', [])]

        if cat_findings:
            status = f'\u274c {len(cat_findings)} finding(s)'
        elif applicable:
            status = '\u26a0\ufe0f Review recommended'
        else:
            status = '\u2705 No findings'

        lines.append(f'### {category}')
        lines.append('')
        lines.append(f'*{info["description"]}*  ')
        lines.append(f'**Question:** {info["question"]}  ')
        lines.append(f'**Status:** {status}')
        lines.append('')

        if cat_findings:
            lines.append('<details>')
            lines.append(f'<summary>View {len(cat_findings)} finding(s)</summary>')
            lines.append('')
            lines.append('| # | ID | Scanner | Severity | Line | Description | Mitigation |')
            lines.append('|---|-----|---------|----------|------|-------------|------------|')
            for i, f in enumerate(cat_findings, 1):
                fid = _extract_id(f)
                desc = _extract_desc(f)[:70]
                line_num = _extract_line(f)
                lines.append(
                    f'| {i} | {fid} | {f["_display_tool"]} | {f["_severity"]} '
                    f'| {line_num} | {desc} | Pending |'
                )
            lines.extend(['', '</details>', ''])

    return lines


def _section_risk_matrix(all_findings, scanner_summaries):
    """Risk matrix — severity vs STRIDE category."""
    lines = [
        '## Risk Matrix', '',
        '| STRIDE Category | Critical | High | Medium | Low | Total |',
        '|----------------|----------|------|--------|-----|-------|',
    ]
    for category in STRIDE:
        cat_findings = [f for f in all_findings if category in f.get('_stride', [])]
        c = sum(1 for f in cat_findings if f['_severity'] == 'CRITICAL')
        h = sum(1 for f in cat_findings if f['_severity'] in ('HIGH', 'ERROR'))
        m = sum(1 for f in cat_findings if f['_severity'] in ('MEDIUM', 'WARNING'))
        lo = sum(1 for f in cat_findings if f['_severity'] in ('LOW', 'INFO'))
        t = len(cat_findings)
        lines.append(f'| {category} | {c} | {h} | {m} | {lo} | {t} |')
    lines.append('')
    return lines


def _section_impacted_assets(all_findings):
    """Identify assets impacted by findings, grouped by type."""
    if not all_findings:
        return []

    # Infer assets from scanner types and finding content
    asset_map = {}  # asset_name -> list of finding IDs
    for f in all_findings:
        tool = f.get('_tool', '').lower()
        fid = _extract_id(f)
        desc = _extract_desc(f).lower()

        # Infer asset from scanner type and finding content
        assets = []
        if tool in ('checkov', 'cdknag', 'cfn-nag'):
            resource = f.get('resource', '')
            if resource:
                assets.append(f'IaC Resource: {resource}')
            else:
                assets.append('Cloud infrastructure configuration')
        if tool in ('semgrep', 'bandit'):
            assets.append('Application source code')
        if tool in ('grype', 'npm-audit'):
            assets.append('Third-party dependencies')
        if tool == 'trivy':
            assets.append('Container images')
        if tool in ('gitleaks', 'detect-secrets') or 'secret' in desc or 'password' in desc or 'credential' in desc:
            assets.append('Credentials and secrets')
        if 'encrypt' in desc or 'key' in desc:
            assets.append('Data protection controls')

        if not assets:
            assets.append('Application components')

        for asset in assets:
            asset_map.setdefault(asset, []).append(fid)

    lines = [
        '## Impacted Assets', '',
        'Assets identified from scan findings. Use this as input when '
        'identifying assets, entry points, and trust levels for threat modeling.', '',
        '| Asset | Related Findings | Count |',
        '|-------|-----------------|-------|',
    ]
    for asset, findings in sorted(asset_map.items()):
        unique = sorted(set(findings))
        display = ', '.join(unique[:5])
        if len(unique) > 5:
            display += f' (+{len(unique) - 5} more)'
        lines.append(f'| {asset} | {display} | {len(unique)} |')
    lines.append('')
    return lines


def _section_assumptions(scanner_summaries, clean_scanners, custom_assumptions=None):
    """Generate assumptions from scan coverage + user-provided assumptions.

    Custom assumptions can come from:
      1. A .security/assumptions.json file in the project repo (recommended)
      2. The 'assumptions' parameter passed to the tool (override/one-off)
    Both sources are merged, with parameter assumptions appended after file ones.
    """
    lines = [
        '## Assumptions', '',
        'Assumptions about the project and scan context. Project assumptions '
        'are provided by the project team (via `.security/assumptions.json` or '
        'tool parameters); auto-generated assumptions are derived from the scan '
        'configuration. Validate all assumptions during a formal security review.', '',
    ]

    # --- Custom assumptions first ---
    if custom_assumptions:
        lines.append('### Project Assumptions')
        lines.append('')
        lines.append('| # | Assumption | Linked Threats | Comments |')
        lines.append('|---|-----------|---------------|----------|')
        for i, a in enumerate(custom_assumptions, 1):
            if isinstance(a, dict):
                text = a.get('assumption', '')
                threats = a.get('linked_threats', '')
                comments = a.get('comments', '')
            else:
                text = str(a)
                threats = ''
                comments = ''
            lines.append(f'| A-{i:03d} | {text} | {threats} | {comments} |')
        lines.append('')

    # --- Auto-generated assumptions ---
    lines.append('### Auto-generated Assumptions')
    lines.append('')
    lines.append('| # | Assumption | Basis |')
    lines.append('|---|-----------|-------|')

    tools_used = {s['tool'].lower() for s in scanner_summaries}
    idx = 1

    if 'checkov' in tools_used or 'cdknag' in tools_used:
        lines.append(f'| AG-{idx:03d} | IaC templates follow the scanned framework conventions '
                     f'(Terraform, CloudFormation, etc.) | Checkov/CDK NAG scan executed |')
        idx += 1

    if 'semgrep' in tools_used or 'bandit' in tools_used:
        lines.append(f'| AG-{idx:03d} | Source code scanned represents the current state of the '
                     f'application | SAST scan executed on local files |')
        idx += 1

    if 'grype' in tools_used or 'npm-audit' in tools_used:
        lines.append(f'| AG-{idx:03d} | Dependency manifests (package.json, requirements.txt, etc.) '
                     f'are up to date | SCA scan executed |')
        idx += 1

    for area, info in ASSESSMENT_AREAS.items():
        relevant = [s for s in info['scanners'] if s in tools_used]
        if not relevant:
            lines.append(f'| AG-{idx:03d} | {area} was not evaluated by automated scanning '
                         f'and requires manual review | No scanner configured |')
            idx += 1

    lines.append(f'| AG-{idx:03d} | Automated scanners may produce false positives and cannot '
                 f'detect business-logic vulnerabilities | Inherent tool limitation |')
    idx += 1
    lines.append(f'| AG-{idx:03d} | Architectural design decisions and trust boundaries require '
                 f'human evaluation beyond automated scanning | Scope limitation |')

    lines.append('')
    return lines


def _section_scan_table(scanner_summaries):
    lines = [
        '## Scan Results by Tool', '',
        '| Scanner | Format/Language | Findings | Critical | High | Medium | Low | Suppressed |',
        '|---------|---------------|----------|----------|------|--------|-----|------------|',
    ]
    for s in scanner_summaries:
        name = s['display_name']
        link = f'[{name}]({_anchor(name)})'
        lines.append(
            f"| {link} | {s['format']} | {s['total']} "
            f"| {s['critical']} | {s['high']} | {s['medium']} "
            f"| {s['low']} | {s['suppressed']} |"
        )
    lines.append('')
    return lines


def _section_resolved(resolved_findings: List[Dict]):
    if not resolved_findings:
        return []
    lines = [
        '## Resolved Findings', '',
        '<details>',
        f'<summary>View {len(resolved_findings)} resolved finding(s)</summary>',
        '',
        '| # | ID | Scanner | Severity | Action Taken | Status |',
        '|---|-----|---------|----------|-------------|--------|',
    ]
    for i, f in enumerate(resolved_findings, 1):
        fid = f.get('id', f.get('check_id', f.get('rule_id', 'N/A')))
        tool = _display_name(f.get('tool', 'unknown'))
        severity = f.get('severity', 'MEDIUM').upper()
        action = f.get('action', 'Remediated')[:60]
        lines.append(f'| {i} | {fid} | {tool} | {severity} | {action} | \u2705 Resolved |')
    lines.extend(['', '</details>', ''])
    return lines


def _section_clean(clean_scanners):
    if not clean_scanners:
        return []
    return [
        '## Areas with No Findings', '',
    ] + [f'- \u2705 {name}' for name in clean_scanners] + ['']


def _section_compliance():
    return [
        '## Compliance Considerations', '',
        'Review the findings above against applicable compliance frameworks. '
        'The [AWS Shared Responsibility Model]'
        '(https://aws.amazon.com/compliance/shared-responsibility-model/) '
        'defines the boundary between AWS-managed and customer-managed controls.', '',
        '> Common frameworks: SOC2, PCI-DSS, HIPAA, GDPR, NIST 800-53.', '',
    ]


def _section_recommendations(tc, th, tm, tl):
    lines = ['## Recommended Actions', '']
    immediate = []
    if tc > 0:
        immediate.append('Address all CRITICAL findings before deployment')
    if th > 0:
        immediate.append('Remediate HIGH severity findings in the current sprint')
    if immediate:
        lines.append('### Immediate (Critical/High)')
        lines.append('')
        for i, a in enumerate(immediate, 1):
            lines.append(f'{i}. {a}')
        lines.append('')
    if tm > 0:
        lines.extend(['### Short-term (Medium)', '',
                       '1. Evaluate MEDIUM findings and schedule remediation',
                       '2. Document accepted risks with justification', ''])
    if tl > 0:
        lines.extend(['### Long-term (Low)', '',
                       '1. Review LOW findings for backlog prioritization',
                       '2. Address opportunistically during related changes', ''])
    lines.extend([
        '### General', '',
        '- Re-scan after remediation to verify resolution',
        '- Update this report after each remediation cycle',
        '- Use this document as input for threat modeling and security reviews', '',
    ])
    return lines


def _section_conclusion(risk, total, clean_scanners, scanner_count, resolved_count):
    lines = ['## Conclusion', '']
    if total == 0 and resolved_count == 0:
        lines.append(
            f'All {scanner_count} scanners completed with no findings. '
            'Manual review is still recommended for business-logic and '
            'architectural concerns not covered by automated scanning.'
        )
    elif total == 0 and resolved_count > 0:
        lines.append(
            f'All {resolved_count} previously identified findings have been resolved. '
            f'All {scanner_count} scanners now report a clean posture.'
        )
    else:
        parts = [f'The scan identified {total} open findings '
                 f'with an overall risk level of {risk}.']
        if resolved_count > 0:
            parts.append(f'{resolved_count} findings have been resolved.')
        if clean_scanners:
            parts.append(f'{len(clean_scanners)} of {scanner_count} scanners '
                         f'({", ".join(clean_scanners)}) found no issues.')
        parts.append('Address findings by priority and re-scan to verify.')
        lines.append(' '.join(parts))
    lines.append('')
    return lines


def _section_references():
    return [
        '---', '',
        '## References', '',
        '- [MCP Security Scanner](https://github.com/aws-samples/sample-mcp-security-scanner)',
        '- [AWS Prescriptive Guidance — Real-time coding security validation]'
        '(https://docs.aws.amazon.com/prescriptive-guidance/latest/patterns/'
        'deploy-real-time-coding-security-validation-by-using-an-mcp-server-'
        'with-kiro-and-other-coding-assistants.html)',
        '- [How to approach threat modeling — AWS Security Blog]'
        '(https://aws.amazon.com/blogs/security/how-to-approach-threat-modeling/)',
        '- [Threat Composer — AWS threat modeling tool]'
        '(https://github.com/awslabs/threat-composer)',
        '',
    ]


# ---------------------------------------------------------------------------
# MCP tool registration
# ---------------------------------------------------------------------------

def register_report_tool(mcp, handle_exceptions):
    """Register the report generation tool with the MCP server."""

    @mcp.tool()
    @handle_exceptions
    async def generate_security_report(
        project_name: str = Field(description='Name of the project being analyzed'),
        scan_results: str = Field(
            description='JSON string with scan results from scan_with_checkov, '
            'scan_with_semgrep, scan_with_bandit, or any other scanning tool. '
            'Can be a single result object or an array of result objects.'
        ),
        resolved_findings: str = Field(
            default='[]',
            description='Optional JSON array of resolved findings with fields: '
            'id, description, tool, severity, action, before, after.'
        ),
        assumptions: str = Field(
            default='[]',
            description='Optional JSON array of project assumptions. Each item '
            'can be a string or an object with fields: assumption (required), '
            'linked_threats (optional), comments (optional). Example: '
            '[{"assumption": "Authentication is handled by Amazon Cognito", '
            '"linked_threats": "Spoofing", "comments": "MFA enabled"}]'
        ),
    ) -> Dict:
        """Generate a SECURITY.md report from scan results.

        Produces a structured security posture document with STRIDE
        classification, risk matrix, coverage analysis, and prioritized
        recommendations. Designed for inclusion in the project repository
        as input for threat modeling and security reviews.

        This report does not replace a formal security assessment by a
        qualified Security Architect.
        """
        try:
            results = json.loads(scan_results)
        except json.JSONDecodeError:
            return {"success": False, "error": "Invalid JSON in scan_results"}

        if isinstance(results, dict):
            results = [results]

        try:
            resolved = json.loads(resolved_findings) if resolved_findings else []
        except json.JSONDecodeError:
            resolved = []

        try:
            custom_assumptions = json.loads(assumptions) if assumptions else []
        except json.JSONDecodeError:
            custom_assumptions = []

        # Load assumptions from .security/config.yaml or .security/assumptions.json
        file_assumptions = _load_assumptions_file()
        if file_assumptions:
            custom_assumptions = file_assumptions + custom_assumptions

        # Load project context for defaults (project name, resolved findings)
        project_context = _load_project_context()
        config_loaded = bool(project_context)

        if not project_name or project_name == 'unknown':
            ctx_project = project_context.get('project', {})
            if isinstance(ctx_project, dict):
                project_name = ctx_project.get('name', project_name)

        # Merge resolved findings from config file
        file_resolved = project_context.get('resolved_findings', [])
        if file_resolved and isinstance(file_resolved, list):
            resolved = file_resolved + resolved

        now = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
        scan_id = uuid.uuid4().hex[:12]

        all_findings, scanner_summaries, clean_scanners = _build_scanner_summaries(results)

        total = len(all_findings)
        tc = sum(s['critical'] for s in scanner_summaries)
        th = sum(s['high'] for s in scanner_summaries)
        tm = sum(s['medium'] for s in scanner_summaries)
        tl = sum(s['low'] for s in scanner_summaries)
        ts = sum(s['suppressed'] for s in scanner_summaries)
        used = [s['display_name'] for s in scanner_summaries]
        risk = _risk_level(tc, th, total)

        lines = []
        lines.extend(_section_header(now, project_name, scan_id, used))
        lines.extend(_section_summary(risk, total, tc, th, tm, tl, ts))
        lines.extend(_section_coverage(scanner_summaries))
        lines.extend(_section_stride(all_findings))
        lines.extend(_section_risk_matrix(all_findings, scanner_summaries))
        lines.extend(_section_impacted_assets(all_findings))
        lines.extend(_section_assumptions(scanner_summaries, clean_scanners, custom_assumptions))
        lines.extend(_section_scan_table(scanner_summaries))
        lines.extend(_section_resolved(resolved))
        lines.extend(_section_clean(clean_scanners))
        lines.extend(_section_compliance())
        lines.extend(_section_recommendations(tc, th, tm, tl))
        lines.extend(_section_conclusion(risk, total, clean_scanners, len(scanner_summaries), len(resolved)))
        lines.extend(_section_references())

        return {
            "success": True,
            "report": '\n'.join(lines),
            "config_loaded": config_loaded,
            "summary": {
                "scan_id": scan_id,
                "risk_level": risk,
                "total_findings": total,
                "total_resolved": len(resolved),
                "total_suppressed": ts,
                "scanners_used": used,
                "clean_scanners": clean_scanners,
            },
        }
