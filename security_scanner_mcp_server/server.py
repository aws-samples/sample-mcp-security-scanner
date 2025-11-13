#!/usr/bin/env python3
"""Security Scanner MCP Server implementation for code security analysis."""

import json
import tempfile
import os
import subprocess
from typing import Dict, Any, List, Optional

from loguru import logger
from mcp.server.fastmcp import FastMCP
from pydantic import Field

# Initialize the MCP server
mcp = FastMCP(
    'security_scanner_mcp_server',
    instructions="""
    Security Scanner MCP Server provides tools to perform security analysis on code using industry-standard tools.
    
    This server enables you to:
    - Scan Infrastructure as Code (IaC) files using Checkov
    - Analyze source code for security vulnerabilities using Semgrep
    - Detect security issues in Python code using Bandit
    
    Supported formats and languages:
    
    Checkov (IaC Security):
    - Terraform (.tf, .tfvars)
    - CloudFormation (.yaml, .yml, .json)
    - Kubernetes (.yaml, .yml)
    - Dockerfile
    - ARM templates (.json)
    - Bicep (.bicep)
    - And many more IaC formats
    
    Semgrep (Source Code Security):
    - Python, JavaScript, TypeScript, Java, Go, C/C++
    - C#, Ruby, PHP, Scala, Kotlin, Rust
    
    Bandit (Python Security):
    - Python (.py) files only
    
    All tools analyze only the provided code snippet, not entire projects.
    """,
    dependencies=[
        'pydantic',
        'loguru',
        'checkov',
        'semgrep',
        'bandit',
    ],
)

def handle_exceptions(func):
    """Decorator to handle exceptions in a consistent way."""
    import functools
    
    @functools.wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(f'Error in {func.__name__}: {e}')
            raise ValueError(f'Error in {func.__name__}: {str(e)}')
    
    return wrapper

class SecurityScanner:
    """Security scanner class with support for multiple tools."""
    
    def __init__(self):
        # Checkov supported IaC formats
        self.checkov_formats = {
            'terraform': ['.tf', '.tfvars', '.tfstate'],
            'cloudformation': ['.yaml', '.yml', '.json', '.template'],
            'kubernetes': ['.yaml', '.yml'],
            'dockerfile': ['Dockerfile'],
            'arm': ['.json'],
            'bicep': ['.bicep'],
            'serverless': ['.yml', '.yaml'],
            'helm': ['.yaml', '.yml', '.tpl'],
            'github_actions': ['.yml', '.yaml'],
            'gitlab_ci': ['.yml', '.yaml'],
            'ansible': ['.yml', '.yaml'],
        }

        # Semgrep supported programming languages
        self.semgrep_languages = {
            'python': '.py',
            'javascript': '.js',
            'typescript': '.ts',
            'java': '.java',
            'go': '.go',
            'c': '.c',
            'cpp': '.cpp',
            'csharp': '.cs',
            'ruby': '.rb',
            'php': '.php',
            'scala': '.scala',
            'kotlin': '.kt',
            'rust': '.rs'
        }

    def run_checkov_scan(self, code: str, format_type: str) -> List[Dict]:
        """Run Checkov analysis on IaC code."""
        logger.info(f"Starting Checkov scan for format: {format_type}")
        
        if format_type not in self.checkov_formats:
            raise ValueError(f"Unsupported IaC format: {format_type}. Supported: {list(self.checkov_formats.keys())}")

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Get the primary extension for the format type
                extensions = self.checkov_formats[format_type]
                primary_extension = extensions[0] if isinstance(extensions, list) else extensions

                # Special handling for different formats
                if format_type == 'dockerfile':
                    file_path = os.path.join(temp_dir, 'Dockerfile')
                else:
                    file_path = os.path.join(temp_dir, f'scan{primary_extension}')

                logger.info(f"Writing code to temporary file: {file_path}")
                
                # Write the code to file
                with open(file_path, 'w') as f:
                    f.write(code)

                # Run checkov via command line for better compatibility
                cmd = ["checkov", "-f", file_path, "--output", "json", "--quiet"]
                logger.info(f"Running command: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )

                logger.info(f"Checkov exit code: {result.returncode}")
                logger.info(f"Checkov stdout length: {len(result.stdout) if result.stdout else 0}")
                logger.info(f"Checkov stderr: {result.stderr[:200] if result.stderr else 'None'}")

                if result.stdout:
                    try:
                        json_result = json.loads(result.stdout)
                        failed_checks = json_result.get('results', {}).get('failed_checks', [])
                        
                        logger.info(f"Parsed {len(failed_checks)} failed checks from Checkov output")
                        
                        # Format results
                        findings = []
                        for check in failed_checks:
                            findings.append({
                                'check_id': check.get('check_id', 'Unknown'),
                                'check_name': check.get('check_name', 'Unknown'),
                                'file_path': check.get('file_path', file_path),
                                'resource': check.get('resource', 'Unknown'),
                                'guideline': check.get('guideline', ''),
                                'severity': check.get('severity', 'MEDIUM'),
                                'description': check.get('description', ''),
                                'line_range': check.get('file_line_range', [])
                            })
                        
                        logger.info(f"Returning {len(findings)} formatted findings")
                        return findings
                    except json.JSONDecodeError as e:
                        logger.error(f"Failed to parse Checkov output: {e}")
                        logger.error(f"Raw output: {result.stdout[:500]}")
                        return []
                else:
                    logger.warning(f"No Checkov stdout. Return code: {result.returncode}")
                    logger.warning(f"Stderr: {result.stderr}")
                    return []

        except Exception as e:
            logger.error(f"Error running Checkov: {e}")
            return []

    def run_semgrep_scan(self, code: str, language: str) -> List[Dict]:
        """Run Semgrep analysis on programming language code."""
        if language not in self.semgrep_languages:
            raise ValueError(f"Unsupported language: {language}. Supported: {list(self.semgrep_languages.keys())}")

        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create temporary file with appropriate extension
                extension = self.semgrep_languages[language]
                file_path = os.path.join(temp_dir, f'scan{extension}')
                with open(file_path, 'w') as f:
                    f.write(code)

                # Run semgrep with security rules
                cmd = [
                    "semgrep", 
                    "--config=auto",
                    "--config=p/security-audit",
                    "--config=p/secrets",
                    "--json", 
                    "--quiet", 
                    file_path
                ]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )

                if result.stdout:
                    try:
                        json_result = json.loads(result.stdout)
                        findings = json_result.get('results', [])
                        
                        # Format results
                        formatted_findings = []
                        for finding in findings:
                            formatted_findings.append({
                                'rule_id': finding.get('check_id', 'Unknown'),
                                'message': finding.get('extra', {}).get('message', 'No message'),
                                'severity': finding.get('extra', {}).get('severity', 'INFO'),
                                'line': finding.get('start', {}).get('line', 0),
                                'column': finding.get('start', {}).get('col', 0),
                                'end_line': finding.get('end', {}).get('line', 0),
                                'code_snippet': finding.get('extra', {}).get('lines', ''),
                                'metadata': finding.get('extra', {}).get('metadata', {})
                            })
                        
                        return formatted_findings
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse Semgrep output: {result.stdout[:500]}")
                        return []
                else:
                    logger.warning(f"No Semgrep output. Error: {result.stderr}")
                    return []

        except Exception as e:
            logger.error(f"Error running Semgrep: {e}")
            return []

    def run_bandit_scan(self, code: str) -> List[Dict]:
        """Run Bandit analysis on Python code."""
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                # Create temporary Python file
                file_path = os.path.join(temp_dir, 'scan.py')
                with open(file_path, 'w') as f:
                    f.write(code)

                # Run bandit with JSON output
                cmd = ["bandit", "-f", "json", file_path]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True
                )

                if result.stdout:
                    try:
                        json_result = json.loads(result.stdout)
                        findings = json_result.get('results', [])
                        
                        # Format results
                        formatted_findings = []
                        for finding in findings:
                            formatted_findings.append({
                                'test_id': finding.get('test_id', 'Unknown'),
                                'test_name': finding.get('test_name', 'Unknown'),
                                'severity': finding.get('issue_severity', 'MEDIUM'),
                                'confidence': finding.get('issue_confidence', 'MEDIUM'),
                                'line_number': finding.get('line_number', 0),
                                'line_range': finding.get('line_range', []),
                                'description': finding.get('issue_text', ''),
                                'code': finding.get('code', ''),
                                'filename': finding.get('filename', file_path)
                            })
                        
                        return formatted_findings
                    except json.JSONDecodeError:
                        logger.error(f"Failed to parse Bandit output: {result.stdout[:500]}")
                        return []
                else:
                    logger.warning(f"No Bandit output. Error: {result.stderr}")
                    return []

        except Exception as e:
            logger.error(f"Error running Bandit: {e}")
            return []

# Initialize scanner
scanner = SecurityScanner()

@mcp.tool()
async def scan_with_checkov(
    code: str = Field(description='Infrastructure as Code content to scan'),
    format_type: str = Field(description='IaC format type (terraform, cloudformation, kubernetes, dockerfile, etc.)'),
) -> Dict:
    """Scan Infrastructure as Code using Checkov for security issues.
    
    This tool analyzes Infrastructure as Code files for security misconfigurations
    and compliance violations using Bridgecrew's Checkov scanner.
    
    Supported formats:
    - terraform: Terraform configuration files
    - cloudformation: AWS CloudFormation templates
    - kubernetes: Kubernetes manifests
    - dockerfile: Docker files
    - arm: Azure Resource Manager templates
    - bicep: Azure Bicep files
    - serverless: Serverless framework files
    - helm: Helm charts
    - github_actions: GitHub Actions workflows
    - gitlab_ci: GitLab CI configurations
    - ansible: Ansible playbooks
    
    Args:
        code: The IaC code content to analyze
        format_type: The type of IaC format being scanned
        
    Returns:
        A dictionary with scan results including found security issues
    """
    try:
        logger.info(f"Starting Checkov scan for format: {format_type}")
        logger.info(f"Code length: {len(code)} characters")
        
        findings = scanner.run_checkov_scan(code, format_type)
        
        logger.info(f"Checkov scan completed. Found {len(findings)} issues")
        
        return {
            "success": True,
            "tool": "checkov",
            "format_type": format_type,
            "total_issues": len(findings),
            "findings": findings,
            "summary": {
                "critical": len([f for f in findings if f.get('severity') == 'CRITICAL']),
                "high": len([f for f in findings if f.get('severity') == 'HIGH']),
                "medium": len([f for f in findings if f.get('severity') == 'MEDIUM']),
                "low": len([f for f in findings if f.get('severity') == 'LOW']),
            }
        }
    except Exception as e:
        logger.error(f"Error in scan_with_checkov: {e}")
        return {
            "success": False,
            "tool": "checkov",
            "format_type": format_type,
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def scan_with_semgrep(
    code: str = Field(description='Source code content to scan'),
    language: str = Field(description='Programming language (python, javascript, typescript, java, go, etc.)'),
) -> Dict:
    """Scan source code using Semgrep for security vulnerabilities.
    
    This tool analyzes source code for security vulnerabilities, bugs, and
    anti-patterns using Semgrep's rule engine with security-focused rulesets.
    
    Supported languages:
    - python: Python source code
    - javascript: JavaScript source code
    - typescript: TypeScript source code
    - java: Java source code
    - go: Go source code
    - c: C source code
    - cpp: C++ source code
    - csharp: C# source code
    - ruby: Ruby source code
    - php: PHP source code
    - scala: Scala source code
    - kotlin: Kotlin source code
    - rust: Rust source code
    
    Args:
        code: The source code content to analyze
        language: The programming language of the code
        
    Returns:
        A dictionary with scan results including found security issues
    """
    try:
        findings = scanner.run_semgrep_scan(code, language)
        
        return {
            "success": True,
            "tool": "semgrep",
            "language": language,
            "total_issues": len(findings),
            "findings": findings,
            "summary": {
                "error": len([f for f in findings if f.get('severity') == 'ERROR']),
                "warning": len([f for f in findings if f.get('severity') == 'WARNING']),
                "info": len([f for f in findings if f.get('severity') == 'INFO']),
            }
        }
    except Exception as e:
        return {
            "success": False,
            "tool": "semgrep",
            "language": language,
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def scan_with_bandit(
    code: str = Field(description='Python code content to scan'),
) -> Dict:
    """Scan Python code using Bandit for security issues.
    
    This tool analyzes Python source code for common security issues
    using PyCQA's Bandit security linter. Bandit is specifically designed
    for Python and can detect issues like:
    
    - Use of insecure functions (pickle, eval, exec)
    - Hardcoded passwords and secrets
    - SQL injection vulnerabilities
    - Command injection risks
    - Weak cryptographic practices
    - Insecure random number generation
    - And many other Python-specific security issues
    
    Args:
        code: The Python code content to analyze
        
    Returns:
        A dictionary with scan results including found security issues
    """
    try:
        findings = scanner.run_bandit_scan(code)
        
        return {
            "success": True,
            "tool": "bandit",
            "language": "python",
            "total_issues": len(findings),
            "findings": findings,
            "summary": {
                "high": len([f for f in findings if f.get('severity') == 'HIGH']),
                "medium": len([f for f in findings if f.get('severity') == 'MEDIUM']),
                "low": len([f for f in findings if f.get('severity') == 'LOW']),
            }
        }
    except Exception as e:
        return {
            "success": False,
            "tool": "bandit",
            "language": "python",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def get_supported_formats() -> Dict:
    """Get list of supported formats and languages for all security scanning tools.
    
    This tool returns information about what file formats and programming
    languages are supported by each of the security scanning tools.
    
    Returns:
        A dictionary with supported formats for each tool
    """
    return {
        "success": True,
        "tools": {
            "checkov": {
                "description": "Infrastructure as Code security scanner",
                "supported_formats": list(scanner.checkov_formats.keys()),
                "format_details": scanner.checkov_formats
            },
            "semgrep": {
                "description": "Source code security scanner",
                "supported_languages": list(scanner.semgrep_languages.keys()),
                "language_extensions": scanner.semgrep_languages
            },
            "bandit": {
                "description": "Python security scanner",
                "supported_languages": ["python"],
                "language_extensions": {".py": "python"}
            }
        }
    }

def main():
    """Run the MCP server with CLI argument support."""
    logger.info('Starting Security Scanner MCP Server.')
    mcp.run()

if __name__ == '__main__':
    main()