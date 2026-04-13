#!/usr/bin/env python3
"""Security Scanner MCP Server implementation for code security analysis."""

import json
import tempfile
import os
import subprocess
import shutil
import warnings
from typing import Dict, Any, List, Optional
from pathlib import Path

from loguru import logger
from mcp.server.fastmcp import FastMCP
from pydantic import Field

# Suppress Pydantic serialization warnings from FastMCP
warnings.filterwarnings('ignore', category=UserWarning, module='pydantic')

from .report_generator import register_report_tool


def resolve_directory_path(directory_path: str) -> Path:
    """Resolve a directory path using WORKSPACE_ROOT or the path itself if absolute.

    Falls back to WORKSPACE_ROOT env var when a relative path is given.
    Never falls back to CWD because the MCP server process CWD is unreliable
    (it is often '/' when launched via uvx).

    Args:
        directory_path: Absolute or relative directory path provided by the agent.

    Returns:
        Resolved absolute Path.

    Raises:
        ValueError: If the path is relative and WORKSPACE_ROOT is not set.
    """
    import os
    dir_path = Path(directory_path)
    if not dir_path.is_absolute():
        workspace_root = os.environ.get('WORKSPACE_ROOT')
        if workspace_root:
            dir_path = Path(workspace_root) / directory_path
            logger.info(f"Resolved path using WORKSPACE_ROOT: {dir_path}")
        else:
            raise ValueError(
                f"Relative path '{directory_path}' cannot be resolved: WORKSPACE_ROOT is not set. "
                "Please pass an absolute path, or set WORKSPACE_ROOT in the MCP server env config "
                "to point to your project root."
            )
    return dir_path.resolve()

# Initialize the MCP server
mcp = FastMCP(
    'security_scanner_mcp_server',
    instructions="""
    Security Scanner MCP Server — real-time security analysis using industry-standard tools.

    TOOLS OVERVIEW:

    Snippet scanners (scan code passed as string):
    - scan_with_bandit: Python security (always use for .py files)
    - scan_with_semgrep: 13+ languages (Python, JS, TS, Java, Go, Rust, C#, etc.)
    - scan_with_checkov: IaC (Terraform, CloudFormation, K8s, Dockerfile, ARM, Bicep, etc.)
    - scan_with_trivy: Dockerfile and IaC security
    - scan_with_ash: Comprehensive multi-tool scan for any file type
    - scan_image_with_trivy: Container image vulnerability scanning

    Directory scanners (scan entire directories, use return_output=True for report generation):
    - scan_directory_with_semgrep: Source code across 13+ languages
    - scan_directory_with_bandit: All Python files
    - scan_directory_with_checkov: All IaC files
    - scan_directory_with_grype: Dependency vulnerabilities (package.json, requirements.txt, etc.)
    - scan_directory_with_ash: Comprehensive multi-tool directory scan
    - scan_directory_with_syft: Software Bill of Materials (SBOM) generation

    Utility tools:
    - check_ash_availability: Verify which scanners are installed
    - get_supported_formats: List supported languages and IaC formats
    - generate_security_report: Generate SECURITY.md from scan results

    SCANNER SELECTION BY FILE TYPE:
    - Python (.py): scan_with_bandit + scan_with_semgrep (use both)
    - JavaScript/TypeScript (.js, .ts): scan_with_semgrep
    - Java, Go, Rust, Kotlin, C#: scan_with_semgrep
    - Terraform (.tf): scan_with_checkov
    - CloudFormation (.yaml, .json): scan_with_checkov
    - Kubernetes manifests: scan_with_checkov
    - Dockerfile: scan_with_checkov + scan_with_trivy
    - Container images: scan_image_with_trivy
    - Dependencies: scan_directory_with_grype

    GENERATING SECURITY.md REPORTS:

    For a single file:
    1. Read the file, identify type, run appropriate scanner(s)
    2. Collect results into a JSON array
    3. Call generate_security_report with project_name and scan_results

    For a full project:
    1. Run check_ash_availability first to see which tools are installed
    2. Run ALL available directory scanners with return_output=True:
       - scan_directory_with_semgrep (always — Python dependency, should be available)
       - scan_directory_with_bandit (always — Python dependency, should be available)
       - scan_directory_with_checkov (always — Python dependency, should be available)
       - scan_directory_with_grype (requires separate install: brew install grype)
       - scan_directory_with_syft (requires separate install: brew install syft)
       - scan_directory_with_ash (if comprehensive scan requested — Python dependency)
       - scan_image_with_trivy (if Dockerfiles present — requires: brew install trivy)
    3. Skip tools that are not installed, collect successful results into a JSON array
    4. Call generate_security_report with project_name and combined scan_results
    5. Save the report field as SECURITY.md
    6. Note any unavailable tools — the report shows them as GAPs automatically

    The generate_security_report tool automatically loads project assumptions
    and resolved findings from .security/config.yaml if it exists.
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
        
        # Check ASH availability
        self._ash_available = None
        self._ash_version = None

    def _save_scan_output(self, tool_name: str, directory_path: str, output_data: str, extension: str = 'json') -> Dict[str, Any]:
        """Save scan output to a dedicated folder and return file path with summary.

        Args:
            tool_name: Name of the scanning tool (e.g., 'ash', 'checkov', 'grype')
            directory_path: Path to the scanned directory
            output_data: The scan output data to save
            extension: File extension (default: 'json')

        Returns:
            Dictionary with file path and metadata
        """
        try:
            from datetime import datetime
            from pathlib import Path
            import os

            # Create tool-specific directory — prefer WORKSPACE_ROOT, then the scanned directory itself
            workspace_root = os.environ.get('WORKSPACE_ROOT')
            if workspace_root:
                base_dir = Path(workspace_root)
            else:
                # Fall back to the scanned directory so we never write to /
                base_dir = Path(directory_path)
                if not base_dir.is_absolute():
                    base_dir = base_dir.resolve()
            output_dir = base_dir / f'.{tool_name}'
            output_dir.mkdir(exist_ok=True)

            # Generate filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            dir_name = Path(directory_path).name
            output_file = output_dir / f'{tool_name}_scan_{dir_name}_{timestamp}.{extension}'

            # Save output to file
            output_file.write_text(output_data)
            logger.info(f"{tool_name.upper()} scan output saved to: {output_file}")

            return {
                'output_file': str(output_file),
                'timestamp': timestamp,
                'scanned_directory': directory_path
            }

        except Exception as e:
            logger.error(f"Error saving {tool_name} scan output: {e}")
            return {
                'error': f'Failed to save output: {str(e)}'
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
                        
                        # Handle both list and dict formats from Checkov
                        failed_checks = []
                        if isinstance(json_result, list):
                            # Checkov can return a list of result objects
                            for result_obj in json_result:
                                if isinstance(result_obj, dict):
                                    failed_checks.extend(result_obj.get('results', {}).get('failed_checks', []))
                        elif isinstance(json_result, dict):
                            # Or a single result object
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

    def check_ash_installation(self) -> Dict[str, Any]:
        """Check if ASH is installed and available, including scanner availability."""
        if self._ash_available is not None:
            # Return cached result with scanner availability
            scanner_availability = self._check_scanner_availability()
            return {
                'available': self._ash_available,
                'version': self._ash_version,
                'cached': True,
                'scanners': scanner_availability
            }
        
        try:
            # Check if ASH is available as a Python module (works in uvx environment)
            import automated_security_helper
            from automated_security_helper.utils.get_ash_version import get_ash_version
            
            version = get_ash_version()
            self._ash_available = True
            self._ash_version = version
            logger.info(f"ASH is available: {version}")
            
            # Check which scanners are available
            scanner_availability = self._check_scanner_availability()
            
            return {
                'available': True,
                'version': version,
                'cached': False,
                'scanners': scanner_availability
            }
                
        except ImportError:
            self._ash_available = False
            logger.warning("ASH module not found - not installed in this environment")
            return {
                'available': False,
                'error': 'ASH not installed in MCP server environment. Add automated-security-helper to dependencies.',
                'cached': False
            }
        except Exception as e:
            self._ash_available = False
            logger.error(f"Error checking ASH installation: {e}")
            return {
                'available': False,
                'error': str(e),
                'cached': False
            }
    
    def _check_scanner_availability(self) -> Dict[str, Dict[str, Any]]:
        """Check which ASH scanners are available based on their dependencies."""
        import shutil
        
        scanners = {
            'bandit': {
                'name': 'Bandit',
                'description': 'Python security linter',
                'check_command': 'bandit',
                'dependency_type': 'python',
                'file_types': ['.py']
            },
            'semgrep': {
                'name': 'Semgrep',
                'description': 'Multi-language SAST',
                'check_command': 'semgrep',
                'dependency_type': 'python',
                'file_types': ['.py', '.js', '.ts', '.java', '.go', '.rb', '.php']
            },
            'checkov': {
                'name': 'Checkov',
                'description': 'IaC security scanner',
                'check_command': 'checkov',
                'dependency_type': 'python',
                'file_types': ['.tf', '.yaml', '.yml', '.json', 'Dockerfile']
            },
            'cfn-nag': {
                'name': 'cfn-nag',
                'description': 'CloudFormation security scanner',
                'check_command': 'cfn_nag',
                'dependency_type': 'ruby',
                'file_types': ['.yaml', '.yml', '.json', '.template']
            },
            'cdk-nag': {
                'name': 'cdk-nag',
                'description': 'AWS CDK security scanner',
                'check_command': 'npm',  # cdk-nag is an npm package
                'dependency_type': 'npm',
                'file_types': ['.ts', '.js']
            },
            'detect-secrets': {
                'name': 'detect-secrets',
                'description': 'Secret detection',
                'check_command': 'detect-secrets',
                'dependency_type': 'python',
                'file_types': ['*']
            },
            'grype': {
                'name': 'Grype',
                'description': 'Vulnerability scanner',
                'check_command': 'grype',
                'dependency_type': 'binary',
                'file_types': ['*']
            },
            'syft': {
                'name': 'Syft',
                'description': 'SBOM generator',
                'check_command': 'syft',
                'dependency_type': 'binary',
                'file_types': ['*']
            },
            'npm-audit': {
                'name': 'npm-audit',
                'description': 'Node.js dependency scanner',
                'check_command': 'npm',
                'dependency_type': 'npm',
                'file_types': ['package.json', 'package-lock.json']
            }
        }
        
        availability = {}
        for scanner_id, scanner_info in scanners.items():
            check_cmd = scanner_info['check_command']
            is_available = shutil.which(check_cmd) is not None
            
            # Special handling for Semgrep - it's excluded from ASH scans
            if scanner_id == 'semgrep':
                availability[scanner_id] = {
                    'name': scanner_info['name'],
                    'description': scanner_info['description'],
                    'available': False,  # Not available via ASH
                    'dependency_type': scanner_info['dependency_type'],
                    'file_types': scanner_info['file_types'],
                    'status': 'available via standalone tool only',
                    'note': 'Semgrep is excluded from ASH scans. Use scan_with_semgrep tool instead.'
                }
            else:
                availability[scanner_id] = {
                    'name': scanner_info['name'],
                    'description': scanner_info['description'],
                    'available': is_available,
                    'dependency_type': scanner_info['dependency_type'],
                    'file_types': scanner_info['file_types'],
                    'status': 'installed' if is_available else 'not installed'
                }
                
                if not is_available:
                    # Add installation hints
                    if scanner_info['dependency_type'] == 'ruby':
                        availability[scanner_id]['install_hint'] = f"gem install {scanner_id}"
                    elif scanner_info['dependency_type'] == 'npm':
                        availability[scanner_id]['install_hint'] = f"npm install -g {scanner_id}"
                    elif scanner_info['dependency_type'] == 'binary':
                        availability[scanner_id]['install_hint'] = f"Install {scanner_info['name']} from official source"
        
        return availability

    def run_ash_scan(self, code: str, file_extension: str, severity_threshold: str = 'MEDIUM') -> Dict[str, Any]:
        """Run ASH scan on code snippet (delta scanning approach)."""
        logger.info(f"Starting ASH scan for file extension: {file_extension}")
        
        # Check if ASH is available
        ash_check = self.check_ash_installation()
        if not ash_check['available']:
            raise ValueError(f"ASH is not available: {ash_check.get('error', 'Unknown error')}")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create a file with the appropriate extension
                if file_extension.startswith('.'):
                    filename = f'scan{file_extension}'
                else:
                    filename = file_extension if file_extension else 'scan.txt'
                
                file_path = temp_path / filename
                file_path.write_text(code)
                
                logger.info(f"Created temporary file: {file_path}")
                
                # Create output directory
                output_dir = temp_path / '.ash' / 'ash_output'
                output_dir.mkdir(parents=True, exist_ok=True)
                
                # Use ASH's Python API instead of command-line
                from automated_security_helper.core.enums import AshLogLevel, RunMode
                from automated_security_helper.interactions.run_ash_scan import run_ash_scan
                
                logger.info(f"Running ASH scan with severity threshold: {severity_threshold}")
                
                # Run the scan using ASH's Python API
                try:
                    run_ash_scan(
                        source_dir=str(temp_path),
                        output_dir=str(output_dir),
                        config=None,
                        mode=RunMode.local,
                        log_level=AshLogLevel.ERROR,  # Keep it quiet
                        fail_on_findings=False,  # Don't exit on findings
                        show_summary=False,  # Don't show summary
                        exclude_scanners=['semgrep'],  # Exclude semgrep to avoid duplication
                    )
                    
                    logger.info(f"ASH scan completed")
                    
                except Exception as scan_error:
                    logger.warning(f"ASH scan completed with error (may be expected): {scan_error}")
                    # Continue to check for results file - ASH may still have produced results
                
                # Parse the aggregated results file
                results_file = output_dir / 'ash_aggregated_results.json'
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        ash_results = json.load(f)
                    
                    logger.info(f"Successfully parsed ASH results")
                    return self._format_ash_results(ash_results, file_path.name)
                else:
                    logger.warning(f"ASH results file not found: {results_file}")
                    return {
                        'success': False,
                        'error': 'ASH results file not found - scan may have failed',
                    }
                    
        except ImportError as e:
            logger.error(f"ASH Python API not available: {e}")
            return {
                'success': False,
                'error': f'ASH Python API not available: {str(e)}'
            }
        except subprocess.TimeoutExpired:
            logger.error("ASH scan timed out")
            return {
                'success': False,
                'error': 'ASH scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running ASH scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_ash_results(self, ash_results: Dict, filename: str) -> Dict[str, Any]:
        """Format ASH results into a consistent structure."""
        try:
            findings = []
            scanner_summary = {}
            
            # ASH stores findings in SARIF format
            sarif_data = ash_results.get('sarif', {})
            runs = sarif_data.get('runs', [])
            
            if runs:
                # Get the first run (ASH typically has one run)
                run = runs[0]
                sarif_results = run.get('results', [])
                
                logger.info(f"Found {len(sarif_results)} SARIF results")
                
                for result in sarif_results:
                    # Extract scanner name from rule ID or tool
                    rule_id = result.get('ruleId', 'Unknown')
                    scanner_name = rule_id.split('/')[0] if '/' in rule_id else 'unknown'
                    
                    # Get severity from level
                    level = result.get('level', 'note')
                    severity_map = {
                        'error': 'HIGH',
                        'warning': 'MEDIUM',
                        'note': 'LOW',
                        'none': 'INFO'
                    }
                    severity = severity_map.get(level, 'UNKNOWN')
                    
                    # Get message
                    message_obj = result.get('message', {})
                    message = message_obj.get('text', 'No description')
                    
                    # Get location
                    locations = result.get('locations', [])
                    line = 0
                    file_path = filename
                    if locations:
                        physical_location = locations[0].get('physicalLocation', {})
                        artifact_location = physical_location.get('artifactLocation', {})
                        file_path = artifact_location.get('uri', filename)
                        region = physical_location.get('region', {})
                        line = region.get('startLine', 0)
                    
                    # Update scanner summary
                    if scanner_name not in scanner_summary:
                        scanner_summary[scanner_name] = {
                            'total': 0,
                            'by_severity': {}
                        }
                    scanner_summary[scanner_name]['total'] += 1
                    scanner_summary[scanner_name]['by_severity'][severity] = \
                        scanner_summary[scanner_name]['by_severity'].get(severity, 0) + 1
                    
                    # Format finding
                    formatted_finding = {
                        'scanner': scanner_name,
                        'severity': severity,
                        'rule_id': rule_id,
                        'message': message,
                        'file': file_path,
                        'line': line,
                        'details': result
                    }
                    findings.append(formatted_finding)
            
            # Also check scanner_results for summary info
            scanner_results = ash_results.get('scanner_results', {})
            for scanner_name, scanner_data in scanner_results.items():
                if scanner_name not in scanner_summary:
                    finding_count = scanner_data.get('finding_count', 0)
                    if finding_count > 0:
                        logger.info(f"Scanner {scanner_name} reported {finding_count} findings but they weren't in SARIF")
            
            # Calculate overall summary
            overall_summary = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
                'unknown': 0
            }
            
            for finding in findings:
                severity = finding['severity'].lower()
                if severity in overall_summary:
                    overall_summary[severity] += 1
                else:
                    overall_summary['unknown'] += 1
            
            return {
                'success': True,
                'tool': 'ash',
                'total_issues': len(findings),
                'findings': findings,
                'summary': overall_summary,
                'scanner_summary': scanner_summary,
                'ash_version': ash_results.get('metadata', {}).get('tool_version', 'unknown')
            }
            
        except Exception as e:
            logger.error(f"Error formatting ASH results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting ASH results: {str(e)}'
            }

    def check_syft_installation(self) -> Dict[str, Any]:
        """Check if Syft is installed and available."""
        try:
            result = subprocess.run(
                ['syft', 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output
                version_line = result.stdout.strip().split('\n')[0]
                version = version_line.split()[-1] if version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Syft command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Syft not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Syft command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def check_grype_installation(self) -> Dict[str, Any]:
        """Check if Grype is installed and available."""
        try:
            result = subprocess.run(
                ['grype', 'version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output
                version_line = result.stdout.strip().split('\n')[0]
                version = version_line.split()[-1] if version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Grype command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Grype not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Grype command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def check_trivy_installation(self) -> Dict[str, Any]:
        """Check if Trivy is installed and available."""
        try:
            result = subprocess.run(
                ['trivy', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output (format: "Version: X.Y.Z")
                version_line = result.stdout.strip().split('\n')[0]
                version = version_line.split()[-1] if 'Version:' in version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Trivy command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Trivy not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Trivy command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def check_bandit_installation(self) -> Dict[str, Any]:
        """Check if Bandit is installed and available."""
        try:
            result = subprocess.run(
                ['bandit', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output
                version_line = result.stdout.strip()
                version = version_line.split()[-1] if version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Bandit command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Bandit not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Bandit command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def check_semgrep_installation(self) -> Dict[str, Any]:
        """Check if Semgrep is installed and available."""
        try:
            result = subprocess.run(
                ['semgrep', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output
                version_line = result.stdout.strip()
                version = version_line.split()[-1] if version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Semgrep command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Semgrep not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Semgrep command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def check_checkov_installation(self) -> Dict[str, Any]:
        """Check if Checkov is installed and available."""
        try:
            result = subprocess.run(
                ['checkov', '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                # Parse version from output
                version_line = result.stdout.strip()
                version = version_line.split()[-1] if version_line else 'unknown'
                
                return {
                    'available': True,
                    'version': version
                }
            else:
                return {
                    'available': False,
                    'error': 'Checkov command failed'
                }
        except FileNotFoundError:
            return {
                'available': False,
                'error': 'Checkov not found in PATH'
            }
        except subprocess.TimeoutExpired:
            return {
                'available': False,
                'error': 'Checkov command timed out'
            }
        except Exception as e:
            return {
                'available': False,
                'error': str(e)
            }

    def run_trivy_scan(self, code: str, scan_type: str = 'config') -> Dict[str, Any]:
        """Run Trivy scan on code snippet (Dockerfile or IaC config)."""
        logger.info(f"Starting Trivy scan for type: {scan_type}")
        
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create a file based on scan type
                if scan_type == 'dockerfile':
                    file_path = temp_path / 'Dockerfile'
                elif scan_type == 'terraform':
                    file_path = temp_path / 'main.tf'
                elif scan_type == 'kubernetes':
                    file_path = temp_path / 'manifest.yaml'
                else:
                    file_path = temp_path / 'config.yaml'
                
                file_path.write_text(code)
                
                logger.info(f"Created temporary file: {file_path}")
                
                # Run Trivy with JSON output
                cmd = [
                    'trivy',
                    'config',
                    '--format', 'json',
                    '--quiet',
                    str(file_path)
                ]
                
                logger.info(f"Running command: {' '.join(cmd)}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=120  # 2 minutes timeout
                )
                
                # Trivy returns non-zero when issues are found, which is expected
                logger.info(f"Trivy exit code: {result.returncode}")
                
                # Parse JSON output
                try:
                    if result.stdout:
                        trivy_results = json.loads(result.stdout)
                    else:
                        logger.warning("No Trivy output received")
                        return {
                            'success': True,
                            'tool': 'trivy',
                            'scan_type': scan_type,
                            'total_issues': 0,
                            'findings': [],
                            'summary': {
                                'critical': 0,
                                'high': 0,
                                'medium': 0,
                                'low': 0,
                                'unknown': 0
                            }
                        }
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Trivy JSON output: {e}")
                    return {
                        'success': False,
                        'error': f'Failed to parse Trivy output: {str(e)}'
                    }
                
                # Format results
                return self._format_trivy_results(trivy_results, scan_type)
                
        except subprocess.TimeoutExpired:
            logger.error("Trivy scan timed out")
            return {
                'success': False,
                'error': 'Trivy scan timed out after 2 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Trivy scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def run_trivy_image_scan(self, image_name: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run Trivy scan on a container image and save output to file by default."""
        logger.info(f"Starting Trivy image scan: {image_name}")
        
        try:
            # Run Trivy with JSON output
            cmd = [
                'trivy',
                'image',
                '--format', 'json',
                '--quiet',
                image_name
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minutes timeout for image download
            )
            
            # Trivy returns non-zero when issues are found, which is expected
            logger.info(f"Trivy exit code: {result.returncode}")
            
            # Parse JSON output
            try:
                if result.stdout:
                    trivy_results = json.loads(result.stdout)
                else:
                    logger.warning("No Trivy output received")
                    return {
                        'success': True,
                        'tool': 'trivy',
                        'scan_type': 'image',
                        'image': image_name,
                        'total_issues': 0,
                        'severity_counts': {
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0,
                            'unknown': 0
                        }
                    }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Trivy JSON output: {e}")
                return {
                    'success': False,
                    'error': f'Failed to parse Trivy output: {str(e)}'
                }
            
            # If user explicitly requests output, return full results
            if return_output:
                return self._format_trivy_image_results(trivy_results, image_name, severity_threshold)
            
            # Otherwise, save to file and return summary
            # Use sanitized image name for filename
            safe_image_name = image_name.replace('/', '_').replace(':', '_')
            file_info = self._save_scan_output('trivy', safe_image_name, result.stdout, 'json')
            summary = self._format_trivy_image_summary(trivy_results, image_name, severity_threshold)
            
            return {
                'success': True,
                'tool': 'trivy',
                'scan_type': 'image',
                'image': image_name,
                **file_info,
                **summary
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Trivy image scan timed out")
            return {
                'success': False,
                'error': 'Trivy image scan timed out after 10 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Trivy image scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_trivy_results(self, trivy_results: Dict, scan_type: str) -> Dict[str, Any]:
        """Format Trivy config scan results into a consistent structure."""
        try:
            findings = []
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            }
            
            # Process results
            results = trivy_results.get('Results', [])
            
            for result in results:
                misconfigurations = result.get('Misconfigurations', [])
                
                for misconfig in misconfigurations:
                    severity = misconfig.get('Severity', 'UNKNOWN').upper()
                    
                    # Count by severity
                    severity_key = severity.lower()
                    if severity_key in severity_counts:
                        severity_counts[severity_key] += 1
                    
                    finding = {
                        'id': misconfig.get('ID', 'Unknown'),
                        'title': misconfig.get('Title', 'Unknown'),
                        'severity': severity,
                        'description': misconfig.get('Description', ''),
                        'message': misconfig.get('Message', ''),
                        'resolution': misconfig.get('Resolution', ''),
                        'references': misconfig.get('References', []),
                        'status': misconfig.get('Status', 'FAIL'),
                        'layer': misconfig.get('Layer', {})
                    }
                    
                    findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Trivy findings")
            
            return {
                'success': True,
                'tool': 'trivy',
                'scan_type': scan_type,
                'total_issues': total_issues,
                'findings': findings,
                'summary': severity_counts
            }
            
        except Exception as e:
            logger.error(f"Error formatting Trivy results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Trivy results: {str(e)}'
            }

    def _format_trivy_image_results(self, trivy_results: Dict, image_name: str, severity_threshold: str) -> Dict[str, Any]:
        """Format Trivy image scan results into a consistent structure with minimized output."""
        try:
            findings = []
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            }
            
            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2
            
            # Process results
            results = trivy_results.get('Results', [])
            
            for result in results:
                target = result.get('Target', 'Unknown')
                vulnerabilities = result.get('Vulnerabilities', [])
                
                if not vulnerabilities:
                    continue
                
                for vuln in vulnerabilities:
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    severity_index = severity_order.index(severity) if severity in severity_order else 4
                    
                    # Filter by threshold
                    if severity_index > threshold_index:
                        continue
                    
                    # Count by severity
                    severity_key = severity.lower()
                    if severity_key in severity_counts:
                        severity_counts[severity_key] += 1
                    
                    # Minimize the finding data - only include essential information
                    finding = {
                        'vulnerability_id': vuln.get('VulnerabilityID', 'Unknown'),
                        'severity': severity,
                        'package': vuln.get('PkgName', 'Unknown'),
                        'installed_version': vuln.get('InstalledVersion', 'Unknown'),
                        'fixed_version': vuln.get('FixedVersion', 'Not available'),
                        'title': vuln.get('Title', 'No title'),
                        'target': target
                    }
                    
                    # Only add description if it's short (to minimize output)
                    description = vuln.get('Description', '')
                    if description and len(description) < 200:
                        finding['description'] = description
                    
                    # Add primary reference URL if available
                    refs = vuln.get('References', [])
                    if refs:
                        finding['reference'] = refs[0]
                    
                    findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Trivy image findings")
            
            # Get metadata
            metadata = trivy_results.get('Metadata', {})
            
            return {
                'success': True,
                'tool': 'trivy',
                'scan_type': 'image',
                'image': image_name,
                'total_issues': total_issues,
                'findings': findings,
                'summary': severity_counts,
                'scan_metadata': {
                    'image_id': metadata.get('ImageID', 'Unknown'),
                    'os': metadata.get('OS', {}).get('Family', 'Unknown'),
                    'trivy_version': metadata.get('Version', 'Unknown')
                }
            }
            
        except Exception as e:
            logger.error(f"Error formatting Trivy image results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Trivy image results: {str(e)}'
            }

    def _format_trivy_image_summary(self, trivy_results: Dict, image_name: str, severity_threshold: str) -> Dict[str, Any]:
        """Format Trivy image scan results into a lightweight summary (no full vulnerability details)."""
        try:
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'unknown': 0
            }

            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2

            # Process results
            results = trivy_results.get('Results', [])
            filtered_count = 0
            total_vulnerabilities = 0

            for result in results:
                vulnerabilities = result.get('Vulnerabilities', [])

                if not vulnerabilities:
                    continue

                for vuln in vulnerabilities:
                    total_vulnerabilities += 1
                    severity = vuln.get('Severity', 'UNKNOWN').upper()
                    severity_index = severity_order.index(severity) if severity in severity_order else 4

                    # Count all severities
                    severity_key = severity.lower()
                    if severity_key in severity_counts:
                        severity_counts[severity_key] += 1

                    # Count filtered issues
                    if severity_index <= threshold_index:
                        filtered_count += 1

            logger.info(f"Generated Trivy image summary: {filtered_count} issues above {severity_threshold} threshold (total: {total_vulnerabilities})")

            # Get metadata
            metadata = trivy_results.get('Metadata', {})

            return {
                'total_vulnerabilities': total_vulnerabilities,
                'filtered_issues': filtered_count,
                'severity_threshold': severity_threshold,
                'severity_counts': severity_counts,
                'scan_metadata': {
                    'image_id': metadata.get('ImageID', 'Unknown'),
                    'os': metadata.get('OS', {}).get('Family', 'Unknown'),
                    'trivy_version': metadata.get('Version', 'Unknown')
                }
            }

        except Exception as e:
            logger.error(f"Error formatting Trivy image summary: {e}")
            return {
                'error': f'Error formatting Trivy image summary: {str(e)}'
            }


    def run_bandit_directory_scan(self, directory_path: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run Bandit scan on a directory and save output to file by default."""
        logger.info(f"Starting Bandit directory scan: {directory_path}")
        
        try:
            # Run Bandit with JSON output
            cmd = [
                'bandit',
                '-r', directory_path,
                '-f', 'json',
                '--quiet'
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Bandit returns non-zero when issues are found, which is expected
            logger.info(f"Bandit exit code: {result.returncode}")
            
            # Parse JSON output
            try:
                if result.stdout:
                    bandit_results = json.loads(result.stdout)
                else:
                    logger.warning("No Bandit output received")
                    return {
                        'success': True,
                        'tool': 'bandit',
                        'total_issues': 0,
                        'severity_counts': {
                            'high': 0,
                            'medium': 0,
                            'low': 0
                        }
                    }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Bandit JSON output: {e}")
                return {
                    'success': False,
                    'error': f'Failed to parse Bandit output: {str(e)}'
                }
            
            # If user explicitly requests output, return full results
            if return_output:
                return self._format_bandit_directory_results(bandit_results, severity_threshold)
            
            # Otherwise, save to file and return summary
            file_info = self._save_scan_output('bandit', directory_path, result.stdout, 'json')
            summary = self._format_bandit_summary(bandit_results, severity_threshold)
            
            return {
                'success': True,
                'tool': 'bandit',
                **file_info,
                **summary
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
            return {
                'success': False,
                'error': 'Bandit scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Bandit scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_bandit_directory_results(self, bandit_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Bandit directory scan results into a consistent structure."""
        try:
            findings = []
            severity_counts = {
                'high': 0,
                'medium': 0,
                'low': 0
            }
            
            # Define severity order for filtering
            severity_order = ['HIGH', 'MEDIUM', 'LOW']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 1
            
            # Process results
            results = bandit_results.get('results', [])
            
            for result in results:
                # Get severity
                severity = result.get('issue_severity', 'MEDIUM').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 1
                
                # Filter by threshold
                if severity_index > threshold_index:
                    continue
                
                # Count by severity
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1
                
                finding = {
                    'test_id': result.get('test_id', 'Unknown'),
                    'test_name': result.get('test_name', 'Unknown'),
                    'severity': severity,
                    'confidence': result.get('issue_confidence', 'MEDIUM'),
                    'file_path': result.get('filename', 'Unknown'),
                    'line_number': result.get('line_number', 0),
                    'line_range': result.get('line_range', []),
                    'description': result.get('issue_text', ''),
                    'code': result.get('code', ''),
                    'more_info': result.get('more_info', '')
                }
                
                findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Bandit findings")
            
            # Cap findings to avoid context window overflow when returning inline
            MAX_INLINE_FINDINGS = 100
            truncated = total_issues > MAX_INLINE_FINDINGS
            findings_out = findings[:MAX_INLINE_FINDINGS]
            
            # Get metrics
            metrics = bandit_results.get('metrics', {})
            
            result = {
                'success': True,
                'tool': 'bandit',
                'total_issues': total_issues,
                'findings': findings_out,
                'summary': severity_counts,
                'scan_metadata': {
                    'files_scanned': metrics.get('_totals', {}).get('loc', 0),
                    'lines_of_code': metrics.get('_totals', {}).get('loc', 0)
                }
            }
            if truncated:
                result['truncated'] = True
                result['truncation_note'] = (
                    f"Results capped at {MAX_INLINE_FINDINGS} of {total_issues} findings to prevent context overflow. "
                    "Full results are saved to the output file."
                )
            return result
            
        except Exception as e:
            logger.error(f"Error formatting Bandit results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Bandit results: {str(e)}'
            }

    def _format_bandit_summary(self, bandit_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Bandit results into a lightweight summary (no full issue details)."""
        try:
            severity_counts = {
                'high': 0,
                'medium': 0,
                'low': 0
            }

            # Define severity order for filtering
            severity_order = ['HIGH', 'MEDIUM', 'LOW']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 1

            # Process results
            results = bandit_results.get('results', [])
            filtered_count = 0

            for result in results:
                severity = result.get('issue_severity', 'MEDIUM').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 1

                # Count all severities
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1

                # Count filtered issues
                if severity_index <= threshold_index:
                    filtered_count += 1

            total_issues = len(results)

            logger.info(f"Generated Bandit summary: {filtered_count} issues above {severity_threshold} threshold (total: {total_issues})")

            # Get metrics
            metrics = bandit_results.get('metrics', {})

            return {
                'total_issues': total_issues,
                'filtered_issues': filtered_count,
                'severity_threshold': severity_threshold,
                'severity_counts': severity_counts,
                'scan_metadata': {
                    'files_scanned': metrics.get('_totals', {}).get('loc', 0),
                    'lines_of_code': metrics.get('_totals', {}).get('loc', 0)
                }
            }

        except Exception as e:
            logger.error(f"Error formatting Bandit summary: {e}")
            return {
                'error': f'Error formatting Bandit summary: {str(e)}'
            }


    def run_semgrep_directory_scan(self, directory_path: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run Semgrep scan on a directory and save output to file by default."""
        logger.info(f"Starting Semgrep directory scan: {directory_path}")
        
        try:
            # Run Semgrep with JSON output
            cmd = [
                'semgrep',
                '--config=auto',
                '--config=p/security-audit',
                '--config=p/secrets',
                '--json',
                '--quiet',
                directory_path
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Semgrep returns non-zero when issues are found, which is expected
            logger.info(f"Semgrep exit code: {result.returncode}")
            
            # Parse JSON output
            try:
                if result.stdout:
                    semgrep_results = json.loads(result.stdout)
                else:
                    logger.warning("No Semgrep output received")
                    return {
                        'success': True,
                        'tool': 'semgrep',
                        'total_issues': 0,
                        'severity_counts': {
                            'error': 0,
                            'warning': 0,
                            'info': 0
                        }
                    }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Semgrep JSON output: {e}")
                return {
                    'success': False,
                    'error': f'Failed to parse Semgrep output: {str(e)}'
                }
            
            # If user explicitly requests output, return full results
            if return_output:
                return self._format_semgrep_directory_results(semgrep_results, severity_threshold)
            
            # Otherwise, save to file and return summary
            file_info = self._save_scan_output('semgrep', directory_path, result.stdout, 'json')
            summary = self._format_semgrep_summary(semgrep_results, severity_threshold)
            
            return {
                'success': True,
                'tool': 'semgrep',
                **file_info,
                **summary
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Semgrep scan timed out")
            return {
                'success': False,
                'error': 'Semgrep scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Semgrep scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_semgrep_directory_results(self, semgrep_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Semgrep directory scan results into a consistent structure."""
        try:
            findings = []
            severity_counts = {
                'error': 0,
                'warning': 0,
                'info': 0
            }
            
            # Define severity order for filtering (Semgrep uses ERROR, WARNING, INFO)
            severity_order = ['ERROR', 'WARNING', 'INFO']
            # Map threshold to Semgrep severity
            threshold_map = {
                'CRITICAL': 'ERROR',
                'HIGH': 'ERROR',
                'MEDIUM': 'WARNING',
                'LOW': 'INFO'
            }
            threshold_severity = threshold_map.get(severity_threshold.upper(), 'WARNING')
            threshold_index = severity_order.index(threshold_severity)
            
            # Process results
            results = semgrep_results.get('results', [])
            
            for result in results:
                # Get severity
                extra = result.get('extra', {})
                severity = extra.get('severity', 'INFO').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 2
                
                # Filter by threshold
                if severity_index > threshold_index:
                    continue
                
                # Count by severity
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1
                
                finding = {
                    'rule_id': result.get('check_id', 'Unknown'),
                    'message': extra.get('message', 'No message'),
                    'severity': severity,
                    'file_path': result.get('path', 'Unknown'),
                    'line': result.get('start', {}).get('line', 0),
                    'column': result.get('start', {}).get('col', 0),
                    'end_line': result.get('end', {}).get('line', 0),
                    'code_snippet': extra.get('lines', ''),
                    'metadata': extra.get('metadata', {})
                }
                
                findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Semgrep findings")
            
            # Cap findings to avoid context window overflow when returning inline
            MAX_INLINE_FINDINGS = 100
            truncated = total_issues > MAX_INLINE_FINDINGS
            findings_out = findings[:MAX_INLINE_FINDINGS]
            
            result = {
                'success': True,
                'tool': 'semgrep',
                'total_issues': total_issues,
                'findings': findings_out,
                'summary': severity_counts,
                'scan_metadata': {
                    'errors': semgrep_results.get('errors', [])
                }
            }
            if truncated:
                result['truncated'] = True
                result['truncation_note'] = (
                    f"Results capped at {MAX_INLINE_FINDINGS} of {total_issues} findings to prevent context overflow. "
                    "Full results are saved to the output file."
                )
            return result
            
        except Exception as e:
            logger.error(f"Error formatting Semgrep results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Semgrep results: {str(e)}'
            }

    def _format_semgrep_summary(self, semgrep_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Semgrep results into a lightweight summary (no full finding details)."""
        try:
            severity_counts = {
                'error': 0,
                'warning': 0,
                'info': 0
            }

            # Define severity order for filtering
            severity_order = ['ERROR', 'WARNING', 'INFO']
            threshold_map = {
                'CRITICAL': 'ERROR',
                'HIGH': 'ERROR',
                'MEDIUM': 'WARNING',
                'LOW': 'INFO'
            }
            threshold_severity = threshold_map.get(severity_threshold.upper(), 'WARNING')
            threshold_index = severity_order.index(threshold_severity)

            # Process results
            results = semgrep_results.get('results', [])
            filtered_count = 0

            for result in results:
                extra = result.get('extra', {})
                severity = extra.get('severity', 'INFO').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 2

                # Count all severities
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1

                # Count filtered issues
                if severity_index <= threshold_index:
                    filtered_count += 1

            total_issues = len(results)

            logger.info(f"Generated Semgrep summary: {filtered_count} issues above {severity_threshold} threshold (total: {total_issues})")

            return {
                'total_issues': total_issues,
                'filtered_issues': filtered_count,
                'severity_threshold': severity_threshold,
                'severity_counts': severity_counts,
                'scan_metadata': {
                    'errors': len(semgrep_results.get('errors', []))
                }
            }

        except Exception as e:
            logger.error(f"Error formatting Semgrep summary: {e}")
            return {
                'error': f'Error formatting Semgrep summary: {str(e)}'
            }


    def run_ash_directory_scan(self, directory_path: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run ASH scan on a directory and save output to file by default."""
        logger.info(f"Starting ASH directory scan: {directory_path}")
        
        # Check if ASH is available
        ash_check = self.check_ash_installation()
        if not ash_check['available']:
            raise ValueError(f"ASH is not available: {ash_check.get('error', 'Unknown error')}")
        
        try:
            # Create output directory
            import tempfile
            from pathlib import Path
            
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                output_dir = temp_path / 'ash_output'
                output_dir.mkdir(parents=True, exist_ok=True)
                
                logger.info(f"ASH output directory: {output_dir}")
                
                # Use ASH's Python API
                from automated_security_helper.core.enums import AshLogLevel, RunMode
                from automated_security_helper.interactions.run_ash_scan import run_ash_scan
                
                logger.info(f"Running ASH scan with severity threshold: {severity_threshold}")
                
                # Run the scan using ASH's Python API
                try:
                    run_ash_scan(
                        source_dir=directory_path,
                        output_dir=str(output_dir),
                        config=None,
                        mode=RunMode.local,
                        log_level=AshLogLevel.ERROR,
                        fail_on_findings=False,
                        show_summary=False,
                        exclude_scanners=['semgrep'],  # Exclude semgrep to avoid duplication
                    )
                    
                    logger.info(f"ASH scan completed")
                    
                except Exception as scan_error:
                    logger.warning(f"ASH scan completed with error (may be expected): {scan_error}")
                
                # Parse the aggregated results file
                results_file = output_dir / 'ash_aggregated_results.json'
                if results_file.exists():
                    with open(results_file, 'r') as f:
                        ash_results_text = f.read()
                        ash_results = json.loads(ash_results_text)
                    
                    logger.info(f"Successfully parsed ASH results")
                    
                    # If user explicitly requests output, return full results
                    if return_output:
                        return self._format_ash_directory_results(ash_results, severity_threshold)
                    
                    # Otherwise, save to file and return summary
                    file_info = self._save_scan_output('ash', directory_path, ash_results_text, 'json')
                    summary = self._format_ash_summary(ash_results, severity_threshold)
                    
                    return {
                        'success': True,
                        'tool': 'ash',
                        **file_info,
                        **summary
                    }
                else:
                    logger.warning(f"ASH results file not found: {results_file}")
                    return {
                        'success': False,
                        'error': 'ASH results file not found - scan may have failed',
                    }
                    
        except ImportError as e:
            logger.error(f"ASH Python API not available: {e}")
            return {
                'success': False,
                'error': f'ASH Python API not available: {str(e)}'
            }
        except subprocess.TimeoutExpired:
            logger.error("ASH scan timed out")
            return {
                'success': False,
                'error': 'ASH scan timed out'
            }
        except Exception as e:
            logger.error(f"Error running ASH scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_ash_directory_results(self, ash_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format ASH directory scan results into a consistent structure."""
        # Reuse the existing _format_ash_results method
        return self._format_ash_results(ash_results, 'directory_scan')

    def _format_ash_summary(self, ash_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format ASH results into a lightweight summary (no full finding details)."""
        try:
            scanner_summary = {}

            # ASH stores findings in SARIF format
            sarif_data = ash_results.get('sarif', {})
            runs = sarif_data.get('runs', [])

            overall_summary = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0,
                'unknown': 0
            }

            total_findings = 0

            if runs:
                run = runs[0]
                sarif_results = run.get('results', [])
                total_findings = len(sarif_results)

                for result in sarif_results:
                    # Extract scanner name
                    rule_id = result.get('ruleId', 'Unknown')
                    scanner_name = rule_id.split('/')[0] if '/' in rule_id else 'unknown'

                    # Get severity
                    level = result.get('level', 'note')
                    severity_map = {
                        'error': 'HIGH',
                        'warning': 'MEDIUM',
                        'note': 'LOW',
                        'none': 'INFO'
                    }
                    severity = severity_map.get(level, 'UNKNOWN')

                    # Update scanner summary
                    if scanner_name not in scanner_summary:
                        scanner_summary[scanner_name] = {
                            'total': 0,
                            'by_severity': {}
                        }
                    scanner_summary[scanner_name]['total'] += 1
                    scanner_summary[scanner_name]['by_severity'][severity] = \
                        scanner_summary[scanner_name]['by_severity'].get(severity, 0) + 1

                    # Update overall summary
                    severity_key = severity.lower()
                    if severity_key in overall_summary:
                        overall_summary[severity_key] += 1
                    else:
                        overall_summary['unknown'] += 1

            logger.info(f"Generated ASH summary: {total_findings} total findings")

            return {
                'total_issues': total_findings,
                'severity_counts': overall_summary,
                'scanner_summary': scanner_summary,
                'ash_version': ash_results.get('metadata', {}).get('tool_version', 'unknown')
            }

        except Exception as e:
            logger.error(f"Error formatting ASH summary: {e}")
            return {
                'error': f'Error formatting ASH summary: {str(e)}'
            }


    def run_checkov_directory_scan(self, directory_path: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run Checkov scan on a directory and save output to file by default."""
        logger.info(f"Starting Checkov directory scan: {directory_path}")
        
        try:
            # Run Checkov with JSON output
            # Skip CDK framework to avoid downloading aws-cdk-lib (47MB) on every run
            cmd = [
                'checkov',
                '-d', directory_path,
                '-o', 'json',
                '--quiet',
                '--compact',
                '--skip-framework', 'cdk'
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Checkov returns non-zero when issues are found, which is expected
            logger.info(f"Checkov exit code: {result.returncode}")
            
            # Parse JSON output
            try:
                if result.stdout:
                    checkov_results = json.loads(result.stdout)
                else:
                    logger.warning("No Checkov output received")
                    return {
                        'success': True,
                        'tool': 'checkov',
                        'total_issues': 0,
                        'severity_counts': {
                            'critical': 0,
                            'high': 0,
                            'medium': 0,
                            'low': 0,
                            'info': 0
                        }
                    }
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Checkov JSON output: {e}")
                return {
                    'success': False,
                    'error': f'Failed to parse Checkov output: {str(e)}'
                }
            
            # If user explicitly requests output, return full results
            if return_output:
                return self._format_checkov_directory_results(checkov_results, severity_threshold)
            
            # Otherwise, save to file and return summary
            file_info = self._save_scan_output('checkov', directory_path, result.stdout, 'json')
            summary = self._format_checkov_summary(checkov_results, severity_threshold)
            
            return {
                'success': True,
                'tool': 'checkov',
                **file_info,
                **summary
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Checkov scan timed out")
            return {
                'success': False,
                'error': 'Checkov scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Checkov scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_checkov_directory_results(self, checkov_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Checkov directory scan results into a consistent structure."""
        try:
            findings = []
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }
            
            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2
            
            # Process failed checks from all result objects
            failed_checks = []
            if isinstance(checkov_results, list):
                for result_obj in checkov_results:
                    if isinstance(result_obj, dict):
                        failed_checks.extend(result_obj.get('results', {}).get('failed_checks', []))
            elif isinstance(checkov_results, dict):
                failed_checks = checkov_results.get('results', {}).get('failed_checks', [])
            
            for check in failed_checks:
                # Get severity (default to MEDIUM if not specified or None)
                severity_raw = check.get('severity', 'MEDIUM')
                severity = (severity_raw or 'MEDIUM').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 2
                
                # Filter by threshold
                if severity_index > threshold_index:
                    continue
                
                # Count by severity
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1
                
                finding = {
                    'check_id': check.get('check_id', 'Unknown'),
                    'check_name': check.get('check_name', 'Unknown'),
                    'severity': severity,
                    'file_path': check.get('file_path', 'Unknown'),
                    'resource': check.get('resource', 'Unknown'),
                    'guideline': check.get('guideline', ''),
                    'description': check.get('description', ''),
                    'line_range': check.get('file_line_range', []),
                    'check_class': check.get('check_class', '')
                }
                
                findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Checkov findings")
            
            # Get summary statistics
            summary_data = {}
            if isinstance(checkov_results, list) and checkov_results:
                summary_data = checkov_results[0].get('summary', {})
            elif isinstance(checkov_results, dict):
                summary_data = checkov_results.get('summary', {})
            
            # Cap findings to avoid context window overflow when returning inline
            MAX_INLINE_FINDINGS = 100
            truncated = total_issues > MAX_INLINE_FINDINGS
            findings_out = findings[:MAX_INLINE_FINDINGS]
            
            result = {
                'success': True,
                'tool': 'checkov',
                'total_issues': total_issues,
                'findings': findings_out,
                'summary': severity_counts,
                'scan_metadata': {
                    'passed': summary_data.get('passed', 0),
                    'failed': summary_data.get('failed', 0),
                    'skipped': summary_data.get('skipped', 0),
                    'parsing_errors': summary_data.get('parsing_errors', 0)
                }
            }
            if truncated:
                result['truncated'] = True
                result['truncation_note'] = (
                    f"Results capped at {MAX_INLINE_FINDINGS} of {total_issues} findings to prevent context overflow. "
                    "Full results are saved to the output file."
                )
            return result
            
        except Exception as e:
            logger.error(f"Error formatting Checkov results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Checkov results: {str(e)}'
            }

    def _format_checkov_summary(self, checkov_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Checkov results into a lightweight summary (no full check details)."""
        try:
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'info': 0
            }

            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2

            # Process failed checks from all result objects
            failed_checks = []
            if isinstance(checkov_results, list):
                for result_obj in checkov_results:
                    if isinstance(result_obj, dict):
                        failed_checks.extend(result_obj.get('results', {}).get('failed_checks', []))
            elif isinstance(checkov_results, dict):
                failed_checks = checkov_results.get('results', {}).get('failed_checks', [])

            filtered_count = 0
            for check in failed_checks:
                severity_raw = check.get('severity', 'MEDIUM')
                severity = (severity_raw or 'MEDIUM').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 2

                # Count all severities
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1

                # Count filtered issues
                if severity_index <= threshold_index:
                    filtered_count += 1

            total_issues = len(failed_checks)

            logger.info(f"Generated Checkov summary: {filtered_count} issues above {severity_threshold} threshold (total: {total_issues})")

            # Get summary statistics
            summary_data = {}
            if isinstance(checkov_results, list) and checkov_results:
                summary_data = checkov_results[0].get('summary', {})
            elif isinstance(checkov_results, dict):
                summary_data = checkov_results.get('summary', {})

            return {
                'total_issues': total_issues,
                'filtered_issues': filtered_count,
                'severity_threshold': severity_threshold,
                'severity_counts': severity_counts,
                'scan_metadata': {
                    'passed': summary_data.get('passed', 0),
                    'failed': summary_data.get('failed', 0),
                    'skipped': summary_data.get('skipped', 0),
                    'parsing_errors': summary_data.get('parsing_errors', 0)
                }
            }

        except Exception as e:
            logger.error(f"Error formatting Checkov summary: {e}")
            return {
                'error': f'Error formatting Checkov summary: {str(e)}'
            }


    def run_syft_directory_scan(self, directory_path: str, output_format: str = 'json', save_sbom: bool = False) -> Dict[str, Any]:
        """Run Syft scan on a directory to generate SBOM.
        
        Args:
            directory_path: Path to directory to scan
            output_format: Output format (json, cyclonedx-json, spdx-json, table)
            save_sbom: If True, save full SBOM to file. If False, only return summary.
        """
        logger.info(f"Starting Syft directory scan: {directory_path} (save_sbom={save_sbom})")
        
        try:
            # Run Syft with JSON output
            cmd = [
                'syft',
                f'dir:{directory_path}',
                '-o', output_format,
                '--quiet'
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                logger.error(f"Syft command failed with return code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                return {
                    'success': False,
                    'error': f'Syft scan failed: {result.stderr}'
                }
            
            # Parse JSON output for summary (only if JSON format)
            if output_format in ['json', 'cyclonedx-json', 'spdx-json']:
                try:
                    syft_results = json.loads(result.stdout)
                    
                    # If save_sbom is True, save to file
                    if save_sbom:
                        from datetime import datetime
                        from pathlib import Path
                        import os
                        
                        # Create .sbom directory in workspace root
                        workspace_root = os.environ.get('WORKSPACE_ROOT', os.getcwd())
                        sbom_dir = Path(workspace_root) / '.sbom'
                        sbom_dir.mkdir(exist_ok=True)
                        
                        # Generate filename with timestamp
                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                        dir_name = Path(directory_path).name
                        
                        # Determine file extension based on format
                        format_extensions = {
                            'json': 'json',
                            'cyclonedx-json': 'cyclonedx.json',
                            'spdx-json': 'spdx.json',
                            'table': 'txt'
                        }
                        extension = format_extensions.get(output_format, 'json')
                        output_file = sbom_dir / f'sbom_{dir_name}_{timestamp}.{extension}'
                        
                        # Save output to file
                        output_file.write_text(result.stdout)
                        logger.info(f"SBOM saved to: {output_file}")
                        
                        # Return summary with file path
                        summary = self._format_syft_summary(syft_results)
                        return {
                            'success': True,
                            'sbom_file': str(output_file),
                            'output_format': output_format,
                            'scanned_directory': directory_path,
                            **summary
                        }
                    else:
                        # Return only summary, no file saved
                        return self._format_syft_results(syft_results)
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Syft JSON output: {e}")
                    return {
                        'success': False,
                        'error': f'Failed to parse Syft output: {str(e)}'
                    }
            else:
                # For non-JSON formats, just return the raw output
                if save_sbom:
                    from datetime import datetime
                    from pathlib import Path
                    import os
                    
                    workspace_root = os.environ.get('WORKSPACE_ROOT', os.getcwd())
                    sbom_dir = Path(workspace_root) / '.sbom'
                    sbom_dir.mkdir(exist_ok=True)
                    
                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                    dir_name = Path(directory_path).name
                    output_file = sbom_dir / f'sbom_{dir_name}_{timestamp}.txt'
                    
                    output_file.write_text(result.stdout)
                    logger.info(f"SBOM saved to: {output_file}")
                    
                    return {
                        'success': True,
                        'sbom_file': str(output_file),
                        'output_format': output_format,
                        'scanned_directory': directory_path
                    }
                else:
                    return {
                        'success': True,
                        'output': result.stdout[:1000],  # Return first 1000 chars
                        'note': 'Full output not saved. Set save_sbom=True to save to file.'
                    }
            
        except subprocess.TimeoutExpired:
            logger.error("Syft scan timed out")
            return {
                'success': False,
                'error': 'Syft scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Syft scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_syft_results(self, syft_results: Dict) -> Dict[str, Any]:
        """Format Syft results into a consistent structure."""
        try:
            artifacts = syft_results.get('artifacts', [])
            
            # Group packages by type
            packages_by_type = {}
            packages_by_language = {}
            
            for artifact in artifacts:
                pkg_type = artifact.get('type', 'unknown')
                pkg_name = artifact.get('name', 'unknown')
                pkg_version = artifact.get('version', 'unknown')
                pkg_language = artifact.get('language', 'unknown')
                
                # Group by type
                if pkg_type not in packages_by_type:
                    packages_by_type[pkg_type] = []
                packages_by_type[pkg_type].append({
                    'name': pkg_name,
                    'version': pkg_version,
                    'language': pkg_language,
                    'locations': artifact.get('locations', []),
                    'licenses': artifact.get('licenses', []),
                    'purl': artifact.get('purl', ''),
                    'cpes': artifact.get('cpes', [])
                })
                
                # Group by language
                if pkg_language != 'unknown':
                    if pkg_language not in packages_by_language:
                        packages_by_language[pkg_language] = []
                    packages_by_language[pkg_language].append({
                        'name': pkg_name,
                        'version': pkg_version,
                        'type': pkg_type
                    })
            
            # Calculate summary statistics
            total_packages = len(artifacts)
            type_counts = {pkg_type: len(pkgs) for pkg_type, pkgs in packages_by_type.items()}
            language_counts = {lang: len(pkgs) for lang, pkgs in packages_by_language.items()}
            
            logger.info(f"Formatted {total_packages} packages from Syft SBOM")
            
            # Get source metadata
            source = syft_results.get('source', {})
            descriptor = syft_results.get('descriptor', {})
            
            return {
                'success': True,
                'tool': 'syft',
                'total_packages': total_packages,
                'packages_by_type': packages_by_type,
                'packages_by_language': packages_by_language,
                'summary': {
                    'type_counts': type_counts,
                    'language_counts': language_counts
                },
                'syft_version': descriptor.get('version', 'unknown'),
                'scan_metadata': {
                    'source': source,
                    'schema_version': syft_results.get('schema', {}).get('version', 'unknown')
                }
            }
            
        except Exception as e:
            logger.error(f"Error formatting Syft results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Syft results: {str(e)}'
            }

    def _format_syft_summary(self, syft_results: Dict) -> Dict[str, Any]:
        """Format Syft results into a lightweight summary (no full package details)."""
        try:
            artifacts = syft_results.get('artifacts', [])

            # Calculate summary statistics only
            packages_by_type = {}
            packages_by_language = {}

            for artifact in artifacts:
                pkg_type = artifact.get('type', 'unknown')
                pkg_language = artifact.get('language', 'unknown')

                # Count by type
                packages_by_type[pkg_type] = packages_by_type.get(pkg_type, 0) + 1

                # Count by language
                if pkg_language != 'unknown':
                    packages_by_language[pkg_language] = packages_by_language.get(pkg_language, 0) + 1

            total_packages = len(artifacts)
            logger.info(f"Generated summary for {total_packages} packages from Syft SBOM")

            # Get source metadata
            source = syft_results.get('source', {})
            descriptor = syft_results.get('descriptor', {})

            return {
                'tool': 'syft',
                'total_packages': total_packages,
                'type_counts': packages_by_type,
                'language_counts': packages_by_language,
                'syft_version': descriptor.get('version', 'unknown'),
                'schema_version': syft_results.get('schema', {}).get('version', 'unknown')
            }

        except Exception as e:
            logger.error(f"Error formatting Syft summary: {e}")
            return {
                'error': f'Error formatting Syft summary: {str(e)}'
            }


    def run_grype_directory_scan(self, directory_path: str, severity_threshold: str = 'MEDIUM', return_output: bool = False) -> Dict[str, Any]:
        """Run Grype scan on a directory and save output to file by default."""
        logger.info(f"Starting Grype directory scan: {directory_path}")
        
        try:
            # Run Grype with JSON output
            cmd = [
                'grype',
                f'dir:{directory_path}',
                '-o', 'json',
                '--quiet'
            ]
            
            logger.info(f"Running command: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode not in [0, 1]:  # Grype returns 1 when vulnerabilities are found
                logger.error(f"Grype command failed with return code {result.returncode}")
                logger.error(f"stderr: {result.stderr}")
                return {
                    'success': False,
                    'error': f'Grype scan failed: {result.stderr}'
                }
            
            # Parse JSON output
            try:
                grype_results = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse Grype JSON output: {e}")
                return {
                    'success': False,
                    'error': f'Failed to parse Grype output: {str(e)}'
                }
            
            # If user explicitly requests output, return full results
            if return_output:
                return self._format_grype_results(grype_results, severity_threshold)
            
            # Otherwise, save to file and return summary
            file_info = self._save_scan_output('grype', directory_path, result.stdout, 'json')
            summary = self._format_grype_summary(grype_results, severity_threshold)
            
            return {
                'success': True,
                'tool': 'grype',
                **file_info,
                **summary
            }
            
        except subprocess.TimeoutExpired:
            logger.error("Grype scan timed out")
            return {
                'success': False,
                'error': 'Grype scan timed out after 5 minutes'
            }
        except Exception as e:
            logger.error(f"Error running Grype scan: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _format_grype_results(self, grype_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Grype results into a consistent structure."""
        try:
            findings = []
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'negligible': 0,
                'unknown': 0
            }
            
            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2
            
            # Process matches
            matches = grype_results.get('matches', [])
            
            for match in matches:
                vulnerability = match.get('vulnerability', {})
                artifact = match.get('artifact', {})
                
                # Get severity
                severity = vulnerability.get('severity', 'UNKNOWN').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 5
                
                # Filter by threshold
                if severity_index > threshold_index:
                    continue
                
                # Count by severity
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1
                
                # Extract vulnerability details
                vuln_id = vulnerability.get('id', 'Unknown')
                description = vulnerability.get('description', 'No description available')
                fixed_in = vulnerability.get('fix', {}).get('versions', [])
                
                # Extract package details
                package_name = artifact.get('name', 'Unknown')
                package_version = artifact.get('version', 'Unknown')
                package_type = artifact.get('type', 'Unknown')
                
                # Extract location
                locations = artifact.get('locations', [])
                location_path = locations[0].get('path', 'Unknown') if locations else 'Unknown'
                
                finding = {
                    'vulnerability_id': vuln_id,
                    'severity': severity,
                    'package': {
                        'name': package_name,
                        'version': package_version,
                        'type': package_type
                    },
                    'description': description,
                    'fixed_in': fixed_in,
                    'location': location_path,
                    'urls': vulnerability.get('urls', [])
                }
                
                findings.append(finding)
            
            total_issues = len(findings)
            
            logger.info(f"Formatted {total_issues} Grype findings")
            
            return {
                'success': True,
                'tool': 'grype',
                'total_issues': total_issues,
                'findings': findings,
                'summary': severity_counts,
                'grype_version': grype_results.get('descriptor', {}).get('version', 'unknown'),
                'scan_metadata': {
                    'source': grype_results.get('source', {}),
                    'distro': grype_results.get('distro', {})
                }
            }
            
        except Exception as e:
            logger.error(f"Error formatting Grype results: {e}")
            import traceback
            traceback.print_exc()
            return {
                'success': False,
                'error': f'Error formatting Grype results: {str(e)}'
            }

    def _format_grype_summary(self, grype_results: Dict, severity_threshold: str) -> Dict[str, Any]:
        """Format Grype results into a lightweight summary (no full vulnerability details)."""
        try:
            severity_counts = {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'negligible': 0,
                'unknown': 0
            }

            # Define severity order for filtering
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'NEGLIGIBLE', 'UNKNOWN']
            threshold_index = severity_order.index(severity_threshold.upper()) if severity_threshold.upper() in severity_order else 2

            # Process matches
            matches = grype_results.get('matches', [])
            filtered_count = 0

            for match in matches:
                vulnerability = match.get('vulnerability', {})
                severity = vulnerability.get('severity', 'UNKNOWN').upper()
                severity_index = severity_order.index(severity) if severity in severity_order else 5

                # Count all severities
                severity_key = severity.lower()
                if severity_key in severity_counts:
                    severity_counts[severity_key] += 1

                # Count filtered issues
                if severity_index <= threshold_index:
                    filtered_count += 1

            total_vulnerabilities = len(matches)

            logger.info(f"Generated Grype summary: {filtered_count} issues above {severity_threshold} threshold (total: {total_vulnerabilities})")

            return {
                'total_vulnerabilities': total_vulnerabilities,
                'filtered_issues': filtered_count,
                'severity_threshold': severity_threshold,
                'severity_counts': severity_counts,
                'grype_version': grype_results.get('descriptor', {}).get('version', 'unknown')
            }

        except Exception as e:
            logger.error(f"Error formatting Grype summary: {e}")
            return {
                'error': f'Error formatting Grype summary: {str(e)}'
            }


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
            },
            "ash": {
                "description": "Automated Security Helper - comprehensive multi-tool scanner",
                "supported_formats": "all of the above plus additional scanners",
                "additional_scanners": [
                    "cfn-nag (CloudFormation)",
                    "cdk-nag (AWS CDK)",
                    "detect-secrets (Secret detection)",
                    "grype (Vulnerability scanning)",
                    "syft (SBOM generation)",
                    "npm-audit (Node.js dependencies)"
                ],
                "installation_check": scanner.check_ash_installation()
            }
        }
    }

@mcp.tool()
@handle_exceptions
async def scan_with_ash(
    code: str = Field(description='Code content to scan'),
    file_extension: str = Field(description='File extension (e.g., .py, .tf, .js, Dockerfile)'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
) -> Dict:
    """Scan code using ASH (Automated Security Helper) for comprehensive security analysis.
    
    ASH is a comprehensive security scanning tool that runs multiple security scanners
    including Bandit, Checkov, cfn-nag, cdk-nag, detect-secrets, and more.
    
    Note: Semgrep is excluded from ASH scans because there's a separate scan_with_semgrep tool.
    
    This tool performs delta scanning on the provided code snippet, creating a temporary
    file and scanning it with ASH in local mode. This approach is optimized for scanning
    code changes rather than entire projects.
    
    Supported file types:
    - Python (.py): Scanned with Bandit, detect-secrets
    - JavaScript/TypeScript (.js, .ts): Scanned with npm-audit
    - Terraform (.tf): Scanned with Checkov
    - CloudFormation (.yaml, .yml, .json): Scanned with Checkov, cfn-nag, cdk-nag
    - Dockerfile: Scanned with Checkov
    - And many more formats supported by the underlying scanners
    
    For Semgrep scanning, use the separate scan_with_semgrep tool.
    
    Args:
        code: The code content to analyze
        file_extension: File extension to determine scanner selection (e.g., '.py', '.tf', 'Dockerfile')
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with aggregated scan results from multiple scanners
        
    Note:
        ASH must be installed and available in PATH. Install with:
        uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.1
        or: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1
    """
    try:
        logger.info(f"Starting ASH scan for file extension: {file_extension}")
        logger.info(f"Code length: {len(code)} characters")
        logger.info(f"Severity threshold: {severity_threshold}")
        
        result = scanner.run_ash_scan(code, file_extension, severity_threshold)
        
        if result.get('success'):
            logger.info(f"ASH scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"ASH scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_with_ash: {e}")
        return {
            "success": False,
            "tool": "ash",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def scan_with_trivy(
    code: str = Field(description='Code content to scan (Dockerfile or IaC config)'),
    scan_type: str = Field(default='dockerfile', description='Type of scan: dockerfile, terraform, kubernetes, or config'),
) -> Dict:
    """Scan Infrastructure as Code or Dockerfile using Trivy for security issues.
    
    Trivy is a comprehensive security scanner that can detect:
    - Misconfigurations in IaC files
    - Security issues in Dockerfiles
    - Vulnerabilities in base images (when scanning Dockerfiles)
    - Best practice violations
    
    Supported scan types:
    - dockerfile: Scan Dockerfile for security issues and misconfigurations
    - terraform: Scan Terraform configuration files
    - kubernetes: Scan Kubernetes manifests
    - config: Generic configuration file scanning
    
    Args:
        code: The code content to analyze
        scan_type: Type of scan to perform (dockerfile, terraform, kubernetes, config)
        
    Returns:
        A dictionary with scan results including found security issues
        
    Note:
        Trivy must be installed and available in PATH. Install with:
        - macOS: brew install trivy
        - Linux: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/
    """
    try:
        logger.info(f"Starting Trivy scan for type: {scan_type}")
        logger.info(f"Code length: {len(code)} characters")
        
        # Check if Trivy is available
        trivy_check = scanner.check_trivy_installation()
        if not trivy_check['available']:
            return {
                'success': False,
                'error': f"Trivy is not available: {trivy_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'macos': 'brew install trivy',
                    'linux': 'See https://aquasecurity.github.io/trivy/latest/getting-started/installation/',
                    'windows': 'See https://aquasecurity.github.io/trivy/latest/getting-started/installation/'
                }
            }
        
        result = scanner.run_trivy_scan(code, scan_type)
        
        if result.get('success'):
            logger.info(f"Trivy scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"Trivy scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_with_trivy: {e}")
        return {
            "success": False,
            "tool": "trivy",
            "scan_type": scan_type,
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def scan_image_with_trivy(
    image_name: str = Field(description='Container image name to scan (e.g., nginx:latest, ghcr.io/owner/image:tag)'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan a container image using Trivy for vulnerabilities.
    
    This tool scans container images for known vulnerabilities in:
    - OS packages (Alpine, Debian, Ubuntu, RHEL, etc.)
    - Application dependencies (Python, Node.js, Java, Go, etc.)
    - Base image vulnerabilities
    
    The output is minimized to show only essential information:
    - Vulnerability ID and severity
    - Affected package and versions
    - Fixed version (if available)
    - Primary reference URL
    
    This is particularly useful for:
    - Scanning base images used in Dockerfiles
    - Checking for vulnerabilities before deployment
    - Security audits of container images
    
    Args:
        image_name: Container image to scan (e.g., nginx:latest, python:3.9, ghcr.io/owner/image:tag)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with vulnerability findings from Trivy (minimized output)
        
    Note:
        Trivy must be installed and available in PATH. Install with:
        - macOS: brew install trivy
        - Linux: See https://aquasecurity.github.io/trivy/latest/getting-started/installation/
        
        The image will be pulled if not available locally.
    """
    try:
        logger.info(f"Starting Trivy image scan: {image_name}")
        
        # Check if Trivy is available
        trivy_check = scanner.check_trivy_installation()
        if not trivy_check['available']:
            return {
                'success': False,
                'error': f"Trivy is not available: {trivy_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'macos': 'brew install trivy',
                    'linux': 'See https://aquasecurity.github.io/trivy/latest/getting-started/installation/',
                    'windows': 'See https://aquasecurity.github.io/trivy/latest/getting-started/installation/'
                }
            }
        
        result = scanner.run_trivy_image_scan(image_name, severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"Trivy image scan completed. Found {result.get('total_issues', 0)} vulnerabilities")
        else:
            logger.error(f"Trivy image scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_image_with_trivy: {e}")
        return {
            "success": False,
            "tool": "trivy",
            "scan_type": "image",
            "image": image_name,
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }

@mcp.tool()
@handle_exceptions
async def scan_directory_with_grype(
    directory_path: str = Field(description='Path to the directory to scan'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan an entire project directory with Grype for dependency vulnerabilities.
    
    This tool scans all dependency files in a directory (Cargo.lock, package.json, 
    requirements.txt, etc.) and reports known vulnerabilities across all ecosystems.
    
    Unlike scan_with_ash which scans code snippets, this tool scans the actual
    project directory to find vulnerabilities in all dependencies.
    
    Supported ecosystems:
    - Rust (Cargo.lock)
    - Python (requirements.txt, setup.py, Pipfile.lock)
    - Node.js (package.json, package-lock.json, yarn.lock)
    - Java (pom.xml, build.gradle)
    - Go (go.mod)
    - Ruby (Gemfile.lock)
    - And many more
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with vulnerability findings from Grype
        
    Note:
        Grype must be installed and available in PATH. Install with:
        - macOS: brew install grype
        - Linux: curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh
    """
    try:
        logger.info(f"Starting Grype directory scan: {directory_path}")
        
        # Check if Grype is available
        grype_check = scanner.check_grype_installation()
        if not grype_check['available']:
            return {
                'success': False,
                'error': f"Grype is not available: {grype_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'macos': 'brew install grype',
                    'linux': 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh',
                    'windows': 'Download from https://github.com/anchore/grype/releases'
                }
            }
        
        # Resolve directory path
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run Grype scan
        result = scanner.run_grype_directory_scan(str(dir_path), severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"Grype scan completed. Found {result.get('total_issues', 0)} vulnerabilities")
        else:
            logger.error(f"Grype scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_grype: {e}")
        return {
            "success": False,
            "tool": "grype",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }


@mcp.tool()
@handle_exceptions
async def scan_directory_with_checkov(
    directory_path: str = Field(description='Path to the directory to scan'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan an entire project directory with Checkov for IaC security issues.
    
    This tool scans all Infrastructure as Code files in a directory for security
    misconfigurations and compliance violations using Checkov.
    
    Unlike scan_with_checkov which scans code snippets, this tool scans the actual
    project directory to find issues across all IaC files.
    
    Supported file types:
    - Terraform (.tf, .tfvars)
    - CloudFormation (.yaml, .yml, .json)
    - Kubernetes (.yaml, .yml)
    - Dockerfile
    - ARM templates (.json)
    - Bicep (.bicep)
    - Serverless framework (.yml, .yaml)
    - Helm charts (.yaml, .yml)
    - GitHub Actions (.yml, .yaml)
    - GitLab CI (.yml, .yaml)
    - Ansible (.yml, .yaml)
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with security findings from Checkov
        
    Note:
        Checkov must be installed and available in PATH. Install with:
        - pip: pip install checkov
        - pipx: pipx install checkov
    """
    try:
        logger.info(f"Starting Checkov directory scan: {directory_path}")
        
        # Check if Checkov is available
        checkov_check = scanner.check_checkov_installation()
        if not checkov_check['available']:
            return {
                'success': False,
                'error': f"Checkov is not available: {checkov_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'pip': 'pip install checkov',
                    'pipx': 'pipx install checkov',
                    'homebrew': 'brew install checkov'
                }
            }
        
        # Resolve directory path
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run Checkov scan
        result = scanner.run_checkov_directory_scan(str(dir_path), severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"Checkov scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"Checkov scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_checkov: {e}")
        return {
            "success": False,
            "tool": "checkov",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }


@mcp.tool()
@handle_exceptions
async def scan_directory_with_bandit(
    directory_path: str = Field(description='Path to the directory to scan'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan an entire project directory with Bandit for Python security issues.
    
    This tool scans all Python files in a directory for security issues using Bandit.
    
    Unlike scan_with_bandit which scans code snippets, this tool scans the actual
    project directory to find issues across all Python files.
    
    Bandit can detect issues like:
    - Use of insecure functions (pickle, eval, exec)
    - Hardcoded passwords and secrets
    - SQL injection vulnerabilities
    - Command injection risks
    - Weak cryptographic practices
    - Insecure random number generation
    - And many other Python-specific security issues
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH)
        
    Returns:
        A dictionary with security findings from Bandit
        
    Note:
        Bandit must be installed and available in PATH. Install with:
        - pip: pip install bandit
        - pipx: pipx install bandit
    """
    try:
        logger.info(f"Starting Bandit directory scan: {directory_path}")
        
        # Check if Bandit is available
        bandit_check = scanner.check_bandit_installation()
        if not bandit_check['available']:
            return {
                'success': False,
                'error': f"Bandit is not available: {bandit_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'pip': 'pip install bandit',
                    'pipx': 'pipx install bandit'
                }
            }
        
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run Bandit scan
        result = scanner.run_bandit_directory_scan(str(dir_path), severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"Bandit scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"Bandit scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_bandit: {e}")
        return {
            "success": False,
            "tool": "bandit",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }


@mcp.tool()
@handle_exceptions
async def scan_directory_with_semgrep(
    directory_path: str = Field(description='Path to the directory to scan'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan an entire project directory with Semgrep for security issues.
    
    This tool scans all supported source code files in a directory for security
    vulnerabilities using Semgrep with security-focused rulesets.
    
    Unlike scan_with_semgrep which scans code snippets, this tool scans the actual
    project directory to find issues across all supported files.
    
    Supported languages:
    - Python, JavaScript, TypeScript, Java, Go, C/C++
    - C#, Ruby, PHP, Scala, Kotlin, Rust
    - And many more
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with security findings from Semgrep
        
    Note:
        Semgrep must be installed and available in PATH. Install with:
        - pip: pip install semgrep
        - pipx: pipx install semgrep
        - homebrew: brew install semgrep
    """
    try:
        logger.info(f"Starting Semgrep directory scan: {directory_path}")
        
        # Check if Semgrep is available
        semgrep_check = scanner.check_semgrep_installation()
        if not semgrep_check['available']:
            return {
                'success': False,
                'error': f"Semgrep is not available: {semgrep_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'pip': 'pip install semgrep',
                    'pipx': 'pipx install semgrep',
                    'homebrew': 'brew install semgrep'
                }
            }
        
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run Semgrep scan
        result = scanner.run_semgrep_directory_scan(str(dir_path), severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"Semgrep scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"Semgrep scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_semgrep: {e}")
        return {
            "success": False,
            "tool": "semgrep",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }


@mcp.tool()
@handle_exceptions
async def scan_directory_with_ash(
    directory_path: str = Field(description='Path to the directory to scan'),
    severity_threshold: str = Field(default='MEDIUM', description='Minimum severity threshold (LOW, MEDIUM, HIGH, CRITICAL)'),
    return_output: bool = Field(default=False, description='Return full output instead of saving to file (default: False)'),
) -> Dict:
    """Scan an entire project directory with ASH for comprehensive security analysis.
    
    This tool scans all files in a directory using ASH (Automated Security Helper),
    which runs multiple security scanners including Bandit, Checkov, cfn-nag, cdk-nag,
    detect-secrets, grype, and more.
    
    Unlike scan_with_ash which scans code snippets, this tool scans the actual
    project directory for comprehensive security analysis.
    
    Note: Semgrep is excluded from ASH scans. Use scan_directory_with_semgrep instead.
    
    Supported file types:
    - Python (.py): Scanned with Bandit, detect-secrets
    - JavaScript/TypeScript (.js, .ts): Scanned with npm-audit
    - Terraform (.tf): Scanned with Checkov
    - CloudFormation (.yaml, .yml, .json): Scanned with Checkov, cfn-nag, cdk-nag
    - Dockerfile: Scanned with Checkov
    - And many more formats supported by the underlying scanners
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        severity_threshold: Minimum severity level to report (LOW, MEDIUM, HIGH, CRITICAL)
        
    Returns:
        A dictionary with aggregated scan results from multiple scanners
        
    Note:
        ASH must be installed and available. Install with:
        - uvx: uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.1
        - pip: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1
    """
    try:
        logger.info(f"Starting ASH directory scan: {directory_path}")
        
        # Check if ASH is available
        ash_check = scanner.check_ash_installation()
        if not ash_check['available']:
            return {
                'success': False,
                'error': f"ASH is not available: {ash_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'uvx': 'uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.1',
                    'pip': 'pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1',
                    'pipx': 'pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1'
                }
            }
        
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run ASH scan
        result = scanner.run_ash_directory_scan(str(dir_path), severity_threshold, return_output)
        
        if result.get('success'):
            logger.info(f"ASH scan completed. Found {result.get('total_issues', 0)} issues")
        else:
            logger.error(f"ASH scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_ash: {e}")
        return {
            "success": False,
            "tool": "ash",
            "error": str(e),
            "total_issues": 0,
            "findings": []
        }


@mcp.tool()
@handle_exceptions
async def scan_directory_with_syft(
    directory_path: str = Field(description='Path to the directory to scan'),
    output_format: str = Field(default='json', description='Output format (json, cyclonedx-json, spdx-json, table)'),
    save_sbom: bool = Field(default=False, description='Save full SBOM to file (default: False, only returns summary)'),
) -> Dict:
    """Scan an entire project directory with Syft to generate Software Bill of Materials (SBOM).
    
    This tool catalogs all software components and dependencies in a directory using Syft.
    Unlike vulnerability scanners, Syft creates an inventory (SBOM) of what's in your software.
    
    Syft catalogs:
    - Container images (Docker, OCI)
    - Filesystems and directories
    - Archive files (tar, zip)
    - Language-specific packages:
      - Python (pip, poetry, pipenv)
      - JavaScript/Node (npm, yarn, pnpm)
      - Java (Maven, Gradle)
      - Go modules
      - Ruby gems
      - Rust crates
      - PHP composer
      - .NET/C#
      - And many more
    
    By default, only a summary is returned. Set save_sbom=True to save the full SBOM to a file
    in the .sbom directory at the workspace root.
    
    The SBOM file can be used with Grype for vulnerability scanning or for compliance/auditing purposes.
    
    Args:
        directory_path: Path to the directory to scan (relative or absolute)
        output_format: Output format - json (default), cyclonedx-json, spdx-json, or table
        save_sbom: Save full SBOM to file (default: False, only returns summary)
        
    Returns:
        A dictionary with:
        - total_packages: Total number of packages found
        - type_counts: Package counts by type
        - language_counts: Package counts by language
        - timestamp: Scan timestamp
        
    Note:
        Syft must be installed and available in PATH. Install with:
        - macOS: brew install syft
        - Linux: curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh
    """
    try:
        logger.info(f"Starting Syft directory scan: {directory_path}")
        
        # Check if Syft is available
        syft_check = scanner.check_syft_installation()
        if not syft_check['available']:
            return {
                'success': False,
                'error': f"Syft is not available: {syft_check.get('error', 'Unknown error')}",
                'installation_instructions': {
                    'macos': 'brew install syft',
                    'linux': 'curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh',
                    'windows': 'Download from https://github.com/anchore/syft/releases'
                }
            }
        
        # Resolve directory path — never falls back to CWD (unreliable when launched via uvx)
        try:
            dir_path = resolve_directory_path(directory_path)
        except ValueError as e:
            return {'success': False, 'error': str(e), 'total_issues': 0, 'findings': []}
        
        if not dir_path.exists():
            return {
                'success': False,
                'error': f'Directory not found: {directory_path} (resolved to: {dir_path}). '
                         'Please provide an absolute path or set WORKSPACE_ROOT in the MCP server env config.',
                'total_issues': 0,
                'findings': []
            }
        
        if not dir_path.is_dir():
            return {
                'success': False,
                'error': f'Path is not a directory: {directory_path} (resolved to: {dir_path})'
            }
        
        logger.info(f"Scanning directory: {dir_path}")
        
        # Run Syft scan
        result = scanner.run_syft_directory_scan(str(dir_path), output_format, save_sbom)
        
        if result.get('success'):
            logger.info(f"Syft scan completed. Found {result.get('total_packages', 0)} packages")
        else:
            logger.error(f"Syft scan failed: {result.get('error', 'Unknown error')}")
        
        return result
        
    except Exception as e:
        logger.error(f"Error in scan_directory_with_syft: {e}")
        return {
            "success": False,
            "tool": "syft",
            "error": str(e),
            "total_packages": 0,
            "packages_by_type": {},
            "packages_by_language": {}
        }


@mcp.tool()
@handle_exceptions
async def check_ash_availability() -> Dict:
    """Check if ASH (Automated Security Helper) is installed and available.
    
    This tool verifies that ASH is properly installed and can be executed.
    It also checks which individual scanners are available, as some require
    external dependencies (e.g., cfn-nag requires Ruby, cdk-nag requires npm).
    
    Use this before attempting to scan with ASH to ensure it's available and
    to understand which scanners will be used.
    
    Returns:
        A dictionary with:
        - ASH installation status and version
        - Scanner availability (which tools are installed)
        - Formatted report for easy reading
        - Installation instructions for missing dependencies
    """
    try:
        result = scanner.check_ash_installation()
        
        if result['available']:
            response = {
                "success": True,
                "available": True,
                "version": result.get('version', 'unknown'),
                "message": f"ASH is installed and available: {result.get('version', 'unknown')}"
            }
            
            # Add scanner availability information
            if 'scanners' in result:
                response['scanners'] = result['scanners']
                
                # Count available vs unavailable scanners
                available_count = sum(1 for s in result['scanners'].values() if s['available'])
                total_count = len(result['scanners'])
                response['scanner_summary'] = {
                    'available': available_count,
                    'total': total_count,
                    'unavailable': total_count - available_count
                }
                
                # Create formatted report
                report_lines = []
                report_lines.append(f"ASH Status: ✅ Installed (version {result.get('version', 'unknown')})")
                report_lines.append(f"Scanner Availability: {available_count} out of {total_count} scanners available")
                report_lines.append("")
                
                # Available scanners
                available_scanners = [(name, info) for name, info in result['scanners'].items() if info['available']]
                if available_scanners:
                    report_lines.append("✅ Available Scanners:")
                    for name, info in available_scanners:
                        report_lines.append(f"  • {info['name']} - {info['description']} ({info['dependency_type']}-based)")
                    report_lines.append("")
                
                # Missing scanners (including Semgrep with special note)
                missing_scanners = [(name, info) for name, info in result['scanners'].items() if not info['available']]
                if missing_scanners:
                    report_lines.append("❌ Not Available via ASH:")
                    for name, info in missing_scanners:
                        report_lines.append(f"  • {info['name']} - {info['description']} ({info['dependency_type']}-based)")
                        if 'note' in info:
                            report_lines.append(f"    Note: {info['note']}")
                        elif 'install_hint' in info:
                            report_lines.append(f"    Install with: {info['install_hint']}")
                    report_lines.append("")
                
                report_lines.append("The tool successfully shows which scanners are available and which ones need additional OS-level dependencies.")
                
                response['formatted_report'] = "\n".join(report_lines)
            
            return response
        else:
            return {
                "success": True,
                "available": False,
                "error": result.get('error', 'Unknown error'),
                "message": "ASH is not available",
                "formatted_report": f"❌ ASH is not available\n\nError: {result.get('error', 'Unknown error')}\n\nInstallation instructions:\n  • uvx: uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.1\n  • pip: pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1\n  • pipx: pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1",
                "installation_instructions": {
                    "uvx": "uvx git+https://github.com/awslabs/automated-security-helper.git@v3.2.1",
                    "pip": "pip install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1",
                    "pipx": "pipx install git+https://github.com/awslabs/automated-security-helper.git@v3.2.1"
                }
            }
    except Exception as e:
        logger.error(f"Error checking ASH availability: {e}")
        return {
            "success": False,
            "available": False,
            "error": str(e),
            "formatted_report": f"❌ Error checking ASH availability\n\nError: {str(e)}"
        }

# Register report generation tool
register_report_tool(mcp, handle_exceptions)


def main():
    """Run the MCP server with CLI argument support."""
    logger.info('Starting Security Scanner MCP Server.')
    mcp.run()

if __name__ == '__main__':
    main()