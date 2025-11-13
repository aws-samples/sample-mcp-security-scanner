#!/usr/bin/env python3
"""Setup script for Security Scanner MCP Server."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="security_scanner_mcp_server",
    version="0.1.0",
    author="Security Scanner MCP",
    description="A Model Context Protocol server for security scanning with Checkov, Semgrep, and Bandit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
    ],
    python_requires=">=3.10, <=3.13",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "security_scanner_mcp_server=security_scanner_mcp_server.server:main",
        ],
    },
)