#!/usr/bin/env python3
"""Test script for the Security Scanner MCP Server."""

import asyncio
import sys
import os

# Add the project root to path so the package can be imported properly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from security_scanner_mcp_server.server import scanner

async def test_checkov():
    """Test Checkov scanning with Terraform code."""
    print("🛡️  Testing Checkov with Terraform code...")
    
    terraform_code = '''
resource "aws_s3_bucket" "insecure_bucket" {
    bucket = "my-insecure-bucket"
    acl    = "public-read"
}

resource "aws_security_group" "wide_open" {
    name        = "allow_all"
    description = "Allow all inbound traffic"
    
    ingress {
        from_port   = 0
        to_port     = 0
        protocol    = "-1"
        cidr_blocks = ["0.0.0.0/0"]
    }
}
    '''
    
    try:
        findings = scanner.run_checkov_scan(terraform_code, 'terraform')
        print(f"✅ Checkov found {len(findings)} issues")
        for finding in findings[:3]:  # Show first 3
            print(f"  - {finding['check_id']}: {finding['check_name']}")
            print(f"    Severity: {finding['severity']}")
    except Exception as e:
        print(f"❌ Checkov test failed: {e}")

async def test_semgrep():
    """Test Semgrep scanning with Python code."""
    print("\n🔍 Testing Semgrep with Python code...")
    
    python_code = '''
import pickle
import subprocess
import yaml
import hashlib

def unsafe_pickle(data):
    return pickle.loads(data)

def run_command(cmd):
    return subprocess.call(cmd, shell=True)

SECRET_KEY = "hardcoded_secret_key_123"

def weak_hash(password):
    return hashlib.md5(password.encode()).hexdigest()
    '''
    
    try:
        findings = scanner.run_semgrep_scan(python_code, 'python')
        print(f"✅ Semgrep found {len(findings)} issues")
        for finding in findings[:3]:  # Show first 3
            print(f"  - {finding['rule_id']}: {finding['message']}")
            print(f"    Severity: {finding['severity']}, Line: {finding['line']}")
    except Exception as e:
        print(f"❌ Semgrep test failed: {e}")

async def test_bandit():
    """Test Bandit scanning with Python code."""
    print("\n🐍 Testing Bandit with Python code...")
    
    python_code = '''
import pickle
import yaml
import subprocess
from flask import Flask, request
import hashlib

app = Flask(__name__)

@app.route('/unsafe_pickle', methods=['POST'])
def unsafe_pickle_usage():
    data = request.get_data()
    return pickle.loads(data)

@app.route('/command_injection', methods=['GET'])
def command_injection():
    command = request.args.get('cmd')
    return subprocess.Popen(command, shell=True)

def weak_crypto():
    password = "secret_password"
    return hashlib.md5(password.encode()).hexdigest()

PASSWORD = "super_secret_password123"
    '''
    
    try:
        findings = scanner.run_bandit_scan(python_code)
        print(f"✅ Bandit found {len(findings)} issues")
        for finding in findings[:3]:  # Show first 3
            print(f"  - {finding['test_id']}: {finding['test_name']}")
            print(f"    Severity: {finding['severity']}, Line: {finding['line_number']}")
    except Exception as e:
        print(f"❌ Bandit test failed: {e}")

async def test_dockerfile():
    """Test Checkov with Dockerfile."""
    print("\n🐳 Testing Checkov with Dockerfile...")
    
    dockerfile_code = '''
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python
COPY . /app
RUN chmod 777 /app
USER root
EXPOSE 22
    '''
    
    try:
        findings = scanner.run_checkov_scan(dockerfile_code, 'dockerfile')
        print(f"✅ Checkov found {len(findings)} Dockerfile issues")
        for finding in findings[:3]:  # Show first 3
            print(f"  - {finding['check_id']}: {finding['check_name']}")
            print(f"    Severity: {finding['severity']}")
    except Exception as e:
        print(f"❌ Dockerfile test failed: {e}")

async def main():
    """Run all tests."""
    print("🚀 Starting Security Scanner MCP Server Tests\n")
    
    await test_checkov()
    await test_semgrep() 
    await test_bandit()
    await test_dockerfile()
    
    print("\n✨ All tests completed!")
    print("\n📋 Summary:")
    print("- Checkov: Infrastructure as Code security scanning")
    print("- Semgrep: Multi-language source code security analysis") 
    print("- Bandit: Python-specific security issue detection")
    print("\n🔧 The MCP server is ready to use with AI assistants!")

if __name__ == '__main__':
    asyncio.run(main())