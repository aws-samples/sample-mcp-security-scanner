#!/usr/bin/env python3
"""Simple test for security scanning functionality without MCP dependencies."""

import json
import tempfile
import os
import subprocess

def test_checkov_basic():
    """Test basic Checkov functionality."""
    print("🛡️  Testing Checkov...")
    
    terraform_code = '''
resource "aws_s3_bucket" "test" {
    bucket = "test-bucket"
    acl    = "public-read"
}
'''
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, 'test.tf')
            with open(file_path, 'w') as f:
                f.write(terraform_code)
            
            cmd = f"checkov -f {file_path} --output json --quiet"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                try:
                    json_result = json.loads(result.stdout)
                    failed_checks = json_result.get('results', {}).get('failed_checks', [])
                    print(f"✅ Checkov found {len(failed_checks)} issues")
                    return True
                except json.JSONDecodeError:
                    print(f"❌ Failed to parse Checkov output")
                    return False
            else:
                print(f"❌ No Checkov output")
                return False
    except Exception as e:
        print(f"❌ Checkov test failed: {e}")
        return False

def test_semgrep_basic():
    """Test basic Semgrep functionality."""
    print("\n🔍 Testing Semgrep...")
    
    python_code = '''
import pickle

def unsafe_function(data):
    return pickle.loads(data)
'''
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, 'test.py')
            with open(file_path, 'w') as f:
                f.write(python_code)
            
            cmd = f"semgrep --config=auto --json --quiet {file_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                try:
                    json_result = json.loads(result.stdout)
                    findings = json_result.get('results', [])
                    print(f"✅ Semgrep found {len(findings)} issues")
                    return True
                except json.JSONDecodeError:
                    print(f"❌ Failed to parse Semgrep output")
                    return False
            else:
                print(f"❌ No Semgrep output")
                return False
    except Exception as e:
        print(f"❌ Semgrep test failed: {e}")
        return False

def test_bandit_basic():
    """Test basic Bandit functionality."""
    print("\n🐍 Testing Bandit...")
    
    python_code = '''
import pickle
PASSWORD = "hardcoded_password"

def unsafe_function(data):
    return pickle.loads(data)
'''
    
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            file_path = os.path.join(temp_dir, 'test.py')
            with open(file_path, 'w') as f:
                f.write(python_code)
            
            cmd = f"bandit -f json {file_path}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            if result.stdout:
                try:
                    json_result = json.loads(result.stdout)
                    findings = json_result.get('results', [])
                    print(f"✅ Bandit found {len(findings)} issues")
                    return True
                except json.JSONDecodeError:
                    print(f"❌ Failed to parse Bandit output")
                    return False
            else:
                print(f"❌ No Bandit output")
                return False
    except Exception as e:
        print(f"❌ Bandit test failed: {e}")
        return False

def main():
    """Run all basic tests."""
    print("🚀 Testing Security Scanner Tools\n")
    
    checkov_ok = test_checkov_basic()
    semgrep_ok = test_semgrep_basic()
    bandit_ok = test_bandit_basic()
    
    print(f"\n📊 Test Results:")
    print(f"  Checkov: {'✅ PASS' if checkov_ok else '❌ FAIL'}")
    print(f"  Semgrep: {'✅ PASS' if semgrep_ok else '❌ FAIL'}")
    print(f"  Bandit:  {'✅ PASS' if bandit_ok else '❌ FAIL'}")
    
    if all([checkov_ok, semgrep_ok, bandit_ok]):
        print("\n🎉 All security tools are working correctly!")
        print("🔧 The MCP server should work properly.")
    else:
        print("\n⚠️  Some tools failed. Check your installation.")

if __name__ == '__main__':
    main()