---
inclusion: auto
---

# Secure Coding Practices

When generating or reviewing code, apply these security principles proactively.

## Application Security

- Validate and sanitize all external inputs at trust boundaries
- Use parameterized queries — never string concatenation for SQL/NoSQL
- Never hardcode secrets, passwords, API keys, or tokens in source code
- Use cryptographically secure random generators (`secrets` module in Python, `crypto.randomBytes` in Node.js)
- Use strong hashing: bcrypt, argon2, or scrypt for passwords; SHA-256+ for integrity checks. Never MD5 or SHA-1 for security purposes
- Avoid dangerous functions: `eval()`, `exec()`, `pickle.loads()`, `yaml.load()` without SafeLoader, `innerHTML`
- Use subprocess with explicit argument lists and `shell=False`
- Implement proper error handling without leaking stack traces or internal details

## Infrastructure Security

- Storage: encryption at rest enabled, public access blocked, versioning on
- Network: least-privilege security groups, no 0.0.0.0/0 ingress unless justified and documented
- Access control: least-privilege policies, no wildcard (*) actions or resources
- Databases: encryption at rest and in transit, automated backups, no public accessibility
- Containers: run as non-root, read-only root filesystem, drop all capabilities, add only what's needed
- Secrets: use a secrets management service, rotate automatically, never store in environment variables in IaC

## Dependency Security

- Flag known vulnerable dependencies when detected
- Recommend pinned versions over ranges
- Suggest alternatives for deprecated or unmaintained packages
- Use `scan_directory_with_grype` to check dependency manifests

## When Fixing Issues

- Explain the vulnerability (include CWE ID when applicable) and why the fix works
- If asked to do something insecure, explain the risk and offer a secure alternative
- Reference OWASP Top 10 and CWE when relevant
