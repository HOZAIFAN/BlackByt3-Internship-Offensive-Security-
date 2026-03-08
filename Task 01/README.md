# Penetration Test Report
### testphp.vulnweb.com &nbsp;·&nbsp; Feb 20 – Mar 1, 2026



A full-scope web application assessment conducted against `testphp.vulnweb.com`, following **NIST SP 800-115** and the **OWASP Testing Guide v4**. The engagement surfaced a cluster of critical and high-severity weaknesses — ranging from injectable endpoints to plaintext credentials sitting in public directories.



## What Was Found

| # | Vulnerability | Location | Severity |
|---|---------------|----------|----------|
| 1 | Outdated PHP (5.6.40, EOL) | `/login.php` | `CRITICAL` |
| 2 | SQL Injection — manual | `/login.php` | `CRITICAL` |
| 3 | SQL Injection — automated | Multiple endpoints | `CRITICAL` |
| 4 | Plaintext credentials exposed | `/pictures/credentials.txt` | `HIGH` |
| 5 | Cross-Site Scripting (XSS) | `/guestbook.php` | `HIGH` |
| 6 | Local File Inclusion (LFI) | `/showimage.php` | `HIGH` |
| 7 | Path Traversal | `/showimage.php` | `HIGH` |
| 8 | Sensitive info disclosure | `/admin` | `HIGH` |
| 9 | Sensitive info disclosure | `/CVS` | `HIGH` |



## The Headline Issues

**SQL Injection** — The `cat` parameter on `/listproducts.php` accepts unsanitized input. An unauthenticated attacker can dump the entire database: passwords, credit card numbers, everything. CVSS 9.8.

**Credential Exposure** — `secret.jpg` and `credentials.txt` are publicly reachable with no authentication. Plaintext username and password, sitting in the open.

**PHP 5.6.40** — End-of-life since December 2018. No patches, no fixes, known RCE vectors. The foundation the app runs on is itself a liability.



## Tooling

- **SQLMap** — injection detection and exploitation  
- **Burp Suite** — request interception and manipulation  
- **Gobuster / FFUF** — directory and endpoint fuzzing  
- **Manual testing** — logic flaws, verification, edge cases



## Fix It

> Immediate

- Upgrade PHP to a current, supported release
- Replace all raw queries with parameterized statements
- Pull sensitive files off the public web root
- Sanitize inputs, encode outputs

> Near-term

- Deploy a WAF
- Set `Content-Security-Policy` headers
- Disable directory listing
- Strip PHP version from response headers

> Ongoing

- Regular penetration tests and code audits
- Hash credentials — never store plaintext
- Enforce a patch cadence
- Secure development training for the team



## Severity Reference

| Rating | CVSS Range |
|--------|------------|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |



*This assessment was conducted in a controlled environment on an intentionally vulnerable target. All findings are documented for educational and remediation purposes.*
