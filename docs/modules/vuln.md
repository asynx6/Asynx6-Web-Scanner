# Vulnerability Modules

| Module | Vulnerability | Severity |
|---|---|---|
| `sqli` | Time-based blind SQLi (MySQL/PostgreSQL/MSSQL) | CRITICAL |
| `xss` | Reflected XSS | HIGH |
| `lfi` | Local file inclusion | CRITICAL |
| `ssrf` | SSRF + AWS IMDS + internal IP detection | CRITICAL/HIGH |
| `open_redirect` | Chain detection with allowlist bypass | MEDIUM |
| `jwt` | alg=none + 50 weak HS256 secrets | CRITICAL |
| `graphql` | Introspection + deep query DoS | MEDIUM |
| `cors` | Wildcard + reflected Origin | MEDIUM/HIGH |
| `headers` | CSP / HSTS / X-Frame-Options audit | HIGH/MEDIUM/LOW |
| `idor` | Param leak + DELETE/PUT + mass assignment | HIGH/CRITICAL |
| `websocket` | CSWSH + endpoint discovery | HIGH/INFO |