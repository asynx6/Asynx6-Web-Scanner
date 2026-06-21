# Reconnaissance Modules

| Module | Purpose | Phase |
|---|---|---|
| `chameleon` | Detect technology stack (PHP/Node/Python/Java + framework) | Always |
| `subdomain` | crt.sh (passive) + wordlist + wildcard DNS filter | Subdomain recon |
| `network` | Port scan, WAF detection, CDN bypass via origin IP probing | Network recon |
| `dns_enum` | SPF / DMARC / MX / TXT records (via `dig`) | DNS enum |
| `wayback` | Wayback Machine historical endpoint discovery | Wayback historical |
| `headless` | Playwright-based SPA crawling | Headless SPA |
| `crawler` | BFS spidering + secret regex extraction | Spidering |
| `architect` | JS bundle analysis (entropy, JWT hints) | JS Architect |