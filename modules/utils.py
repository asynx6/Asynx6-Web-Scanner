import random
import logging
from rich.console import Console

console = Console()
JITTER_MIN = 0.5
JITTER_MAX = 2.0

def adjust_jitter(status_code, headers):
    global JITTER_MIN, JITTER_MAX
    if status_code in [403, 429] or "cloudflare" in str(headers).lower() or "sucuri" in str(headers).lower():
        JITTER_MIN, JITTER_MAX = 3.0, 7.0 
    else:
        JITTER_MIN, JITTER_MAX = 0.5, 2.0

def is_login_page(content):
    content_lower = content.lower()
    indicators = ['type="password"', 'name="password"', 'action="/login"', 'name="login"']
    return any(ind in content_lower for ind in indicators)

def is_confirmed_bypass(content):
    content_lower = content.lower()
    
    if is_login_page(content): 
        return False
        
    strict_indicators = [
        "id=\"user_profile\"", "href=\"/logout\"", "user management", 
        "total users:", "system status", "server load", "config editing",
        "welcome, admin", "signed in as"
    ]
    matches = sum(1 for ind in strict_indicators if ind in content_lower)
    
    return matches >= 2

def check_honeypot(headers, content):
    honeypot_indicators = ["x-honeypot", "x-traps", "kfsensor"]
    for ind in honeypot_indicators:
        if ind in str(headers).lower(): return True
    if len(set(content)) < 10 and len(content) > 500:
        return True
    return False

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.6045.163 Mobile Safari/537.36"
]

GLOBAL_BLACK_LIST = {
    "init", "read", "write", "emit", "on", "off", "toString", "toJSON", "apply", "concat", 
    "reset", "slice", "splice", "push", "pop", "shift", "unshift", "length", "prototype",
    "constructor", "render", "state", "props", "dispatch", "action", "effect", "mount",
    "unmount", "click", "hover", "touch", "scroll", "resize", "load", "error", "success",
    "translate", "changeLanguage", "getResource", "addResource", "exists", "resolve",
    "format", "reload", "save", "loadUrl", "create", "delete", "update", "patch", "get",
    "post", "put", "options", "head", "connect", "trace", "second", "minute", "hour",
    "day", "week", "month", "year", "unidentified", "unrecognized", "anonymous",
    "language", "namespaces", "interpolation", "plural", "suffix", "prefix", "fallback",
    "bundle", "resource", "definition", "handle", "callback", "listener", "event",
    "component", "element", "node", "fragment", "portal", "context", "provider",
    "consumer", "hook", "reducer", "store", "selector", "dispatch", "thunk", "saga"
}

def is_junk_secret(value):
    val_str = str(value).strip()
    if len(val_str) < 8:
        return True
    if any(c in val_str for c in "()[]{},;><="):
        return True
    if val_str.startswith(".") or val_str.startswith("_"):
        return True
    import re
    if re.match(r'^[a-z]+[A-Z][a-z]+', val_str):
        if val_str.lower() in GLOBAL_BLACK_LIST: return True
        verbs = ["get", "set", "add", "remove", "has", "is", "on", "to", "from", "create", "handle"]
        if any(val_str.lower().startswith(v) for v in verbs):
            return True

    if val_str.lower() in GLOBAL_BLACK_LIST:
        return True
        
    return False

def mask_secret(secret):
    if not secret: return "*******"
    if len(secret) <= 8:
        return "*******"
    return f"{secret[:4]}****{secret[-4:]}"

def calculate_entropy(s):
    import math
    if not s: return 0
    probabilities = [n_x/len(s) for n_x in [s.count(c) for c in set(s)]]
    entropy = - sum([p * math.log(p, 2) for p in probabilities])
    return entropy

def get_morphing_headers():
    browser_profiles = [
        {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Sec-Ch-Ua": '"Google Chrome";v="119", "Chromium";v="119", "Not?A_Brand";v="24"',
            "Sec-Ch-Ua-Mobile": "?0",
            "Sec-Ch-Ua-Platform": '"Windows"',
        },
        {
            "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-GB,en;q=0.9",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
        }
    ]
    profile = random.choice(browser_profiles)
    
    spoofed_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    profile.update({
        "X-Forwarded-For": spoofed_ip,
        "X-Real-IP": spoofed_ip,
        "X-Client-IP": spoofed_ip,
        "X-Forwarded-Host": "localhost",
    })
    return profile

def get_confidence_score(vuln_type, status_code, content_matched=True):
    score = 50
    if content_matched: score += 30
    if status_code == 200: score += 10
    if "SQL" in vuln_type or "RCE" in vuln_type: score += 5
    return min(score, 100)

def get_session(pool_connections=50, pool_maxsize=50, use_proxy=False):
    import requests
    import time
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize, max_retries=retries)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    session.headers.update(get_morphing_headers())
    return session

def send_chunked_request(url, data, headers=None):
    import requests
    def gen():
        yield data.encode('utf-8')
    
    session = get_session()
    if headers:
        session.headers.update(headers)
    
    return session.post(url, data=gen(), timeout=10)

class SensitiveRedactionFilter(logging.Filter):
    def filter(self, record):
        msg = str(record.msg)
        sensitive_patterns = [
            (r'x-api-key\s*[:=]\s*["\']?[a-zA-Z0-9_\-]+["\']?', "x-api-key: [REDACTED]"),
            (r'password\s*[:=]\s*["\']?[a-zA-Z0-9_\-]+["\']?', "password: [REDACTED]"),
            (r'authorization\s*[:]\s*bearer\s+[a-zA-Z0-9\._\-]+', "Authorization: Bearer [REDACTED]")
        ]
        import re
        for pattern, replacement in sensitive_patterns:
            msg = re.sub(pattern, replacement, msg, flags=re.IGNORECASE)
        record.msg = msg
        return True

def setup_logging(log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    fh = logging.FileHandler(log_file, mode='a', encoding='utf-8')
    fh.setFormatter(formatter)
    fh.addFilter(SensitiveRedactionFilter())
    
    logger.handlers = [fh]

def log_sensitive_loot(target, data_type, value, output_dir):
    vault_path = f"{output_dir}/LOOT_VAULT.md"
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    masked_val = mask_secret(value)
    
    with open(vault_path, "a", encoding="utf-8") as f:
        if f.tell() == 0:
            f.write(f"# 🗝️ LOOT VAULT - {target}\n")
            f.write("> [!CAUTION]\n> THIS FILE CONTAINS SENSITIVE RAW DATA. DO NOT SHARE UNREDACTED.\n\n")
            f.write("| Timestamp | Type | Value (Raw) |\n| --- | --- | --- |\n")
        f.write(f"| {timestamp} | {data_type} | `{value}` |\n")
    
    console.print(f"[bold yellow][!] SENSITIVE LOOT SECURED IN VAULT: {data_type} ({masked_val})[/]")

def generate_poc_report(target, vulns, output_dir, recon_data=None):
    report_path = f"{output_dir}/BUG_BOUNTY_POC.md"
    import time
    
    content = f"# 🎯 OMNISCIENT PoC REPORT - {target}\n"
    content += f"**Date:** `{time.strftime('%Y-%m-%d %H:%M:%S')}` | **Engine:** `AsynX6 V1.0`\n\n"
    
    if recon_data:
        content += "## 🔍 1. RECONNAISSANCE SUMMARY\n"
        if recon_data.get('subdomains'):
            content += "### Subdomains Discovered\n"
            content += "| Subdomain | IP Address |\n| --- | --- |\n"
            for sub in recon_data['subdomains']:
                content += f"| {sub['subdomain']} | {sub['ip']} |\n"
            content += "\n"
        
        if recon_data.get('origin_ips'):
            content += "### CDN Bypass: Potential Origin IPs\n"
            content += "| Sub | IP Address | Confidence | Ports |\n| --- | --- | --- | --- |\n"
            for entry in recon_data['origin_ips']:
                ports_str = ", ".join([str(p['port']) for p in entry.get('ports', [])])
                content += f"| {entry['sub']} | {entry['ip']} | {entry['confidence']} | {ports_str} |\n"
            content += "\n"

    content += "## 📝 2. EXECUTIVE SUMMARY\n"
    content += f"During the security audit of `{target}`, a total of {len(vulns)} high-confidence vulnerabilities were discovered. "
    content += "The system prioritized the identification of high-impact exploits using context-aware fuzzing and adaptive stealth.\n\n"
    
    content += "## 🚀 3. TECHNICAL FINDINGS\n"
    if not vulns:
        content += "*No high-confidence vulnerabilities found during this audit cycle.*\n"
    else:
        for i, vuln in enumerate(vulns, 1):
            severity_icon = "🔴" if vuln.get('severity') == "CRITICAL" else "🟠" if vuln.get('severity') == "HIGH" else "🟡"
            content += f"### {severity_icon} {i}. {vuln['type']}\n"
            content += f"- **Severity:** `{vuln.get('severity', 'UNKNOWN')}`\n"
            content += f"- **Confidence:** `{vuln.get('confidence', 0)}%` (Sniper Tracking)\n"
            content += f"- **Location:** `{vuln.get('location', 'N/A')}`\n"
            if 'payload' in vuln:
                content += f"- **Payload:** `{vuln['payload']}`\n"
            
            content += "\n#### Impact & Description\n"
            content += f"{vuln.get('description', 'High impact on confidentiality and integrity.')}\n\n"
            content += "---\n\n"
    
    content += "## 🛡️ 4. REMEDIATION STRATEGY\n"
    content += "- **Input Validation**: Implement strict allow-list validation for all user-supplied data.\n"
    content += "- **Database Security**: Use prepared statements for all queries and disable direct database exposure (Port 3306).\n"
    content += "- **Access Control**: Enforce server-side session validation and implement IP-whitelisting for administrative endpoints.\n"
    content += "- **Infrastructure**: Ensure WAF rules are configured to detect and block common attack patterns (SQLi, XSS, LFI).\n"
    
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)
    return report_path
