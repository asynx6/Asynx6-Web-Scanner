import requests
import logging
from modules import utils

def run(url):
    print(f"\n[+] Scanning Headers (The Truth Hunter): {url}")
    session = utils.get_session()
    vulnerabilities = []
    
    try:
        res = session.get(url, timeout=5)
        headers = res.headers
        
        sec_headers = {
            "Content-Security-Policy": "HIGH",
            "Strict-Transport-Security": "MEDIUM",
            "X-Frame-Options": "LOW",
            "X-Content-Type-Options": "LOW"
        }
        
        for h, sev in sec_headers.items():
            if h not in headers:
                print(f"  [!!] MISSING: {h}")
                vulnerabilities.append({"type": f"Missing {h}", "severity": sev, "location": url})
            else:
                print(f"  [OK] {h}")

        leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Runtime"]
        for lh in leaky_headers:
            if lh in headers:
                print(f"  [!] LEAK: {lh} = {headers[lh]}")
                vulnerabilities.append({
                    "type": "Information Exposure",
                    "severity": "LOW",
                    "location": url,
                    "description": f"Server disclosing technology stack via {lh} header."
                })
        if headers.get("Access-Control-Allow-Origin") == "*":
            print(f"  [bold red][!!!] CRITICAL: Wildcard CORS Detected![/]")
            vulnerabilities.append({
                "type": "CORS Misconfiguration",
                "severity": "HIGH",
                "location": url,
                "description": "Access-Control-Allow-Origin is set to *, allowing any domain to read response data."
            })

    except requests.RequestException as e:
        print(f"  [!] Error: {e}")
    
    return vulnerabilities