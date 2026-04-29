import time
import random
from urllib.parse import urljoin
try:
    from modules import utils
except ImportError:
    import utils

def run(url, session=None):
    if not url.endswith('/'): url += '/'
    print(f"  [~] Starting API Fuzzing & IDOR Check...")
    vulnerabilities = []
    if not session:
        session = utils.get_session()
    
    api_paths = ["/api/v1/", "/api/v2/", "/api/admin/", "/api/user/"]
    if "/api/" in url.lower():
        print(f"  [!] /api/ detected! Switching to Specialized API Wordlist...")
        api_paths.extend(["/api/swagger/", "/api/graphql/", "/api/config/", "/api/private/"])
    aggressive_params = ["user_id", "order_token", "payment_status", "uuid", "client_id", "auth_key"]
    
    for path in api_paths:
        target = urljoin(url, path)
        try:
            for param in aggressive_params:
                time.sleep(random.uniform(utils.JITTER_MIN, utils.JITTER_MAX))
                fuzz_url = f"{target}?{param}=1"
                r = session.get(fuzz_url, timeout=5)
                leaks = ["password", "email", "secret", "token", "balance", "admin"]
                if r.status_code == 200:
                    for leak in leaks:
                        if leak in r.text.lower() and len(r.text) < 5000:
                            utils.console.print(f"[bold red][!] ALERT: API DATA LEAK CONFIRMED AT {fuzz_url}[/]")
                            vulnerabilities.append({
                                "type": "API IDOR/Data Leak",
                                "severity": "HIGH",
                                "confidence": 95,
                                "location": fuzz_url,
                                "description": f"Sensitive data leakage found by fuzzing parameter: {param}"
                            })

            for method in ["PUT", "DELETE"]:
                time.sleep(random.uniform(utils.JITTER_MIN, utils.JITTER_MAX))
                r_method = session.request(method, target, timeout=5)
                if r_method.status_code in [200, 204]:
                     r_check = session.get(target, timeout=5)
                     if method == "DELETE" and r_check.status_code == 404:
                         utils.console.print(f"[bold red][!] ALERT: API {method} CONFIRMED AT {target}[/]")
                         vulnerabilities.append({
                            "type": "Confirmed Unprotected DELETE",
                            "severity": "CRITICAL",
                            "confidence": 100,
                            "location": target,
                            "description": "CRITICAL: Verified resource deletion via unauthorized DELETE method."
                        })
                     elif method == "PUT" and r_method.text != r_check.text:
                         utils.console.print(f"[bold red][!] ALERT: API {method} CONFIRMED AT {target}[/]")
                         vulnerabilities.append({
                            "type": "Confirmed Unprotected PUT",
                            "severity": "CRITICAL",
                            "confidence": 100,
                            "location": target,
                            "description": "CRITICAL: Verified resource modification via unauthorized PUT method."
                        })
            
            mass_params = {"is_admin": True, "role": "admin", "privileges": "all", "balance": 999999}
            
            r_mass = session.post(target, json=mass_params, timeout=5)
            
            if r_mass.status_code in [200, 201]:
                r_verify = session.get(target, timeout=5)
                if '"role":"admin"' in r_verify.text.lower() or '"is_admin":true' in r_verify.text.lower():
                    utils.console.print(f"[bold red][!] CRITICAL: MASS ASSIGNMENT CONFIRMED AT {target}[/]")
                    vulnerabilities.append({
                        "type": "API Mass Assignment",
                        "severity": "CRITICAL",
                        "confidence": 100,
                        "location": target,
                        "description": "CRITICAL: Privileges escalated by injecting admin parameters into API request."
                    })
            large_data = {"data": "A" * 50000}
            r_fuzz = session.post(target, json=large_data, timeout=10)
            if r_fuzz.status_code == 500:
                vulnerabilities.append({
                    "type": "API Logic Failure",
                    "severity": "MEDIUM",
                    "location": target,
                    "description": "Server crashed (500) on large payload."
                })
        except: pass
            
    return vulnerabilities
