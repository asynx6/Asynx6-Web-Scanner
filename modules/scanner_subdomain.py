import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

def get_passive_subdomains(domain):
    print(f"  [~] Querying SSL Certificate Transparency logs (Passive Recon)...")
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        res = requests.get(url, timeout=15)
        if res.status_code == 200:
            for entry in res.json():
                name = entry['name_value']
                for sub in name.split('\n'):
                    sub = sub.strip().lower()
                    if sub.endswith(domain) and "*" not in sub:
                        subdomains.add(sub)
    except: pass
    return list(subdomains)

def scan_subdomain(domain, sub):
    target = f"{sub}.{domain}" if not sub.endswith(domain) else sub
    try:
        ip = socket.gethostbyname(target)
        return {"subdomain": target, "ip": ip}
    except:
        return None

def run(url, threads=30):
    domain = urlparse(url).netloc
    if ":" in domain: domain = domain.split(":")[0]
    
    print(f"  [~] Starting Apex Level Subdomain Discovery: {domain}")
    try:
        wildcard_ip = socket.gethostbyname(f"apex-predator-test-{socket.gethostname()}.{domain}")
        print(f"  [!] WILDCARD DNS DETECTED! IP: {wildcard_ip}. Filtering results...")
        is_wildcard = True
    except:
        is_wildcard = False
        wildcard_ip = None
    passive_subs = get_passive_subdomains(domain)
    wordlist = [
        "dev", "staging", "api", "api-test", "v1", "v2", "test", "demo", 
        "beta", "admin", "administrator", "portal", "dashboard", "manage", 
        "webmail", "mail", "vpn", "remote", "git", "gitlab", "jenkins", 
        "docker", "k8s", "aws", "s3", "cloud", "billing", "payment", "shop"
    ]
    targets = set(wordlist) | set([s.replace(f".{domain}", "") for s in passive_subs])
    
    discovered = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(scan_subdomain, domain, sub) for sub in targets]
        for future in as_completed(futures):
            res = future.result()
            if res:
                if is_wildcard and res['ip'] == wildcard_ip:
                    continue
                discovered.append(res)
                
    return sorted(discovered, key=lambda x: x['subdomain'])
