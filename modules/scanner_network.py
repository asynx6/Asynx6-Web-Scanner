import socket
import requests
import logging
from urllib.parse import urlparse
import concurrent.futures
try:
    from modules import utils
except ImportError:
    import utils

def find_origin_ip(domain, target_url=None):
    print(f"  [~] Attempting CDN Bypass & Content Validation...")
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    origin_subs = ["direct", "origin", "dev", "staging", "api", "vpn", "mail"]
    found_ips = []
    proto = "https" if target_url and "https" in target_url else "http"
    main_len = 0
    try:
        main_res = requests.get(f"{proto}://{domain}", timeout=5, headers=utils.get_morphing_headers(), verify=False)
        main_len = len(main_res.content)
    except: pass

    for sub in origin_subs:
        try:
            target_sub = f"{sub}.{domain}"
            ip = socket.gethostbyname(target_sub)
            try:
                sub_res = requests.get(f"{proto}://{ip}", timeout=5, headers={"Host": domain}, verify=False)
                sub_len = len(sub_res.content)
                if main_len > 0 and abs(sub_len - main_len) < (main_len * 0.2): 
                    found_ips.append({"sub": sub, "ip": ip, "confidence": "HIGH (Content Match)"})
                else:
                    found_ips.append({"sub": sub, "ip": ip, "confidence": "LOW (Different Content)"})
            except:
                found_ips.append({"sub": sub, "ip": ip, "confidence": "MEDIUM (No Content Access)"})
        except: pass
    return found_ips

def detect_waf(url):
    print(f"  [~] Detecting WAF & Active Shield Presence...")
    session = utils.get_session()
    waf_detected = "None"
    try:
        res = session.get(url, timeout=5)
        headers = str(res.headers).lower()
        if "cloudflare" in headers: waf_detected = "Cloudflare"
        elif "sucuri" in headers: waf_detected = "Sucuri"
        elif "akamai" in headers: waf_detected = "Akamai"
        payload = "<script>alert('WAF_TEST')</script>"
        waf_poke_url = f"{url}?id={payload}"
        poke_res = session.get(waf_poke_url, timeout=5)
        
        if poke_res.status_code in [403, 406, 429, 501]:
            waf_detected += " (Confirmed via Payload Blocking)"
            utils.console.print(f"  [!] WAF ACTIVE: Payload blocked with status {poke_res.status_code}")
            
    except: pass
    return waf_detected

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1.5)
            if s.connect_ex((ip, port)) == 0:
                banner = "Unknown"
                try:
                    if port in [80, 8080]:
                        s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                        banner = s.recv(1024).decode(errors='ignore').split('\n')[0].strip()
                    elif port == 3306:
                        banner = s.recv(1024).decode(errors='ignore')[5:20].strip()
                    else:
                        s.sendall(b"\r\n")
                        banner = s.recv(1024).decode(errors='ignore').strip()
                except:
                    pass
                
                try:
                    service = socket.getservbyport(port)
                except (socket.error, OverflowError):
                    service = "Unknown"
                if port == 445:
                    banner += " [Detected Windows OS - Potential SMB vulnerability]"
                elif port == 3389:
                    banner += " [Detected Windows OS - Potential RDP vulnerability]"
                elif port == 3306:
                    banner += " [MariaDB/MySQL - Exploitable if Auth is weak]"

                severity = "LOW"
                if port == 3306: severity = "CRITICAL"
                elif port in [22, 21, 445, 3389, 1433, 5432]: severity = "HIGH"

                return {
                    "port": port, 
                    "status": "OPEN", 
                    "service": service,
                    "severity": severity,
                    "banner": banner[:100] if banner else "None"
                }
    except Exception as e:
        logging.debug(f"Error scanning port {port} on {ip}: {e}")
    return None

def run_port_scan(domain, full_scan=False):
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror as e:
        logging.error(f"Could not resolve domain {domain}: {e}")
        return []
    
    if full_scan:
        print(f"  [!] STARTING FULL PORT SCAN (1-61111) for {domain}. This will take time...")
        ports = range(1, 61112)
        workers = 500
    else:
        print(f"  [~] Scanning common ports for {domain}...")
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521, 3306, 3389, 5432, 8080, 8443, 9000, 27017]
        workers = 20
        
    if domain in ["localhost", "127.0.0.1", "::1"]:
        workers = min(workers, 10)

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(scan_port, ip, port) for port in ports]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)
                
    return sorted(open_ports, key=lambda x: x['port'])

def run(target_url, full_port_scan=False):
    domain = urlparse(target_url).netloc
    if ":" in domain: domain = domain.split(":")[0]
    
    origin_ips = find_origin_ip(domain, target_url)
    
    try:
        ip = socket.gethostbyname(domain)
        
        if ip in ["127.0.0.1", "::1"] or domain == "localhost":
            return {
                "ip": ip,
                "waf": detect_waf(target_url),
                "ports": run_port_scan(domain, full_port_scan),
                "location": "Localhost",
                "isp": "Loopback"
            }
            
        location = "Unknown"
        isp = "Unknown"
        providers = [
            f"https://ipapi.co/{ip}/json/",
            f"http://ip-api.com/json/{ip}"
        ]
        
        for p_url in providers:
            try:
                res = requests.get(p_url, timeout=5)
                data = res.json()
                if "city" in data:
                    location = f"{data.get('city')}, {data.get('country_name') or data.get('country')}"
                    isp = data.get('org') or data.get('isp')
                    break
            except: continue

        main_ports = run_port_scan(domain, full_port_scan)
        
        for entry in origin_ips:
            if entry['confidence'].startswith("HIGH"):
                print(f"  [!] High Confidence Origin found! Scanning ports on {entry['ip']}...")
                entry['ports'] = run_port_scan(entry['ip'], full_port_scan)
            else:
                entry['ports'] = []

        return {
            "ip": ip,
            "waf": detect_waf(target_url),
            "ports": main_ports,
            "origin_ips": origin_ips,
            "location": location,
            "isp": isp
        }
    except Exception as e:
        logging.error(f"Error in network scan for {target_url}: {e}")
        return {"error": str(e), "ip": None, "waf": "None", "ports": []}