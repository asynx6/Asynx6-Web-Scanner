import requests
import logging
from urllib.parse import urlparse
from modules import utils

def detect_stack(url):
    print(f"  [~] Detecting Technology Stack (The Chameleon)...")
    session = utils.get_session()
    stack = {
        "language": "Unknown",
        "framework": "Unknown",
        "cms": "None",
        "server": "Unknown"
    }
    
    try:
        r = session.get(url, timeout=10)
        headers = r.headers
        content = r.text.lower()
        
        stack["server"] = headers.get("Server", "Unknown")
        
        if "php" in headers.get("X-Powered-By", "").lower() or ".php" in content or "phpsessid" in session.cookies.get_dict().keys():
            stack["language"] = "PHP"
            if "wp-content" in content or "wp-includes" in content:
                stack["cms"] = "WordPress"
        
        if "react" in content or "next.js" in content or "_next/" in content:
            stack["language"] = "JavaScript (Node.js)"
            stack["framework"] = "React/Next.js"
        elif "vue" in content:
            stack["language"] = "JavaScript"
            stack["framework"] = "Vue.js"
        elif "express" in headers.get("X-Powered-By", "").lower():
            stack["language"] = "Node.js"
            stack["framework"] = "Express"
            
        if "jsessionid" in session.cookies.get_dict().keys():
            stack["language"] = "Java"
        elif "django" in content or "csrftoken" in session.cookies.get_dict().keys():
            stack["language"] = "Python (Django)"
            
    except Exception as e:
        logging.error(f"Stack detection error: {e}")
        
    return stack

def run_wp_scan(url):
    print(f"  [~] Running WordPress Specific Audit...")
    vulnerabilities = []
    session = utils.get_session()
    try:
        r = session.get(f"{url}/?author=1", timeout=5, allow_redirects=True)
        if "/author/" in r.url:
            username = r.url.split('/')[-2]
            vulnerabilities.append({
                "type": "WP User Enumeration",
                "severity": "MEDIUM",
                "location": f"{url}/?author=1",
                "description": f"Successfully identified valid WP username: {username}"
            })
    except: pass
    try:
        r = session.get(f"{url}/wp-content/uploads/", timeout=5)
        if "Index of" in r.text:
            vulnerabilities.append({
                "type": "Directory Listing",
                "severity": "HIGH",
                "location": f"{url}/wp-content/uploads/",
                "description": "Sensitive files might be exposed in uploads directory."
            })
    except: pass

    return vulnerabilities
