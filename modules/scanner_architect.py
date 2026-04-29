import re
from modules import utils

def analyze_jwt(token):
    import base64
    import json
    try:
        parts = token.split('.')
        if len(parts) != 3: return None
        header = json.loads(base64.urlsafe_b64decode(parts[0] + '==').decode())
        if header.get('alg') == 'none':
            return "CRITICAL: JWT alg=none vulnerability detected!"
    except: pass
    return None

def deobfuscate_js(text):
    patterns = {
        "Midtrans Server Key": r'Mid-server-[0-9a-zA-Z_-]{24}',
        "Stripe Secret Key": r'sk_live_[0-9a-zA-Z]{24}',
        "JWT Secret?": r'(?:jwt_secret|app_key|token_secret)\s*[:=]\s*["\']([^"\']{10,})["\']',
        "PHP Config Leak": r'db_password|db_user|db_host|mysqli_connect'
    }
    patterns.update({
        "Firebase URL": r'https://[a-zA-Z0-9-]+\.firebaseio\.com',
        "AWS Access Key": r'AKIA[0-9A-Z]{16}',
        "Slack Webhook": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
        "Internal IP Leak": r'10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}',
        "Hidden Endpoint": r'["\'](/[a-zA-Z0-9_\-/]{4,})["\']'
    })
    
    found = []
    for name, pattern in patterns.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        for m in matches:
            if name == "Hidden Endpoint":
                junk_endpoints = ["/assets/", "/static/", "/css/", "/js/", "/img/", "/images/", "/fonts/"]
                if any(m.startswith(j) for j in junk_endpoints): continue
                if len(m) < 5: continue
            
            found.append({"type": name, "value": m})
            
    potential_keys = re.findall(r'["\']([a-zA-Z0-9\-_]{25,60})["\']', text)
    
    for key in potential_keys:
        if utils.is_junk_secret(key): continue
        
        entropy = utils.calculate_entropy(key)
        if entropy > 4.8: 
            found.append({"type": "High Entropy Secret (Potential Key)", "value": key, "severity": "HIGH"})
            
    return found

def run(url, content, output_dir=None):
    results = []
    secrets = deobfuscate_js(content)
    for secret in secrets:
        if utils.is_junk_secret(secret['value']) and secret['type'] != "Hidden Endpoint": 
            continue
        
        if output_dir:
            utils.log_sensitive_loot(url, secret['type'], secret['value'], output_dir)
            
        masked_val = utils.mask_secret(secret['value'])
        results.append({
            "type": secret["type"],
            "severity": secret.get("severity", "HIGH"),
            "description": f"Exposed sensitive string found: {masked_val}",
            "raw_value": secret['value']
        })
    return results
