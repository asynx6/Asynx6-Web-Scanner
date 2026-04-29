import logging
import re
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
try:
    from modules import utils
except ImportError:
    import utils

class Crawler:
    def __init__(self, base_url, max_pages=30, session=None, output_dir=None):
        self.base_url = base_url
        self.domain = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited = set()
        self.to_visit = [base_url]
        self.parameters = set()
        self.forms = []
        self.hidden_endpoints = set()
        self.sensitive_info = []
        self.session = session if session else utils.get_session()
        self.output_dir = output_dir

    def extract_sensitive_info(self, text, url):
        patterns = {
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "Stripe API Key": r'sk_live_[0-9a-zA-Z]{24}',
            "Google API Key": r'AIza[0-9A-Za-z\\-_]{35}',
            "Auth Token": r'(?:Bearer|Token|JWT)\s+([a-zA-Z0-9\._\-]{20,})',
            "Generic Secret": r'(?:password|pwd|secret|key|auth)\s*[:=]\s*["\']([^"\']{6,})["\']',
            "Database Connection": r'(?:mongodb|mysql|postgresql|redis)://[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+'
        }
        
        for name, pattern in patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                if utils.is_junk_secret(match): continue
                
                if self.output_dir:
                    utils.log_sensitive_loot(url, name, match, self.output_dir)
                    
                self.sensitive_info.append({
                    "type": name,
                    "value": match,
                    "location": url
                })

    def is_internal(self, url):
        return urlparse(url).netloc == self.domain

    def extract_endpoints_from_text(self, text, base_url):
        pattern = r'["\']((?:/[a-zA-Z0-9_\-\.]+)+/?(?:[\?#][^"\']*)?)["\']'
        matches = re.findall(pattern, text)
        for match in matches:
            if len(match) > 1:
                full_url = urljoin(base_url, match)
                if self.is_internal(full_url):
                    self.hidden_endpoints.add(full_url)
                    if '?' in full_url:
                        self.parameters.add(full_url)

        param_pattern = r'(?:[\?&])([a-zA-Z0-9_\-]+)='
        params_found = re.findall(param_pattern, text)
        
        for p in params_found:
            if p not in ['id', 'page', 's', 'lang', 'v']: 
                self.parameters.add(f"{base_url.split('?')[0]}?{p}=FUZZ")

    def crawl(self):
        print(f"  [~] Starting Deep Spidering (JS/CSS Analysis Enabled): {self.base_url}")
        count = 0
        while self.to_visit and count < self.max_pages:
            url = self.to_visit.pop(0)
            if url in self.visited:
                continue
            
            try:
                self.visited.add(url)
                count += 1
                r = self.session.get(url, timeout=5)
                if r.status_code != 200:
                    continue

                self.extract_sensitive_info(r.text, url)

                if any(url.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx', '.css']):
                    self.extract_endpoints_from_text(r.text, url)
                    
                    api_pattern = r'(?:axios|fetch)\s*\.\s*(?:get|post|put|delete|patch)?\s*\(\s*["\']([^"\']+)["\']'
                    api_matches = re.findall(api_pattern, r.text)
                    for match in api_matches:
                        full_url = urljoin(url, match)
                        if self.is_internal(full_url):
                            self.hidden_endpoints.add(full_url)
                    continue

                soup = BeautifulSoup(r.text, 'html.parser')
                
                tags = {
                    'a': 'href',
                    'script': 'src',
                    'link': 'href',
                    'iframe': 'src'
                }

                for tag, attr in tags.items():
                    for element in soup.find_all(tag, **{attr: True}):
                        link = urljoin(url, element[attr])
                        link = link.split('#')[0]
                        
                        if self.is_internal(link):
                            if '?' in link:
                                self.parameters.add(link)
                            if any(link.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx', '.css']) and link not in self.visited:
                                self.to_visit.append(link)
                            elif link not in self.visited:
                                self.to_visit.append(link)

                for form in soup.find_all('form'):
                    action = form.get('action')
                    method = form.get('method', 'get').lower()
                    form_url = urljoin(url, action) if action else url
                    
                    inputs = []
                    for input_tag in form.find_all(['input', 'textarea', 'select']):
                        name = input_tag.get('name')
                        type_ = input_tag.get('type', 'text')
                        if name:
                            inputs.append({"name": name, "type": type_})
                    
                    if inputs:
                        self.forms.append({
                            "url": form_url,
                            "method": method,
                            "inputs": inputs
                        })

            except Exception as e:
                logging.error(f"Crawler error at {url}: {e}")

        return {
            "visited": list(self.visited),
            "urls_with_params": list(self.parameters | self.hidden_endpoints),
            "forms": self.forms,
            "hidden_endpoints": list(self.hidden_endpoints),
            "sensitive_info": self.sensitive_info
        }

def run(url, max_pages=30, session=None, output_dir=None):
    crawler = Crawler(url, max_pages, session, output_dir)
    return crawler.crawl()
