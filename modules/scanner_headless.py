import logging
import random
from urllib.parse import urlparse
try:
    from playwright.sync_api import sync_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False

try:
    from modules import utils
except ImportError:
    import utils

def run(url):
    if not PLAYWRIGHT_AVAILABLE:
        print(f"  [!] Playwright module not found. Skipping Headless Analysis.")
        return {"links": set(), "hidden_elements": [], "screenshots": [], "content": ""}
    
    print(f"  [~] Launching Headless Engine (Crawl Level Dewa): {url}")
    results = {
        "links": set(),
        "hidden_elements": [],
        "screenshots": [],
        "content": ""
    }
    
    try:
        with sync_playwright() as p:
            viewports = [
                {'width': 1920, 'height': 1080},
                {'width': 1366, 'height': 768},
                {'width': 1536, 'height': 864},
                {'width': 1440, 'height': 900}
            ]
            
            browser_type = p.chromium
            browser = browser_type.launch(headless=True)
            
            headers = utils.get_morphing_headers()
            context = browser.new_context(
                user_agent=headers['User-Agent'], 
                viewport=random.choice(viewports)
            )
            page = context.new_page()
            domain = urlparse(url).netloc
            hidden_api_calls = []

            def handle_request(request):
                api_types = ["fetch", "xhr"]
                if request.resource_type in api_types:
                    if domain in request.url or "/api/" in request.url.lower():
                        hidden_api_calls.append(request.url)

            page.on("request", handle_request)
            page.goto(url, wait_until="networkidle", timeout=60000)
            
            buttons_to_try = ["#login", ".btn-login", "#accept", ".cookie-accept"]
            for btn in buttons_to_try:
                try:
                    if page.is_visible(btn):
                        page.click(btn)
                        page.wait_for_timeout(1000)
                except: pass
            results["hidden_api_endpoints"] = list(set(hidden_api_calls))

            results["content"] = page.content()
            links = page.query_selector_all("a")
            for link in links:
                href = link.get_attribute("href")
                if href and href.startswith("http"):
                    clean_href = href.split('#')[0]
                    results["links"].add(clean_href)
            browser.close()
    except Exception as e:
        logging.error(f"Headless Engine Error: {e}")
        print(f"  [!] Headless Engine Failed. Falling back to static requests.")
        
    return results
