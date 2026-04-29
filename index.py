import os
import sys
import logging
import zipfile
from datetime import datetime
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, TextColumn
from rich.theme import Theme
from modules import scanner_network, scanner_vulnerability, scanner_brute, scanner_crawler, scanner_api, scanner_subdomain, scanner_chameleon, scanner_architect, exploit_db, utils
from multiprocessing import Pool

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "danger": "bold red",
    "success": "bold green",
    "critical": "bold white on red",
    "apocalypse": "bold white on dark_red",
    "bounty": "bold black on green",
    "omniscient": "bold white on purple"
})

def run_batch_worker(args):
    target, aggressive = args
    LScanMaster(target, aggressive).run()

console = Console(theme=custom_theme, force_terminal=True)

class LScanMaster:
    def __init__(self, target, aggressive=False):
        self.target = target if target.startswith("http") else "http://" + target
        self.domain = urlparse(self.target).netloc.replace(":", "_")
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.base_dir = f"results/{self.domain}_{self.timestamp}"
        self.loot_dir = f"{self.base_dir}/loot"
        self.aggressive = aggressive
        self.setup_dirs()
        self.session = utils.get_session()

    def setup_dirs(self):
        os.makedirs(self.loot_dir, exist_ok=True)
        self.logger = logging.getLogger(self.domain)
        self.logger.setLevel(logging.INFO)
        log_path = f"{self.base_dir}/audit.log"
        fh = logging.FileHandler(log_path, encoding='utf-8')
        fh.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(fh)
        
        self.log_file = open(log_path, "a", encoding="utf-8")

    def log(self, msg, style="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        console.print(f"[[dim]{timestamp}[/]] {msg}", style=style)
        self.log_file.write(f"[{timestamp}] {msg}\n")
        self.logger.info(msg)

    def banner(self):
        feature_table = Table(show_header=False, border_style="dim", padding=(0, 2))
        feature_table.add_row("[success]✔[/] Passive Subdomain Recon", "[success]✔[/] JS Architect Engine")
        feature_table.add_row("[success]✔[/] WAF/CDN Bypass Logic", "[success]✔[/] Oracle Time-Based SQLi")
        feature_table.add_row("[success]✔[/] Headless Dynamic Crawler", "[success]✔[/] Zero-Leak Redacted Logs")
        feature_table.add_row("[success]✔[/] REST API Fuzzing Hub", "[success]✔[/] Automated PoC Reporting")
        disclaimer = Panel(
            "[bold red]LEGAL DISCLAIMER & ETHICAL USAGE[/]\n"
            "[white]This software is strictly for educational and authorized security auditing.\n"
            "The author ([omniscient]asynx6[/]) is not responsible for any misuse or damage.\n"
            "Attacking targets without prior written consent is strictly prohibited.[/]",
            border_style="danger",
            title="[bold yellow]STRICT NOTICE[/]",
            subtitle="[dim]Engineered by asynx6[/] [bold yellow]V1.0[/]"
        )
        console.print(Panel(feature_table, title="[info]SYSTEM CAPABILITIES[/]", border_style="info"))
        console.print(disclaimer)
        console.print("\n")

    def get_hash(self, content):
        import hashlib
        return hashlib.md5(content).hexdigest()

    def save_loot(self, filename, content):
        if not filename: filename = "index.html"
        safe_name = filename.replace("://", "_").replace("/", "_").replace(".", "_")
        if not safe_name: safe_name = "index.html"
        path = f"{self.loot_dir}/{safe_name}"
        
        current_hash = self.get_hash(content)
        self.log(f"LOOTED: {filename} | MD5: [dim]{current_hash}[/]")
        
        with open(path, "wb") as f:
            f.write(content)
        return path

    def compress_loot(self):
        if os.path.exists(self.loot_dir) and os.listdir(self.loot_dir):
            zip_path = f"{self.base_dir}/loot_archive.zip"
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(self.loot_dir):
                    for file in files:
                        zipf.write(os.path.join(root, file), arcname=file)
            self.log(f"Loot compressed: [bold]{zip_path}[/]", style="success")

    def run(self):
        self.banner()
        self.log(f"Initiating OMNISCIENT Audit on [bold]{self.target}[/]")
        
        crawl_results = {}
        vulns = []
        infra = {}
        subdomains = []
        downloaded = 0

        with Progress(
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            
            task_stack = progress.add_task("[omniscient]Chameleon: Detecting Stack...", total=None)
            stack = scanner_chameleon.detect_stack(self.target)
            progress.update(task_stack, completed=True)
            self.log(f"Stack: [bold]{stack['language']}[/] | Framework: [bold]{stack['framework']}[/]")

            task0 = progress.add_task("[green]Recon: Subdomain Discovery...", total=None)
            subdomains = scanner_subdomain.run(self.target)
            progress.update(task0, completed=True)

            task1 = progress.add_task("[cyan]Recon: Infrastructure & WAF Bypass...", total=None)
            infra = scanner_network.run(self.target)
            progress.update(task1, completed=True)
            self.log(f"IP: [bold]{infra.get('ip')}[/] | WAF: [bold]{infra.get('waf')}[/]")

            task_headless = progress.add_task("[purple]Headless Engine: Rendering Dynamic Content...", total=None)
            headless_links = set()
            try:
                from modules import scanner_headless
                headless_data = scanner_headless.run(self.target)
                dynamic_content = headless_data["content"]
                headless_links = headless_data["links"]
                if headless_links:
                    self.log(f"Headless Engine found [bold]{len(headless_links)}[/] dynamic links.", style="success")
            except ImportError:
                dynamic_content = ""
            progress.update(task_headless, completed=True)

            task2 = progress.add_task("[blue]Spidering: Crawling & Architect Analysis...", total=None)
            crawl_results = scanner_crawler.run(self.target, max_pages=40, session=self.session, output_dir=self.base_dir)
            
            all_pages = set(crawl_results['visited']) | headless_links
            
            for page in all_pages:
                if page.endswith('.js'):
                    try:
                        r = self.session.get(page, timeout=5)
                        vulns.extend(scanner_architect.run(page, r.text, output_dir=self.base_dir))
                    except: pass
            progress.update(task2, completed=True)

            task3 = progress.add_task("[yellow]Vulnerability Audit: Oracle Validation...", total=None)
            vulns.extend(scanner_vulnerability.run_all(self.target, session=self.session))
            progress.update(task3, completed=True)

            task4 = progress.add_task("[green]API Fuzzing: Layered Verification...", total=None)
            vulns.extend(scanner_api.run(self.target, session=self.session))
            progress.update(task4, completed=True)

            if any(p['port'] == 3306 for p in infra.get('ports', [])):
                task5 = progress.add_task("[red]DB Exploit...", total=None)
                vulns.extend(exploit_db.run(infra['ip'], 3306))
                progress.update(task5, completed=True)

            task6 = progress.add_task("[magenta]Smart Fuzzing: Contextual Wordlist Extension...", total=None)
            loot_results = scanner_brute.run(self.target, aggressive=self.aggressive, threads=25, session=self.session, content_baseline=dynamic_content)
            for item in loot_results:
                if item['status'] == 200:
                    self.save_loot(os.path.basename(item['url']), item['content'])
                    downloaded += 1
            progress.update(task6, completed=True)

        recon_data = {
            "subdomains": subdomains,
            "origin_ips": infra.get('origin_ips', [])
        }
        
        if vulns or subdomains or infra.get('origin_ips'):
            poc_path = utils.generate_poc_report(self.target, vulns, self.base_dir, recon_data=recon_data)
            self.log(f"PoC Report generated: [bold]{poc_path}[/]", style="omniscient")

        table = Table(title=f"OMNISCIENT SUMMARY - {self.target}", show_header=True)
        table.add_column("Category", style="cyan")
        table.add_column("Result", style="white")
        table.add_row("Vulnerabilities", str(len(vulns)))
        table.add_row("Subdomains Found", str(len(subdomains)))
        table.add_row("Origin IPs Found", str(len(infra.get('origin_ips', []))))
        table.add_row("Files Looted", str(downloaded))
        console.print(table)
        
        self.compress_loot()
        self.log_file.close()

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="OMNISCIENT ENGINE - Apex Predator Edition")
    parser.add_argument("target", nargs="?", help="Target URL or path to .txt list")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive fuzzing & discovery")
    args = parser.parse_args()

    console.print(Panel("[bold white]ASYNX6 ENGINE V1.0[/]\n[dim]Apex Predator Security Audit Suite[/]", border_style="purple"))
    
    target_input = args.target if args.target else console.input("[bold cyan]>> Enter Target URL or .txt list: [/]").strip()
    if not target_input:
        console.print("[danger][!] Error: No target specified. Exiting...[/]")
        sys.exit(0)

    is_aggressive = args.aggressive
    if not args.aggressive:
        choice = console.input("[bold yellow]>> Enable Aggressive Mode (Extra Fuzzing)? (y/n): [/]").lower()
        is_aggressive = choice == 'y'

    if os.path.isfile(target_input):
        with open(target_input, 'r') as f:
            targets = [t.strip() for t in f if t.strip()]
        
        console.print(f"[info][*] Batch Mode: Detected {len(targets)} targets. Launching Pool (Aggressive: {is_aggressive})...[/]")
        with Pool(processes=5) as pool:
            pool.map(run_batch_worker, [(t, is_aggressive) for t in targets])
    else:
        if target_input:
            LScanMaster(target_input, is_aggressive).run()
        else:
            console.print("[danger][!] Error: No target specified. Exiting...[/]")