"""Translation strings (English default + Indonesian)."""

from __future__ import annotations


EN: dict[str, str] = {
    "scan.start": "Starting scan",
    "scan.target": "Target",
    "scan.aggressive": "Aggressive mode",
    "scan.completed": "Scan completed",
    "scan.findings": "Findings",
    "scan.subdomains": "Subdomains",
    "scan.loot": "Loot items",
    "phase.subdomain": "Subdomain recon",
    "phase.network": "Network recon",
    "phase.headless": "Headless SPA crawler",
    "phase.crawler": "Spidering",
    "phase.vuln": "Vulnerability audit",
    "phase.fuzz": "Smart fuzzing",
    "phase.dns": "DNS enum",
    "phase.wayback": "Wayback historical",
    "vuln.found": "Finding detected",
    "report.written": "Report written",
    "error.no_target": "No target specified. Exiting.",
    "error.scan_failed": "Scan failed",
}

ID: dict[str, str] = {
    "scan.start": "Memulai pemindaian",
    "scan.target": "Target",
    "scan.aggressive": "Mode agresif",
    "scan.completed": "Pemindaian selesai",
    "scan.findings": "Temuan",
    "scan.subdomains": "Subdomain",
    "scan.loot": "Item jarahan",
    "phase.subdomain": "Pengintaian subdomain",
    "phase.network": "Pengintaian jaringan",
    "phase.headless": "Perayap SPA headless",
    "phase.crawler": "Spidering",
    "phase.vuln": "Audit kerentanan",
    "phase.fuzz": "Fuzzing cerdas",
    "phase.dns": "Enumerasi DNS",
    "phase.wayback": "Riwayat Wayback",
    "vuln.found": "Temuan terdeteksi",
    "report.written": "Laporan ditulis",
    "error.no_target": "Tidak ada target. Keluar.",
    "error.scan_failed": "Pemindaian gagal",
}


SUPPORTED = ["en", "id"]