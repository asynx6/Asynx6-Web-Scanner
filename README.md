# 🚀 Asynx6 Web Scanner (V1.0)

**Asynx6 Web Scanner** is an advanced web security reconnaissance suite developed in Python. It is engineered to detect sensitive file leakages, hidden directory structures, and server misconfigurations with high precision.

Equipped with **Apex Predator Logic**, this scanner effectively filters out false positives typically triggered by WAF or CDN protections (such as HCDN), ensuring that only actionable intelligence is reported.

---

## ✨ Key Features

-   **HCDN/WAF Bypass Logic**: Utilizes advanced header morphing techniques to penetrate Edge Network protections.
-   **SPA Baseline Detection**: Intelligently distinguishes between actual sensitive files and soft-404/redirect pages common in Single Page Applications.
-   **Smart Contextual Fuzzing**: Dynamically generates wordlists by extracting keywords from the target's live content.
-   **High-Concurrency Engine**: Multi-threaded execution with adjustable performance scales for rapid auditing.
-   **Pure Gold Filter**: Automatically discards common JavaScript library noise to focus exclusively on hardcoded secrets, API keys, and credentials.
-   **Automated PoC Reporting**: Consolidates findings into structured Markdown reports and compressed loot archives.

## 🛠️ Installation

Ensure you have **Python 3.10+** installed on your system.

1. **Clone the Repository**
   ```bash
   git clone https://github.com/asynx6/Asynx6-Web-Scanner.git
   cd Asynx6-Web-Scanner
   ```

2. **Set Up a Virtual Environment** (Recommended)
   ```bash
   python -m venv venv
   # Windows:
   venv\Scripts\activate
   # Linux/Mac:
   source venv/bin/activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Headless Engine (Playwright)**
   ```bash
   playwright install chromium
   ```

---

## 🚀 Usage

Launch the main engine and follow the interactive terminal prompts:
```bash
python index.py
```

### Scanning Modes:
- **Normal Mode**: Optimized for speed and standard reconnaissance.
- **Aggressive Mode**: Deep-fuzzing targeting sensitive system directories (Laravel, Git, Environment backups, and Config archives).

---

## 📋 System Requirements

The following core libraries are required (automatically managed via `requirements.txt`):
- **requests**: Robust HTTP handling with custom morphing headers.
- **rich**: For the advanced terminal-based Dashboard UI and real-time logs.
- **beautifulsoup4**: Contextual keyword extraction and DOM structure parsing.
- **playwright**: Powers the Dewa-Level Headless Engine for SPA crawling.
- **mysql-connector-python**: Required for direct DB infrastructure auditing.

---

## ⚠️ Disclaimer

This tool is strictly for educational purposes and authorized security auditing. The author (**asynx6**) assumes no liability for any misuse, unauthorized access, or damage caused by this software. Use only on targets where you have explicit, written consent.