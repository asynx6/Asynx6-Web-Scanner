# Installation

Requires **Python 3.10+**.

## From source

```bash
git clone https://github.com/asynx6/Asynx6-Web-Scanner.git
cd Asynx6-Web-Scanner
pip install -r requirements.txt
playwright install chromium
```

## From PyPI (when published)

```bash
pip install asynx6-web-scanner
playwright install chromium
```

## Optional dependencies

| Feature | Package |
|---|---|
| Web dashboard | `pip install fastapi uvicorn` |
| ML false-positive filter | `pip install scikit-learn` |
| Notifications | (uses `requests`, already installed) |

## Verify installation

```bash
python index.py --version
```