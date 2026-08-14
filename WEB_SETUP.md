# Aegis Web Setup Guide

Simple local web interface for the Aegis security assessment tool.

## Installation

### Prerequisites
- Python 3.8+
- pip (Python package manager)

### Setup Steps

1. **Install dependencies:**
```bash
pip install -r requirements.txt
```

2. **Run the web app:**
```bash
python app.py
```

3. **Open in browser:**
```
http://127.0.0.1:5050
```

That's it! 🎉

> **Why port 5050 and not 5000?** On macOS, port 5000 is claimed by the
> **AirPlay Receiver** (part of ControlCenter), which binds `*:5000` on both
> IPv4 and IPv6 and answers every HTTP request with `403 Forbidden` —
> "You don't have authorization to view this page". Aegis defaults to 5050 to
> sidestep it. Override with `AEGIS_PORT=8080 python app.py`.

## Features

✅ **Web Interface** - No CLI needed  
✅ **Local Storage** - SQLite database (`aegis_results.db`)  
✅ **Scan History** - View all previous scans  
✅ **Customer Exports** - Download raw results as TXT or JSON  
✅ **Risk Vectors** (in assessment order):
   1. Web Application Security
   2. SSL/TLS Configuration
   3. SSL/TLS Certificates
   4. Open Ports
   5. Email Security (SPF/DKIM/DMARC)

> DNS Analysis is CLI-only (`python main.py`, option 6) and is intentionally
> not exposed in the web version.

## Exporting for Customers

Both buttons sit in the **Scan Results** header:

- **Export TXT** — a plain-text report: a short header (risk vector, target,
  timestamp, status) followed by the **raw scanner output verbatim**. This is
  the evidence-style artifact to hand to a customer.
- **Export JSON** — machine-readable. Same raw output under `raw_output`, plus
  a `findings[]` array where each entry carries `section`, `severity`
  (`pass` / `fail` / `warning` / `info` / `detail`) and the **verbatim**
  message, and a `summary` with severity counts.

Finding text is never reworded — only the section and severity are attached.

Direct URLs, if you want to script it:
```
/api/export/<scan_id>?format=txt
/api/export/<scan_id>?format=json
```

## File Structure

```
aegis-web/
├── app.py                 # Flask web app
├── requirements.txt       # Python dependencies
├── aegis_results.db      # SQLite database (created on first run)
├── templates/
│   └── index.html        # Main web page
├── static/
│   ├── style.css         # Styling
│   └── app.js            # Frontend logic
└── scanners/             # Your existing scanners
```

## How It Works

1. **Select a scanner** from dropdown
2. **Enter target** (domain or IP)
3. **Optional: Add port** (e.g., 443 or 161/udp)
4. **Click "Start Scan"**
5. **Results appear** in scan history
6. **Click scan** to view full results
7. **Export as JSON** if needed

## Stopping the App

Press `Ctrl+C` in the terminal to stop the server.

## Notes

- Database file (`aegis_results.db`) stays on your machine
- No data is sent anywhere
- Fully local and private
- Results persist between restarts
- Add `--host 0.0.0.0` to `app.py` to allow other machines to connect (not recommended without auth)

## Troubleshooting

**HTTP 403 "You don't have authorization to view this page"?**

You're hitting macOS AirPlay Receiver, not Aegis. Confirm with:
```bash
lsof -nP -iTCP:5000
```
If you see `ControlCe`, that's AirPlay. Either use the default port 5050, or
disable *AirPlay Receiver* in System Settings → General → AirDrop & Handoff.

**Port already in use?**
```bash
AEGIS_PORT=8080 python app.py
```

**Dependencies not installing?**
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

**sslscan not found?**
```bash
# macOS
brew install sslscan

# Ubuntu/Debian
sudo apt install sslscan

# Other systems - see https://github.com/rbsec/sslscan
```

---

Happy scanning! 🛡️
