# Vörn - Mini Penetration Testing Framework

**Vörn** (Old Norse for "Protection") is a lightweight, web-based penetration testing framework built in Python using Flask, Jinja2, and Bootstrap 5.  
It allows security enthusiasts and developers to perform basic automated security scans on **publicly accessible endpoints** for sites they own or have permission to test.

## Features

- Configurable target site and payloads via a web-based **Settings page**  
- Scan menu with individual options or full scan:
  1. Security Headers
  2. SSL Certificate
  3. Open Ports
  4. Directory / Endpoint Discovery
  5. XSS Test
  6. SQL Injection (SQLi) Test
  7. CSRF Detection
  8. Form Fuzzing (XSS + SQLi)
  9. Full Scan
- Endpoint crawling and discovery  
- Automatic form fuzzing with XSS and SQLi payloads  
- CSRF detection for missing tokens in POST forms  
- Color-coded HTML report and saved JSON snapshots  
- Bootstrap 5 interface, responsive and mobile-friendly  
- Safe for OAuth-only sites (scans **public endpoints only**)  

## Installation

1. Clone the repository:

```bash
git clone https://github.com/tottaz/sct-v-rn.git
cd sct-vorn
```

2. Install required Python packages:

```bash
pip install -r requirements.txt
```

Run the app:

```bash
python app.py
```

Open a web browser and go to http://127.0.0.1:5000

Usage

Navigate to the Settings page to configure:

Target site URL

Common ports

Common directories

XSS payloads

SQLi payloads

CSRF keywords

From the Menu, select individual tests or run a full scan.

View the color-coded report in the browser; JSON snapshots are saved automatically.

Safety Notice

Only use Vörn on sites you own or have explicit permission to test.

Do not attempt to bypass OAuth or authentication mechanisms.

This is a learning and internal auditing tool, not for illegal penetration testing.

License

MIT License

Contribution

Contributions are welcome! Feel free to submit pull requests or open issues.

Author: Social CLimate Tech
GitHub: https://github.com/tottaz/sct-v-rn

AI Setup (Optional)

Install Ollama
```bash
https://www.ollama.com/
```

Pull a local model:

```bash
ollama pull codellama
```

Start Ollama (runs on http://localhost:11434 by default).

API Endpoints

POST /scan → run a scan and save report

GET /reports → list all reports

POST /compare → compare two reports and get AI explanation

POST /ask → ask AI about latest report
