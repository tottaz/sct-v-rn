# app.py
import json
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ssl
import socket
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash

app = Flask(__name__)
app.secret_key = "change-me-to-a-secure-random-value"

# -------------------------------
# Default configuration (can be edited in UI)
CONFIG_FILE = "scanner_config.json"
DEFAULT_CONFIG = {
  "target": "https://socialclimate.tech",
  "common_ports": [21, 22, 25, 80, 443, 3306, 8080],
  "common_dirs": ["admin/", "backup/", "config/", "uploads/", "login/", "dashboard/", "api/", "data/", "docs/"],
  "xss_test_payloads": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"],
  "sqli_test_payloads": ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"],
  "csrf_keywords": ["csrf", "token"]
}

try:
    with open(CONFIG_FILE, "r") as f:
        CONFIG = json.load(f)
except Exception as e:
    print(e)
    CONFIG = DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(CONFIG, f, indent=2)
    except Exception as e:
        print(e)

# -------------------------------
# Globals used per-scan
SESSION = requests.Session()


# report structure
def new_report():
    return {
        "meta": {
            "target": CONFIG.get("target"),
            "started": str(datetime.now())
        },
        "headers": [],
        "ssl": [],
        "ports": [],
        "endpoints": [],
        "xss": [],
        "sqli": [],
        "csrf": [],
        "form_fuzz": []
    }


# ===============================
# Security Headers
def check_security_headers(url, report):

    try:
        r = SESSION.get(url, timeout=10)
        headers = ["Strict-Transport-Security", "Content-Security-Policy",
                   "X-Frame-Options", "X-Content-Type-Options",
                   "Referrer-Policy", "Permissions-Policy"]
        for h in headers:
            report["headers"].append(h + ": " + str(r.headers.get(h)))
    except Exception as e:
        print(e)


# ===============================
# SSL Check
def check_ssl_cert(hostname, report):

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=hostname)
        conn.settimeout(5)
        conn.connect((hostname, 443))
        cert = conn.getpeercert()
        report["ssl"].append({
            "issuer": dict(x[0] for x in cert["issuer"]),
            "valid_from": cert["notBefore"],
            "valid_until": cert["notAfter"]
        })
        conn.close()
    except Exception as e:
        print(e)


# ===============================
# Open Ports
def check_open_ports(hostname, report):

    for port in CONFIG.get("common_ports", []):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((hostname, port))
            report["ports"].append((port, result == 0))
            sock.close()
        except Exception as e:
            print(e)


# ===============================
# Endpoint Discovery
def crawl_site(base_url, report):

    visited = set()
    endpoints = set()

    def crawl(url):
        try:
            if url in visited:
                return
            visited.add(url)
            r = SESSION.get(url, timeout=7)
            endpoints.add(url)
            soup = BeautifulSoup(r.text, "html.parser")
            for link in soup.find_all("a", href=True):
                href = link['href']
                full_url = urljoin(base_url, href)
                if urlparse(full_url).netloc == urlparse(base_url).netloc:
                    crawl(full_url)
        except Exception as e:
            print(e)

    crawl(base_url)
    for d in CONFIG.get("common_dirs", []):
        endpoints.add(urljoin(base_url, d))
    report["endpoints"].extend(sorted(list(endpoints)))
    return list(endpoints)


# ===============================
# XSS Test Only
def test_xss(endpoints, report):

    for url in endpoints:
        for payload in CONFIG.get("xss_test_payloads", []):
            try:
                test_url = urljoin(url, "?q=" + payload)
                r = SESSION.get(test_url, timeout=7)
                if r and payload in r.text:
                    report["xss"].append(test_url)
            except Exception as e:
                print(e)


# ===============================
# SQLi Test Only
def test_sqli(endpoints, report):

    for url in endpoints:
        for payload in CONFIG.get("sqli_test_payloads", []):
            try:
                test_url = urljoin(url, "?id=" + payload)
                r = SESSION.get(test_url, timeout=7)
                if r and any(err in r.text.lower() for err in ["sql syntax", "mysql", "unclosed quotation"]):
                    report["sqli"].append(test_url)
            except Exception as e:
                print(e)


# ===============================
# CSRF Detection
def check_csrf(endpoints, report):

    for url in endpoints:
        try:
            r = SESSION.get(url, timeout=7)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form", method="post")
            for f in forms:
                inputs = f.find_all("input")
                if not any(CONFIG.get("csrf_keywords", ["csrf"])[0] in i.get('name', '').lower() for i in inputs):
                    report["csrf"].append(url)
        except Exception as e:
            print(e)


# ===============================
# Automatic Form Fuzzing (XSS + SQLi + CSRF)
def form_fuzz(endpoints, report):

    for url in endpoints:
        try:
            r = SESSION.get(url, timeout=7)
            soup = BeautifulSoup(r.text, "html.parser")
            forms = soup.find_all("form")
            for f in forms:
                action = f.get('action') or url
                method = f.get('method', 'get').lower()
                inputs = f.find_all("input")
                for payload in CONFIG.get("xss_test_payloads", []) + CONFIG.get("sqli_test_payloads", []):
                    data = {}
                for i in inputs:
                    name = i.get("name")
                    if name:
                        data[name] = payload
                try:
                    if method == "post":
                        r2 = SESSION.post(urljoin(url, action), data=data, timeout=7)
                    else:
                        r2 = SESSION.get(urljoin(url, action), params=data, timeout=7)
                    if payload in r2.text:
                        report["form_fuzz"].append("[" + payload + "] " + url)
                except Exception as e:
                    print(e)
        except Exception as e:
            print(e)


# ===============================
# HTML Report (rendered with template)
def generate_report(filename="pentest_report.html", report=None):

    try:
        # here we just save a JSON snapshot for later or download
        with open(filename, "w") as f:
            f.write("Report generated at: " + str(datetime.now()) + "\n\n")
            f.write(json.dumps(report, indent=2))
            return True
    except Exception as e:
        print(e)
        return False


# -------------------------------
# Flask routes
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", config=CONFIG)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if request.method == "POST":
        try:
            # basic form fields, update CONFIG and save
            CONFIG["target"] = request.form.get("target", CONFIG.get("target"))
            ports_raw = request.form.get("common_ports", ",".join([str(p) for p in CONFIG.get("common_ports", [])]))
            try:
                CONFIG["common_ports"] = [int(x.strip()) for x in ports_raw.split(",") if x.strip()]
            except Exception as e:
                print(e)
            dirs_raw = request.form.get("common_dirs", ",".join(CONFIG.get("common_dirs", [])))
            CONFIG["common_dirs"] = [x.strip() for x in dirs_raw.split(",") if x.strip()]
            xss_raw = request.form.get("xss_test_payloads", ",".join(CONFIG.get("xss_test_payloads", [])))
            CONFIG["xss_test_payloads"] = [x for x in [s.strip() for s in xss_raw.split(",")] if x]
            sqli_raw = request.form.get("sqli_test_payloads", ",".join(CONFIG.get("sqli_test_payloads", [])))
            CONFIG["sqli_test_payloads"] = [x for x in [s.strip() for s in sqli_raw.split(",")] if x]
            csrf_raw = request.form.get("csrf_keywords", ",".join(CONFIG.get("csrf_keywords", [])))
            CONFIG["csrf_keywords"] = [x.strip() for x in csrf_raw.split(",") if x.strip()]
            try:
                with open(CONFIG_FILE, "w") as f:
                    json.dump(CONFIG, f, indent=2)
            except Exception as e:
                print(e)
            flash("Settings saved.")
            return redirect(url_for("settings"))
        except Exception as e:
            print(e)
        flash("Error saving settings.")
        return redirect(url_for("settings"))

    return render_template("settings.html", config=CONFIG)


@app.route("/run", methods=["POST"])
def run_scan():
    # which scan: headers, ssl, ports, crawl, xss, sqli, csrf, fuzz, full
    kind = request.form.get("kind", "full")
    report = new_report()
    host = urlparse(CONFIG.get("target")).netloc
    endpoints = []

    try:
        if kind == "headers":
            check_security_headers(CONFIG.get("target"), report)
        elif kind == "ssl":
            check_ssl_cert(host, report)
        elif kind == "ports":
            check_open_ports(host, report)
        elif kind == "crawl":
            endpoints = crawl_site(CONFIG.get("target"), report)
        elif kind == "xss":
            if not endpoints:
                endpoints = crawl_site(CONFIG.get("target"), report)
            test_xss(endpoints, report)
        elif kind == "sqli":
            if not endpoints:
                endpoints = crawl_site(CONFIG.get("target"), report)
            test_sqli(endpoints, report)
        elif kind == "csrf":
            if not endpoints:
                endpoints = crawl_site(CONFIG.get("target"), report)
            check_csrf(endpoints, report)
        elif kind == "fuzz":
            if not endpoints:
                endpoints = crawl_site(CONFIG.get("target"), report)
            form_fuzz(endpoints, report)
        else:
            # full
            endpoints = crawl_site(CONFIG.get("target"), report)
            check_security_headers(CONFIG.get("target"), report)
            check_ssl_cert(host, report)
            check_open_ports(host, report)
            test_xss(endpoints, report)
            test_sqli(endpoints, report)
            check_csrf(endpoints, report)
            form_fuzz(endpoints, report)
    except Exception as e:
        print(e)
        flash("Error during scan: " + str(e))

    # save JSON snapshot to disk (optional)
    try:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = "report_" + stamp + ".json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)
    except Exception as e:
        print(e)

    return render_template("report.html", report=report, config=CONFIG)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
