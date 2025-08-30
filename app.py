# app.py
import json
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import ssl
import socket
import os
from openai import OpenAI
import ollama
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify

app = Flask(__name__)
app.secret_key = "socialclimatetech"


SCAN_CONFIG_FILE = "scanner_config.json"
AI_CONFIG_FILE = "config.json"

DEFAULT_SCAN_CONFIG = {
    "target": "https://socialclimate.tech",
    "common_ports": [21, 22, 25, 80, 443, 3306, 8080],
    "common_dirs": ["admin/", "backup/", "config/", "uploads/", "login/", "dashboard/", "api/", "data/", "docs/"],
    "xss_test_payloads": ["<script>alert('XSS')</script>", "\"><script>alert('XSS')</script>"],
    "sqli_test_payloads": ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"],
    "csrf_keywords": ["csrf", "token"]
}


def load_scan_config():
    if os.path.exists(SCAN_CONFIG_FILE):
        with open(SCAN_CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_SCAN_CONFIG.copy()


def save_scan_config(config):
    with open(SCAN_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# -------------------------------
# AI / Email config
# -------------------------------
AI_CONFIG_FILE = "config.json"
DEFAULT_AI_CONFIG = {
    "email": "",
    "app_password": "",
    "use_openai": False,
    "openai_api_key": "",
    "ollama_base_url": "http://localhost:11434/v1",
    "delete_processed": False
}


def load_ai_config():
    if os.path.exists(AI_CONFIG_FILE):
        with open(AI_CONFIG_FILE, "r") as f:
            return json.load(f)
    return DEFAULT_AI_CONFIG.copy()


def save_ai_config(config):
    with open(AI_CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


# Load CONFIG at startup
CONFIG = load_scan_config()
AI_CONFIG = load_ai_config()

# -------------------------------
# Helper: Save report
# -------------------------------
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)


def save_report(report_name, content):
    path = os.path.join(REPORTS_DIR, f"{report_name}.json")
    with open(path, "w") as f:
        json.dump(content, f, indent=2)
    print(f"[+] Report saved: {path}")
    return report_name + ".json"


def list_reports():
    return [f for f in os.listdir(REPORTS_DIR) if f.endswith(".json")]


def load_report(report_name):
    path = os.path.join(REPORTS_DIR, report_name)
    with open(path, "r") as f:
        return json.load(f)


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


def ai_explain(body, context="", system_prompt="You are a security expert AI assistant."):
    if not AI_CONFIG.get("use_openai", False) and not AI_CONFIG.get("ollama_base_url"):
        return "AI features are disabled in config.json"

    if CONFIG.get("use_openai"):
        try:
            client = OpenAI(api_key=AI_CONFIG["openai_api_key"])
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": f"{body}\n\nContext:\n{context}"}
                ]
            )
            return response.choices[0].message.content.strip()
        except Exception as e:
            print(e)
            return "Error connecting to OpenAI"

    else:
        try:
            ping = ollama.list()
            print("Ollama is running:", ping)
        except Exception:
            return "Ollama server is not running. Start it with: `ollama serve`"

        try:
            response = ollama.chat(
                model="llama3.2:latest",
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": body}
                ]
            )
            return response["message"]["content"].strip()
        except Exception as e:
            print(e)
            return "Error connecting to Ollama"


# -------------------------------
# Flask routes
@app.route("/", methods=["GET"])
def index():
    return render_template("index.html", config=CONFIG)


@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({"message": "Jörn Security Scanner API is running"})


@app.route("/scan", methods=["POST"])
def scan():
    # Placeholder: Run scan here with CONFIG
    result = {
        "target": CONFIG["target"],
        "scan_time": str(datetime.datetime.now()),
        "findings": {
            "xss": [],
            "sqli": [],
            "csrf": []
        }
    }

    report_file = save_report(result)
    return jsonify({"status": "completed", "report": report_file})


@app.route("/compare", methods=["POST"])
def compare_reports():
    files = request.json.get("files", [])
    if len(files) != 2:
        return jsonify({"error": "Please provide exactly 2 report filenames"}), 400

    try:
        with open(os.path.join(REPORTS_DIR, files[0]), "r") as f1, open(os.path.join(REPORTS_DIR, files[1]), "r") as f2:
            r1, r2 = json.load(f1), json.load(f2)

        # Simple comparison: difference in findings
        diff = {
            "new_findings": [f for f in r2["findings"] if f not in r1["findings"]],
            "resolved_findings": [f for f in r1["findings"] if f not in r2["findings"]]
        }

        explanation = ai_explain("Compare these two scan results", context=json.dumps(diff))
        return jsonify({"comparison": diff, "ai_explanation": explanation})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/ask", methods=["POST"])
def ask():
    user_question = request.json.get("question", "")
    context = ""

    # Add last report as context
    reports = list_reports()
    if reports:
        with open(os.path.join(REPORTS_DIR, reports[-1]), "r") as f:
            context = f.read()

    answer = ai_explain(user_question, context=context)
    return jsonify({"question": user_question, "answer": answer})


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
                with open(CONFIG, "w") as f:
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


# -------------------------------
# Reports List Page
# -------------------------------
@app.route("/reports/list", methods=["GET"])
def reports_list():
    try:
        reports_files = list_reports()
        return render_template("reports_list.html", reports=reports_files, config=CONFIG)
    except Exception as e:
        print(e)
        flash("Error loading reports list.")
        return redirect(url_for("index"))


# -------------------------------
# Report View Page (with full JSON display)
# -------------------------------
@app.route("/reports/view/<report_name>", methods=["GET"])
def report_view(report_name):
    try:
        report_data = load_report(report_name)
        return render_template("report_view.html", report=report_data, report_name=report_name, config=CONFIG)
    except Exception as e:
        print(e)
        flash(f"Error loading report {report_name}.")
        return redirect(url_for("reports_list"))


@app.route("/reports/delete/<report_name>", methods=["POST"])
def delete_report(report_name):
    try:
        path = os.path.join(REPORTS_DIR, report_name)
        if os.path.exists(path):
            os.remove(path)
            flash(f"Report {report_name} deleted.")
        else:
            flash(f"Report {report_name} not found.")
    except Exception as e:
        flash(f"Error deleting report: {e}")
    return redirect(url_for("reports_list"))


@app.route("/reports/<report_name>")
def view_report(report_name):
    try:
        report = load_report(report_name)
        return render_template("report.html", report=report, config=CONFIG, report_name=report_name)
    except Exception as e:
        flash(f"Could not load report: {e}", "danger")
        return redirect(url_for("reports_list"))


# List and delete reports (HTML)
# -------------------------------
@app.route("/reports", methods=["GET", "POST"])
def reports():
    if request.method == "POST":
        # handle delete action
        report_to_delete = request.form.get("delete_report")
        if report_to_delete:
            path = os.path.join(REPORTS_DIR, report_to_delete)
            if os.path.exists(path):
                os.remove(path)
                flash(f"Report {report_to_delete} deleted.", "success")
            else:
                flash(f"Report {report_to_delete} not found.", "danger")
        return redirect(url_for("reports"))

    report_files = list_reports()
    return render_template("reports_list.html", reports=report_files, config=CONFIG)


@app.route("/ask/ui", methods=["GET", "POST"])
def ask_ui():
    answer = None
    question = None
    selected_report = request.args.get("report")
    reports = list_reports()
    context = ""
    task = "summary"

    if selected_report and selected_report in reports:
        context = json.dumps(load_report(selected_report), indent=2)

    if request.method == "POST":
        question = request.form.get("question")
        chosen_report = request.form.get("report_select")
        task = request.form.get("task", "summary")

        if chosen_report:
            context = json.dumps(load_report(chosen_report), indent=2)

        # if no freeform question but a task was chosen -> use ai_explain_report
        if not question and chosen_report:
            report_data = load_report(chosen_report)
            answer = ai_explain_report(report_data, task=task)
        else:
            answer = ai_explain(question, context=context)

    return render_template(
        "ask.html",
        question=question,
        answer=answer,
        reports=reports,
        selected_report=selected_report,
        task=task
    )


def ai_explain_report(report, task="summary"):
    """
    task options:
    - summary: plain-language summary of the report
    - risk: rank issues by severity
    - explanation: explain each vulnerability in simple terms
    - patch: suggest secure code changes
    """
    body = f"Task: {task}\nReport:\n{json.dumps(report, indent=2)}"
    return ai_explain(body,
                      system_prompt="You are a cybersecurity AI assistant providing clear guidance to developers.")


@app.route("/compare/ui", methods=["GET", "POST"])
def compare_ui():
    reports = list_reports()
    diff = None
    score_card = None
    explanation = None

    # Pre-select report1 from query param
    selected_report1 = request.args.get("report1", "")

    if request.method == "POST":
        r1_name = request.form.get("report1")
        r2_name = request.form.get("report2")

        if not r1_name or not r2_name:
            flash("Please select two reports", "warning")
            return redirect(url_for("compare_ui"))

        r1, r2 = load_report(r1_name), load_report(r2_name)

        diff = {
            "new_findings": [f for f in r2.get("xss", []) + r2.get("sqli", [])
                             if f not in r1.get("xss", []) + r1.get("sqli", [])],
            "resolved_findings": [f for f in r1.get("xss", []) + r1.get("sqli", [])
                                  if f not in r2.get("xss", []) + r2.get("sqli", [])],
        }

        score_card = {
            "report1_issues": len(r1.get("xss", [])) + len(r1.get("sqli", [])),
            "report2_issues": len(r2.get("xss", [])) + len(r2.get("sqli", [])),
            "new_issues": len(diff["new_findings"]),
            "resolved_issues": len(diff["resolved_findings"]),
        }

        explanation = ai_explain(
            "Compare two scan reports and explain the differences, suggest priorities",
            context=json.dumps({"diff": diff, "score_card": score_card}, indent=2)
        )

    return render_template(
        "compare.html",
        reports=reports,
        diff=diff,
        explanation=explanation,
        score_card=score_card,
        selected_report1=selected_report1
    )


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
        filename = f"report_{stamp}.json"
        filepath = os.path.join(REPORTS_DIR, filename)
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        print(f"[+] Report saved: {filepath}")

    except Exception as e:
        print(e)

    return render_template("report.html", report=report, config=CONFIG, report_filename=filename)


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
