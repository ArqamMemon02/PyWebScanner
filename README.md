# Web Vulnerability Scanner

A Python-based web vulnerability scanner that crawls authenticated web applications and tests for common security flaws. Built as a portfolio project to demonstrate practical knowledge of web security concepts and offensive tooling.

Tested against DVWA(Damn Vulnerable Web Application) (https://github.com/digininja/DVWA) running locally via Docker.

## What It Does

The scanner logs into a target web app, crawls all reachable pages, and runs five vulnerability checks:

- SQL Injection — injects payloads into form fields and checks responses for database error strings
- Cross-Site Scripting (XSS) — submits script tags into forms and checks if they appear unescaped in the response
- Directory Traversal — injects `../` sequences into URL parameters and looks for `/etc/passwd` signatures
- Sensitive File Exposure — probes common paths like `/.env`, `/.git/config`, `/phpinfo.php` for readable content
- Open Redirect — injects an external URL into redirect-like parameters and checks the `Location` header

Results are printed to the terminal and saved to a timestamped `.txt` report file.

---

## Requirements

- Python 3.8+
- requests
- beautifulsoup4

Install dependencies:

bash
pip install requests beautifulsoup4

## Setup

The scanner is configured for DVWA by default. To run it yourself:

**1. Start DVWA with Docker:**

bash
docker run -d -p 8080:80 --name dvwa vulnerables/web-dvwa


**2. Open http://localhost:8080 in your browser, log in with admin / password, and click "Create / Reset Database".**

**3. Set the security level to "Low" at `http://localhost:8080/security.php`.**

**4. Update the config block at the top of `web_vuln_scanner.py` to match your setup:**

python
TARGET_URL = "http://localhost:8080/"
LOGIN_URL  = "http://localhost:8080/login.php"
USERNAME   = "admin"
PASSWORD   = "password"


**5. Run the scanner:**

bash
python web_vuln_scanner.py

## Sample Output


[*] Logged in as admin
[*] Starting crawl on http://localhost:8080/
...
[*] Crawl complete.
    URLs visited    : 33
    Pages with forms: 18

STAGE 2 — SQL INJECTION SCAN
[!] Found 4 SQL injection vulnerabilities

  URL     : http://localhost:8080/vulnerabilities/sqli/
  Payload : '
  Error   : you have an error in your sql syntax

STAGE 3 — XSS SCAN
[!] Found 3 XSS vulnerabilities

  URL     : http://localhost:8080/vulnerabilities/xss_r/
  Payload : <script>alert('XSS')</script>
  Method  : GET

...

[*] Report saved to: report_2026-04-09_23-38-29.txt


---

## Report Format

Each scan generates a `.txt` report in the working directory:

```
============================================================
        WEB VULNERABILITY SCANNER — REPORT
============================================================
  Target        : http://localhost:8080/
  Scanned       : 2026-04-09 23:38:29
  URLs Found    : 33
  Total Findings: 8

[ SUMMARY ]

  Vulnerability                  Findings
  ------------------------------ --------
  SQL Injection                         4
  Cross-Site Scripting (XSS)            3
  Directory Traversal                   0
  Sensitive File Exposure               1
  Open Redirect                         0
  ...


## How Each Scanner Works

**SQL Injection**
Submits payloads like `'` and `' OR 1=1--` into every text field on every form. If the response contains a database error string (e.g. `you have an error in your sql syntax`), the field is flagged as injectable.

**XSS**
Submits `<script>alert('XSS')</script>` into form fields. If the exact string appears in the response HTML without encoding, the page reflects unsanitized input.

**Directory Traversal**
Takes every URL with a query parameter and replaces its value with `../` sequences targeting `/etc/passwd`. Checks the response for known file signatures like `root:x:0:0`.

**Sensitive File Exposure**
Requests a list of commonly misconfigured paths directly. Flags any that return HTTP 200 and contain recognizable content signatures (e.g. `DB_PASSWORD` in a `.env` file).

**Open Redirect**
Injects `http://evil.com` into URL parameters with redirect-like names (`url`, `next`, `redirect`, etc.). Checks if the server responds with a `Location` header pointing to the injected URL.

---

## Limitations

- Only tests forms found by crawling — does not fuzz arbitrary endpoints
- SQL injection detection relies on error-based responses only (no blind injection)
- XSS detection is reflected only — does not detect DOM-based XSS
- Directory traversal is Linux-focused (`/etc/passwd`) — Windows paths not covered
- Requires valid credentials for authenticated targets
