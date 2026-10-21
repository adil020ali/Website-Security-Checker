"""Website Security Checker - educational defensive tool.

Checks a public HTTPS site for: verified HTTPS connection, TLS certificate
details, redirects, and selected HTTP security headers.
Use ONLY on sites you own or have permission to assess.
"""
import csv
import io
import ipaddress
import os
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests
from flask import Flask, Response, jsonify, render_template, request

app = Flask(__name__)

TIMEOUT = 8
MAX_REDIRECTS = 3
MAX_BODY_BYTES = 1_000_000  # we never download more than this

# header -> (what it does, recommendation when missing)
SECURITY_HEADERS = {
    "Strict-Transport-Security": (
        "Encourages browsers to keep using HTTPS after a secure visit.",
        "Enable HSTS only after HTTPS works across all intended hosts, "
        "e.g. max-age=31536000.",
    ),
    "Content-Security-Policy": (
        "Restricts the sources scripts, styles, images and other content may load from.",
        "Create a policy that fits the site's resources; test it in "
        "report-only mode first.",
    ),
    "X-Content-Type-Options": (
        "Helps prevent MIME-type sniffing.",
        "Consider setting the value to nosniff.",
    ),
    "X-Frame-Options": (
        "Controls whether pages may be shown inside frames.",
        "Choose a framing policy (DENY or SAMEORIGIN); CSP frame-ancestors "
        "is also relevant.",
    ),
    "Referrer-Policy": (
        "Controls how much referrer information is shared with other sites.",
        "Choose a policy suited to the site's privacy needs, e.g. "
        "strict-origin-when-cross-origin.",
    ),
    "Permissions-Policy": (
        "Restricts selected browser features (camera, microphone, etc.).",
        "Disable features the site does not need, after testing.",
    ),
}

# Example values shown in the "how to fix" panel.
EXAMPLES = {
    "Strict-Transport-Security": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "X-Content-Type-Options: nosniff",
    "X-Frame-Options": "X-Frame-Options: SAMEORIGIN",
    "Referrer-Policy": "Referrer-Policy: strict-origin-when-cross-origin",
    "Permissions-Policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
}

# Headers that may reveal technology details (informational only).
DISCLOSURE_HEADERS = ("Server", "X-Powered-By")


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------
def resolve_public_addresses(host):
    """Resolve host and make sure every address is public. Returns the IPs."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise ValueError("The hostname could not be resolved.")
    addresses = []
    for item in infos:
        ip = item[4][0].split("%")[0]
        if ip not in addresses:
            addresses.append(ip)
    if not addresses:
        raise ValueError("No IP addresses were found.")
    for ip in addresses:
        if not ipaddress.ip_address(ip).is_global:
            raise ValueError("Private or non-public destinations are blocked.")
    return addresses


def validate_public_url(url):
    """Basic validation for an educational, local prototype."""
    if not url:
        raise ValueError("Enter a valid HTTPS URL.")
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("Enter a valid HTTPS URL (it must start with https://).")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing credentials are not allowed.")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL contains an invalid port.")
    if port not in (None, 443):
        raise ValueError("Only the standard HTTPS port is allowed.")
    resolve_public_addresses(parsed.hostname)
    return parsed


# --------------------------------------------------------------------------
# TLS certificate inspection
# --------------------------------------------------------------------------
def _name_to_str(rdns):
    parts = {}
    for rdn in rdns or ():
        for key, value in rdn:
            parts[key] = value
    return parts.get("organizationName") or parts.get("commonName") or "Unknown"


def inspect_certificate(host):
    """Open a verified TLS connection and return certificate metadata.

    Verification and hostname checking stay enabled (default context).
    """
    ip = resolve_public_addresses(host)[0]
    ctx = ssl.create_default_context()
    with socket.create_connection((ip, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    not_after = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc
    )
    not_before = datetime.fromtimestamp(
        ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc
    )
    days_left = (not_after - datetime.now(timezone.utc)).days
    sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
    return {
        "issuer": _name_to_str(cert.get("issuer")),
        "subject": _name_to_str(cert.get("subject")),
        "valid_from": not_before.strftime("%Y-%m-%d"),
        "valid_until": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "tls_version": version,
        "sans": sans[:10],
    }


# --------------------------------------------------------------------------
# Scanning
# --------------------------------------------------------------------------
def fetch(url):
    """GET with manual redirect handling; every hop is validated as HTTPS/public."""
    chain = []
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        validate_public_url(current)
        resp = requests.get(
            current,
            timeout=TIMEOUT,
            allow_redirects=False,
            verify=True,
            stream=True,  # do not download the body
            headers={"User-Agent": "BeginnerSecurityChecker/1.0"},
        )
        resp.close()
        chain.append((current, resp.status_code))
        if resp.status_code in (301, 302, 303, 307, 308) and resp.headers.get("Location"):
            current = urljoin(current, resp.headers["Location"])
            continue
        return resp, chain
    return resp, chain  # redirect limit reached


def check_header(name, value):
    """Return (status, details) for one security header."""
    explanation, recommendation = SECURITY_HEADERS[name]
    if not value:
        return "Warning", "Header not found in the response."
    if name == "Strict-Transport-Security":
        digits = "".join(
            c for c in value.lower().split("max-age=")[-1].split(";")[0] if c.isdigit()
        )
        if "max-age=" not in value.lower() or not digits or int(digits) < 15552000:
            return "Warning", f"Present: {value}. max-age looks short (6+ months recommended)."
    if name == "X-Content-Type-Options" and value.strip().lower() != "nosniff":
        return "Warning", f"Present: {value}. Expected the value nosniff."
    return "Pass", f"Present: {value}"


def scan_website(url):
    parsed = validate_public_url(url)
    host = parsed.hostname
    response, chain = fetch(url)

    results = [{
        "name": "HTTPS connection",
        "status": "Pass",
        "details": "A verified HTTPS request succeeded (certificate chain and hostname verified).",
    }]

    # Certificate
    cert = None
    try:
        cert = inspect_certificate(host)
        if cert["days_left"] < 0:
            status, msg = "Fail", "The certificate has expired."
        elif cert["days_left"] < 30:
            status, msg = "Warning", f"Expires in {cert['days_left']} days. Renew soon."
        else:
            status, msg = "Pass", f"Valid for another {cert['days_left']} days."
        results.append({"name": "TLS certificate", "status": status, "details": msg})
    except (ssl.SSLError, OSError, KeyError, ValueError):
        results.append({
            "name": "TLS certificate",
            "status": "Info",
            "details": "Certificate details could not be read.",
        })

    # Redirects
    if len(chain) > 1:
        hops = " → ".join(f"{u} ({c})" for u, c in chain)
        results.append({
            "name": "Redirects",
            "status": "Info",
            "details": f"{len(chain) - 1} redirect(s) followed, each re-validated: {hops}",
        })
        if chain[-1][1] in (301, 302, 303, 307, 308):
            results.append({
                "name": "Redirect limit",
                "status": "Warning",
                "details": f"Stopped after {MAX_REDIRECTS} redirects; headers below are from the last response.",
            })

    # Headers
    headers = {k.lower(): v for k, v in response.headers.items()}
    for header in SECURITY_HEADERS:
        status, details = check_header(header, headers.get(header.lower()))
        results.append({
            "name": header, "status": status, "details": details,
            "what": SECURITY_HEADERS[header][0],
            "fix": SECURITY_HEADERS[header][1] if status != "Pass" else "",
            "example": EXAMPLES[header] if status != "Pass" else "",
        })

    for header in DISCLOSURE_HEADERS:
        value = headers.get(header.lower())
        if value:
            results.append({
                "name": header,
                "status": "Info",
                "details": f"Present: {value}. Reveals technology details; consider limiting.",
            })

    counts = {s: sum(1 for r in results if r["status"] == s)
              for s in ("Pass", "Warning", "Fail", "Info")}
    scored = counts["Pass"] + counts["Warning"] + counts["Fail"]
    score = round(100 * counts["Pass"] / scored) if scored else 0
    return {
        "score": score,
        "url": host,
        "final_url": chain[-1][0],
        "http_status": response.status_code,
        "cert": cert,
        "results": results,
        "counts": counts,
        "scanned_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def run_scan(url):
    """Run a scan and return (report, error)."""
    try:
        return scan_website(url), None
    except ValueError as exc:
        return None, str(exc)
    except requests.exceptions.SSLError:
        return None, "TLS certificate verification failed. The site's certificate is not trusted."
    except requests.exceptions.Timeout:
        return None, "The request timed out."
    except requests.exceptions.RequestException:
        return None, "The request failed. Check the address and try again."


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    report = error = None
    url = ""
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        report, error = run_scan(url)
    return render_template("index.html", report=report, error=error, url=url)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """JSON endpoint used by the interactive page (no page reload)."""
    data = request.get_json(silent=True) or {}
    report, error = run_scan(str(data.get("url", "")).strip())
    if error:
        return jsonify({"error": error}), 400
    return jsonify(report)


@app.route("/export", methods=["POST"])
def export():
    """Download the report for a URL as CSV (re-runs the scan)."""
    url = request.form.get("url", "").strip()
    report, error = run_scan(url)
    if error:
        return Response(error, status=400, mimetype="text/plain")
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Host", report["url"]])
    writer.writerow(["Scanned at", report["scanned_at"]])
    writer.writerow(["HTTP status", report["http_status"]])
    writer.writerow([])
    writer.writerow(["Check", "Status", "Details"])
    for r in report["results"]:
        # Prefix risky leading characters to prevent spreadsheet formula injection
        details = r["details"]
        if details[:1] in ("=", "+", "-", "@"):
            details = "'" + details
        writer.writerow([r["name"], r["status"], details])
    filename = f"security-report-{report['url']}.csv"
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.after_request
def add_security_headers(resp):
    """The checker should follow its own advice."""
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
    )
    return resp


if __name__ == "__main__":
    # Debug mode is OFF by default. Enable locally with: FLASK_DEBUG=1 python app.py
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
