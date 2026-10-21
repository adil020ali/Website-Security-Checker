# Website Security Checker

A small Flask app that checks the public security setup of a website. Enter an
HTTPS address and it reports on the certificate, redirects and common HTTP
security headers, then suggests how to improve anything that is missing.

> **Use it only on websites you own or have permission to test.**
> This is a learning project, not a full vulnerability scanner.

## What it checks

- **HTTPS connection:** a request with certificate and hostname verification on
- **TLS certificate:** issuer, start and end dates, days left, TLS version
- **Redirects:** up to 3, each one checked again before it is followed
- **Security headers:**
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Content-Type-Options
  - X-Frame-Options
  - Referrer-Policy
  - Permissions-Policy
- **Technology headers:** notes `Server` and `X-Powered-By` if they are shown

A missing header is an observation, not proof of a vulnerability. The right
settings depend on the site, so the score is a snapshot and not a verdict.

## Features

- Scans without reloading the page, with a loading screen
- Score ring out of 100 (the share of checks that passed)
- Filter results by Pass, Warning, Fail or Note
- Expandable cards with an explanation, a fix and a copyable example header
- Light and dark theme
- Last 5 scanned addresses, saved in the browser
- Download the report as a CSV file

## Requirements

- Python 3.9 or newer
- An internet connection

## Setup

Open a terminal in the project folder (the one that contains `app.py`).

Windows (PowerShell):

    python -m venv .venv
    .venv\Scripts\Activate.ps1
    pip install -r requirements.txt

macOS or Linux:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

If PowerShell blocks the activate script, run this once and try again:

    Set-ExecutionPolicy -Scope CurrentUser RemoteSigned

## Run

    python app.py

Then open http://127.0.0.1:5000 in your browser. Press Ctrl+C in the terminal
to stop the server.

To turn on Flask's debug mode while developing, set `FLASK_DEBUG=1` first. It
is off by default.

## Project structure

    website-security-checker/
    ├── app.py              Flask app and all scanning logic
    ├── requirements.txt    Python libraries
    ├── templates/
    │   └── index.html      Page layout
    └── static/
        ├── style.css       Styling, including the dark theme
        └── app.js          Scanning, filters, cards, CSV download

## Webpage Interface

<img width="1296" height="615" alt="Screenshot 2026-10-19 224252" src="https://github.com/user-attachments/assets/681dfcf1-a28c-443f-ab9a-eb21d27b87b6" />
<img width="1271" height="890" alt="Screenshot 2026-10-19 224356" src="https://github.com/user-attachments/assets/51d84544-7fdf-4581-a695-0bed19432319" />
<img width="1176" height="905" alt="Screenshot 2026-10-19 224601" src="https://github.com/user-attachments/assets/5a80cd2e-6b4f-4e41-b81f-9d5d5dd93172" />
<img width="1170" height="827" alt="Screenshot 2026-10-19 224640" src="https://github.com/user-attachments/assets/f7cf9806-66d2-48c6-a287-f092c988b0ed" />
<img width="1190" height="887" alt="Screenshot 2026-10-19 224708" src="https://github.com/user-attachments/assets/486548d1-2c5b-4959-b069-9d3f38aa79e5" />

## How it works

1. You enter an address and the page sends it to `/api/scan`.
2. The server checks that it is HTTPS, uses port 443, has no login details in
   it, and points to a public IP address. Private addresses are blocked.
3. It makes the request and reads the response headers.
4. It opens a separate verified TLS connection to read the certificate.
5. It builds the report and sends it back as JSON, and the page displays it.

## Limitations

- It checks one response from one page, so other pages can differ.
- The address check can be bypassed in some network setups, such as DNS
  rebinding. Do not put this tool on the public internet as it is.
- The built-in Flask server is for local use only.
- Scan history is kept only in the browser, and the report disappears on reload.

## Ideas for next steps

- Dashboard with saved scans
- Scan history and comparison with SQLite
- PDF export

## Learning resources

- Flask: https://flask.palletsprojects.com/
- Requests: https://requests.readthedocs.io/
- MDN, HTTP headers: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
- OWASP Secure Headers Project: https://owasp.org/www-project-secure-headers/
- Python ssl module: https://docs.python.org/3/library/ssl.html
