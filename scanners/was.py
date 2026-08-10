import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import re
from urllib.parse import urlparse

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"; BOLD="\033[1m"; END="\033[0m"

def ok(msg): print(f"{GREEN}[✓]{END} {msg}")
def warn(msg): print(f"{YELLOW}[!]{END} {msg}")
def bad(msg): print(f"{RED}[✗]{END} {msg}")

HEADERS=[
("Content-Security-Policy","Missing CSP"),
("Strict-Transport-Security","Missing HSTS"),
("X-Frame-Options","Missing X-Frame-Options"),
("X-Content-Type-Options","Missing X-Content-Type-Options"),
("Referrer-Policy","Missing Referrer-Policy"),
("Permissions-Policy","Missing Permissions-Policy"),
]

def fetch(url):
    try:
        return requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            verify=False,
            headers={
                "User-Agent": "Aegis/0.7"
            },
        )
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection failed: {e}")
        return None

def check_headers(r):
    print("\n[*] Security Headers")
    for h,msg in HEADERS:
        if h in r.headers:
            ok(f"{h}: {r.headers[h]}")
        else:
            bad(msg)
    csp=r.headers.get("Content-Security-Policy","")
    if csp:
        if "'unsafe-inline'" in csp:
            warn("CSP contains 'unsafe-inline'")
        if "'unsafe-eval'" in csp:
            warn("CSP contains 'unsafe-eval'")
        if "default-src" not in csp:
            warn("CSP missing default-src")

"""
def check_server(r):
    print("\n[*] Server Disclosure")
    for h in ("Server","X-Powered-By"):
        if h in r.headers:
            warn(f"{h}: {r.headers[h]}")
        else:
            ok(f"{h} not disclosed")
"""

def check_cors(r):
    print("\n[*] CORS")
    o=r.headers.get("Access-Control-Allow-Origin")
    c=r.headers.get("Access-Control-Allow-Credentials")
    if not o:
        ok("No Access-Control-Allow-Origin header present.")
        return
    if o=="*" and c=="true":
        bad("Wildcard Access-Control-Allow-Origin with credentials")
    elif o=="*":
        bad("Wildcard Access-Control-Allow-Origin")
    else:
        ok(f"Origin restricted to {o}")

"""
def check_methods(url):
    print("\n[*] HTTP Methods")
    try:
        r=requests.options(url,timeout=10)
        allow=r.headers.get("Allow","")
        if allow:
            print(" Allowed:",allow)
            for m in ("TRACE","PUT","DELETE","CONNECT"):
                if m in allow.upper():
                    bad(f"{m} enabled")
        else:
            warn("Allow header not returned")
    except Exception:
        warn("OPTIONS request failed")
"""
"""
def check_files(base):
    print("\n[*] robots.txt / security.txt")
    for p in ("/robots.txt","/.well-known/security.txt"):
        try:
            r=requests.get(urljoin(base,p),timeout=5)
            if r.status_code==200:
                ok(f"Found {p}")
            else:
                warn(f"{p} not found")
        except Exception:
            warn(f"Unable to query {p}")
"""
"""
def check_directory(r):
    print("\n[*] Directory Listing")
    if "<title>Index of" in r.text or "Directory listing for" in r.text:
        bad("Directory listing detected")
    else:
        ok("No obvious directory listing")
"""
def check_https_redirect(target, port):
    print("\n[*] HTTP to HTTPS Redirect")

    try:

        if port == 80:
            url = f"http://{target}"
        else:
            url = f"http://{target}"

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=False,
            verify=False,
            headers={"User-Agent": "Aegis/0.7"},
        )

        location = response.headers.get("Location", "")

        if response.status_code in (301, 302, 307, 308):

            if location.startswith("https://"):
                ok(f"Redirects to HTTPS ({response.status_code})")
            else:
                warn(f"Redirects, but not to HTTPS ({location})")

        else:
            bad("No HTTP → HTTPS redirect configured.")

    except Exception as e:
        warn(f"Unable to test redirect ({e})")

def check_mixed(r):
    print("\n[*] Mixed Content")
    if r.url.startswith("https://") and 'http://' in r.text:
        warn("HTTP resources referenced")
    else:
        ok("No obvious mixed content")

def check_https_downgrade(target, port):
    print("\n[*] HTTPS Downgrade Check")

    url = f"https://{target}" if port == 443 else f"https://{target}:{port}"

    try:
        r = requests.get(
            url,
            allow_redirects=False,
            verify=False,
            timeout=10,
            headers={"User-Agent": "Aegis/0.7"},
        )

        location = r.headers.get("Location", "")

        if location.startswith("http://"):
            bad(f"HTTPS redirects to HTTP ({location})")
        else:
            ok("HTTPS does not downgrade to HTTP.")

    except requests.RequestException as e:
        warn(f"Unable to test HTTPS redirect ({e})")
"""
def check_forms(r):
    print("\n[*] HTML Forms")
    soup=BeautifulSoup(r.text,"html.parser")
    forms=soup.find_all("form")
    if not forms:
        ok("No forms found")
        return
    for i,f in enumerate(forms,1):
        action=f.get("action","")
        if action.startswith("http://"):
            bad(f"Form {i} submits over HTTP")
        else:
            ok(f"Form {i} action OK")
"""
def check_js(r):
    print("\n[*] JavaScript Libraries")

    soup = BeautifulSoup(r.text, "html.parser")

    libraries = {
        "jQuery": r"jquery(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Bootstrap": r"bootstrap(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "AngularJS": r"angular(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "React": r"react(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Vue": r"vue(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Lodash": r"lodash(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Moment.js": r"moment(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Backbone": r"backbone(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Ember": r"ember(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Dojo": r"dojo(?:[-.]|/)?(\d+\.\d+\.\d+)?",
        "Prototype": r"prototype(?:[-.]|/)?(\d+\.\d+\.\d+)?",
    }

    found = False
    reported = set()

    scripts = soup.find_all("script", src=True)

    for script in scripts:
        src = script["src"]
        src_lower = src.lower()
        has_integrity = script.has_attr("integrity")

        # 1. Identificação da Biblioteca
        for library, regex in libraries.items():
            # REMOVIDO: if library in reported: continue (agora verifica sempre)

            if library.lower().replace(".js", "") in src_lower:
                version = None
                match = re.search(regex, src_lower)

                if match and match.group(1):
                    version = match.group(1)
                else:
                    query = re.search(r"(?:v|ver|version)=([0-9]+\.[0-9]+(?:\.[0-9]+)?)", src_lower)
                    if query:
                        version = query.group(1)
                    else:
                        generic = re.search(r"([0-9]+\.[0-9]+(?:\.[0-9]+)?)", src_lower)
                        if generic:
                            version = generic.group(1)

                if version:
                    warn(f"{library} {version}")
                else:
                    warn(f"{library} detected (version unknown)")

                print(f"    Source: {src}")
                found = True

        if not found:
            ok("No common JavaScript libraries detected.")

"""
def fingerprint(r):
    print("\n[*] Fingerprinting")
    txt=(r.text+r.headers.get("Server","")).lower()
    tech=[]
    for t in ("wordpress","drupal","joomla","shopify","wix","cloudflare","nginx","apache","iis"):
        if t in txt:
            tech.append(t)
    if tech:
        ok("Detected: "+", ".join(sorted(set(tech))))
    else:
        warn("No common technologies identified")
"""
def check_sri(r):
    print("\n[*] Subresource Integrity (SRI)")
    soup = BeautifulSoup(r.text, "html.parser")
    scripts = soup.find_all("script", src=True)

    if not scripts:
        ok("No script tags with 'src' found.")
        return

    # Lista de domínios com scripts dinâmicos onde o SRI normalmente não é aplicado
    dynamic_widgets = [
        "platform.twitter.com",
        "connect.facebook.net",
        "googletagmanager.com",
        "google-analytics.com",
        "analytics.js"
    ]

    missing_sri = 0
    external_scripts = 0

    for script in scripts:
        src = script.get("src", "").strip()
        has_integrity = script.has_attr("integrity")

        # Verifica se é um script externo/CDN
        is_external = src.startswith("http://") or src.startswith("https://") or src.startswith("//")

        if is_external:
            external_scripts += 1
            
            # Verifica se pertence a um widget dinâmico conhecido
            is_dynamic = any(widget in src.lower() for widget in dynamic_widgets)

            if not has_integrity:
                if is_dynamic:
                    warn(f"Dynamic third-party script without SRI (expected): {src}")
                else:
                    bad(f"Missing integrity attribute on external CDN: {src}")
                    missing_sri += 1
            else:
                ok(f"SRI integrity present: {src}")

    if external_scripts == 0:
        ok("No external CDN scripts detected.")
    elif missing_sri == 0:
        ok("All critical external CDN scripts have SRI configured.")

def print_redirect_chain(r):
    print("\n[*] Redirect Chain")

    if not r.history:
        ok("No redirects (direct connection).")
        print(f"    [{r.status_code}] {r.url}")
        return

    for response in r.history:
        location = response.headers.get("Location", "")
        print(f"    [{response.status_code}] {response.url}")

        if location:
            print("         │")
            print(f"         └──> {location}")

    print("         │")
    print(f"         └──> [{r.status_code}] {r.url}")


def run(target, port=443):
    if port == 80:
        primary_url = f"http://{target}"
        fallback_url = f"https://{target}"
    elif port == 443:
        primary_url = f"https://{target}"
        fallback_url = f"http://{target}"
    else:
        primary_url = f"https://{target}:{port}"
        fallback_url = f"http://{target}:{port}"

    print("=" * 40)
    print(" WEB APPLICATION SECURITY")
    print(f" Target: {target}")
    print("=" * 40)

    r = fetch(primary_url)

    if r is None:
        print(f"[*] Primary connection failed, trying {fallback_url}...")
        r = fetch(fallback_url)

    if r is None:
        bad("Unable to connect to the target.")
        return

    print(f"\n[+] Connected successfully")
    print(f"Resolved URL: {r.url}")

    check_headers(r)
    #check_server(r)
    check_cors(r)
    #check_methods(r.url)
    #check_files(r.url)
    #check_directory(r)
    #check_https_redirect(target, port)
    check_https_downgrade(target, port)
    check_mixed(r)
    #check_forms(r)
    check_js(r)
    check_sri(r)
    #fingerprint(r)
    print_redirect_chain(r)