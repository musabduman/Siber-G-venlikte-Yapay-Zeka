"""
Generates deterministic development (dev) and test (test) payload corpora for AI-SOC evaluation.
Adheres strictly to test design constraints:
- Clear dev / test separation (no testing on dev data).
- At least 40 attack variants (SQLi, XSS, SSH) in test set.
- Less than or equal to 50% of test attack payloads end with '--'.
- At least 100 innocent logs in test set (with benign keywords: '--', SELECT, union, script, etc.).
"""

import json
from pathlib import Path
import random

RANDOM_SEED = 42
random.seed(RANDOM_SEED)

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)


def build_dev_corpus():
    attacks = [
        {"attack_type": "SQLi", "technique": "Classic OR 1=1 with dash", "raw_text": "GET /login?user=admin' OR 1=1-- HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Union Select", "raw_text": "GET /products?id=1 UNION SELECT null, username, password FROM users-- HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "URL Encoded Union", "raw_text": "GET /search?q=%27%20UNION%20SELECT%201,2-- HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Inline Comment", "raw_text": "GET /item?id=1'/**/OR/**/'1'='1 HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Basic Script Tag", "raw_text": "GET /search?q=<script>alert(1)</script> HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Img Onerror", "raw_text": "GET /avatar?url=x<img src=x onerror=alert(1)> HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Javascript URI", "raw_text": "GET /redirect?url=javascript:alert(document.cookie) HTTP/1.1", "source": "Apache-HTTP"},
        {"attack_type": "SSH", "technique": "Exceeded attempts", "raw_text": "sshd[512]: error: maximum authentication attempts exceeded for root from 198.51.100.22 port 44321 ssh2", "source": "Syslog-SSH"},
    ]
    innocent = [
        {"category": "innocent", "technique": "Clean GET", "raw_text": "GET /index.html HTTP/1.1 200 OK", "source": "Apache-HTTP"},
        {"category": "innocent", "technique": "Dashes in slug", "raw_text": "GET /posts/how-to--code HTTP/1.1 200 OK", "source": "Apache-HTTP"},
        {"category": "innocent", "technique": "Select in query", "raw_text": "GET /shop?q=select+items HTTP/1.1 200 OK", "source": "Apache-HTTP"},
        {"category": "innocent", "technique": "Union word", "raw_text": "GET /news?topic=credit-union HTTP/1.1 200 OK", "source": "Apache-HTTP"},
        {"category": "innocent", "technique": "Script asset", "raw_text": "GET /static/app-script.js HTTP/1.1 200 OK", "source": "Apache-HTTP"},
        {"category": "innocent", "technique": "Single failed ssh", "raw_text": "sshd[101]: Failed password for invalid user admin from 10.0.0.1 port 52123 ssh2", "source": "Syslog-SSH"},
    ]
    return {"attacks": attacks, "innocent": innocent}


def build_test_corpus():
    # 45+ Attack variants across SQLi, XSS, SSH
    # Exactly 10 out of 25 SQLi end with '--' (well below 50% of all attacks)
    attacks = [
        # --- SQL Injection Variants (22 samples) ---
        # 1-10: Ending with '--'
        {"attack_type": "SQLi", "technique": "Classic OR 1=1 trailing dash", "raw_text": "GET /login?user=admin' OR 1=1-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Union Select with dash", "raw_text": "GET /items?cat=1 UNION SELECT 1,table_name FROM information_schema.tables-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "URL Encoded Quote and Dash", "raw_text": "GET /search?id=%27%20OR%201=1-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Double URL Encoded Quote", "raw_text": "GET /search?id=%2527%20UNION%20SELECT%20null-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Mixed Case Union Select", "raw_text": "GET /data?id=1 uNiOn sElEcT user,password from users-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Whitespace Tabs Injection", "raw_text": "GET /login?user=admin'\tOR\t1=1-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Newline SQL Injection", "raw_text": "GET /login?user=admin'\nOR\n1=1-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Hex Literal Injection", "raw_text": "GET /login?user=admin' OR 0x313=0x313-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Comment defragmentation UN/**/ION", "raw_text": "GET /search?q=1' UN/**/ION SELECT 1,2-- HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Stacked Drop Table", "raw_text": "POST /admin?id=1; DROP TABLE users;-- HTTP/1.1 200", "source": "Apache-HTTP"},
        # 11-22: NOT ending with '--'
        {"attack_type": "SQLi", "technique": "Quoted String Match OR", "raw_text": "GET /login?user=admin' OR '1'='1 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Inline Comment Closure", "raw_text": "GET /login?user=admin' OR 1=1/* HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Time-based Sleep Injection", "raw_text": "GET /api?id=1' AND (SELECT sleep(5)) AND '1'='1 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Benchmark Delay", "raw_text": "GET /check?id=1' AND (SELECT benchmark(5000000,MD5(1))) AND '1'='1 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Information Schema Query", "raw_text": "GET /dump?col=1 SELECT column_name FROM information_schema.columns WHERE table_name='users' HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "CHAR Function Obfuscation", "raw_text": "GET /auth?user=' OR user=CHAR(97,100,109,105,110) HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Word Splitting MySQL Comments", "raw_text": "GET /users?id=1 UN/*!*/ION /*!*/SELECT 1,2,3 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Union All Select Numeric", "raw_text": "GET /page?id=-1 UNION ALL SELECT 1,2,3,4 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Scientific Notation Numeric Bypass", "raw_text": "GET /calc?id=1e0 UNION SELECT null,null HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Stacked Update Statement", "raw_text": "POST /profile?id=5; UPDATE accounts SET role='admin' WHERE id=5 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Mixed URL Encoding", "raw_text": "GET /search?term=admin' UN%49ON SE%4CECT 1,2 HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "SQLi", "technique": "Hex Encoded Admin String", "raw_text": "GET /login?user=0x61646d696e OR 1=1 HTTP/1.1 200", "source": "Apache-HTTP"},

        # --- XSS Variants (15 samples) ---
        {"attack_type": "XSS", "technique": "Classic Script Tag", "raw_text": "GET /search?q=<script>alert(1)</script> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Img Tag Onerror", "raw_text": "GET /user?name=<img src=x onerror=alert('xss')> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "SVG Tag Onload", "raw_text": "GET /view?svg=<svg onload=alert(document.domain)> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "URL Encoded Script Tag", "raw_text": "GET /find?k=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Unicode Escape Script Tag", "raw_text": "GET /find?k=\\u003cscript\\u003ealert(1)\\u003c/script\\u003e HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "HTML Entity Script Tag", "raw_text": "GET /profile?bio=&lt;script&gt;alert(1)&lt;/script&gt; HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Javascript URI Scheme", "raw_text": "GET /redirect?url=javascript:alert(1) HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Document Cookie Theft", "raw_text": "GET /track?c=document.cookie HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Body Tag Onload", "raw_text": "POST /comment?body=<body onload=alert(1)> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Iframe Source Javascript", "raw_text": "GET /embed?src=<iframe src=javascript:alert(1)> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Anchor Onclick Event", "raw_text": "GET /link?val=<a href=# onclick=alert(1)>click</a> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Input Autofocus Onfocus", "raw_text": "GET /form?input=<input type=text autofocus onfocus=alert(1)> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Video Source Onerror", "raw_text": "GET /media?v=<video><source onerror=javascript:alert(1)> HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Double Encoded Script", "raw_text": "GET /query?q=%253Cscript%253Ealert(1)%253C/script%253E HTTP/1.1 200", "source": "Apache-HTTP"},
        {"attack_type": "XSS", "technique": "Mixed Case Svg OnLoad", "raw_text": "GET /icon?name=<SvG oNLoAd=alert(1)> HTTP/1.1 200", "source": "Apache-HTTP"},

        # --- SSH Attack Scenarios (Evaluated as real Brute-Force Bursts >= 5 attempts) ---
        {"attack_type": "SSH", "technique": "SSH Brute Force: Root Password Spray (6 rapid attempts)", "raw_text": "sshd[1105]: Failed password for root from 185.220.101.5 port 39215 ssh2", "source": "Syslog-SSH", "ip_src": "185.220.101.5", "burst_count": 6},
        {"attack_type": "SSH", "technique": "SSH Brute Force: User Enumeration (6 rapid attempts)", "raw_text": "sshd[1205]: Invalid user oracle from 198.51.100.99 port 51105 ssh2", "source": "Syslog-SSH", "ip_src": "198.51.100.99", "burst_count": 6},
        {"attack_type": "SSH", "technique": "SSH Authentication Attempts Exceeded Marker", "raw_text": "sshd[1106]: error: maximum authentication attempts exceeded for invalid user test from 185.220.101.5 port 39216 ssh2", "source": "Syslog-SSH", "ip_src": "185.220.101.5", "burst_count": 1},
        {"attack_type": "SSH", "technique": "SSH Brute Force: Admin Dictionary Attack (6 rapid attempts)", "raw_text": "sshd[1305]: Failed password for admin from 203.0.113.55 port 42105 ssh2", "source": "Syslog-SSH", "ip_src": "203.0.113.55", "burst_count": 6},
        {"attack_type": "SSH", "technique": "SSH Brute Force: Automated Scanner Probe (6 rapid attempts)", "raw_text": "sshd[1405]: Invalid user deploy from 192.0.2.77 port 33105 ssh2", "source": "Syslog-SSH", "ip_src": "192.0.2.77", "burst_count": 6},
    ]

    # --- 108 Innocent Logs (Diverse, containing benign keywords) ---
    innocent = []

    # Category A: Logs containing '--' but innocent (15 samples)
    dash_templates = [
        "GET /docs/getting-started--guide HTTP/1.1 200 4520",
        "GET /static/css/theme--dark.css HTTP/1.1 200 1280",
        "GET /static/css/theme--light.css HTTP/1.1 200 1250",
        "GET /api/report?from=2026-01-01--2026-02-01 HTTP/1.1 200 890",
        "GET /blog/post--123-building-modern-apps HTTP/1.1 200 3410",
        "GET /assets/style--v2.4.1.css HTTP/1.1 200 9400",
        "GET /download/package--release.tar.gz HTTP/1.1 200 89200",
        "GET /faq/question--42-account-security HTTP/1.1 200 2100",
        "GET /docs/cli-reference--advanced HTTP/1.1 200 7800",
        "GET /images/logo--monochrome.svg HTTP/1.1 200 3200",
        "GET /changelog/v1.0--v2.0.md HTTP/1.1 200 5600",
        "GET /products/item-sku--99482 HTTP/1.1 200 1850",
        "GET /config/network--interface-eth0.json HTTP/1.1 200 640",
        "GET /archive/2025--recap.html HTTP/1.1 200 4200",
        "GET /reports/quarterly--summary.pdf HTTP/1.1 200 128000",
    ]
    for text in dash_templates:
        innocent.append({"category": "innocent", "subgroup": "dash_benign", "raw_text": text, "source": "Apache-HTTP"})

    # Category B: Logs containing SQL keywords (SELECT, UNION, OR) in benign context (20 samples)
    sql_kw_templates = [
        "GET /search?q=how+to+SELECT+a+laptop HTTP/1.1 200 3200",
        "GET /products?category=union+jack+flags HTTP/1.1 200 4500",
        "GET /articles?tag=trade-unions HTTP/1.1 200 5120",
        "GET /api/v1/user/selection HTTP/1.1 200 120",
        "GET /items?sort=select_best HTTP/1.1 200 1840",
        "GET /forum/thread?title=european-union-news HTTP/1.1 200 6200",
        "GET /blog/understanding-credit-union-rules HTTP/1.1 200 4800",
        "GET /help?query=select+multiple+checkboxes HTTP/1.1 200 2400",
        "GET /courses/database-basics-select-queries.html HTTP/1.1 200 7400",
        "GET /shop/apparel?color=select_blue HTTP/1.1 200 3100",
        "GET /jobs/position?title=union-steward HTTP/1.1 200 2900",
        "GET /travel/destination?place=grand-junction-or-denver HTTP/1.1 200 4300",
        "GET /api/products/or_filter?state=active HTTP/1.1 200 850",
        "GET /catalog?brand=western-union HTTP/1.1 200 3700",
        "GET /wiki/Rugby_Union_Championship HTTP/1.1 200 9100",
        "GET /docs/css-selector-guide HTTP/1.1 200 5200",
        "GET /ui/components/custom-select-dropdown.js HTTP/1.1 200 3150",
        "GET /search?q=the+union+of+mathematical+sets HTTP/1.1 200 2800",
        "GET /music/album?name=state-of-the-union HTTP/1.1 200 3300",
        "GET /books/review?isbn=select-book-9812 HTTP/1.1 200 2100",
    ]
    for text in sql_kw_templates:
        innocent.append({"category": "innocent", "subgroup": "sql_keyword_benign", "raw_text": text, "source": "Apache-HTTP"})

    # Category C: Logs containing "script" keyword in benign context (15 samples)
    script_templates = [
        "GET /static/js/script.min.js HTTP/1.1 200 14200",
        "GET /docs/powershell-scripts.html HTTP/1.1 200 4100",
        "GET /tutorials/typescript-tutorial HTTP/1.1 200 6200",
        "GET /assets/subscription-script.js HTTP/1.1 200 8900",
        "GET /static/vendor/modernizr-script.js HTTP/1.1 200 11500",
        "GET /api/v1/build-scripts/list HTTP/1.1 200 340",
        "GET /downloads/install-script.sh HTTP/1.1 200 2100",
        "GET /blog/history-of-ecmascript HTTP/1.1 200 5800",
        "GET /fonts/script-handwriting.woff2 HTTP/1.1 200 45000",
        "GET /articles/manuscript-submission-guidelines HTTP/1.1 200 7300",
        "GET /static/js/analytics-script.js HTTP/1.1 200 6400",
        "GET /code/sample-python-script.py HTTP/1.1 200 1800",
        "GET /faq/why-disable-scripts-in-email HTTP/1.1 200 3100",
        "GET /assets/js/theme-switcher-script.js HTTP/1.1 200 4200",
        "GET /cdn/libraries/script-loader.js HTTP/1.1 200 8200",
    ]
    for text in script_templates:
        innocent.append({"category": "innocent", "subgroup": "script_keyword_benign", "raw_text": text, "source": "Apache-HTTP"})

    # Category D: Isolated/Benign SSH logs (10 samples)
    ssh_benign_templates = [
        ("sshd[2101]: Invalid user test from 10.0.0.51 port 52101 ssh2", "10.0.0.51"),
        ("sshd[2102]: Failed password for john from 192.168.1.105 port 48112 ssh2", "192.168.1.105"),
        ("sshd[2103]: Accepted publickey for ubuntu from 172.16.0.4 port 33100 ssh2", "172.16.0.4"),
        ("sshd[2104]: Connection closed by 192.168.1.200 port 55104 [preauth]", "192.168.1.200"),
        ("sshd[2105]: Received disconnect from 10.0.0.88 port 41200:11: Bye [preauth]", "10.0.0.88"),
        ("sshd[2106]: Accepted password for deploy from 192.168.1.50 port 59123 ssh2", "192.168.1.50"),
        ("sshd[2107]: session opened for user ubuntu by (uid=0)", "127.0.0.1"),
        ("sshd[2108]: session closed for user ubuntu", "127.0.0.1"),
        ("sshd[2109]: Server listening on 0.0.0.0 port 22", "0.0.0.0"),
        ("sshd[2110]: Invalid user temp from 10.10.10.42 port 49100 ssh2", "10.10.10.42"),
    ]
    for text, ip in ssh_benign_templates:
        innocent.append({"category": "innocent", "subgroup": "ssh_benign", "raw_text": text, "source": "Syslog-SSH", "ip_src": ip})

    # Category E: Standard normal web traffic & API pings (48 samples)
    routes = [
        "/", "/about", "/contact", "/pricing", "/features", "/login", "/register",
        "/dashboard", "/settings", "/profile", "/status", "/healthz", "/metrics",
        "/api/v1/users", "/api/v1/orders", "/api/v1/inventory", "/api/v1/status",
        "/favicon.ico", "/robots.txt", "/sitemap.xml", "/apple-touch-icon.png",
        "/static/css/bootstrap.min.css", "/static/js/jquery.min.js", "/static/images/hero.jpg",
    ]
    for i, route in enumerate(routes):
        innocent.append({"category": "innocent", "subgroup": "web_standard_get", "raw_text": f"GET {route} HTTP/1.1 200 OK", "source": "Apache-HTTP"})
        innocent.append({"category": "innocent", "subgroup": "web_standard_head", "raw_text": f"HEAD {route} HTTP/1.1 200 OK", "source": "Apache-HTTP"})

    return {"attacks": attacks, "innocent": innocent}


def main():
    dev_data = build_dev_corpus()
    test_data = build_test_corpus()

    dev_path = DATA_DIR / "payloads_dev.json"
    test_path = DATA_DIR / "payloads_test.json"

    with open(dev_path, "w", encoding="utf-8") as f:
        json.dump(dev_data, f, indent=2)

    with open(test_path, "w", encoding="utf-8") as f:
        json.dump(test_data, f, indent=2)

    num_test_attacks = len(test_data["attacks"])
    num_test_dash_attacks = sum(1 for a in test_data["attacks"] if a["raw_text"].rstrip().endswith("--"))
    num_test_innocent = len(test_data["innocent"])

    print(f"Generated dev corpus -> {dev_path} ({len(dev_data['attacks'])} attacks, {len(dev_data['innocent'])} innocent)")
    print(f"Generated test corpus -> {test_path}")
    print(f"  Test attacks: {num_test_attacks} (ending with '--': {num_test_dash_attacks}/{num_test_attacks} = {num_test_dash_attacks/num_test_attacks:.1%})")
    print(f"  Test innocent: {num_test_innocent}")


if __name__ == "__main__":
    main()
