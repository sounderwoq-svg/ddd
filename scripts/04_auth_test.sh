#!/usr/bin/env bash
# Этап 4: Тестирование аутентификации и сессий
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
BASE_URL="https://$TARGET"
OUT="scanning/${TARGET}/auth"
mkdir -p "$OUT"

echo "[*] Тестирование аутентификации: $BASE_URL"

# --- Поиск форм логина ---
echo "[+] Поиск страниц входа..."
for path in \
    "/login" "/signin" "/auth" "/account/login" \
    "/user/login" "/members/login" "/wp-login.php" \
    "/admin/login" "/panel/login" "/auth/login"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
    [ "$STATUS" = "200" ] && echo "LOGIN PAGE: $BASE_URL$path" >> "$OUT/login_pages.txt"
done

# --- Default credentials ---
echo "[+] Проверка дефолтных учётных данных..."
LOGIN_URL=$(head -1 "$OUT/login_pages.txt" 2>/dev/null | awk '{print $2}' || echo "$BASE_URL/login")

CREDS=(
    "admin:admin"
    "admin:password"
    "admin:123456"
    "admin:admin123"
    "administrator:administrator"
    "root:root"
    "test:test"
    "user:user"
    "guest:guest"
)

for CRED in "${CREDS[@]}"; do
    USER="${CRED%%:*}"
    PASS="${CRED##*:}"
    RESPONSE=$(curl -sk -c /tmp/cookies_test.txt \
        -d "username=$USER&password=$PASS&login=Login" \
        -X POST "$LOGIN_URL" 2>/dev/null)
    # Эвристика: успешный логин обычно редиректит или убирает слово "error"
    if ! echo "$RESPONSE" | grep -qiE "(invalid|incorrect|error|failed|неверн|ошибк)"; then
        echo "[!] POSSIBLE HIT: $USER:$PASS at $LOGIN_URL" >> "$OUT/default_creds.txt"
    fi
done
rm -f /tmp/cookies_test.txt

# --- Брутфорс защита (rate limiting) ---
echo "[+] Проверка rate limiting..."
for i in $(seq 1 20); do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
        -d "username=admin&password=wrongpass$i" -X POST "$LOGIN_URL" 2>/dev/null)
    echo "Request $i: $STATUS" >> "$OUT/rate_limit.txt"
done

# --- Session security ---
echo "[+] Проверка безопасности сессий..."
{
    echo "=== Cookies ==="
    curl -sk -D - "https://$TARGET" -o /dev/null 2>&1 | grep -i "set-cookie"

    echo ""
    echo "=== Session fixation check ==="
    # Получить сессию до и после гипотетического логина
    SESSION_PRE=$(curl -sk -c - "https://$TARGET/login" 2>/dev/null | grep -i "session" | awk '{print $NF}')
    echo "Pre-auth session token: $SESSION_PRE"
} > "$OUT/session_security.txt" 2>&1

# --- Password reset flow ---
echo "[+] Проверка сброса пароля..."
for path in "/forgot-password" "/reset-password" "/password/reset" "/account/forgot"; do
    STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "$BASE_URL$path")
    echo "$STATUS $BASE_URL$path" >> "$OUT/password_reset.txt"
done

echo "[*] Тестирование аутентификации завершено → $OUT/"
