#!/usr/bin/env bash
# Этап 1: Разведка
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
OUT="recon/${TARGET}"
mkdir -p "$OUT"

echo "[*] Цель: $TARGET"
echo "[*] Результаты: $OUT/"

# --- Пассивная разведка ---

echo "[+] WHOIS..."
whois "$TARGET" > "$OUT/whois.txt" 2>&1 || true

echo "[+] DNS записи..."
dig ANY "$TARGET" +noall +answer > "$OUT/dns_all.txt" 2>&1 || true
dig "$TARGET" A    +short > "$OUT/dns_a.txt"    2>&1 || true
dig "$TARGET" MX   +short > "$OUT/dns_mx.txt"   2>&1 || true
dig "$TARGET" TXT  +short > "$OUT/dns_txt.txt"  2>&1 || true
dig "$TARGET" NS   +short > "$OUT/dns_ns.txt"   2>&1 || true

echo "[+] Поиск поддоменов..."
if command -v subfinder &>/dev/null; then
    subfinder -d "$TARGET" -o "$OUT/subdomains.txt" 2>/dev/null
elif command -v amass &>/dev/null; then
    amass enum -passive -d "$TARGET" -o "$OUT/subdomains.txt" 2>/dev/null
else
    # Базовый перебор через DNS
    for sub in www mail ftp admin api dev test stage vpn webmail portal; do
        if dig +short "$sub.$TARGET" | grep -qE '^[0-9]'; then
            echo "$sub.$TARGET" >> "$OUT/subdomains.txt"
        fi
    done
fi

echo "[+] Определение технологий (whatweb)..."
if command -v whatweb &>/dev/null; then
    whatweb -a 3 "https://$TARGET" > "$OUT/whatweb.txt" 2>&1 || true
fi

echo "[+] Проверка WAF (wafw00f)..."
if command -v wafw00f &>/dev/null; then
    wafw00f "https://$TARGET" > "$OUT/waf.txt" 2>&1 || true
fi

echo "[+] HTTP заголовки..."
curl -sk -I -L "https://$TARGET" > "$OUT/headers.txt" 2>&1 || true
curl -sk -I -L "http://$TARGET"  >> "$OUT/headers.txt" 2>&1 || true

echo "[+] Robots.txt и Sitemap..."
curl -sk "https://$TARGET/robots.txt"        > "$OUT/robots.txt"   2>&1 || true
curl -sk "https://$TARGET/sitemap.xml"       > "$OUT/sitemap.xml"  2>&1 || true
curl -sk "https://$TARGET/sitemap_index.xml" >> "$OUT/sitemap.xml" 2>&1 || true

echo "[+] SSL/TLS аудит..."
if command -v sslscan &>/dev/null; then
    sslscan "$TARGET" > "$OUT/sslscan.txt" 2>&1 || true
fi
# Проверка через openssl
echo | openssl s_client -connect "$TARGET:443" -servername "$TARGET" 2>/dev/null \
    | openssl x509 -noout -text > "$OUT/cert.txt" 2>&1 || true

echo "[+] Поиск в Wayback Machine..."
curl -sk "https://web.archive.org/cdx/search/cdx?url=$TARGET/*&output=text&fl=original&collapse=urlkey&limit=500" \
    > "$OUT/wayback_urls.txt" 2>&1 || true

echo "[*] Разведка завершена → $OUT/"
