#!/usr/bin/env bash
# Этап 5: Генерация отчёта
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
DATE=$(date +%Y-%m-%d)
REPORT="reporting/pentest_report_${TARGET}_${DATE}.md"

mkdir -p reporting

cat > "$REPORT" <<EOF
# Отчёт о пентесте: $TARGET
**Дата:** $DATE
**Тестировщик:** [Ваше имя]
**Цель:** https://$TARGET

---

## Исполнительное резюме

*Заполнить после анализа результатов*

---

## 1. Разведка (Reconnaissance)

### 1.1 WHOIS
\`\`\`
$(cat "recon/$TARGET/whois.txt" 2>/dev/null | head -30 || echo "Нет данных")
\`\`\`

### 1.2 DNS
\`\`\`
$(cat "recon/$TARGET/dns_all.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### 1.3 Поддомены
\`\`\`
$(cat "recon/$TARGET/subdomains.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### 1.4 Технологии
\`\`\`
$(cat "recon/$TARGET/whatweb.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### 1.5 WAF
\`\`\`
$(cat "recon/$TARGET/waf.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### 1.6 SSL/TLS
\`\`\`
$(cat "recon/$TARGET/sslscan.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

---

## 2. Сканирование

### 2.1 Открытые порты (Nmap)
\`\`\`
$(cat "scanning/$TARGET/nmap_top1000.nmap" 2>/dev/null || echo "Нет данных")
\`\`\`

### 2.2 Nikto
\`\`\`
$(cat "scanning/$TARGET/nikto.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### 2.3 Найденные директории
\`\`\`
$(grep -E "Status: 200|Status: 301|Status: 302|Status: 403" "scanning/$TARGET/gobuster_dirs.txt" 2>/dev/null | head -50 || echo "Нет данных")
\`\`\`

### 2.4 Nuclei
\`\`\`
$(cat "scanning/$TARGET/nuclei.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

---

## 3. Уязвимости OWASP Top 10

### A01 — Broken Access Control
\`\`\`
$(grep -v "^404" "scanning/$TARGET/web_vulns/access_control.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### A02 — Cryptographic Failures
\`\`\`
$(cat "scanning/$TARGET/web_vulns/crypto.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### A03 — SQL Injection
\`\`\`
$(cat "scanning/$TARGET/web_vulns/sqlmap_summary.txt" 2>/dev/null | head -30 || echo "Нет данных")
\`\`\`

### A07 — XSS
\`\`\`
$(grep -v "^safe" "scanning/$TARGET/web_vulns/xss.txt" 2>/dev/null || echo "Нет найденных XSS")
\`\`\`

### A08 — Security Headers
\`\`\`
$(cat "scanning/$TARGET/web_vulns/security_headers.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### Чувствительные файлы
\`\`\`
$(cat "scanning/$TARGET/web_vulns/sensitive_files.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

---

## 4. Аутентификация

### Найденные страницы входа
\`\`\`
$(cat "scanning/$TARGET/auth/login_pages.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### Дефолтные учётные данные
\`\`\`
$(cat "scanning/$TARGET/auth/default_creds.txt" 2>/dev/null || echo "Не найдены")
\`\`\`

### Rate Limiting
\`\`\`
$(cat "scanning/$TARGET/auth/rate_limit.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

### Безопасность сессий
\`\`\`
$(cat "scanning/$TARGET/auth/session_security.txt" 2>/dev/null || echo "Нет данных")
\`\`\`

---

## 5. Найденные уязвимости

| # | Уязвимость | Критичность | CVSS | Статус |
|---|-----------|------------|------|--------|
| 1 | | | | |

---

## 6. Рекомендации

*Заполнить после анализа*

---

## 7. Заключение

*Заполнить после анализа*

---
*Отчёт сгенерирован: $(date)*
EOF

echo "[*] Отчёт создан: $REPORT"
