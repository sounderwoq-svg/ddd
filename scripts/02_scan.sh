#!/usr/bin/env bash
# Этап 2: Активное сканирование
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
OUT="scanning/${TARGET}"
mkdir -p "$OUT"

IP=$(dig +short "$TARGET" | head -1)
echo "[*] Цель: $TARGET ($IP)"
echo "[*] Результаты: $OUT/"

# --- Сканирование портов ---

echo "[+] Nmap — быстрое сканирование топ-1000 портов..."
nmap -sV -sC -T4 --open "$TARGET" -oA "$OUT/nmap_top1000" 2>&1 || true

echo "[+] Nmap — полное сканирование всех портов..."
nmap -sV -p- -T4 --open "$TARGET" -oA "$OUT/nmap_full" 2>&1 || true

echo "[+] Nmap — скрипты уязвимостей..."
nmap -sV --script=vuln "$TARGET" -oA "$OUT/nmap_vuln" 2>&1 || true

# --- Веб-сканирование ---

echo "[+] Nikto..."
if command -v nikto &>/dev/null; then
    nikto -h "https://$TARGET" -output "$OUT/nikto.txt" -Format txt 2>&1 || true
fi

echo "[+] Gobuster — директории..."
if command -v gobuster &>/dev/null; then
    WORDLIST="/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    [ -f "$WORDLIST" ] || WORDLIST="/usr/share/wordlists/dirb/common.txt"
    gobuster dir \
        -u "https://$TARGET" \
        -w "$WORDLIST" \
        -x php,html,txt,asp,aspx,jsp,bak,zip,sql,env,config,yml,yaml,json \
        -t 30 \
        -o "$OUT/gobuster_dirs.txt" 2>&1 || true
fi

echo "[+] Gobuster — поддомены..."
if command -v gobuster &>/dev/null; then
    SUBLIST="/usr/share/wordlists/subdomains-top1million-5000.txt"
    if [ -f "$SUBLIST" ]; then
        gobuster dns -d "$TARGET" -w "$SUBLIST" -o "$OUT/gobuster_subs.txt" 2>&1 || true
    fi
fi

# --- Поиск по шаблонам CVE ---

echo "[+] Nuclei..."
if command -v nuclei &>/dev/null; then
    nuclei -u "https://$TARGET" \
        -t exposures/ \
        -t vulnerabilities/ \
        -t misconfiguration/ \
        -t cves/ \
        -severity low,medium,high,critical \
        -o "$OUT/nuclei.txt" 2>&1 || true
fi

echo "[*] Сканирование завершено → $OUT/"
