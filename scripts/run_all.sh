#!/usr/bin/env bash
# Главный скрипт — запускает все этапы последовательно
set -euo pipefail

TARGET="${1:?Usage: $0 <domain>}"
LOG="reporting/pentest_$(date +%Y%m%d_%H%M%S).log"
mkdir -p reporting

echo "============================================"
echo " PENTEST: $TARGET"
echo " Начало: $(date)"
echo "============================================" | tee "$LOG"

bash scripts/01_recon.sh     "$TARGET" 2>&1 | tee -a "$LOG"
bash scripts/02_scan.sh      "$TARGET" 2>&1 | tee -a "$LOG"
bash scripts/03_web_vulns.sh "$TARGET" 2>&1 | tee -a "$LOG"
bash scripts/04_auth_test.sh "$TARGET" 2>&1 | tee -a "$LOG"
bash scripts/05_report.sh    "$TARGET" 2>&1 | tee -a "$LOG"

echo "============================================"
echo " Завершено: $(date)"
echo " Отчёт: reporting/"
echo "============================================" | tee -a "$LOG"
