#!/usr/bin/env bash
# AWS GPU örneğinde eğitimi başlatır. DİKKAT: AWS üzerinde henüz denenmedi (H6 keşif oturumunda
# doğrulanacak); yerelde yalnızca sözdizimi ve eğitim kodu (CPU duman testi) doğrulandı.
#
# Önkoşullar (örnekte): git ile depo klonlu, `aws` CLI ve S3 yetkisi olan IAM rolü, CUDA'lı Python ortamı,
# parolasız sudo (shutdown için). tmux/nohup altında çalıştır (SSH kopsa da sürsün diye HUP yok sayılır).
# Mac'ten veri yükleme (bir kez):
#   aws s3 sync data/out s3://$S3_BUCKET/secagent/data/ --exclude "*" --include "*.jsonl"
# Kullanım:
#   S3_BUCKET=kova RUN_ID=run1 ./train/launch.sh [--set anahtar=değer ...]
# Ortam: MAX_HOURS (varsayılan 12; aşılırsa eğitim durdurulur), NO_SHUTDOWN=1 (hata ayıklama için
#        makineyi KAPATMA), REPO_DIR (varsayılan: bu betiğin üst dizini), STEP_TIMEOUT (varsayılan 20m).
#
# GÜVENLİK: EC2 üzerinde çıkışta (başarı, hata, zaman aşımı, Ctrl-C) makine KAPATILIR; GPU saati
# sızmaz. EC2 DEĞİLSE (ör. yanlışlıkla yerelde) asla kapatılmaz. Her harici adımın zaman aşımı var:
# takılan bir indirme/yükleme GPU'yu açık tutamaz.
set -Eeuo pipefail
trap '' HUP

: "${S3_BUCKET:?S3_BUCKET gerekli}" "${RUN_ID:?RUN_ID gerekli}"
if [[ ! "$S3_BUCKET" =~ ^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$ ]] || [[ ! "$RUN_ID" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] \
   || [[ "$RUN_ID" == *..* ]]; then
  echo "S3_BUCKET/RUN_ID geçersiz (RUN_ID harf/rakamla başlamalı, '..' içeremez)" >&2; exit 64
fi
MAX_HOURS="${MAX_HOURS:-12}"
STEP_TIMEOUT="${STEP_TIMEOUT:-20m}"
REPO_DIR="${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
RUN_URI="s3://${S3_BUCKET}/secagent/${RUN_ID}"
OUT_DIR="outputs/${RUN_ID}"

on_ec2() {  # Nitro örneklerinde board_asset_tag "i-..." ile başlar
  grep -q '^i-' /sys/devices/virtual/dmi/id/board_asset_tag 2>/dev/null
}

# Son güvence: önce COMPLETE işareti HARİÇ her şey, sonra yalnızca işaretler (tam checkpoint
# garantisi, bkz. s3sync.py). Zaman aşımı: takılırsa makine yine de kapanır.
final_sync() {
  [[ -d "$OUT_DIR" ]] || return 0
  timeout "$STEP_TIMEOUT" aws s3 sync "$OUT_DIR" "${RUN_URI}/ckpt" --exclude "*/COMPLETE" --only-show-errors || return 0
  timeout "$STEP_TIMEOUT" aws s3 sync "$OUT_DIR" "${RUN_URI}/ckpt" --exclude "*" --include "*/COMPLETE" --only-show-errors || true
}

finish() {
  local code=$?
  echo "[launch] çıkış kodu: ${code}"
  final_sync || true
  sync
  if [[ "${NO_SHUTDOWN:-0}" == "1" ]]; then
    echo "[launch] NO_SHUTDOWN=1: makine açık bırakıldı"
  elif on_ec2; then
    echo "[launch] makine kapatılıyor"; sudo -n shutdown -h now || sudo -n poweroff -f
  else
    echo "[launch] EC2 değil: makine kapatılmadı"
  fi
}
trap finish EXIT

cd "$REPO_DIR"
timeout "$STEP_TIMEOUT" python -m pip install -q -c train/constraints.txt -e ".[train,train-gpu]"
mkdir -p data/out
timeout "$STEP_TIMEOUT" aws s3 sync "s3://${S3_BUCKET}/secagent/data/" data/out/ --only-show-errors

# 75 = Spot kesintisi (kod kaldığı yerden devam eder: aynı komutu yeni örnekte tekrar çalıştır)
timeout -k 5m "${MAX_HOURS}h" secagent-train --config train/config.yaml \
  --set "s3.uri=${RUN_URI}/ckpt" --set "output_dir=${OUT_DIR}" "$@"
