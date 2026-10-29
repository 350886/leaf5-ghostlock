#!/usr/bin/env bash
# deploy.sh —— 把编译产物推到设备
#
#   ./scripts/deploy.sh                 # 推 preload.so + 内嵌 su
#   ./scripts/deploy.sh so              # 只推 preload.so
#   ./scripts/deploy.sh scripts          # 只推设备端 shell 脚本
#
# 设备端布局：
#   /data/local/tmp/exploit/aarch64/preload.so
#   /data/local/tmp/device_root.sh
#
# 为什么 preload.so 要单独放一个目录：LD_PRELOAD=./preload.so 是相对路径，
# 必须在 cd 到该目录之后才能加载。
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"

WHAT="${1:-all}"
SO="$REPO/out/exploit/aarch64/preload.so"

command -v cygpath >/dev/null 2>&1 && W() { cygpath -m "$1"; } || W() { printf '%s' "$1"; }

die() { echo "[-] $*" >&2; exit 1; }

"$ADB" get-state >/dev/null 2>&1 || die "设备未连接（adb devices 看看，屏幕上有授权弹窗就点允许）"

push_so() {
  [ -f "$SO" ] || die "缺 $SO —— 先 make exploit"
  "$ADB" shell "mkdir -p $DEV_BIN" || die "建目录失败"
  "$ADB" push "$(W "$SO")" "$DEV_BIN/preload.so" || die push
  "$ADB" shell "chmod 755 $DEV_BIN/preload.so"
  # 设备上算 md5，写进 env 让 run_chain.sh 能核对（防止推了旧 so）
  local m
  m=$("$ADB" shell "md5sum $DEV_BIN/preload.so 2>/dev/null" | tr -d '\r' | cut -d' ' -f1)
  echo "[+] preload.so -> $DEV_BIN  md5=$m"
  echo "$m" > "$LOGDIR/.so_md5"
}

push_scripts() {
  "$ADB" push "$(W "$REPO/scripts/device_root.sh")" "$DEV_ROOT/device_root.sh" || die push
  "$ADB" shell "chmod 755 $DEV_ROOT/device_root.sh"
  echo "[+] device_root.sh -> $DEV_ROOT"
}

case "$WHAT" in
  all)     push_so; push_scripts ;;
  so)      push_so ;;
  scripts) push_scripts ;;
  *)       echo "usage: $0 {all|so|scripts}"; exit 1 ;;
esac
