#!/usr/bin/env bash
# build_leaf5.sh — 用本机 NDK 直接编译 leaf5-ghostlock 的探针（不走 Docker / make）
#
# 用法:
#   ./build_leaf5.sh            # 编译全部
#   ./build_leaf5.sh mmleak     # 只编 S02 mm 泄漏
#   ./build_leaf5.sh probes     # 只编 S04/S05 探针
#
# 产物:
#   leaf5-ghostlock/out/exploit/aarch64/tests/test_mm_leak
#   leaf5-ghostlock/out/exploit/aarch64/tests/test_futex_hash
#   leaf5-ghostlock/out/stages/S04-ghostlock-trigger/arm64/ghostlock_edeadlk_detect
#   leaf5-ghostlock/out/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/arm64/ghostlock_uaf_reclaim_consumer
set -euo pipefail

# clang.exe 是 Windows 程序：路径必须给它 Windows 形式，且不能被 MSYS 改写
unset MSYS2_ARG_CONV_EXCL MSYS_NO_PATHCONV 2>/dev/null || true

REPO="${REPO:-/e/BOOX/leaf5-ghostlock}"
NDK="${NDK:-/c/Users/thelu/AppData/Local/Android/Sdk/ndk/27.0.12077973}"
BIN="$NDK/toolchains/llvm/prebuilt/windows-x86_64/bin"

# 传给编译器的所有路径统一转 Windows 形式（E:/... 而非 /e/...）
w() { cygpath -m "$1"; }

# API 35 的包装器本身带 --target + sysroot，直接当 CC 用
CC="$BIN/aarch64-linux-android35-clang"
CFLAGS=(-O2 -Wall -pthread)

[ -x "$CC" ] || { echo "NDK clang missing: $CC"; exit 1; }
[ -d "$REPO/exploit" ] || { echo "repo missing: $REPO"; exit 1; }

EXPLOIT_OUT="$(w "$REPO/out/exploit/aarch64/tests")"
PROBE10="$(w "$REPO/out/stages/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/arm64")"
PROBE04="$(w "$REPO/out/stages/S04-ghostlock-trigger/arm64")"

do_mmleak() {
  mkdir -p "$EXPLOIT_OUT"
  cd "$REPO/exploit"
  # test_mm_leak / test_futex_hash 需要 target.h 偏移常量（#38 g77c132eccfab）
  for t in test_mm_leak test_futex_hash; do
    echo "==> $t"
    "$CC" "${CFLAGS[@]}" -pie \
      -Isrc -Itargets/onyx-leaf5 \
      -DFUTEX_KEY_LAYOUT_V1 \
      -DTARGET_CONFIG_H=\"targets/onyx-leaf5/target.h\" \
      "test-programs/$t.c" -o "$EXPLOIT_OUT/$t"
  done
}

do_probes() {
  mkdir -p "$PROBE10" "$PROBE04"
  # EDEADLK 触发边（安全，不崩机）
  echo "==> ghostlock_edeadlk_detect"
  "$CC" "${CFLAGS[@]}" -static \
    "$(w "$REPO/leaf5/stages")/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/ghostlock_edeadlk_detect.c" \
    -o "$PROBE04/ghostlock_edeadlk_detect"
  # UAF + reclaim consumer（会 kernel panic，按需手动跑）
  echo "==> ghostlock_uaf_reclaim_consumer"
  "$CC" "${CFLAGS[@]}" -static \
    "$(w "$REPO/leaf5/stages")/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/ghostlock_uaf_reclaim_consumer.c" \
    -o "$PROBE10/ghostlock_uaf_reclaim_consumer"
  # 设备面触达基线（#38 slot_b）
  echo "==> slotb_surface_reach"
  "$CC" "${CFLAGS[@]}" -static \
    "$(w "$REPO/leaf5/stages")/S05-stack-overwrite/routes/10-ghostlock-true-uaf/probes/slotb_surface_reach.c" \
    -o "$PROBE10/slotb_surface_reach"
}

case "${1:-all}" in
  mmleak) do_mmleak ;;
  probes) do_probes ;;
  all)    do_mmleak; do_probes ;;
  *) echo "unknown target: $1"; exit 1 ;;
esac

echo
echo "=== artifacts ==="
find "$REPO/out" -type f -printf '%10s  %p\n'
