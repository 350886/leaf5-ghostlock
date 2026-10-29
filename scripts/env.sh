#!/usr/bin/env bash
# env.sh —— 所有脚本共用的路径与 adb 设置
#
# 用法：在其它脚本里 `source "$(dirname "$0")/env.sh"`
# 每一项都能被同名环境变量覆盖，所以换机器不用改文件。
#
# Windows 两个必须关的东西（不关就会把 /data/local/tmp 变成 C:/Program Files/Git/...）：
#   MSYS_NO_PATHCONV=1
#   MSYS2_ARG_CONV_EXCL='*'
set -uo pipefail

# ---- 仓库根：脚本在 <repo>/scripts/ 下，往上一层就是根 ----
REPO="${REPO:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
export REPO

# ---- adb ----
# 优先用 $ADB；其次找 PATH 里的 adb；最后试 Windows SDK 默认位置。
if [ -z "${ADB:-}" ]; then
  if command -v adb >/dev/null 2>&1; then
    ADB="$(command -v adb)"
  else
    for c in \
      "/c/Users/$USER/AppData/Local/Android/Sdk/platform-tools/adb" \
      "$HOME/Android/Sdk/platform-tools/adb" \
      "$HOME/Library/Android/sdk/platform-tools/adb"
    do
      [ -x "$c" ] && { ADB="$c"; break; }
    done
  fi
fi
[ -n "${ADB:-}" ] || { echo "[-] 找不到 adb，设置 ADB=/path/to/adb" >&2; return 1 2>/dev/null || exit 1; }
export PATH="$(dirname "$ADB"):$PATH"

# 本机 adb server 端口。多设备/多用户抢 5037 时改成独立端口。
export ANDROID_ADB_SERVER_PORT="${ANDROID_ADB_SERVER_PORT:-5037}"

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

# ---- 设备端路径 ----
DEV_ROOT="${DEV_ROOT:-/data/local/tmp}"
DEV_BIN="${DEV_BIN:-$DEV_ROOT/exploit/aarch64}"
DEV_RUNS="${DEV_RUNS:-$DEV_ROOT/runs}"

# ---- 本机日志目录（不入库，见 .gitignore）----
LOGDIR="${LOGDIR:-$REPO/logs}"
mkdir -p "$LOGDIR" 2>/dev/null

# ---- 单轮 exploit 的总时限（秒）----
# preload.so 挂在 /system/bin/sleep 上跑，这个数是 sleep 的参数，
# 也是 timeout 的上限。成功后监控会提前收工，不会等满。
RUNSEC="${RUNSEC:-540}"
SLEEPSEC="${SLEEPSEC:-480}"

# ---- 设备就绪判据 ----
# ★ 硬约束：reboot 后 uptime < 90s 就起跑，三轮会全部崩在 round 1 刚起步。
#   见 docs/ROOT_CHAIN.md 「约束 C1」。
MIN_UP="${MIN_UP:-90}"

# 需要 CAP_SYS_ADMIN（bit21）才收工 —— 该位由 KASLR slide 抽签决定，
# 约一半概率，设 1 后平均要多跑一倍次数。
REQUIRE_SYSADMIN="${REQUIRE_SYSADMIN:-0}"
export REQUIRE_SYSADMIN

# ---- 已验证的 chain 配置（B405/B407/B410 三次实测）----
# 改动前先读 docs/ROOT_CHAIN.md：这里面每一个变量都对应一条死路。
CHAIN_ENV="${CHAIN_ENV:-\
SKIP_LEAK=1 PERF_CRED=1 PERF_TASK=1 \
WRITE_PLAN=selinux,prmptr,bsetptr THREAD_RACE=1 ROUTE_ROUNDS=3 \
STACK_LOCK=1 PARENT_PAINT=1 CAPS_FULL_FINISH=1 FAST_ROOT=1 INPROC_SU=1 \
PSELECT_ROUTE_ATTEMPTS=2 PAGE_SETUP_ATTEMPTS=1 MM_SPRAY_SLABS=0}"

# NO_IDLE=1 会起纯自旋线程钉住 cpu1..cpuN-1。默认关：
# 7 个自旋把 load 推到 12，adb 处处超时，单轮 535 秒（负优化，B408 实测）。
NO_IDLE="${NO_IDLE:-0}"
[ "$NO_IDLE" = "1" ] && CHAIN_ENV="$CHAIN_ENV NO_IDLE=1"

export ADB DEV_BIN DEV_RUNS LOGDIR RUNSEC SLEEPSEC MIN_UP CHAIN_ENV

# 只在 Windows 上杀 adb.exe；Linux/macOS 上 taskkill 不存在，忽略即可。
kill_adb() {
  command -v taskkill >/dev/null 2>&1 && taskkill /F /IM adb.exe >/dev/null 2>&1
  return 0
}

# 等设备到 device 状态
wait_device() {
  local n="${1:-40}" i
  for i in $(seq 1 "$n"); do
    [ "$("$ADB" devices 2>/dev/null | awk 'NR>1 && $2=="device"{print $1;exit}')" != "" ] && return 0
    sleep 1
  done
  return 1
}
