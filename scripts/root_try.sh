#!/usr/bin/env bash
# root_try.sh —— 最多 N 次自动重试，成功即停
#
#   ./scripts/root_try.sh            # 默认 3 次
#   ./scripts/root_try.sh 6
#   REQUIRE_SYSADMIN=1 ./scripts/root_try.sh 8   # 必须带 CAP_SYS_ADMIN 才收工
#
# 一轮 = (必要时 reboot → 等就绪) → 一个进程内三轮 route
#        → CAPS_FULL_FINISH 落 uid=0 → FAST_ROOT 起 su daemon → 校验
#
# 单轮成功率约 2/3（失败几乎都死在 round 2/3 的 rtmutex 断言）。
# 三次独立重试后 ≈ 1-(1/3)^3 = 96%。
#
# 判定成功三条同时成立：
#   1) /proc/uptime 没有回绕（回绕 = 中途 panic 重启了）
#   2) exec_probe.txt 的 CapEff 不是 0xc0 / 0
#   3) /data/local/tmp/su -c "id" 输出 uid=0
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/env.sh"

TRIES="${1:-3}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

sh_() { timeout "${2:-10}" "$ADB" shell "$1" 2>/dev/null | tr -d '\r'; }
cur_up() { sh_ 'cut -d. -f1 /proc/uptime' 8; }

# 等设备进入"可跑"状态：uptime >= MIN_UP
wait_ready() {
  local up="" need="${1:-$MIN_UP}"
  for _ in $(seq 1 90); do
    up=$(cur_up)
    if [ -n "$up" ] && [ "${up:-0}" -ge "$need" ] 2>/dev/null; then
      echo "$up"; return 0
    fi
    sleep 2
  done
  echo ""; return 1
}

ok_round=0
for i in $(seq 1 "$TRIES"); do
  TAG="T$(date +%H%M)_$i"
  echo "=============================================================="
  echo "=== 第 $i/$TRIES 次    tag=$TAG    $(date +%H:%M:%S)"

  up_now=$(cur_up)
  if [ -n "$up_now" ] && [ "${up_now:-0}" -ge "$MIN_UP" ] 2>/dev/null; then
    # 设备活着且已稳 —— 直接用。成功的三次都是这么跑的，不重启。
    echo "    设备已就绪 uptime=${up_now}s，不重启直接用"
  else
    echo "    当前 uptime=${up_now:-?}s 不够，重启并等 ${MIN_UP}s"
    timeout 10 "$ADB" reboot >/dev/null 2>&1
    sleep 8
    up0=$(wait_ready)
    [ -z "$up0" ] && { echo "    !! 等不到就绪状态，跳过这轮"; continue; }
    # 刚够 MIN_UP 时 package manager 可能还在扫包，再让它从容一会儿
    sleep 20
  fi
  up0=$(cur_up)
  echo "    起跑  uptime=${up0}s  enforce=$(sh_ getenforce)"

  # 上一轮的探针必须清掉，否则读到的可能是旧的"成功"
  sh_ "rm -f $DEV_ROOT/exec_probe.txt $DEV_ROOT/root_ok" 8 >/dev/null

  bash "$SCRIPT_DIR/run_chain.sh" "$TAG" 150 "$CHAIN_ENV" >/dev/null 2>&1

  up1=$(cur_up)
  if [ -z "$up1" ]; then
    echo "    adb 无响应（大概率 panic），等它起来再来"
    wait_ready 60 >/dev/null
    continue
  fi
  if [ "${up1:-0}" -lt "${up0:-0}" ] 2>/dev/null; then
    echo "    uptime ${up0}s → ${up1}s 回绕 = 中途 panic 重启，这轮废了"
    continue
  fi
  echo "    存活  uptime=${up1}s (+$((up1 - up0))s)"

  probe=$(sh_ "grep -m1 '^CapEff' $DEV_ROOT/exec_probe.txt" 8 | awk '{print $2}')
  idout=$(sh_ "$DEV_ROOT/su -c \"id\"" 15 | head -1)
  echo "    CapEff=${probe:-<无>}   su id: ${idout:-<无>}"

  # ★ 掩码看 route 日志的 bnd=，不要看 exec 后的 CapEff ★
  # 那个内核 execve 的 pP' 落在 inheritable 上，CapEff 只是 inh 的镜像，
  # 用它判断 CAP_SYS_ADMIN 会误判（踩过两轮）。
  bnd=$(sh_ "grep -a 'round 3 caps' $DEV_RUNS/$TAG.log | tail -1" 8 | sed 's/.*bnd=//')
  vm=0
  if [ -n "$bnd" ]; then
    vm=$((16#$bnd)) 2>/dev/null || vm=0
    echo "    掩码 bnd=${bnd}  低位=$(printf '%x' $((vm & 0x3fffff)))  bit21(SYS_ADMIN)=$(( (vm >> 21) & 1 ))"
  fi

  case "${probe:-}" in
    "" | *00000000000000c0 | *0000000000000000)
      echo "    cap 没抬起来，下一轮"; continue ;;
  esac
  case "${idout:-}" in
    *"uid=0"*) ;;
    *) echo "    cap 有了但 uid 没到 0，下一轮"; continue ;;
  esac
  if [ "${REQUIRE_SYSADMIN:-0}" = "1" ] && [ -n "${bnd:-}" ]; then
    if [ $(( (vm >> 21) & 1 )) -eq 0 ]; then
      echo "    这轮没有 CAP_SYS_ADMIN（KASLR slide 抽签决定），换一个"
      continue
    fi
  fi

  ok_round=$i
  break
done

echo "=============================================================="
if [ "$ok_round" -eq 0 ]; then
  echo "=== $TRIES 次都没成。日志：$LOGDIR/chain_T*.txt"
  exit 1
fi

echo "=== 成功：第 $ok_round 次"
sh_ "$DEV_ROOT/su -c \"id\"" 15 | head -1
echo "--- 能力"
sh_ "$DEV_ROOT/su -c \"grep -E '^Cap(Eff|Bnd)' /proc/self/status\"" 15
echo "--- 写测试"
sh_ "$DEV_ROOT/su -c \"touch $DEV_ROOT/root_ok && echo TOUCH_OK\"" 15
echo "--- 挂载测试（要 CAP_SYS_ADMIN 才成）"
sh_ "$DEV_ROOT/su -c \"mkdir -p $DEV_ROOT/m && mount -t tmpfs tmpfs $DEV_ROOT/m && echo MOUNT_OK && umount $DEV_ROOT/m\"" 20
exit 0
