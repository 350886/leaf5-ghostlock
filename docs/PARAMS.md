# 参数全表

> 所有参数都通过环境变量传入，代码里没有写死的开关。
> 「实证值」= B405 / B407 / B410 三次成功实际用过的值，已打包在 `scripts/env.sh` 的 `CHAIN_ENV` 里。
> 改任何一项之前先看 [`ROOT_CHAIN.md`](ROOT_CHAIN.md) 对应的避坑条目 —— 大部分参数改了就是 panic。
>
> **基准环境**：ONYX BOOX Leaf5 / Android 13（SDK 33）/ ONYX 固件 `4.2.3-rel_0928_656b72278`
> / 内核 `4.19.157-perf-g77c132eccfab-dirty` #38 / arm64-v8a。

---

## A. 链路骨架（必开）

| 参数 | 源码默认 | 实证值 | 作用 | 改了会怎样 |
|------|----------|--------|------|-----------|
| `SKIP_LEAK` | `0` | `1` | 跳过 kernelsnitch 现场扫描，直接用已知 slide | 关掉要等扫描，慢几十秒；slide 未知时不能关 |
| `PERF_TASK` | `0` | `1` | 用 perf 采样泄漏 `current` 的 `task_struct` 地址 | 不开则 `STACK_LOCK` 无上下文 |
| `PERF_CRED` | `0` | `1` | 用 perf 采样泄漏 `current->cred` 地址 | **不开则 `prmptr`/`bsetptr` 直接报错退出** |
| `STACK_LOCK` | `0` | `1` | 在自身上下文里种 fake `rt_mutex` | 不开则没有可写的 `lock->waiters` |
| `PARENT_PAINT` | `0` | `1` | 用 sigreturn 帧把 waiter 十个 word 画到内核栈 | 不开则 `waiter->task` 指向垃圾 |
| `WRITE_PLAN` | 空 | `selinux,prmptr,bsetptr` | 每轮写什么，逗号分隔 | 见 §B |
| `ROUTE_ROUNDS` | `1` | `3` | 做几轮 route（范围 1..4） | 少于 3 拿不到整片 bset；多于 3 无意义且风险累积 |
| `THREAD_RACE` | `0` | `1` | 第 2 轮起换新线程，且线程跑完常驻 | **关掉 = 同一线程连做两轮 = `rtmutex_common.h:60` 必崩** |
| `RB_LEFTMOST_PAD` | `0` | `1` | `rb_leftmost` 指向 pad 槽，让 erase 落进 case1 | 关掉则不走 `+0x78` 那段，写原语失效 |
| `FAKE_LOCK_HELD` | `0` | `0` | 让 `trylock` 成功才会走到 `tbnz w28` | 设 1 则提前返回，写不落 |
| `CAPS_FULL_FINISH` | `0` | `1` | capset → ambient raise → setresuid → 再 capset | 不开则 uid 到 0 但 execve 后能力全丢 |
| `FAST_ROOT` | `0` | `1` | euid=0 后直接装 su + 起 daemon，不走 physrw | 不开则拿到 root 也没法用 |
| `INPROC_SU` | `0` | `1` | daemon 不 execve，直接在 fork 出的子进程里跑 | 关掉则 daemon 的 `CapEff=0`，DAC 操作失败 |

---

## B. `WRITE_PLAN` 取值

一轮只能表达一个 `(target, value)`，所以三项对应三轮。

| 取值 | 形态 | target | value | 状态 |
|------|------|--------|-------|------|
| `selinux` | shape0 | `selinux_state` | `.bss` 低零垫片 | ✅ 稳，四次验证 |
| `prmptr` | shape0 | `cred+0x30` | `kbase+0x40a01cf` | ✅ B384 起 |
| `bsetptr` | shape0 | `cred+0x40` | `kbase+0x40a01cf` | ✅ B392 起 |
| `selinux6` | shape6 | 同 `selinux` | 同 `selinux` | ⚠️ 仅用于验证 shape6 |
| `prm` / `bset` / `eff` | shape6 | `cred+0x30/0x40/0x38` | `0x3fffffffff` | ❌ B398/B400 必崩 |
| `cred:0xNN` | shape4 | `cred+NN` | `0` | ⚠️ 写零用，B227 有坑 |
| `fops` | shape2 | `ashmem_misc.fops` | payload 页假表 | ⚠️ 单轮，不能配 `fopsowner` |
| `fopsowner` | shape4 | `fake_fops` | `0` | ⚠️ 同上 |
| `pagetest` | shape0 | `.bss` 低零垫片 | payload 页 | 诊断用 |
| `taskcred` | — | `current->cred` | `= init_cred` | ❌ 三次全崩 |
| `nop` | — | — | — | 占位 |

> `prmptr` / `bsetptr` 的 `value` 为什么长这样，见 `ROOT_CHAIN.md` §2.2 ——
> shape0 会把它当指针解引用一次，所以必须是"可读内核地址 + 低位等于想要的 cap 集"。

---

## C. 时序与容量

| 参数 | 源码默认 | 实证值 | 说明 |
|------|----------|--------|------|
| `PSELECT_ROUTE_DELAY_USEC` | `0`（内部爬梯 0→100ms） | **`150`** | **不是"等多久"，是时序对齐**。`delay=0` 时 `adjust_prio_chain` 第一次读 `waiter->lock` 读到旧值，与第二次读（已被 `fd_set` 拷贝覆盖）不等 ⇒ `b.ne +0x70c` 退出。压到 90/60 直接 `rtmutex_common.h:60`（B319/B320/B321）。 |
| `PSELECT_ROUTE_NFDS` | `640` | `640` | **必须 > 320**。`core_sys_select` 在小 nfds 时用栈内 `fd_set`，会把 waiter 直接 memset 掉。 |
| `PSELECT_ROUTE_ATTEMPTS` | 见 `fops.c:2773` | `2` | route 重试次数（不是 chain 轮数） |
| `READV_IOV_SEGS` | `READV_PAINT_SEGS_DEFAULT` | `8` | 8 = 10 个 waiter word 全控；5 = 只控 `tree_entry` |
| `PAINT_SRC` | 未设 | `sigret` | sigreturn 帧作画布 |
| `PAINT_HOLD` | 未设 | `spin` | 自旋保持，不让 pselect 提前返回 |
| `PAINT_SPIN_MAX` | — | `400000000` | 自旋上限（防死等） |
| `PI_CONSUMER` | 未设 | `sched_setattr` | 触发 pi 链的消费者 |
| `PAGE_SETUP_ATTEMPTS` | `0`（内部默认） | `1` | payload 页 setUp 重试 |
| `MM_SPRAY_SLABS` | `20` | `0` | slab spray 量。链里关掉（配合 `SKIP_LEAK`） |

---

## D. 泄漏与采样

| 参数 | 默认 | 说明 |
|------|------|------|
| `PERF_TASK_FILTER` | `1` | 采样时按 tid 过滤，只认自己 |
| `PERF_TASK_MIN_VOTES` | — | 票数门槛；与 `PERF_CRED` 共用"跨 attempt 地址一致即采信" |
| `PERF_CRED_MIN_VOTES` | — | 同上。高负载下票数会低到 4/9，别再抬门槛 |
| `PERF_CRED_DELTA` | — | `cred` 相对 `task` 的偏移候选 |
| `PERF_LOOPS` | — | 采样轮数 |
| `PERF_PERIOD` | — | `perf_event` 周期 |
| `KSNITCH_COLLISIONS` | — | kernelsnitch 哈希碰撞轮数（`SKIP_LEAK=1` 时不生效） |

**`GETUID_CRED_OFF_LO` 不是环境变量，是源码常量**：`0x0de7d4`。
`0x0de7d0` 是 `ldr x8,[x8,#0x7e0]` 本身，停在那条上时 `x8` 还是 `task`（B368）。

---

## E. 调试与排障

| 参数 | 默认 | 说明 |
|------|------|------|
| `NO_IDLE` | `0` | 起纯自旋线程钉住 `cpu1..cpuN-1`。**负优化**：loadavg 到 12，adb 超时，单轮 535 秒，且不改善成功率（B408）。 |
| `NO_IDLE_MS` | — | 自旋线程的运行时长 |
| `WAITER_WORDS_DUMP` | — | 打印 waiter 十个 word 的现场值 |
| `SIGRET_DUMP` | — | 打印 sigreturn 帧 |
| `LOG_FSYNC` | — | 每条日志 `fsync`，panic 前的最后一行不会丢 |
| `KSNITCH_VERBOSE` | — | kernelsnitch 逐轮输出 |
| `INPROC_PROBE` | — | daemon 侧探针 |

---

## F. 设备脚本层的变量（`scripts/env.sh`）

这些不在 `preload.so` 里，是主机侧脚本用的。

| 变量 | 默认 | 说明 |
|------|------|------|
| `REPO` | 脚本上一级 | 仓库根 |
| `ADB` | 自动探测 | adb 路径 |
| `ANDROID_ADB_SERVER_PORT` | `5037` | 抢端口时改成独立端口 |
| `DEV_ROOT` | `/data/local/tmp` | 设备端根 |
| `DEV_BIN` | `$DEV_ROOT/exploit/aarch64` | `preload.so` 所在（`LD_PRELOAD=./preload.so` 是相对路径，必须 cd 进来） |
| `DEV_RUNS` | `$DEV_ROOT/runs` | 日志目录 |
| `LOGDIR` | `$REPO/logs` | 主机侧日志目录 |
| `MIN_UP` | `90` | 起跑前要求的最小 uptime（秒）。见 `ROOT_CHAIN.md` C1 |
| `RUNSEC` | `540` | 单轮总时限 |
| `SLEEPSEC` | `480` | `LD_PRELOAD` 宿主进程（`/system/bin/sleep`）的参数 |
| `REQUIRE_SYSADMIN` | `0` | 设 1 则必须 bit21=1 才收工 |
| `CHAIN_ENV` | 见 §A | 上面所有参数拼成的字符串，一处覆盖全局 |
| `SO_MD5` | 读 `logs/.so_md5` | 推错 so 会让所有判据失效 |

---

## G. 一次改一个

调参顺序（每次只动一项，跑 3 次看结果）：

```
1. MIN_UP          —— 只影响起跑时机，最安全
2. ROUTE_ROUNDS    —— 只能 3；改成 2 拿不到 bset
3. PSELECT_ROUTE_DELAY_USEC —— 只能 150；已扫过 0..150 全区间
4. PSELECT_ROUTE_NFDS —— 只能 >320；640 已验证
5. WRITE_PLAN      —— 改顺序或换形态，风险最高
```

`NO_IDLE`、`MM_SPRAY_SLABS`、`PSELECT_ROUTE_ATTEMPTS` 都属于"改了不改善成功率"的一类，
不要拿来反复试。
