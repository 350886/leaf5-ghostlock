# Leaf5 #38 — 配置闸门 + T1（futex_lock_pi consumer）实测

运行时：`4.19.157-perf-g77c132eccfab-dirty #38` · slot `_b` · Android 13 · shell `u:r:shell:s0`
真源：设备 `/proc/config.gz`（sha256 与仓库 `leaf5/raw/config.gz` 字节相同）
日期：2026-10-26

---

## 1. 配置闸门（`/proc/config.gz`，6228 行，直接读的）

### 1.1 被配置判死的路

| 路线 | 关键开关 | 判定 |
|---|---|---|
| E — `modprobe_path` / `core_pattern` / `poweroff_cmd` | `CONFIG_STATIC_USERMODEHELPER=y` | **死**。所有 usermode helper 走 `static_usermodehelper_path`，改这三个字符串不生效 |
| I — 栈页交叉缓存 | `CONFIG_VMAP_STACK=y` | **死**（与仓库判断一致：vmalloc 栈与 kmalloc-32/64 交叉回收不现实） |
| userns 类（DirtyPipe 变体、CVE 大批） | `# CONFIG_USER_NS is not set` | **死**，无 unprivileged user namespace |
| C — 用户态 fake `task_struct` | `CONFIG_ARM64_PAN=y`（+UAO 不救） | **基本死**：PAN 生效，内核直接解引用用户页会 fault，除非走 uaccess 路径 |
| 关 SELinux 再打 | `# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set` | **死**：`androidboot.selinux=permissive` 无效（`SECURITY_SELINUX_DEVELOP=y` 单独不起作用） |
| kexec 系 | `# CONFIG_KEXEC is not set` | 死 |
| `/proc/kcore` 读内核 | `# CONFIG_PROC_KCORE is not set` | 死（且 shell EACCES） |

### 1.2 对你有利的（和仓库判断一致，这里给配置证据）

| 项 | 值 | 意义 |
|---|---|---|
| `# CONFIG_CFI_CLANG is not set` | 无 | 无内核 CFI，fops/函数指针劫持不需要签名 |
| `# CONFIG_KASAN is not set` | 无 | UAF 不会被 KASAN 抓住/静默 |
| `# CONFIG_UNMAP_KERNEL_AT_EL0 is not set` | 无 KPTI | 侧信道与直映引用更干净 |
| `# CONFIG_ARM64_PTR_AUTH` / `# CONFIG_SHADOW_CALL_STACK` | 无 | 无 PAC/SCS |
| `# CONFIG_INIT_ON_ALLOC_DEFAULT_ON` / `# CONFIG_INIT_ON_FREE_DEFAULT_ON` | 无 | 堆不清零，spray 命中率高（实测 sk_buff 4/4 各 65536 B） |
| `# CONFIG_SLUB_DEBUG` / `# CONFIG_DEBUG_LIST` | 无 | 链表/红黑树被踩不会被 debug 检查当场 BUG() |
| `# CONFIG_PANIC_ON_OOPS is not set` | 无 | **oops 只杀任务，不整机 panic** → 可以更激进地试探 |
| `CONFIG_KALLSYMS_ALL=y` | 有 | 一旦拿到任意读，`/proc/kallsyms` 之外还有完整符号表可用 |
| `CONFIG_SECURITY_SELINUX_DEVELOP=y` | 有 | 有 `security_setenforce` 实现；拿到写原语后 `selinux_state.enforcing=0` 比改 cred 更省事 |
| `CONFIG_ASHMEM=y` / `CONFIG_QCOM_KGSL=y` / `CONFIG_ANDROID_BINDER_IPC=y` | 有 | 三条用户态可达面都在（ashmem 被 SELinux 挡在 open，另两条通） |

### 1.3 `STATIC_USERMODEHELPER=y` 的实际后果

这条最容易被忽略：**即使 GhostLock 拿到任意写，`modprobe_path` 那套也不成立**。要 root 只能：
- 改 `current->cred` / `init_cred`（需要"读+写"或精确的固定值写），或
- 置 `selinux_state.enforcing=0` + 已有 cap，或
- 走 `fops` → 自建任意读写 → 再改 cred（仓库 S07 设想）

仓库 S07 的 `fops→physrw→root` 路线与这个配置是自洽的；`POST_B` 里 E 方向（`modprobe_path`）在你机器上可以整块划掉。

---

## 2. T1 实测：`FUTEX_LOCK_PI` 当 consumer 会不会产生 store

仓库 `VERIFY_2026-08-13_slotb.md §11` 把 T1 列为开放待办，前提写的是"先反汇编该入口的 chwalk/orig_waiter"。我直接给了三组设备对照，先用实测判生死。

### 2.1 三组对照

| # | 载体 | lock 来源 | consumer | 结果 |
|---|---|---|---|---|
| A | `ghostlock_uts_oracle`（stage 探针） | `empty_zero_page` | `sched_setattr` ×8 | **PANIC，整机重启**（adb 掉线，uptime 归零） |
| B | `preload.so`（exploit 路径） | sk_buff spray `fake_lock` | `sched_setattr` ×8 | **存活**，`hit=0`，`root=0` |
| C | `preload.so`（exploit 路径） | sk_buff spray `fake_lock` | **`futex_lock_pi`** | **存活**，`consumer ret=0 errno=0`，`hit=0`，`root=0` |

### 2.2 C 组原始输出（关键行）

```
[*] KernelSnitch mm found addr=ffffff80000aca28 sz=0x388
[*] fake payload mode=0 write_shape=0 lock=ffffff80000a84d0 w0=ffffff80000a93a0 task=ffffff80000aa380
    write_parent=454c4341524f4c47 write_right=0 write_left=ffffff800381bf2c
[*] sk_buff reclaim send 1/4 ret=65536 … 4/4 ret=65536
[*] pselect route setup attempt=8 simple=0 shift=15 page=ffffff80000a8000
    fake_lock=ffffff80000a84d0 fake_w0=ffffff80000a93a0 fake_task=ffffff80000aa380
    out5=ffffff800381bf24 out7=454c4341524f4c47 ex3(prio)=0x82
[*] consumer futex_LOCK_PI seq=8 ret=0 errno=0
[*] consumer done seq=8 mode=futex_lock_pi fake_lock=ffffff80000a84d0 fake_fops=ffffff80000a8180
[*] pselect returned attempt=8 ret=0 errno=0 calls=1 success=1
[*] uts oracle after sysname='Linux' hit=0 target=ffffff800381bf2c value=454c4341524f4c47
[*] skip CFI probe (WRITE_ORACLE non-fops or SKIP_CFI_PROBE)
[+] pipe-physrw-summary pid=4094 done=0 root=0 kaslr=1 base=ffffff8008080000 slide=0000000000000000
[+] pipe physrw pid=4094 done=0 root=0 read_ok=0 write_ok=0 rw64=0/0
    uid=4294967295->4294967295 selinux=255->255
```

### 2.3 结论

1. **T1 关闭**：`FUTEX_LOCK_PI` 作为 consumer，在 `fake_lock` 几何下 **不产生任何 store** —— `uname.sysname` 保持 `Linux`，`hit=0`，`uid` 不变。它和 `sched_setattr` 一样在 `0xa080` 之前退出 walk。不需要再为它反汇编了，实测已判死。
2. **A 组的 panic 不是 consumer 造成的**，是 `empty_zero_page` 当 `waiter->lock` 的craft 不稳（仓库 2026-07-26 就记录过这一点，这次在你机器上再次复现）。以后做 consumer 实验**必须走 exploit 的 spray `fake_lock`**，别用 stage 探针的零页版本。
3. **UAF 在你的机器上是活的**：A 组把整机打崩了，说明 residual 确实被解引用。
4. `slide=0`、`base=ffffff8008080000` —— 你这台 KASLR 没实际偏移，仓库 §10.2 的绝对 VA（`ashmem_misc=ffffff800b9710a8` 等）可以直接用。
5. `# PANIC_ON_OOPS` 没开，但 A 组是整机重启 —— 说明那次不是普通 oops，是 panic 级（空页当 lock 走到不该走的地方）。

---

## 3. 还活的路（按这台的配置重新排）

| 序 | 方向 | 依据 | 第一动作 |
|---|---|---|---|
| 1 | **T4 KGSL 独立 LPE** | `kgsl_ioctl=ffffff80087a32d8`（#38，+0x6f8）；`DRAWCTXT_CREATE flags=0x12` 实测通；`gpuobj/sparse/timeline` 符号齐 | 用 #38 ELF 对 ioctl nr↔handler，查 CVE-2024-23380 族 patch-gap |
| 2 | **T5/T6 Binder patch-gap** | `/dev/binder`、`/dev/hwbinder` shell 可 open；`binder_transaction=ffffff8008dd3cb0` 已漂 | CVE-2024-46740 合法 handle + readbuf hexdump 判补丁；CVE-2023-20938 `buffer_release` 检查点 |
| 3 | **T2 wakeup erase** | 只有它能绕开"rb_erase 在 PI walk 里不可达" | 静态写 `mark_wakeup_next_waiter` 的 `rb_erase_cached` 触发条件（leftmost=residual） |
| 4 | ~~T1~~ | 本次实测关闭 | — |
| — | per-se 侧信道增强 | `perf_event_paranoid=-1`，SW/HW 都通 | 只作辅助，不是 LPE |

**不要再碰**：SHIFT×shape 同构扫描、ashmem fops−8、`sched_setattr` 当 store、`futex_lock_pi` 当 store（本次新增结论）、shell BPF（`bpf MAP_CREATE` 实测 EACCES）。

---

## 4. 资源现状

| 项 | 位置 | 说明 |
|---|---|---|
| #38 符号 | `VERIFY_2026-08-13_slotb.md §10.2` | 只有 6 个符号；`init_task`/`init_uts_ns`/`selinux_state` 与 #245 同值 |
| #38 完整 ELF | **仓库里没有**（`raw/slotb_38/` 被 gitignore） | 要 T2/T4/T5 的 patch-gap，必须自己 EDL 只读 dump `boot_b` 重建 |
| loader | 作者用的是 `palma2pro.bin`（HWID `0x0013f0e1`，与 Leaf5 同机） | 这是能进 Firehose 的关键参数 |
| 构建 | 本机 NDK r27，`build_leaf5.sh` / `run_leaf5.sh` | 无 Docker/make 依赖 |
