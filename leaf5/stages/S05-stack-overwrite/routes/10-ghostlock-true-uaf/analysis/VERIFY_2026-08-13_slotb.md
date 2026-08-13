# 验证记录：slot `_b` / kernel #38（2026-08-13）

> **runtime**: `4.19.157-perf-g77c132eccfab-dirty` **#38** · slot `_b` · serial `ac340d06`  
> **闸门**: 初轮不匹配；随后 **EDL 只读** `boot_b` → ELF 已对齐 `#38`  
> **刷写**: 排除；仅 `r boot_b` + `reset`  
> **权威**: 本文件 + `identity.txt` / `config.gz` / `leaf5/raw/slotb_38/vmlinux.elf`

---

## 0. 闸门（先读）

| 项 | #245 仓库真源 | 今日设备 | 判定 |
|----|---------------|----------|------|
| uname hash | `g3d47a6619220` | `g77c132eccfab` | ❌ 不同构建 |
| build | `#245` Apr 10 | `#38` Jul 28 | ❌ |
| slot | 当时 `_a`（boot_a） | **`_b`** (`mmcblk0p14`) | 另一槽 |
| userspace | — | `2026-08-03_11-15_4.2-rel_0803_3c19bf624` | 新系统镜像 |
| CONFIG key 集 | `raw/config.gz` | 本目录 `config.gz` | **0 项变化** |
| kheaders UTS | `#244` / 旧 hash | `#37` / 新 hash（uname `#38`） | 同「差 1」模式 |

**禁止**用 `leaf5/raw/vmlinux*` / `target.h` 地址跑 shaped pselect / UTS / fops / parent-crash。  
**允许**无偏移探针：EDEADLK、adjtimex 宽窗、设备 open、ioctl errno、bpf/perf。

要继续 GhostLock **写几何**（真 shape0 / rb_erase）：需 **只读** 提取 `boot_b` → 重建 ELF（非刷写）。

---

## 1. 清单逐项

| ID | 项 | 本轮 | 证据 |
|----|----|------|------|
| G0 | runtime / 镜像对齐 | ❌ 闸门失败 | uname vs `#245` |
| G1 | EDEADLK 边仍在 | ✅ | `CMP ret=-1 errno=35`；WAIT `110` |
| G2 | UAF 活性（0x41 + consumer） | ✅ **仍 live** | adjtimex-only 存活；consumer → `kernel_panic,null` |
| G3 | 真 shape0 + parent crash / UTS | ❌ erase 仍不可达 | §10：`out5=0x4141…` ×8 存活；uts hit=0 |
| G4 | ashmem fops oracle | ❌ shell 不可 open | native `open` errno=**13**（#245 C 探针曾可） |
| G5 | BPF | ❌ | `PROG_LOAD/MAP_CREATE` errno=13 |
| G6 | perf | ✅ 可达 | SW/HW fd≥0；非 LPE |
| G7 | KGSL 触达 + sparse/gpuobj | ✅ 面在 | ctx `0x12` OK；多 nr EFAULT；sparse 类 **524** |
| G8 | Binder 46740 最小触发 | ⚠️ 未证补丁 | WRITE_READ 存活；未证明走到 `object_offset` 检查 |
| G9 | GPU 固件 21479/21480 | ⚠️ 读不到 fw | `Adreno619v1`；`/vendor/firmware_mnt` shell 拒 |
| G10 | Context+ | ⚠️ 面在未调用 | `service list` 230 行；`vendor.perfservice` 在 |
| H3 | 刷写 / Magisk | ⛔ 用户排除 | — |

---

## 2. GhostLock（无偏移）

### 2.1 EDEADLK

`ghostlock_edeadlk_detect`（arm64）：

```
CMP_REQUEUE_PI ret=-1 errno=35
WAIT_REQUEUE_PI ret=-1 errno=110
KERNEL SURVIVED
```

与 #245 同信号。EDEADLK **本身**在修/未修 `remove_waiter` 时都会出现。

### 2.2 对照 + UAF consumer

| 探针 | 结果 | 含义 |
|------|------|------|
| `ghostlock_edeadlk_adjtimex_only` | EDEADLK + adjtimex errno=1 → **SURVIVED** | 无 consumer 不崩 |
| `ghostlock_uaf_reclaim_consumer` | 打印 adjtimex 后 adb 断；重启 `bootreason=kernel_panic,null` | **UAF 仍被 walk** |

**结论**: `#38` 上 CVE-2026-43499 **代码面未关**（至少 `pi_blocked_on` 仍被错误路径留下并可解引用）。  
adjtimex 208B 宽窗仍够到 waiter 槽（不必用 `#245` SHIFT）。

### 2.3 写链 / rb_erase（未跑）

静态复查 `#245` `fops.c`（仪器，非本机几何）：

- `PSELECT_WRITE_SHAPE_DEFAULT=1` 会把未显式区分的 `LOCK_SHAPE=0` **改成 shape 1**
- `PSELECT_PARENT_CRASH` 原先只写在 shape 0 分支
- §57 parent-crash 存活 **不能**证明 `rb_erase` 不可达

**代码**: `exploit/src/fops.c` 已改：`PSELECT_LOCK_SHAPE` 显式值优先生效；`PARENT_CRASH` 在选定 shape 之后一律覆盖 `parent`。  
**设备**: 未在 `#38` 跑 exploit（地址会错）。重测条件 = 匹配 ELF。

---

## 3. 触达面（native）

`slotb_surface_reach` + `bpf_perf_reach`：

| 节点 / 调用 | 结果 |
|-------------|------|
| `/dev/kgsl-3d0` R/W | ✅；`DRAWCTXT_CREATE flags=0x12` id=11 |
| `/dev/binder` `/dev/hwbinder` | ✅ |
| `/dev/uhid` `/dev/uinput` | ✅ |
| `/dev/ashmem` | ❌ errno=13（**CORRECTED** vs #245 C open） |
| `/dev/ion` | R only |
| `/dev/qce` `/dev/diag` `/dev/dri/*` | ❌ 13 |
| `bpf` | ❌ 13 |
| `perf_event_open` SW/HW | ✅ |

ashmem 作 CFI/fops oracle 在 **本 userspace/策略** 下对 shell 关闭。

---

## 4. KGSL sparse / gpuobj（非 23380）

`kgsl_sparse_gpuobj_reach`：context 成功。零结构非 EINVAL/ENOTTY：

| nr | 零结构 | 坏指针 0x8 |
|----|--------|------------|
| 0x40 | ret=0 | EFAULT |
| 0x45 | ret=0（含 named GPUOBJ_ALLOC?） | EFAULT |
| 0x48 | errno=**524** | EFAULT |
| 0x4b | EOPNOTSUPP | EFAULT |
| 0x50–0x55 | 524 | EFAULT |
| 0x58 | ret=0 | EFAULT |
| 0x4d / 0x4e | ENOTTY | — |

大量 nr 到 `copy_from_user`（EFAULT）。524 = 本树「功能关/不支持」（sparse 很像）。  
**不是**独立 LPE 证明；符号↔nr 映射要 `#38` vmlinux。旧 CFU 盖 waiter **不重打**。

---

## 5. Binder CVE-2024-46740

`binder_offset_oversize`：`BINDER_VERSION proto=8`，mmap OK，`BC_TRANSACTION` + `object_offset=0x100 > data_size=0x10`，ioctl ret=0，进程存活。  
read 8B 的 BR 解析不可靠（未 hexdump），**不能**判定已修/未修。  
下一步（需新 ELF 或更完整 SM 事务）：合法 handle + hexdump `BR_FAILED_REPLY`。

CVE-2023-20938：本轮无独立触发。

---

## 6. GPU 固件 / Context+

- GPU：**Adreno619v1**；`ro.gfx.driver.1=com.qualcomm.qti.gpudrivers.lito.api30`；`persist.sys.force_sw_gles=1`
- `/vendor/firmware_mnt` shell Permission denied → **21479/21480 固件版本未知**
- `service list` 230 行；`vendor.perfservice` 在。未 `service call`（避免误触）

---

## 7. CONFIG（相对 #245）

`config.gz` 关键项与 `leaf5/raw/config.gz`：**only_new=0 only_old=0 changed=0**。  
`FUTEX_PI=y`，无 CFI，无 KPTI，`USER_NS` 关，`VMAP_STACK=y`，`NF_TABLES` 关，`IO_URING` 关。  
策略/SELinux/userspace **有变**（ashmem EACCES），不是 CONFIG 变。

---

## 8. 文件

| 路径 | 说明 |
|------|------|
| `analysis/VERIFY_2026-08-13_slotb/` | config.gz、kheaders.tar.xz、identity、service_list |
| `analysis/VERIFY_2026-08-13_slotb.md` | 本文 |
| `probes/slotb_surface_reach.c` | native 触达 |
| `probes/binder_offset_oversize.c` | 46740 风格 |
| `probes/kgsl_sparse_gpuobj_reach.c` | ioctl 面 |
| 既有 EDEADLK / adjtimex / bpf 探针 | 复测 #38 |

---

## 10. EDL 只读 `boot_b` + ELF + 真 shape0（同日续）

### 10.1 提取

| 步 | 结果 |
|----|------|
| loader | `/Users/tautcony/Documents/repos/edl/palma2pro.bin`（HWID `0x0013f0e1`，与 `edl/leaf5.md` 同机） |
| 命令 | `edl.py --loader=palma2pro.bin --memory=eMMC r boot_b …/stock_read/boot_b.img` |
| 大小 | 96MB（sector 1508352 × 196608） |
| banner | `g77c132eccfab-dirty #38` **= uname** |
| reset | firehose `reset`（无写分区）；设备回到 `#38` |
| Image | boot v2 page=4K，内核未压缩 `ARM\x64` → `raw/vmlinux_extracted_38` |
| ELF | `raw/slotb_38/vmlinux.elf` · 121896 symbols · `_text=0xffffff8008080000` |

### 10.2 符号对照（#245 vs #38）

| 符号 | #38 VA | vs #245 |
|------|--------|---------|
| `remove_waiter` | `0xffffff800814af10` | SAME |
| `rt_mutex_adjust_prio_chain` | `0xffffff8008149eb0` | SAME |
| `do_futex` / `adjust_pi` | 同旧 | SAME |
| `init_task` / `init_uts_ns` / `selinux_state` | 同旧 | SAME |
| `ashmem_misc` | `0xffffff800b9710a8` | **+0x140** |
| `ashmem_fops` | `0xffffff8009a284d0` | **−0x100** |
| `kgsl_ioctl` | `0xffffff80087a32d8` | +0x6f8 |
| `binder_transaction` | `0xffffff8008dd3cb0` | 漂移 |

`remove_waiter+0x64`: `mrs x20,sp_el0` 后 **`str xzr,[x20,#0x8d0]`** — bug 仍在（与 panic 一致）。  
`tbnz w28,#0 → 0xa1a4` 仍在 `0xffffff800814a0a4`。

### 10.3 真 shape0 parent-crash（仪器已修）

`PSELECT_LOCK_SHAPE=0 TMP_UNAME_PSELECT_WRITE_SHAPE=0 PSELECT_PARENT_CRASH=1 WRITE_ORACLE=uts`  
spray `fake_lock` · prio=0x82 · `sched_setattr` nice=19 · 8 轮：

```
write_shape=0
out5(tree_parent)=4141414141414141
ex2(lock)=fake_lock
ex3(prio)=82
CMP errno=35 · pselect ret=0 · sched_setattr ret=0
uts hit=0 · KERNEL SURVIVED · root=0
```

日志：`VERIFY_2026-08-13_slotb/exploit_shape0_parent_crash.txt`

**结论**: 修掉 shape 覆盖后 **`rb_erase` 仍不可达**。§57「parent-crash 存活 ⇒ 无 erase」在 **真 shape0** 上成立。空 `empty_zero_page` lock 的对照也会 panic，不能单独当 erase 证据。

### 10.4 独立面（ELF 后）

- KGSL：`gpuobj_*` / `sparse_*` / `timeline_*` **符号都在**（VA +0x6f8）；ioctl 面见 §4。
- Binder 46740：新 ELF **无** `object offset exceeds` 字符串；补丁仍未证。
- ashmem BSS 已漂；且 shell open EACCES → fops oracle 双关。

### 10.5 owner-follow ±1（usage @ task+0x68）[BIN]

`adjust_prio_chain` 在跳过 `rb_erase` 后：`atomic_dec(task+0x68)`，再 `owner=lock+0x18`，`atomic_inc(owner+0x68)`。  
`TASK_USAGE_OFF` **CORRECTED 0x28→0x68**（`add x8,x19,#0x68` / `__put_task_struct ldr [x19,#0x68]`）。

| 探针 | env | 结果 |
|------|-----|------|
| follow-inc crash | `LOCK_OWNER_CRASH=1`（owner=0x41） | **存活**；若走到 inc 会写 `0x40+0x68` 而崩 |
| UTS +1 oracle | `LOCK_OWNER_INC_UTS=1` owner=`sysname-0x68` + sampler | **hit=0**；`uname` 仍 `Linux` |

日志：`lock_owner_crash.txt`、`lock_owner_inc_uts.txt`。  
**结论**: 当前 `sched_setattr` 路径 **既不 `rb_erase`，也不走 owner-follow ±1**。walk 在 `0xa080` 之前退出。±1 不能当现成写原语。

---

## 11. 待办（开放，需新 [BIN]）

刷写 / Magisk / EDL 写已排除。下列才排期：

| ID | 项 | 前提 | 不做 |
|----|----|------|------|
| T1 | 换 consumer：`FUTEX_LOCK_PI` / `task_blocks_on_rt_mutex` 是否带非空 `orig_waiter` 进 `0xa080` | 先反汇编该入口的 `chwalk`/`orig_waiter` | 同几何再扫 `sched_setattr` |
| T2 | `mark_wakeup_next_waiter` 的 `rb_erase_cached`：构造 unlock/wake，leftmost=residual | 静态写出触发条件 | 无公式盲打 |
| T3 | 第二轮 fake waiter：owner-follow 进 spray 后再置 `w28=1` | T1/T2 或先证明能到 follow | 与 T1 重叠则合并 |
| T4 | KGSL 独立 LPE：`gpuobj`/`sparse`/`timeline` 用 `#38` ELF 对 nr↔符号 + patch-gap | 已有触达/符号 | 旧 CFU 盖 waiter；CVE-2024-23380 VBO 原样 |
| T5 | Binder CVE-2024-46740：合法 handle + readbuf hexdump 判补丁 | proto=8 已通 | 混进 GhostLock 矩阵 |
| T6 | Binder CVE-2023-20938：`buffer_release` 关键检查对照 | 同上 | — |

关闭且勿重开：SHIFT×shape 同构、ashmem fops−8、`sched_setattr` 当 store、shell BPF、nf_tables/DirtyPipe/io_uring。
