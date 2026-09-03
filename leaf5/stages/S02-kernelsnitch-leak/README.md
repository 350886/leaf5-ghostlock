> **阶段**: S02 | **状态**: ✅ 完成 | **最后更新**: 2026-07-25（复测 CORRECTED）

# S02 — Kernelsnitch 内核地址泄漏

## 目标
通过 futex 哈希碰撞时序侧信道泄漏 `mm_struct`，并推算 direct-map / KASLR。

## 代码

### stages 探针（组件预检，**不是**完整 mm 泄漏）

| 文件 | 架构 | 作用 | 效果 | 备注 |
|------|------|------|------|------|
| `probes/test_ks_minimal.c` | 32/64 | 大 mmap + touch | ✅ 2026-07-25 | 128MB mmap OK |
| `probes/test_kernelsnitch_minimal.c` | 32/64 | mmap + 非阻塞 futex | ✅ 2026-07-25 | 勿用会阻塞的 FUTEX_WAIT |

### 真正的 mm_struct 泄漏（在 exploit 测试 / 集成路径）

| 文件 | 效果 | 复测 2026-07-25 |
|------|------|-----------------|
| `exploit/test-programs/test_futex_hash.c` | 哈希自洽 + pile-up 时序 | ✅ pile-up ~6–8× baseline |
| `exploit/test-programs/test_mm_leak.c` | 碰撞 + bruteforce | ✅ **FOUND** mm @ `0xffffff8600181c40`（`KSNITCH_COLLISIONS=2`） |
| `exploit/src/kernelsnitch/*` + `slide.c` | 生产路径 | ✅ 同参 |

```bash
# 编译（Docker）
cd exploit && ./docker-build.sh tests

# 设备
adb push out/exploit/aarch64/tests/test_mm_leak /data/local/tmp/
adb shell 'KSNITCH_COLLISIONS=2 /data/local/tmp/test_mm_leak'
```

## 结果摘要
- **`KSNITCH_COLLISIONS=2` 时可靠泄漏**（&lt;1s 量级，候选数 ~1–2k）
- 无 KPTI → 侧信道更干净
- stages 下两个 `.c` 只证明运行环境可做大 mmap/futex，**不能**单独当作「泄漏成功」证据

## 下游
→ S03 heap spray 使用泄漏的内核地址定向 reclaim。

---

## 2026-09-03 复测：kernelsnitch 稳定性改进移植后（RAM clamp / 两相碰撞 / plausible 校验）

**来源**：移植 `ghostlock-cve-2026-43499-4.19-k40`（Redmi K40/oplus 4.19.157-perf）kernelsnitch v1.4–v1.9 改进。

**代码变更**：
- `exploit/src/kernelsnitch/kernelsnitch.h`
  - state 新增 `identity_end` / `ram_bytes`（运行时 RAM 窗，setup 默认 `IDENTITY_END`/0）
  - `find_collisions` 改 **two-phase**：先量每个候选 pre-pile wake time，pile 后仅收「post > 5×baseline 且 > 3×自身 pre」者；结束后 `FUTEX_WAKE_PRIVATE` 清桶
  - pile 线程钉到 core 1..N-1（把 core 0 留给测量线程）
  - `bruteforce` 按 `identity_end` 分区窗口（clamp 到 RAM）；`__mm_leak` 加 coarse/slab end clamp
- `exploit/src/util.c`
  - `detect_memory()`：`/proc/meminfo` MemTotal → direct-map 窗（1GB 对齐，1–32GB）
  - `clamp_ks_identity()` 在 setup / prepare_kernel_page 后夹取 `identity_end`
  - `run_kernelsnitch_bruteforce()`：bruteforce 后 **mm_plausible(phys<RAM)** 校验；失败/超窗按 `ksnitch_mm_sizes[]` 换 stride 重试；全部失败则归 `-1`（不让 implausible 候选泄漏给调用方）

**设备复测**（`#38` / `g77c132eccfab`，MemTotal 3533784 kB，`STOP_AFTER_PAGE_PREPARE=1` smoke）：
- RAM 窗检测：`memory detected ram=0x100000000 (4 GB) window_end=ffffff8100000000`
- **默认 `KSNITCH_COLLISIONS=2`：5/5 首轮成功**，每次 ~11–13s，无 retry/无 implausible；mm 均 sz=0x388
  - `ffffff80000226d8` / `ffffff800002bf90` / `ffffff80004e11a8` / `ffffff8000062350` / `ffffff8000141c40`
- **`KSNITCH_COLLISIONS=4` 不可用**：two-phase 在 wanted=3 时夹带 ≥1 假 collider → 全部 stride 的 bruteforce 均无全匹配（mm=-1）→ 72 次 retry 空转。结论：Leaf5 上**保持默认 2**；若需更高可靠性优先修 collider 纯度，而非提高 collisions。

**编译**：aarch64 preload.so / arm32 / arm32-pie 全部 Docker 编译通过（0 error；仅既有 `%016llx` vs `uint64_t` 风格告警）。

