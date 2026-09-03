# 攻击面加宽矩阵：实现 root 的候选（不限于 GhostLock）

> **日期**: 2026-09-03
> **设备**: Onyx Leaf5 · `#38` kernel `4.19.157-perf-g77c132eccfab` · Android 13 · SPL **2026-04-01** · `ro.debuggable=0` `ro.secure=1`
> **目的**: 回答「除 GhostLock 外还有什么漏洞/路径」。枚举**当前实测可达**面 + 候选族 + 静态闸门，并按可达性/武器化难度排序。
> **关系**: 上游文档 `SECOND_BUG_AND_CVE_CANDIDATES.md`（CVE 级）+ `POST_B_ALTERNATIVES.md`（方向级）；本文 = **设备侧攻击面实测补充**（不只 CVE 编号）。

---

## 0. 设备实测安全姿态（2026-09-03）

| 项 | 值 | 含义 |
|----|----|------|
| shell | uid 2000 `u:r:shell:s0`，groups=shell,input,log,adb,sdcard_rw,inet,uhid,readtracefs…；CapEff=0 | 低权限域 |
| bootloader | **`ro.boot.verifiedbootstate=orange`，`ro.boot.flash.locked=0`** | **已解锁** → 授权刷写即确定 root（H3） |
| SELinux | Enforcing（`/proc/self/attr/current` 读被拒） | 无 permissive |
| perf | `perf_event_paranoid=-1`，perf open 可行 | 侧信道/采样放大 |
| 内核特征 | `RANDOMIZE_BASE=y`(实测 slide 0 / KIMAGE 固定)、`VMAP_STACK=y`、`SLAB_FREELIST_HARDENED+RANDOM=y`、`HARDENED_USERCOPY=y`、`STATIC_USERMODEHELPER=y`、无 CFI/KPTI | 堆 harder、无栈覆盖捷径；无 modprobe 路径 |
| 关掉的网红面 | `USER_NS=n`、`NF_TABLES=n`、`KEXEC=n`、`IO_URING`(无)、`USERFAULTFD=n`、`TIPC/VSOCKETS/CAN=n`、`DMABUF_HEAPS`(无) | nf_tables/io_uring/userns 系全 ❌ |

## 1. 设备节点 / 子系统实测（shell 可达性）

| 面 | 节点 / 触发 | 权限/SELinux | shell? | 状态/价值 |
|----|-------------|--------------|--------|-----------|
| **KGSL / Adreno** | `/dev/kgsl-3d0` | **0666** world rw, `gpu_device` | ✅（ioctl 面已探：ctx✅ gpuobj? sparse 族） | **P0 独立内核面**（公开 kgsl 族多） |
| ashmem | `/dev/ashmem` | 0666 | ✅ | oracle/写目标；自身对象洞次优先 |
| binder | `/dev/binderfs/binder` | binder_device | ✅ | 20938/21255 ❌、46740 倾向已修（见 §7.1.1） |
| perf | syscall | paranoid=-1 | ✅ | 仅辅助 |
| keyring | `add_key`/`keyctl` syscall | 需 SELinux（工具缺失未测） | ? | KEYS=y；先做 syscall 探针看 EPERM |
| ION | `/dev/ion` | 0664 system:`system`, `ion_device` | ❌ | Context+ 后 |
| qce | `/dev/qce` | 0660 system:drmrpc | ❌ | Context+ 后 |
| ADSPrpc | `/dev/adsprpc-smd` | 0660 system (qdsp) | ❌ | Context+ 后 |
| diag | `/dev/diag` | 0660 vendor_qti_diag | ❌ | Context+ 后 |
| e-ink/EPDC | EPDC 内核线程在（`root [EPDC_*]`），**无 shell 可见节点**（无 /dev/fb0、/dev/graphics、无 eink/epd 名） | — | ❌ | 系统域后可能成 Onyx 专属面 |
| 网络 | inet 组可用；无 NF_TABLES/io_uring/USER_NS | — | ⚠️ | xfrm 需 CAP_NET_ADMIN → ❌；通用 net 4.19 洞面（见 §3） |

## 2. 用户态 / 厂商域（Context+ → 打开 §1 死面）

| 面 | 证据 | 思路 |
|----|------|------|
| **Onyx 厂商 binder 服务** | `onyx_device_service`(IOnyxDeviceService)、`oec_service`(IOECService) 在 `service list`；`com.onyx.*` 全家（kreader/ota/appmarket/…） | shell 若能 `service call`（SELinux allow shell→onyx_* 待探），找 command/file/update 类方法 → 提 vendor/system 域 → 再开 kgsl 深层/ION/qce/EPDC |
| **Onyx OTA/系统应用** | `com.onyx.android.onyxotaservice`、`com.onyx.android.production.test`、`com.onyx` | OTA 常 root/system；查其组件 exported、AIDL、是否有 shell 可调危险方法 / 以 root 跑的 helper 脚本 |
| AOSP 服务 | UpdateEngine / recovery / system_update | 需 root；非入口 |

## 3. 内核「补丁缺口」候选族（4.19.157 基线 + SPL 仅 2026-04）

> 不能只凭版本号判，方法 = 取 **Android Security Bulletin (Kernel 段) + Qualcomm bulletin** 每条 fix commit，在 #38 ELF 反汇编比关键检查（同 §7.1.1 binder 方法）。

| 候选族 | 典型 | shell 触达 | 备注 |
|--------|------|-----------|------|
| KGSL/sparse/gpuobj（qualcomm） | 2023–2026 kgsl 内存族 | ✅ 0666 | **第一优先**（独立 I） |
| binder 后续 | 46740 之外 | ✅ | 已收敛两条 |
| 通用 net（无 CAP 触发） | 4.19 stable 修复的 dst/sock UAF | ⚠️ inet 可 | 需逐条 patch-gap |
| mm / seq_file / procfs | 4.19 stable 修复 | ⚠️ | 同上 |
| keyring | 4.19 stable 修复 | ? 先探 SELinux | KEYS=y |
| 厂商：wlan 固件/驱动 | QC WLAN | ⚠️ 部分 socket | 模块符号未对齐，独立项目 |

## 4. 确定性与“研究”两条路

```text
目标 = 自有设备 root
 ├─ 确定性：H3 刷写（bootloader orange & unlocked 已实测）
 │    授权 Magisk/KernelSU/boot 替换 → root（不依赖任何 0day）
 └─ 研究性（本仓库持续）：
     P0 独立 = KGSL sparse/gpuobj patch-gap（shell 0666 直达）
     P0 复用 = GhostLock 自身 S1/S2/S5/S7（已有 EDEADLK/reclaim/panic 资产）
     P1 Context+ = Onyx binder 服务 → system/vendor → 开 qce/ION/EPDC
     P1 补丁缺口 = ASB-Kernel + Qualcomm 缩表 × #38 反汇编
```

## 5. 结论（决策用）
1. **不限于 GhostLock 时，最高价值仍是 KGSL**：shell 0666 直达、公开补丁族多、无需 Context+。
2. **第二个真正“新”的门 = Onyx 厂商服务/OTA**（Context+）：这是 GhostLock 覆盖不到、且把 qce/ION/EPDC/diag 等 system-only 面打开的钥匙；需先做 SELinux allow 探针。
3. e-ink/EPDC 面仅在 system 域后可见（无 shell 节点），归入 Context+ 之后的 Onyx 专属研究。
4. 若目标仅是“拿到 root 做研究”，**H3 刷写是确定解**；漏洞链是研究选项。

## 6. 下一步（最小动作）
- [ ] kgsl sparse/gpuobj 补丁对照（`probes/kgsl_sparse_gpuobj_reach.c` 已有面数据）
- [ ] shell → onyx binder 服务 SELinux allow 探针 + `service list`/`dumpsys service onyx_device_service` 接口枚举
- [ ] keyring syscall SELinux 探针（确认 KEYS 面开/关）
- [ ] (可选) Ghidra 复证 binder 46740 收尾

## 7. 修订记录
| 日期 | 变更 |
|------|------|
| 2026-09-03 | 初版：设备攻击面实测 + 加宽矩阵（KGSL/ION/qce/EPDC/Onyx 服务/确定性 H3） |
