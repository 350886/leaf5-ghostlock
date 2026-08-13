> **阶段**: S00 | **状态**: ⚠️ runtime 已切槽 | **最后更新**: 2026-08-13

# S00 — 设备画像与数据采集

## 目标
建立 Leaf5 运行时指纹：内核版本、CONFIG、安全面、分区/接口、与 boot 镜像一致性。

## 2026-08-13 CORRECTED

同机 `ac340d06` 现为 slot **`_b`**，`uname` = `4.19.157-perf-g77c132eccfab-dirty` **#38**。  
`leaf5/raw/vmlinux*` 与 `boot_a.bin` 仍对齐 **#245** `g3d47a6619220` → **禁止**当本机偏移真源。  
新 config / kheaders / 触达矩阵：[`../S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/VERIFY_2026-08-13_slotb.md`](../S05-stack-overwrite/routes/10-ghostlock-true-uaf/analysis/VERIFY_2026-08-13_slotb.md)。

## 代码

| 文件 | 作用 | 效果 | 原因/备注 |
|------|------|------|-----------|
| `scripts/collect_device.py` | adb 采集 → `raw/` | ✅ 成功 | 产出 device_identity、security_runtime、config 等 |
| `scripts/summarize_config.py` | 解析 config.gz 安全相关项 | ✅ 成功 | 确认 FUTEX_PI、无 CFI、无 KPTI |

## 关键产物（`leaf5/raw/`）
- `config.gz` / `kernel_config.txt` — 权威 CONFIG
- `device_identity.txt` — uname/getprop
- `security_runtime.txt` — SELinux/caps/devices
- `analysis_snapshot.json`

## 下游
→ **S01** 依赖 vmlinux / kheaders / boot_a.bin（本地 gitignore）做偏移提取。

## 运行
```bash
cd leaf5 && uv run leaf5-collect && uv run leaf5-summarize
```
