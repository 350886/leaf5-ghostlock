# KGSL ioctl 分发表还原与 patch-gap 现状

> **日期**: 2026-09-03 · **ELF**: `leaf5/raw/slotb_38/vmlinux.elf` · 目标: KGSL sparse/gpuobj 补丁缺口
> 状态：**分发表结构已还原；nr→handler 符号映射被 RELA 阻断（见 §3）；patch-gap 待补 QC fix diff 或改走定向审计**

## 1. 分发结构（capstone 确认）
- `kgsl_ioctl`(0xffffff80087a32d8) → `kgsl_ioctl_helper`(0xffffff80087a3188)。
- 表基址 = **0xffffff80099d2400**（`kgsl_ioctl_funcs`），`w4=0x5e`(94 项，nr 0–0x5d)。
- helper 逻辑（反汇编）：
  - `w9 = cmd & 0xff`(nr)；`if nr>=cnt → -0x203(-ENOTTY)`
  - `entry = base + nr*16`；cmd(u32)@+0；**func(u64)@+8**；
  - `size=(cmd>>16)&0x3fff`，`if size>=0x81 → -EINVAL(0x16)`；
  - `if size: copy_in(user→stack buf)` → `blr func(dev, cmd, buf)` → `if cmd 含写位: copy_out(buf→user)`。
- 表中 cmd 与实机 ioctl 编码吻合（如 nr0x40 cmd=`0xc0100940`）。

## 2. 已还原 cmd（可达/相关 nr）
nr: 0x02,0x07,0x10,0x13–0x17,0x20–0x21,0x24,0x2f,0x32–0x37,0x3c–0x3d,
**0x40–0x43,0x45–0x4a,0x4c,0x50–0x55,0x57–0x5d**（含实机 EFAULT/OK 的整段 0x40–0x58）。

## 3. 阻断：func 槽在 vmlinux.elf 内为 0
- 表 entry+8 在文件内全 0；`.rela.dyn` 对这些槽是 **R_AARCH64_RELATIVE，symbol=_head，addend=0**（vmlinux-to-elf 产物），启动时才写实际地址 → 文件名拿不到 handler 符号。
- 出路 A：从 **raw `vmlinux_extracted_38`（未剥 Image）** 按 link-VA 直接读 entry+8 的**链接绝对地址**（slide=0 时即运行时地址）→ 需确认 Image↔ELF 的 VA/偏移映射（text_offset/头部）后重建 nr→handler 表。
- 出路 B：不依赖名字——把 0x40–0x5d 每个 nr 当独立 handler，**最小结构 fuzz + 崩溃/行为判别**（需小心重启，参照 2026-09-03 曾重启一次）。

## 4. patch-gap 需求
公开 QC KGSL CVE 的 fix diff（针对 `drivers/gpu/msm` 老世代、LA.UM.9.12 系）与 #38 对应函数比对；现无可靠 diff 源。若拿到任一 fix（gpuobj/sparse/context 族），方法同 binder §7.1.1：定位 fix 新增检查 → 反汇编比对。

## 5. 建议下一步（二选一）
1. 重建 nr→handler 表（Image 直读，本地纯静态）→ 锁定具体函数再 hunt；
2. 定向实机探针：对 0x40/0x45/0x58 等「零结构即 OK/弱校验」handler 做最小参数审计。
