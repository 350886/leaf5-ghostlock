# 为什么 mm slab 页「free 了却永远回不到 buddy」

实测基线（Leaf5，4.19.157-perf-g77c132eccfab #38，8×CPU，4K 页）：

| run | payload delta | 读的偏移 | 读到 |
|-----|---------------|----------|------|
| B257 / B260~B263 | -0xe80 | `base+0x180` | `6`（5 次一致）|
| B264 | 0 | `base+0x1000` | `0x5c7e3acec8` |
| B265 | 0 | `base+0x1000` | `0x610bef0ec8` |
| B266 | -0xe80 | `base+0x180` | **`6`**（做了 250 次 order-3 申请之后仍然 6）|

B266 是判据：如果只是「回收页被别的分配抢走」，250 次 order-3 申请里必有
一次落在我们那页；仍然是 `6` ⇒ **那页根本没有回到 buddy**。

## 一、几何是对的（二进制实证，不是估算）

`proc_caches_init` 里唯一一次 `kmem_cache_create_usercopy`：

```
0xffffff800b4091a4  mov  w1, #0x388        ; sizeof(struct mm_struct)
0xffffff800b4091a8  mov  w4, #0x150        ; useroffset = saved_auxv
0xffffff800b4091ac  mov  w5, #0x170        ; usersize   = AT_VECTOR_SIZE
0xffffff800b4091b0  mov  w2, #0            ; align
0xffffff800b4091b4  mov  w3, w19           ; 0x04042000 = HWCACHE_ALIGN|PANIC|ACCOUNT
0xffffff800b4091c8  bl   kmem_cache_create_usercopy
```

⇒ `s->size = ALIGN(0x388, 64) = 0x3c0`
⇒ 8 CPU ⇒ `slub_min_objects = 4*(fls(8)+1) = 20` ⇒ `slab_order` 取 order 3
⇒ `objs_per_slab = 32768 / 0x3c0 = 34`

B265 现场：`mm-leak off=0x5a00 slot=24 rem=0` —— off 是 0x3c0 整数倍，落位自洽。
（slot 不固定是 `CONFIG_SLAB_FREELIST_RANDOM` 打乱发牌，判据只能看 `rem==0`。）

## 二、根因：`put_cpu_partial` 把空 slab 冻在 per-CPU partial 链表里

`__slab_free()`（mm/slub.c）关键分支：

```c
prior = page->freelist;
new.inuse -= cnt;
if ((!new.inuse || !prior) && !was_frozen) {
        if (kmem_cache_has_cpu_partial(s) && !prior) {
                /* 原来是 full 的 slab：不直接判空，先冻起来挂到
                   per-cpu partial 链表，new.frozen = 1              */
        } else if (!new.inuse && n->nr_partial >= s->min_partial) {
                m = M_FREE;            /* ← 只有这条才会 discard_slab 还页 */
        }
}
```

我们的目标 slab 是**被我们自己填满**的（pre 的 33 个 + leak child 的 1 个，
正好 34），所以第一次 free 进来时 `prior == NULL` ⇒ 走第一支 ⇒ 整块被
`put_cpu_partial()` 冻住；此后每一次 free 都命中 `was_frozen` 为真，
整个 `if` 直接跳过 —— **即使 inuse 归零也不会 discard**。

解冻只有一条路：`put_cpu_partial()` 里

```c
if (drain && pobjects > s->cpu_partial) {
        unfreeze_partials(s, this_cpu_ptr(s->cpu_slab));
}
```

`pobjects` 统计的是 per-cpu partial 链表上**所有 slab 的空闲对象总数**，
而每个 slab 只在「从 full 变成 partial 的那一刻」被加进去一次，所以
**每个 slab 只贡献 1**。

`cpu_partial` 按 size 取值（`set_cpu_partial`）：

| s->size | cpu_partial |
|---------|-------------|
| order == 0 | 30 |
| ≥ PAGE_SIZE | 2 |
| ≥ 1024 | 6 |
| **≥ 256（我们：0x3c0=960）** | **13** |
| < 256 | 30 |

原设计的 spray = `(1 + MM_PARTIALS) * 34` 且「每 slab 只关一个 memfd」，
只造出 **6** 个 partial slab；加上 pre / 目标 / post 也不过 ~9 个
⇒ `pobjects ≈ 9 < 13` ⇒ **永远不触发 unfreeze** ⇒ 目标页永久冻结。

这解释了 B257~B266 全部现场，也解释了为什么把发送次数从 4 加到 250 无效。

## 三、修法

1. **把 per-cpu partial 链表顶爆**：`MM_SPRAY_SLABS ≥ 14`（每 slab 只 free 一个
   对象）。链表在超过 `cpu_partial=13` 时被 `unfreeze_partials()` 整体解冻，
   目标 slab 此时 inuse=1（leak 还活着）⇒ 落到 node partial（unfrozen）。
2. 之后 `close(memfd_leak)` 是**解冻后**的最后一次 free ⇒ 命中
   `!new.inuse && n->nr_partial >= s->min_partial(4)` ⇒ `discard_slab` ⇒ 还页。
3. 顺序必须是「spray 的 free 在 close(memfd_leak) 之前」（现有代码已满足）。
4. 还页之后才做 skb 发送（现有代码已满足）。

对应环境变量：`MM_SPRAY_SLABS=20`（默认仍 6，实验时显式给）。

## 四、还页之后仍要注意的两件事（B264 的次要故障）

`sendmsg` 的内部顺序是 `alloc_skb(header)` → `alloc_pages(order 3)`。
header 是 order-0 slab 页，若 pcp 空就会把 free_list[order3] 栈顶块
**劈成 8 个 order-0 页**（B264 读到的 `0x…ec8` 就是加密 freelist 指针的样子）。
对策已实现：

- `RECLAIM_DRAIN_PAIRS`：发送前用多对 AF_UNIX socket 把 kmalloc-32k 抽干
  （`unix_recvq_full` 卡 `sk_max_ack_backlog`≈10，所以要开多对）；
- `RECLAIM_BURY_PAIRS`：还页后先关掉几对，把目标页压到 free_list 第 N 层，
  让劈块只劈栈顶；
- `RECLAIM_EXTRA_PAIRS`：落页阶段再猛发 100+ 次，确保吃到目标层。
