/**
 * slotb_surface_reach.c — #38 / slot _b 触达面（不依赖旧 vmlinux 偏移）
 *
 * 测: native open 矩阵、ashmem、kgsl context(0x12)、bpf、perf。
 * 不做利用，只记 errno。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_bpf
#if defined(__aarch64__)
#define __NR_bpf 280
#else
#define __NR_bpf 386
#endif
#endif
#ifndef __NR_perf_event_open
#if defined(__aarch64__)
#define __NR_perf_event_open 241
#else
#define __NR_perf_event_open 364
#endif
#endif

#define BPF_MAP_CREATE 0
#define BPF_PROG_LOAD 5
#define BPF_PROG_TYPE_SOCKET_FILTER 1
#define BPF_MAP_TYPE_HASH 1

#define KGSL_IOCTL(nr, sz) \
  ((((uint32_t)3) << 30) | (((uint32_t)(sz)) << 16) | \
   (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

static void try_open(const char *path, int flags, const char *tag) {
  errno = 0;
  int fd = open(path, flags);
  int e = errno;
  printf("open %-28s flags=%d fd=%d errno=%d (%s)\n", tag, flags, fd, fd < 0 ? e : 0,
         fd < 0 ? strerror(e) : "OK");
  if (fd >= 0)
    close(fd);
}

int main(void) {
  printf("slotb_surface_reach — native open / bpf / perf / kgsl ctx\n");

  static const char *devs[] = {
      "/dev/kgsl-3d0", "/dev/ashmem",  "/dev/binder",
      "/dev/hwbinder", "/dev/uhid",    "/dev/uinput",
      "/dev/ion",      "/dev/qce",     "/dev/diag",
      "/dev/adsprpc-smd", "/dev/dri/card0",
  };
  for (size_t i = 0; i < sizeof(devs) / sizeof(devs[0]); i++) {
    try_open(devs[i], O_RDWR, devs[i]);
    try_open(devs[i], O_RDONLY, "  +O_RDONLY");
  }

  /* kgsl context flags=0x12 */
  {
    int fd = open("/dev/kgsl-3d0", O_RDWR);
    if (fd < 0) {
      printf("kgsl ctx: open errno=%d\n", errno);
    } else {
      struct {
        uint32_t flags;
        uint32_t id;
      } ctx;
      memset(&ctx, 0, sizeof(ctx));
      ctx.flags = 0x12; /* PREAMBLE | NO_GMEM_ALLOC */
      errno = 0;
      int r = ioctl(fd, KGSL_IOCTL(0x13, 8), &ctx);
      printf("kgsl DRAWCTXT_CREATE flags=0x12 ret=%d errno=%d id=%u (%s)\n", r,
             r < 0 ? errno : 0, ctx.id, r < 0 ? strerror(errno) : "OK");
      if (r == 0 && ctx.id) {
        uint32_t id = ctx.id;
        errno = 0;
        r = ioctl(fd, KGSL_IOCTL(0x14, 4), &id);
        printf("kgsl DRAWCTXT_DESTROY id=%u ret=%d errno=%d\n", id, r,
               r < 0 ? errno : 0);
      }
      close(fd);
    }
  }

  /* bpf */
  {
    struct {
      uint32_t map_type, key_size, value_size, max_entries;
      uint32_t map_flags, inner_map_fd, numa_node;
      char map_name[16];
    } ma;
    memset(&ma, 0, sizeof(ma));
    ma.map_type = BPF_MAP_TYPE_HASH;
    ma.key_size = 4;
    ma.value_size = 4;
    ma.max_entries = 1;
    errno = 0;
    long r = syscall(__NR_bpf, BPF_MAP_CREATE, &ma, sizeof(ma));
    printf("bpf MAP_CREATE ret=%ld errno=%d (%s)\n", r, r < 0 ? errno : 0,
           r < 0 ? strerror(errno) : "OK");
  }

  /* perf SW + HW */
  {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_SOFTWARE;
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.disabled = 1;
    errno = 0;
    long r = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    printf("perf SW_CPU_CLOCK ret=%ld errno=%d (%s)\n", r, r < 0 ? errno : 0,
           r < 0 ? strerror(errno) : "OK");
    if (r >= 0)
      close((int)r);

    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = PERF_TYPE_HARDWARE;
    attr.config = PERF_COUNT_HW_CPU_CYCLES;
    attr.disabled = 1;
    errno = 0;
    r = syscall(__NR_perf_event_open, &attr, 0, -1, -1, 0);
    printf("perf HW_CYCLES ret=%ld errno=%d (%s)\n", r, r < 0 ? errno : 0,
           r < 0 ? strerror(errno) : "OK");
    if (r >= 0)
      close((int)r);
  }

  printf("KERNEL SURVIVED\n");
  return 0;
}
