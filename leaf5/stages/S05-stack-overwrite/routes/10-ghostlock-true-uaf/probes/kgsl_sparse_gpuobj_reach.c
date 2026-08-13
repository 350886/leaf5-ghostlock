/**
 * kgsl_sparse_gpuobj_reach.c — 64-bit KGSL sparse/gpuobj/timeline 触达（非 VBO/23380）
 *
 * 对 nr 0x40–0x58 扫 ioctl：零结构 + 坏指针。
 * ENOTTY=未注册; EINVAL=进 handler 校验失败; EFAULT=到 copy_from_user。
 * 先 CREATE context flags=0x12。不提交 GPU 命令。
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define KGSL_IOCTL(nr, sz) \
  ((((uint32_t)3) << 30) | (((uint32_t)(sz)) << 16) | \
   (((uint32_t)0x09) << 8) | ((uint32_t)(nr)))

static const char *ename(int e) {
  if (e == 0)
    return "OK";
  if (e == 22)
    return "EINVAL";
  if (e == 14)
    return "EFAULT";
  if (e == 25)
    return "ENOTTY";
  if (e == 13)
    return "EACCES";
  if (e == 95)
    return "EOPNOTSUPP";
  if (e == 19)
    return "ENODEV";
  return strerror(e);
}

static void try_cmd(int fd, uint32_t nr, uint32_t sz, void *arg, const char *tag) {
  unsigned long req = KGSL_IOCTL(nr, sz);
  errno = 0;
  int r = ioctl(fd, req, arg);
  int e = r < 0 ? errno : 0;
  /* 压缩噪声：全 EINVAL 的零结构仍打印一行摘要 */
  printf("  nr=0x%02x sz=%-3u %-16s ret=%d errno=%d %s\n", nr, sz, tag, r, e,
         ename(e));
}

int main(void) {
  printf("kgsl_sparse_gpuobj_reach — 64-bit ioctl surface\n");
  int fd = open("/dev/kgsl-3d0", O_RDWR);
  if (fd < 0) {
    printf("open errno=%d\n", errno);
    return 1;
  }

  struct {
    uint32_t flags;
    uint32_t id;
  } ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.flags = 0x12;
  errno = 0;
  int r = ioctl(fd, KGSL_IOCTL(0x13, 8), &ctx);
  printf("CREATE flags=0x12 ret=%d errno=%d id=%u\n", r, r < 0 ? errno : 0,
         ctx.id);

  uint8_t zbuf[256];
  memset(zbuf, 0, sizeof(zbuf));
  if (ctx.id)
    memcpy(zbuf, &ctx.id, 4);

  printf("=== zero-struct nr 0x40-0x58 sz=16/32/48/64 ===\n");
  static const uint32_t sizes[] = {16, 32, 48, 64};
  for (uint32_t nr = 0x40; nr <= 0x58; nr++) {
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
      memset(zbuf, 0, sizeof(zbuf));
      if (ctx.id)
        memcpy(zbuf, &ctx.id, 4);
      unsigned long req = KGSL_IOCTL(nr, sizes[si]);
      errno = 0;
      r = ioctl(fd, req, zbuf);
      int e = r < 0 ? errno : 0;
      if (e != 25 && e != 22) {
        printf("  HIT nr=0x%02x sz=%u ret=%d errno=%d %s\n", nr, sizes[si], r, e,
               ename(e));
      }
    }
  }

  printf("=== bad-ptr (0x8) same nr/sz — want EFAULT ===\n");
  void *bad = (void *)(uintptr_t)0x8;
  for (uint32_t nr = 0x40; nr <= 0x58; nr++) {
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
      unsigned long req = KGSL_IOCTL(nr, sizes[si]);
      errno = 0;
      r = ioctl(fd, req, bad);
      int e = r < 0 ? errno : 0;
      if (e == 14) {
        printf("  EFAULT nr=0x%02x sz=%u (CFU reached)\n", nr, sizes[si]);
      } else if (e != 25 && e != 22) {
        printf("  other nr=0x%02x sz=%u ret=%d errno=%d %s\n", nr, sizes[si], r,
               e, ename(e));
      }
    }
  }

  /* Named 64-bit candidates from QC uapi (sizes may mismatch → EINVAL/ENOTTY) */
  printf("=== named guesses ===\n");
  try_cmd(fd, 0x45, 48, zbuf, "GPUOBJ_ALLOC?");
  try_cmd(fd, 0x46, 16, zbuf, "GPUOBJ_FREE?");
  try_cmd(fd, 0x47, 32, zbuf, "GPUOBJ_INFO?");
  try_cmd(fd, 0x48, 32, zbuf, "SPARSE_PHYS?");
  try_cmd(fd, 0x49, 16, zbuf, "SPARSE_PFREE?");
  try_cmd(fd, 0x4a, 32, zbuf, "SPARSE_VIRT?");
  try_cmd(fd, 0x4b, 16, zbuf, "SPARSE_VFREE?");
  try_cmd(fd, 0x4c, 32, zbuf, "SPARSE_BIND?");
  try_cmd(fd, 0x4d, 64, zbuf, "GPU_COMMAND?");
  try_cmd(fd, 0x4e, 16, zbuf, "TIMELINE_CREATE?");

  if (ctx.id) {
    uint32_t id = ctx.id;
    ioctl(fd, KGSL_IOCTL(0x14, 4), &id);
  }
  close(fd);
  printf("KERNEL SURVIVED\n");
  return 0;
}
