# SM-S9210（港版 Galaxy S24 / e1q）CZD2（One UI 8.0 / Android 16）内核分析报告

> 定标日期：2026-10-26
> 状态：**自动定标完成 + 一处人工修正；载荷编译通过，待真机验证**（`tested=false`）
> 触发：GitHub issue #20（SM-S9210 / Android 16 / S9210ZHS5CZD2 用户请求适配），
>   维护者回复「可用美版/欧版载荷，若确需专门适配请提供 boot 镜像」后用户提供了原厂 boot.img。
> 素材：`devices_ports/tgy_oneui8.0_czd2_boot.img`（100,663,296 B，sha256 `06a925ab7142ee74f70e677e7f9b96d3785cba3bd0477e635ed9047b13b79f2b`）
> 目标：`fusion-s24u` → `src/targets/e1q-S9210ZHS5CZD2/`
> 模板：`e1q-S9210ZCU4BYH7`（同为 e1q / Exynos 2400 平台，6.1.99）

---

## 0. 内核信息

| 项 | 值 |
|---|---|
| 机型 / 平台 | SM-S9210 港版 Galaxy S24（e1q，Exynos 2400） |
| 系统 | One UI 8.0 / Android 16 |
| 内核版本 | `6.1.128-android14-11-31999054-abS9210ZHS5CZD2` |
| 构建号 | **31999054**（与 e3q 的 CZA1 同一内核构建） |
| 构建时间 | 2026-04-08 |
| CSC | ZHS（港版） |
| raw ARM64 Image | 37,022,208 B |
| vmlinux ELF | `vmlinux_czd2.elf`（41,946,294 B，100,754 条符号） |
| BTF 切片 | `vmlinux_czd2.btf`（5,859,386 B，magic `0xeb9f`） |

**为何用 BYH7 而不是 CZA1 当模板**：两者虽然内核构建号相同（31999054），但
**e1q 是 Exynos 2400、e3q 是骁龙 8 Gen 3**，`P0_PHYS_OFFSET` / `P0_KERNEL_PHYS_LOAD` /
CPU 拓扑等平台常量不同。因此模板必须取**同平台**的 `e1q-S9210ZCU4BYH7`；
符号偏移由「符号身份迁移」按符号名重新解析，不受内核代差影响。

## 1. 定标方法（自动化）

由 `tools/calibrate_target.py` 完成（与 AXK5 / BYD9 / CZA1-EUR 同一套流程）：

1. **符号身份迁移**：模板 `target.h` 的 `*_OFF` → `KIMAGE_TEXT_BASE + 值` 命中模板 ELF
   符号名 → 该符号名在目标 ELF 中的新地址（跨内核世代不会误用偏移；符号改名有候选回退）。
2. **镜像实测**：`ashmem_misc(s)+0x10`（回读 == `ashmem_fops`）、`random_table+0x108`
   （回读 == `sysctl_bootid`）、`worker_thread+0xA0`、唯一字符串 `nfulnl_logger`、
   tracefs 事件 id = `(__event_sched_blocked_reason − __start_ftrace_events)/8 + 20`。
3. **BTF 核对**：从内核自带 `__start_BTF` 切片，逐项实测结构体字段偏移与结构体大小。
4. 生成 `target.h` + `p0_fingerprint.h`，输出审计 TSV + Markdown 报告。

**结果：迁移 19 项 / 镜像派生 6 项 / 沿用 114 项（其中 47 项 BTF 实测通过）/ 未解析 1 项（已人工修正）。**

## 2. 符号身份迁移（19 项）

| 宏 | 模板 | 新值 | Δ | 符号 |
|---|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | 0x0011a4490 | 0x0011b6bd0 | +0x12740 | `anon_pipe_buf_ops` |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x000cd6350 | 0x000cdac50 | +0x4900 | `compat_ashmem_ioctl` |
| `ASHMEM_FOPS_OFF` | 0x00134bc98 | 0x00135e7a0 | +0x12b08 | `ashmem_fops` |
| `ASHMEM_IOCTL_OFF` | 0x000cd5a68 | 0x000cda318 | +0x48b0 | `ashmem_ioctl` |
| `ASHMEM_MMAP_OFF` | 0x000cd63a8 | 0x000cdaca8 | +0x4900 | `ashmem_mmap` |
| `ASHMEM_OPEN_OFF` | 0x000cd65d4 | 0x000cdaed4 | +0x4900 | `ashmem_open` |
| `ASHMEM_RELEASE_OFF` | 0x000cd665c | 0x000cdaf5c | +0x4900 | `ashmem_release` |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x000cd677c | 0x000cdb07c | +0x4900 | `ashmem_show_fdinfo` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x0000d58f4 | 0x0000d388c | -0x2068 | `call_usermodehelper_exec_work` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x00046dc10 | 0x00046e9f0 | +0xde0 | `configfs_bin_write_iter` |
| `CONFIGFS_READ_ITER_OFF` | 0x00046d6e0 | 0x00046e4c0 | +0xde0 | `configfs_read_iter` |
| `COPY_SPLICE_READ_OFF` | 0x0003ec12c | 0x0003ecac8 | +0x99c | `generic_file_splice_read` |
| `INIT_TASK_OFF` | 0x00215f040 | 0x00216f8c0 | +0x10880 | `init_task` |
| `KMALLOC_CACHES_OFF` | 0x0016bad78 | 0x0016d09d8 | +0x15c60 | `kmalloc_caches` |
| `NOOP_LLSEEK_OFF` | 0x00039e594 | 0x00039ed18 | +0x784 | `noop_llseek` |
| `ROOT_TASK_GROUP_OFF` | 0x00234bd80 | 0x00235cd80 | +0x11000 | `root_task_group` |
| `SLIDE_LOGGERS_0_1_OFF` | 0x002152a18 | 0x002162a20 | +0x10008 | `nfulnl_logger` |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0024c2628 | 0x0024d35a8 | +0x10f80 | `sysctl_bootid` |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x00214ae60 | 0x00215ae60 | +0x10000 | `system_unbound_wq` |

## 3. 镜像派生（6 项）

| 宏 | 新值 | 证据 |
|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | 0x022cfc30ULL | ashmem_miscs+0x10；内容 qword=0xffffffc00935e7a0 vs ashmem_fops=0xffffffc00935e7a0 ✓ |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x0161b7e3ULL | nfulnl_logger@0x2162a20.name=0xffffffc00961b7e3 → 0x00161b7e3；镜像唯一字符串命中 ['0x161b7e3'] ✓ |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x0228ab38ULL | random_table+0x108；内容 qword=0xffffffc00a4d35a8 vs sysctl_bootid=0xffffffc00a4d35a8 ✓ |
| `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x022cfc30ULL | ashmem_miscs+0x10；内容 qword=0xffffffc00935e7a0 vs ashmem_fops=0xffffffc00935e7a0 ✓ |
| `SLIDE_TRACEFS_EVENT_ID` | 106 | 索引=(0xffffffc00a11f3b8-0xffffffc00a11f108)/8=86；+20 → id=106 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db048ULL | worker_thread+0xa0 |

## 4. 沿用模板项与 BTF 实测

**沿用模板项（114 项，6.1 KMI 冻结的结构体字段/调优常量）**，其中 **47 项已用目标内核自带 BTF
实测核对通过**。

- `MM_STRUCT_SZ`：BTF 实测 `sizeof(mm_struct)=0x3c0`，而模板 stable 分支写 `0x400`。
  这是**载荷调优值而非结构体大小**（它是 KernelSnitch bruteforce 的步长），
  按 2026-10-25 的实测结论保留 `0x400`（同机型 AXK5/BYD9 用 0x3c0 会 100% 泄漏失败）。
- `SLIDE_WAIT_NSEC=300ms` / `APP_FOPS_FRESH_PAGE_ATTEMPTS=5`：随模板继承（BYH7 为 e1q 平台
  调出来的 PI-futex 触发参数）。
- 跨 target 体检：与交叉检查的其它 target 完全一致。

## 5. 人工修正：`SELINUX_ENFORCING_OFF`

校准器把该宏当符号型处理，但在**模板 ELF 里找不到 `selinux_state` 符号**，于是沿用了
BYH7 的旧值 `0x02420441`（= `selinux_state + 1`）——BYH7 从未真机验证过，该值是错的。

- BTF 实测：`selinux_state.enforcing` 偏移 **0**（`checkreqprot` 才在 1）
- 已验证 target 对照：DZF2 `selinux_state+0`、CZA1 `selinux_state+0`
- 本内核符号：`selinux_state` = `ffffffc00a431460` → 镜像偏移 `0x2431460`
- **修正为 `0x02431460`**（与同构建的 CZA1 完全一致）

## 6. 构建验证

| 项 | 结果 |
|---|---|
| `make TARGET=e1q-S9210ZHS5CZD2 stable all` | ✓ 通过 |
| `cve-2026-43499-app.stable.so` | **104,128 B**（上限恰好） |
| sha256 | `7e2a28b6758850368375a0a8c321c65bd90d46debe76dcbb1f0ddfafa0676851` |
| P0 指纹 | `ok`（readback 校验通过） |
| target.h sha256 | `9f4043247e58b8539c513196d4675c13b4836d2362d4214ed24e48b726d3b5ac` |

## 7. 待真机验证清单

- [ ] 真机验证 root 流程（建议采集 `getprop ro.build.fingerprint`、
  `getprop ro.build.id`；确认 `ro.build.version.oneui`）
- [ ] 若 mm 阶段异常 → 已按 0x400 处理，无需再调
- [ ] 若 PI-futex 触发 `triggered=0` → 已继承 BYH7 的 300ms / 5 次，观察是否仍失败
- [ ] KernelSU 驱动：沿用通用 `ksud-selected`（6.1 KMI，运行时按 vermagic 替换）
- [ ] 通过后把 App 条目 `S9210CZD2` 置为 `tested = true`

## 8. 产物索引

- target：`02_exploit工程/fusion-s24u/src/targets/e1q-S9210ZHS5CZD2/{target.h,p0_fingerprint.h}`
- 审计：`02_exploit工程/fusion-s24u/work_S9210_offsets/czd2/{report_*.md,audit_*.tsv,nm_*.txt}`
- 镜像与 ELF：`devices_ports/tgy_oneui8.0_czd2_boot.img`、`devices_ports/czd2_unpacked/{kernel,vmlinux_czd2.elf,vmlinux_czd2.btf}`

> **同构建号 ≠ 同机型/同平台**：CZD2（e1q / Exynos）与 CZA1（e3q / 骁龙）内核构建号同为
> 31999054，90 个同名偏移里有 25 个不同（text 区恒定 Δ+0x800、ashmem 函数区 Δ+0xa54 等），
> 因此**不能直接互换载荷**，必须按平台分别定标。
