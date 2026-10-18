# SM-S928B（欧版 S24 Ultra）EZIF 内核分析报告

> 日期：2026-10-18
> 状态：**定标完成，载荷与专属驱动已随 beta v3.5.1-beta.203 发布（2026-10-18），待真机验证**
> （正式 target `e3q-S928BXXU6EZIF`；App 载荷 `cve-2026-43499-app.stable.so` 104,128 B 已就绪）
> 素材：`/home/nt/下载/S24Ultra Europe One UI 9.0.zip`
> （zip sha256 `f2239fe2c8fa639545f382e68ae0de744d769df95e9b6ecc3c932f44b70324d4`；
> 内含 boot.img.lz4 + init_boot.img.lz4；解出的 boot.img sha256
> `b98326455c825062e5350ae88b75488f4de4c7b1e587a47105fffdc41be37500`，
> 归档 `devices_ports/eur_oneui9.0_ezif_boot.img`；Samsung 签名 `SM-S928B_EUR_XX_QKEY2`）
> 参考：港版 S9280 DZE2（`e3q-S9280ZHS6DZE2`，主模板）、美版 S926U1 DZE2（`e2q-S926USQS6DZE2`）

---

## 1. 内核信息

| 项 | SM-S928B EZIF（欧版 / One UI 9.0） | 港版 S9280 DZE2（参考） |
|---|---|---|
| 内核版本 | `6.1.162-android14-11-34343818-abS928BXXU6EZIF` | `6.1.145-android14-11-33419968-abS9280ZHS6DZE2` |
| 构建号 | **34343818** | 33419968 |
| 构建时间 | 2026-09-19 08:12:04 UTC | 2026-05-19 |
| 编译器 | clang 17.0.2 (r487747c)，同 DZE2 字串 | 同 |
| KIMAGE_TEXT_BASE | `0xffffffc008000000` | 同（6.1 平台常量） |
| ARM64 Image | raw 38,140,416 B；头 text_offset=0 / image_size=0x2710000 / flags=0xa | raw 38,005,248 B；image_size=0x26f0000 |
| 恢复 ELF | `vmlinux_ezif.elf` 43,222,470 B / **107,567** 条符号 | 43,070,883 B / 107,253 条 |

内核代际：6.1.145 → **6.1.162**（+17 个 LTS 补丁版本），构建号 33419968 → 34343818；
KMI 仍为 `android14-6.1`，但段内布局已全量位移，**偏移必须整体重标**（不能沿用任何旧载荷）。

## 2. 符号偏移全量迁移（25 项变化宏）

迁移方式：以港版 `e3q-S9280ZHS6DZE2` 为模板，用 `gen_target_h.py` 做「符号身份迁移」
（模板 `*_OFF` → 模板 ELF 符号名 → EZIF ELF 同符号新地址），重标 **23 项**；
另有 2 项非符号地址（字符串 / 数据结构槽）按 EZIF 镜像**实测**（见第 3 节）。
其余 60 项结构体字段/常量偏移保持模板值（6.1 KMI 稳定分支冻结）。

| 宏 | 港版 DZE2 | EZIF（新） | Δ |
|---|---|---|---|
| `ANON_PIPE_BUF_OPS_OFF` | 0x001219d90 | 0x00122ad50 | +0x10fc0 |
| `ASHMEM_COMPAT_IOCTL_OFF` | 0x000d3ac4c | 0x000d457c4 | +0xab78 |
| `ASHMEM_FOPS_OFF` | 0x0013d1140 | 0x0013e2e30 | +0x11cf0 |
| `ASHMEM_IOCTL_OFF` | 0x000d3a314 | 0x000d44e8c | +0xab78 |
| `ASHMEM_MISC_FOPS_OFF` | 0x0023bb5b0 | 0x0023dc200 | +0x20c50 |
| `ASHMEM_MMAP_OFF` | 0x000d3aca4 | 0x000d4581c | +0xab78 |
| `ASHMEM_OPEN_OFF` | 0x000d3aed0 | 0x000d45a48 | +0xab78 |
| `ASHMEM_RELEASE_OFF` | 0x000d3af58 | 0x000d45ad0 | +0xab78 |
| `ASHMEM_SHOW_FDINFO_OFF` | 0x000d3b078 | 0x000d45bf0 | +0xab78 |
| `CALL_USERMODEHELPER_EXEC_WORK_OFF` | 0x0000d39cc | 0x0000d3be0 | +0x214 |
| `CONFIGFS_BIN_WRITE_ITER_OFF` | 0x0004717d4 | 0x0004730b4 | +0x18e0 |
| `CONFIGFS_READ_ITER_OFF` | 0x0004712a4 | 0x000472b84 | +0x18e0 |
| `COPY_SPLICE_READ_OFF` | 0x0003ef340 | 0x0003f07c4 | +0x1484 |
| `INIT_TASK_OFF` | 0x00224f8c0 | 0x00226f6c0 | +0x1fe00 |
| `KMALLOC_CACHES_OFF` | 0x00176c6f8 | 0x001781458 | +0x14d60 |
| `NOOP_LLSEEK_OFF` | 0x0003a14e4 | 0x0003a235c | +0xe78 |
| `ROOT_TASK_GROUP_OFF` | 0x00244cd80 | 0x00246dd80 | +0x21000 |
| `SELINUX_ENFORCING_OFF` | 0x002521588 | 0x002542618 | +0x21090 |
| `SLIDE_LOGGERS_0_1_OFF` | 0x002242a20 | 0x002262828 | +0x1fe08 |
| `SLIDE_NFULNL_LOGGER_OFF` | 0x0016a61e6 | 0x0016ba45d | +0x14277 |
| `SLIDE_RANDOM_BOOT_ID_DATA_OFF` | 0x0023762f0 | 0x002396a98 | +0x207a8 |
| `SLIDE_S928_PROBE_TARGET_IMAGE_OFF` | 0x0023bb5b0 | 0x0023dc200 | +0x20c50 |
| `SLIDE_SYSCTL_BOOTID_OFF` | 0x0026046e8 | 0x002625768 | +0x21080 |
| `SLIDE_TRACEFS_WORKER_CALLER_OFF` | 0x0000db1a0 | 0x0000db39c | +0x1fc |
| `SYSTEM_UNBOUND_WQ_OFF` | 0x00223ae60 | 0x00225ac60 | +0x1fe00 |

> 位移模式：text 段 +0x1fc ~ +0xab78；data/rodata/bss 段 +0x14277 ~ +0x21090
> （内核数据区约 +0.13 MB）。逐符号位移不等，印证「按符号名迁移」是唯一可靠方式。

## 3. 两项手工实测（非符号地址）

### 3.1 `SLIDE_NFULNL_LOGGER_OFF = 0x016ba45d`

- 镜像中 `nfnetlink_log\0` 字符串**唯一出现**于 `0x16ba45d`（港版 `0x16a61e6`）；
- 双重验证：`nfulnl_logger` 符号（`0x02262828`）首 qword = `0xffffffc0096ba45d`，
  减 `KIMAGE_TEXT_BASE` 恰好 = `0x016ba45d` ✓（即结构体 .name 指针指向该字符串）；
- 用途：`slide_read_stext()` 由 boot_id 泄漏指针反推 `stext = leaked - 0x016ba45d`。

### 3.2 `SLIDE_RANDOM_BOOT_ID_DATA_OFF = 0x02396a98`

- 语义：`random_table[]`（sysctl 随机数表）中 **boot_id 表项**（entry4，+0x100）的
  `.data` 指针槽（+0x108）——fops.c / util.c / slide_app.c 共用的锚定可写数据槽；
- 验证：EZIF `random_table` = `0x02396990`，+0x108 处 qword = `0xffffffc00a625768`
  = `sysctl_bootid` 符号地址 ✓；港版同构（`0x023761e8` +0x108 = 港版 `sysctl_bootid`），
  双内核互证 `+0x108` 结构规则不变。

## 4. tracefs 预判参数复核

- `SLIDE_TRACEFS_EVENT_ID = 106` **维持**：
  - `sched_blocked_reason` 在 `__ftrace_events` 链接表中的索引：港版 **86** / EZIF **86**
    （表规模 1,126 → 1,128，新增事件位于索引 86 之后）；
  - 港版实测 id = 索引 86 + 注册保留号段 20 = 106 → EZIF 推断同为 106；
  - 真机复核命令：`cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`。
- `SLIDE_TRACEFS_WORKER_CALLER_OFF = worker_thread + 0xA0` 规则：
  港版 `0xdb100`+0xA0 = `0xdb1a0` ✓；EZIF `worker_thread`=`0xdb2fc` → **`0xdb39c`** ✓。

## 5. CVE 链核查（remove_waiter）

- EZIF `remove_waiter`：**154 条指令**（港版同为 154 条）；
- 关键访问按相同相对偏移出现：`str xzr,[x20,#0x950]`（+0x8c，清 `current->pi_blocked_on`）、
  `ldr x8,[x21,#0x950]`（+0x1a4，经 owner 读阻塞 waiter）——与港版逐一对齐；
- 归一化（助记符/寄存器/操作数形状）指令序列对比：**0 差异 / 154 条**；
  原始字节差异 48 条，全部为分支/调用目标的**重定位位移**
  （归属函数同名：`_raw_spin_lock` / `rb_next` / `rb_erase` / `_raw_spin_unlock` …）；
- 调用点符号齐备：`rt_mutex_start_proxy_lock` / `rt_mutex_cleanup_proxy_lock` /
  `rt_mutex_slowlock` / `task_blocks_on_rt_mutex`；
- 结论：**「清 current 而非 waiter->task」的竞态窗口在 6.1.162 上原样保留**，
  exploit 链假设成立。

## 6. P0 指纹（KASLR）

- 生成：`generate_p0_fingerprint.pl <raw Image> 0x1f0000 p0_fingerprint.h`，
  脚本自校验 32 行 × 8 qword（256 qword）通过；
- 与旧版差异：vs 港版 **235/256** qword 不同；vs 美版同为 **235/256**
  （内核代际变化导致指令数据全面更替，**必须全新指纹**）；
- 产物 sha256 `06d0fb6ea4aa285cbcd0e04cceb7e6f1b0f1ae1adafdf30b82ff6dbdec32360c`
  （`devices_ports/ezif_draft/` 与正式 target 同文件）。

## 7. 编译验证（draft 全链路）

命令（/tmp 副本，未动仓库工作树）：

```bash
TARGET=e3q-S928BXXU6EZIF ANDROID_NDK_HOME=.../android-ndk-r29 make stable all
```

| 产物 | 大小 | 说明 | sha256 |
|---|---|---|---|
| `cve-2026-43499-app.stable.so` | **104,128 B**（与约束零误差） | App 载荷（真机稳版） | `5215587861d4a6ae2ddb9d7437dee3d71bdb0910b0542f789e4478a866ac6be6` |
| `cve-2026-43499-app.so` | 127,392 B | adb 验证用（指南 §8.1） | `9e247f52f4588c093eeff88d0d922e004ce00f90c77e0772e3b3c83d00234a95` |
| `cve-2026-43499-root` | 27,496 B | root 守护（与 F741N 同尺寸） | `d2dccd05d027fde632301613e65337274ef72f395173d6ffb48ceef50babba19` |
| `cve-2026-43499`（preload） | 97,176 B | 无 App 直载版 | `c07d3c928bf4c9b74eb97101c8221122d3b0a03d94c5de3b2303e7cbfffcc56f` |

- 内嵌标签 `e3q-S928BXXU6EZIF-app-physical-p0-oracle` 正确；编译无 error；
- `target.h` sha256 `320b113d565f4bc24ec71d599cd9b74c227ef5530d408ee25ce55c68314793b9`
  （draft 与正式 target 逐字节一致）。

### 7.1 KernelSU 专属驱动（3.3.0 / 32601）

按 F741N 先例走 DDK 重建管线（`adapt-ksu.sh EZIF vmlinux_ezif.elf android14-6.1`：
目标内核 Module.symvers / vermagic 注入，绝不覆盖官方 Manager 的哈希与尺寸校验）：

| 产物 | 大小 | sha256 |
|---|---|---|
| `kernelsu-EZIF.ko`（内核模块） | 404,840 B | `7973e28bff2a04aa2c9d4e9692307dd7a7999cf3833dd9e3d3fef6fe3066795a` |
| `ksud-ezif-32601`（内嵌驱动的 ksud，App 资产） | 5,107,192 B | `51881cdd113adb80cf00e18669ebb8a8fa4af00c27ae4a9a88ad7fdc704c00fe` |

- vermagic 与真机逐字节一致：`6.1.162-android14-11-34343818-abS928BXXU6EZIF SMP preempt mod_unload modversions aarch64`；
- 静态审计（RMG `audit_module_against_target.py --manual-relocation`）：未定义符号 202 /
  缺失 0 / kallsyms 解析 70 / CRC 不一致 0；与 F741N 专属模块节级对比仅 `.modinfo`、
  build-id 两节不同，与已发货 DZF2/DZH3 模块对比另加 `.symtab` 少量字节差异；
- 内嵌模块校验、版本常量（32601 / 3.3.0）、官方 Manager 哈希（`c371061b…`）全部通过；
- 本机型无 3.2.5 驱动回退（vermagic 与任何既有 ksud 均不同）。

## 8. 结论与建议

1. **定标完成**：EZIF 是 S24 系首个 One UI 9.0 / 6.1.162 目标；与港版同平台同 KMI，
   但 25 项偏移宏需重标（23 符号迁移 + 2 实测），P0 指纹全量重生成——全部可复现、已入仓。
2. **下一步 · 真机验证**（指南 §8）：`adb push` 两个文件后以 shell 域 `LD_PRELOAD` 运行；
   成功判据见指南 §8.3，失败按 §8.4 分类。建议顺手采集：
   - `getprop ro.build.fingerprint`（回填 target 元数据，当前为占位 TODO）；
   - `cat /sys/kernel/tracing/events/sched/sched_blocked_reason/id`（复核 106）。
3. **接入（已完成）**：App `FirmwareVersion` 条目 `S928BEZIF`（资产
   `cve-2026-43499-S928BXXU6EZIF`，外版分组、tested=false）、服务端 `payloads.json`
   （tested=false、ksu `ksud-ezif-32601`、minVc=202）、专属驱动按 F741N 先例构建（见 §7.1）——
   已随 **beta v3.5.1-beta.203（2026-10-18）** 发布；真机验证通过后翻转 tested。
4. **风险**：内核跨代（17 个 LTS 版本）但 CVE 链结构经指令级核查未变；
   真机失败时优先按指南 §8.4「偏移不匹配」分支排查并回报完整日志。

## 9. 证据与产物索引

| 文件 | 说明 |
|---|---|
| `devices_ports/eur_oneui9.0_ezif_boot.img` | 原始 boot（100,663,296 B，sha256 `b9832645…`，gitignore） |
| `devices_ports/ezif_unpacked/kernel` | 解出的 raw ARM64 Image（38,140,416 B） |
| `devices_ports/ezif_unpacked/vmlinux_ezif.elf` | 恢复的带符号 ELF（43,222,470 B，107,567 符号） |
| `devices_ports/ezif_draft/target.h.draft` | 定标 target 草案（= 正式 target，sha256 `320b113d…`） |
| `devices_ports/ezif_draft/p0_fingerprint.h` | P0 指纹（自校验通过，sha256 `06d0fb6e…`） |
| `devices_ports/ezif_draft/cve-2026-43499-app.stable.so` | App 载荷 104,128 B |
| `devices_ports/ezif_draft/cve-2026-43499-app.so` | adb 验证载荷（127,392 B） |
| `devices_ports/ezif_draft/cve-2026-43499-root` | root 守护（27,496 B） |
| `02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXU6EZIF/` | 正式 target（可直接 `make`） |
| `devices_ports/dze2_unpacked/` | 港版 DZE2 参考（主模板） |

复现命令：

```bash
# 1) 解包（zip 内 boot.img.lz4 → boot.img → raw Image @offset 4096，boot v4 头）
unzip "/home/nt/下载/S24Ultra Europe One UI 9.0.zip"
lz4 -d boot.img.lz4 boot.img
python3 -c "d=open('boot.img','rb').read(); open('kernel','wb').write(d[4096:4096+38140416])"

# 2) 恢复符号（注：pipx 安装已失效，用 PYTHONPATH 直跑）
PYTHONPATH=/home/nt/项目/samsung_root_research/06_工具链/vmlinux-to-elf python3 -c \
  "from vmlinux_to_elf.scripts.vmlinux_to_elf import main; main()" kernel vmlinux_ezif.elf

# 3) P0 指纹
perl /home/nt/固件/rootmygalaxy/Root-My-Galaxy-Payloads/tools/generate_p0_fingerprint.pl \
  kernel 0x1f0000 p0_fingerprint.h

# 4) 构建
cd "/home/nt/项目/samsung_root_research/02_exploit工程/fusion-s24u"
ANDROID_NDK_HOME=/home/nt/项目/samsung_root_research/06_工具链/android-ndk-r29 \
  make TARGET=e3q-S928BXXU6EZIF stable all
```
