# S9280 免解锁 Root 研究资料索引

> 整理时间：2026-08-17；最近更新：2026-10-18。按"研究阶段"归档，方便回看。

## 一、固件与内核（阶段 1）

| 文件（`01_固件内核/`） | 说明 |
|---|---|
| `boot_dzf2.img.lz4` | 从 AP 固件提取的 boot 分区原始镜像（22MB） |
| `boot_dzf2.img` | 解压后的 boot 镜像（100MB，可用 magiskboot unpack） |
| `kernel_dzf2_raw` | 解压后的内核映像（38MB，zImage 原始字节） |
| `vmlinux_dzf2.elf` | **核心资产**：vmlinux-to-elf 恢复的 ELF，含全部符号（43MB） |
| `p0_fingerprint_dzf2.h` | KASLR 滑动指纹（32 行 × 8 qword，设备验证 32/32） |

固件版本：S9280ZCS6DZF2（One UI 8.5，2026-06），内核 `6.1.145-android14-11-3254743-abS9280ZCS6DZF2`。

### 1b. W23（SM-W9023N）适配中 — 2026-10-02

目标设备：**SM-W9023N**（心系天下 W23 5G，Fold4 国行 W 系），平台串 `SM-W9023_CHN_CHC_QKEY0`（CHC）。
与 S9280 是**完全不同的平台与内核世代**：cape / SM8450（Snapdragon 8 Gen 1）、**Android 12**、内核 **5.10.236**，
而 S9280 是 e3q / SM8550、Android 14、6.1.145。**结构体布局不可跨代复用。**

| 文件（`01_固件内核/`） | 说明 |
|---|---|
| `boot_W23AIZF1.img` | boot 分区镜像（100663296 B，HEADER_VER 4，KERNEL_SZ 41421312，ramdisk lz4_legacy） |
| `kernel_W23AIZF1_raw` | 内核映像（41 MB，raw 未压缩，MZ 头，`cape` 平台） |
| `vmlinux_W23AIZF1.elf` | vmlinux-to-elf 恢复的 ELF，**112081 符号（111816 具名）** |
| `release_W23AIZF1.txt` / `vermagic_W23AIZF1.txt` | 内核 release / vermagic |

- 固件构建：`W9023ZCSAIZF1`，构建日期 2026-06-16
- vermagic：`5.10.236-android12-9-2755199-abW9023ZCSAIZF1 SMP preempt mod_unload modversions aarch64`
- boot 源 md5：`6bc4661972040fd12039beef382cda8b`（与下载件逐字节一致）
- ELF 恢复警告"100% 偏移为绝对地址"属该内核正常表现，基址 `ffffffc008000000` 下符号自洽

**已验证事实（勿重复劳动）：**

1. **内核含 CVE-2026-43499**。判据：`remove_waiter`（`0xffffffc0081888fc`）全程**不访问 `waiter->task`**，
   而执行 `str xzr, [x20, #0x898]`，其中 `x20 = mrs x20, SP_EL0`（= `current`）。
   即清空了 `current->pi_blocked_on` 而非 `waiter->task->pi_blocked_on` —— 正是上游补丁
   *"rtmutex: Use waiter::task instead of current in remove_waiter()"* 所修的错误路径。
2. **`task_struct` 5.10 布局**（反汇编实测）：`pi_lock = 0x86c`、`pi_blocked_on = 0x898`。
   对比 6.1（DZF2）的 `0x924` / `0x950`，PI 簇整体前移约 **0xb8**。
3. 利用链锚点符号齐备：`ashmem_fops` `ashmem_ioctl` `ashmem_miscs` `anon_pipe_buf_ops` `noop_llseek`
   `call_usermodehelper_exec_work` `system_unbound_wq` `kmalloc_caches` `init_task` `root_task_group`
   `selinux_state` `loggers` `random_boot_id`，以及 rtmutex/futex 全组。

**⚠ 适配阻塞点（未解决）：**

- 内核**无 BTF、无 DWARF**（仅 `.symtab`），结构体偏移无捷径，需逐字段从反汇编推导。
- `tools/gen_target_h.py` 的设计前提是"同一 6.1.x KMI 内结构体布局冻结"，
  对 5.10 **不成立** —— 其"字段偏移沿用模板"策略在此会产生错误常量。
  需为 5.10 独立推导 `FAKE_TASK_*`、`FAKE_WAITER_*`、`PWQ_*`、`STRUCT_PAGE_*`、`FOPS_*` 等。
- 目标 `02_exploit工程/fusion-s24u/src/targets/<tag>/` 的 tag 与 `p0_fingerprint.h` 尚未生成。

**进展（2026-10-02 晚）**：定标已完成并编译通过，详见
`02_exploit工程/fusion-s24u/work_W23_offsets/W23定标报告.md`。

- 产物：`src/targets/cape-W9023ZCSAIZF1/{target.h,p0_fingerprint.h}`；
  `build/cape-W9023ZCSAIZF1/cve-2026-43499`（97,176 B，NDK r29，API=30）
- 实测结构体偏移 34 项。关键结论：**三种位移量并存** ——
  `usage`/`prio`/`normal_prio` 与 6.1 同址；`sched_task_group` −0x38；
  PI 簇（`pi_lock`/`pi_waiters`/`pi_top_task`/`pi_blocked_on`）−0xb8。
  `struct page` 四项与 6.1 **完全一致**；`PIPE_BUFFER_SLOTS` 属运行时 `F_SETPIPE_SZ` 实参、免改。
- **最大风险项（已修复）**：`util.c:put_fake_fops_table()` 原先把 configfs 回调写进
  `FOPS_READ_ITER_OFF(+0x20)`/`FOPS_WRITE_ITER_OFF(+0x28)`，而 5.10 的 configfs 用
  `.read`/`.write`（`+0x10`/`+0x18`）→ `pread` 会命中空指针必崩。
  已通过目标侧开关 `CONFIGFS_FOPS_USE_READ_WRITE`（仅 cape 声明）分叉修复，
  其余 6.1 目标走原布局、零影响；两个目标均编译通过。
- 另有两项非本适配引入的既有问题：`slide_app.c` 的 `slide_route_stop` 未声明
  （app 变体编不过，模板目标同样报错）；Makefile 无 `release` 目标且 `API ?= 35`
  与 NDK r29 不符。

### 1c. BakaSU late-load 三星适配（SM-S9280 · DZH3）— 2026-10-17 真机验证通过

承接 `dzg1_resukisu_plan.md` 的 ReSukiSU 路线：在 DZH3 上用 **BakaSU**（`Baka-SU/BakaSU`，分支 `samsung-port`：`02a11f6e` + `3befe299`）完成三星 KDP/RKP/DEFEX 适配，
`ksud late-load` 直接加载精确构建的内核模块（不写 boot、不动 Knox）。

- **验证**：`/proc/modules` `kernelsu Live`；`ksud debug info` version `35171` / `lkm:true` / `late_load:true` / `uapi_version:4`；管理器「工作中 / LKM / 越狱模式」
- **报告**：`devices_ports/dzh3_bakasu_late_load.md`；移植记录：`07_发布物/bakasu/BAKASU_SAMSUNG_PORT_NOTES.md`
- **归档**：`07_发布物/bakasu/`（ksud 35171、root 守护进程 + 源码；`.ko` 按 `.gitignore` 惯例不入库，脚本可重建）
- **独立仓库**（补丁/脚本/构建）：<https://github.com/NanoTurtle1145/BakaSU-S9280>；App 集成：RootMyS24 v3.5.0-beta.185「BakaSU 内核（实验）」
- **要点**：RKP 禁 live patch_text（触发 RAMDUMP）→ 回退 setresuid kretprobe + sucompat 地址级 kprobe；ksud 须在加载**前** staging 到 `/data/adb/ksud`；UAPI 按 4 上报对齐 rc3 管理器

### 1d. 美版 SM-S926U1（S24+）DZE2 定标 + issue #10 修复 — 2026-10-17

**触发**：issue #10 —— SM-S926U1（S926U1UES6DZE2）用港版 e3q DZE2 载荷连续
`phys step cache gate failed` 9 次 + 触发失败 2 次，偶发自动重启。

| 项 | 内容 |
|---|---|
| 素材 | `devices_ports/xaa_oneui8.5_dze2_boot.img`（boot sha256 `1d52c164…`，S926U1UES6DZE2） |
| 内核 | `6.1.145-android14-11-33419968-abS926USQS6DZE2`（与港版 DZE2 **同构建号**） |
| ELF | `devices_ports/dze2_xaa_unpacked/vmlinux_dze2_xaa.elf`（107,253 条符号） |
| 结论 | 与港版全量符号对比：代码/数据符号 100% 同址；仅 7 项 `.rodata` 字符串常量偏移（-0x2e×6 / -0x6a×1） |
| 关键重标 | `SLIDE_NFULNL_LOGGER_OFF`：港版 `0x016a61e6` → 美版 **`0x016a61b8`** |
| P0 指纹 | 按美版原始 Image 重新生成；与港版 255/256 qword 相同、1 qword 不同 |
| target | `02_exploit工程/fusion-s24u/src/targets/e2q-S926USQS6DZE2/`（本次新增） |
| App | RootMyS24 **v3.5.0-beta.185**（2026-10-17）新增 `S926U1DZE2("cve-2026-43499-dze2-xaa", tested=false)`；定标报告见 App 仓库 `docs/dze2-xaa-target-complete.md` |
| 状态 | 定标完成；**未纳入 RootMyS24 v3.5.1**（尚无真机实测，验证后再发布） |

> issue #10 根因：港版/美版同构建号但 `.rodata` 字符串区整体差 0x2e，
> 直接套用港版载荷会因 `nfnetlink_log` 标记偏移错误而无法完成 KASLR 定标/
> 后续 pipe gate。适配不同 CSC/区域时必须按原始 Image 实测字符串偏移。

### 1e. 韩版 SM-F741N（Z Flip 6）DZE1 定标与接入 — 2026-10-18 真机验证通过

| 项 | 内容 |
|---|---|
| 素材 | `/home/nt/下载/download.img`（= `boot.2.zip`/boot.img；`SM-F741N_KOR_KX_QKEY2`，Samsung 签名 2026-05-15） |
| 内核 | `6.1.145-android14-11-33418572-abF741NKSS4DZE1`（构建号 33418572） |
| ELF | `devices_ports/f741n_unpacked/vmlinux_f741n_dze1.elf`（107,253 条符号记录 / 103,520 个 name+type 键） |
| vs 美版 S926U1 DZE2 | 仅 **2** 个 `.rodata` 局部字符串标签差 +0x2e（`task_index_to_char.state_char`、`zero_mask`）；代码/数据符号 100% 同址 |
| vs 港版 S9280 DZE2 | **6** 个字符串标签差（-0x2e×5 / -0x3c×1，属美版↔港版偏移模式） |
| nfnetlink_log | `0x016a61b8`（美版布局；港版 `0x016a61e6`） |
| remove_waiter | `0x268` B / 154 条指令，三内核**逐字节相同**；漏洞写 `str xzr,[x20,#0x950]`（`x20=SP_EL0=current`）→ 清 `current->pi_blocked_on`；调用点覆盖 proxy-lock 活路径 → CVE 假设成立 |
| P0 指纹 | 按 F741N Image 生成；与美版差 1 qword（`slide=0xa0000` 第 2 个：`0x9106d021…` vs `0x9105e021…`），与港版 256/256 相同 |
| 编译验证 | 正式 target `src/targets/b6q-F741NKSS4DZE1/` 构建通过（与 draft 逐字节一致）；App 载荷 `cve-2026-43499-F741NKSS4DZE1` 104,128 B；专属驱动 `ksud-f741n-32601`（KSU 3.3.0 / 32601，vermagic 逐字节匹配） |
| 报告/产物 | `devices_ports/f741n_dze1_analysis.md`、`devices_ports/f741n_dze1_draft/`、`02_exploit工程/fusion-s24u/src/targets/b6q-F741NKSS4DZE1/` |
| 决策 | 2026-10-18：**已接入 App 并真机验证通过**（beta.191 / issue #16）；v3.5.1 起 `tested=true` 正式发布；服务端 `payloads.json` 已同步翻转 |

### 1f. 欧版 SM-S928B（S24 Ultra）EZIF 定标 — 2026-10-18 draft 已构建，待真机验证

| 项 | 内容 |
|---|---|
| 素材 | `/home/nt/下载/S24Ultra Europe One UI 9.0.zip`（boot.img.lz4 + init_boot.img.lz4；`SM-S928B_EUR_XX_QKEY2`，Samsung 签名 2026-09-19；One UI 9.0） |
| 内核 | `6.1.162-android14-11-34343818-abS928BXXU6EZIF`（构建号 34343818） |
| ELF | `devices_ports/ezif_unpacked/vmlinux_ezif.elf`（107,567 条符号；43,222,470 B） |
| vs 港版 S9280 DZE2 | 内核代际跃升（6.1.145→6.1.162）：**25 项偏移宏变化**（23 项符号身份迁移 + 2 项镜像实测） |
| 关键词 | `nfnetlink_log` `0x016ba45d`；random_table boot_id 槽 `0x02396a98`；tracefs 事件 ID 维持 **106**（索引 86 同港版）；`remove_waiter` 154 条指令序列与港版**零差异** |
| P0 指纹 | 按 EZIF Image 生成（自校验通过）；vs 港版/美版均 **235/256** qword 不同（代际变化，必须全新指纹） |
| 编译验证 | 正式 target `src/targets/e3q-S928BXXU6EZIF/` 构建通过；App 载荷 `cve-2026-43499-app.stable.so` **104,128 B**；adb 验证件与 root 守护齐备 |
| 报告/产物 | `devices_ports/s928b_ezif_analysis.md`、`devices_ports/ezif_draft/`、`02_exploit工程/fusion-s24u/src/targets/e3q-S928BXXU6EZIF/` |
| 决策 | **待真机验证**（adb 流程）；接入 App / KernelSU 驱动（vermagic 需专属）待定 |

### 1g. 欧版 SM-S928B（S24 Ultra）AXK5 / BYD9 / CZA1 三连定标 — 2026-10-24 自动定标完成，待真机验证

| 项 | 内容 |
|---|---|
| 素材 | `/home/nt/下载/s24uboot.img`（RAR5，34.8 MB）内 3 个 boot：`boot-S928BXXU4AXK5-Android 14.img`、`boot-S928BXXU4BYD9-Android 15.img`、`boot-S928BXXS4CZA1-Android 16.img`（均 `SM-S928B_EUR_XX_QKEY2` 签名）；已重命名归档为 `devices_ports/eur_oneui{6.1,7.0,8.0}_*.img`（100,663,296 B/个） |
| 三代内核 | AXK5 `6.1.75 / 29543898`（One UI 6.1 / A14）、BYD9 `6.1.99 / 30958380`（One UI 7.0 / A15）、CZA1 `6.1.128 / 31999054`（One UI 8.0 / A16）；均为 e3q 平台 |
| 新工具 | **`02_exploit工程/fusion-s24u/tools/calibrate_target.py`**：把 `ADAPTATION_GUIDE` 阶段 1/2 全自动——`llvm-nm` 双 ELF 符号身份迁移 + 6 项镜像实测（`ashmem_misc(s)+0x10`、`random_table+0x108`、`worker_thread+0xA0`、`nfnetlink_log`、tracefs 事件 id）+ **目标内核自带 BTF 结构体核对** + P0 指纹生成 + 审计 TSV/Markdown 报告，异常时非零退出 |
| 结果 | 三个目标全部 **20 项符号迁移 / 6 项镜像派生 / 112 项沿用（48 项 BTF 实测通过）/ 0 未解析**；载荷 `cve-2026-43499-app.stable.so` 均 **104,128 B** |
| 关键差异 | ① 欧版 S928B 与港版 S9280 **跨机型**：即使 CZA1 同构建号 31999054，`SLIDE_NFULNL_LOGGER_OFF` 也差 8 B（EUR `0x0160b70d` vs TGY `0x0160b705`）；② tracefs 事件 ID 三代均为 **106**（索引 86）；③ `MM_STRUCT_SZ` 为载荷调优值，BTF 实测六个内核 `sizeof(mm_struct)` 全为 `0x3c0` |
| BTF 结论 | 6.1 KMI 冻结：6 个内核（6.1.75/99/128/145/162）的 `task_struct`/`rt_mutex_waiter`/`file_operations`/`pool_workqueue`/`worker_pool`/`workqueue_struct`/`slab` 字段偏移**逐项一致**，沿用模板的结构体常量安全 |
| 编译验证 | 正式 target `src/targets/{e3q-S928BXXU4AXK5,e3q-S928BXXU4BYD9,e3q-S928BXXS4CZA1}/` 构建通过；三件载荷齐备（app.so 127,392 B / stable.so 104,128 B / root 27,496 B，preload 97,176 B） |
| 报告/产物 | `devices_ports/s928b_{axk5,byd9,cza1_eur}_analysis.md`、`devices_ports/{axk5,byd9,cza1_eur}_draft/`、`02_exploit工程/fusion-s24u/work_S928B_offsets/{axk5,byd9,cza1_eur}/`（报告 + 审计 TSV + nm 表） |
| 决策 | **待真机验证**；接入 App（`RootViewModel.FirmwareVersion` + 服务端 `payloads.json`）与 KernelSU 专属驱动（vermagic 逐代不同）待定 |



### 1h. 港版 SM-S9260（S24+）CZC1 定标（issue #6）— 2026-11-01 自动定标完成，待真机验证

| 项 | 内容 |
|---|---|
| 素材 | `/home/nt/下载/boot.img (1).lz4`（21,569,067 B，sha256 `1abb434d…`）→ 解压归档 `devices_ports/tgy_oneui8.0_czc1_boot.img`（100,663,296 B，sha256 `22454bc2…`）；boot header v4 / `KERNEL_SZ=37,022,208` / `RAMDISK_SZ=0` / `OS_PATCH_LEVEL=2026-03` / `SAMSUNG_SEANDROID`+`VBMETA` |
| 机型 / 系统 | **SM-S9260 港版 Galaxy S24+（e2q / SM8550）**；One UI 8.0 / Android 16，安全补丁 2026-03-05 |
| 内核 | `6.1.128-android14-11-31999054-abS9260ZHS5CZC1`（构建号 31999054，构建时间 2026-03-12 04:30:18 UTC） |
| ELF / BTF | `devices_ports/czc1_unpacked/vmlinux_czc1.elf`（100,754 条符号，41,946,294 B）、`vmlinux_czc1.btf`（5,859,386 B） |
| 模板选择依据 | 与 **CZD2**（`S9210ZHS5CZD2`，6.1.128/31999054，2026-04-08 构建）：**100,754 个符号地址 100% 相同**、BTF 大小一致、`remove_waiter` 反汇编逐字节相同 → 同镜像结构；相比之下 CZA1（同为 31999054）**不同址**（text ~+0x800、data ~+0x10000）→ issue #6 的 180/180 失败根因 |
| 定标结果 | 迁移 20 / 派生 6 / 沿用 114（BTF 实测 47）/ **未解析 0**；符号项全部 Δ=0；唯一镜像派生差异 `SLIDE_NFULNL_LOGGER_OFF` **0x0161b835**（模板 0x0161b7e3，+0x52）；tracefs 事件 ID 106 |
| 人工核对 | ① `BUILD_FINGERPRINT` 换成 issue #6 真机指纹 `samsung/e2qzhx/e2q:16/BP2A.250605.031.A3/…`；② `P0_FINGERPRINT_HEADER` 修模板残留路径；③ `SELINUX_ENFORCING_OFF` 注释改为"由符号迁移继承 CZD2 已修正值" |
| 漏洞路径 | `remove_waiter`（0x268 B）与 CZD2 逐字节相同，含 `str xzr,[x20,#0x950]`（x20=SP_EL0=current）→ 上游补丁所修错误分支仍在，`pi_lock=0x924`/`pi_blocked_on=0x950` 与 target 常量一致 |
| P0 指纹 | 按本机 Image 重生成（32×8=256 qword，末行首词=MZ 头自校验通过）；vs CZD2 仅 **2 个 qword** 不同 |
| 编译验证 | 正式 target `src/targets/e2q-S9260ZHS5CZC1/` 构建通过；载荷 `cve-2026-43499-app.stable.so` **104,128 B**（sha256 `e14d2b89…`，PI 窗口取 **125ms** 保守值，模板为 300ms），内嵌标签/32 行指纹全部校验通过，重编译逐字节可复现；vs CZD2 载荷仅 4.52% 字节不同 |
| 报告/产物 | `devices_ports/s9260_czc1_analysis.md`、`devices_ports/czc1_unpacked/`、`02_exploit工程/fusion-s24u/work_S9260_offsets/czc1/`（报告+审计 TSV+nm 表） |
| 决策 | **待真机验证**：按 2026-11-01 决定走 **gamma 一对一渠道**（RootMyS9280 只打包该载荷，`tested=false`）；`SLIDE_WAIT_NSEC` 取 **125ms**（EZIF 实测 300ms 会 panic、125ms 成功；窗口过短只 triggered=0，风险不对称）；通过后转正式条目并回馈 Root-My-Galaxy-Payloads |

## 二、Exploit 工程（阶段 3）

| 路径 | 说明 |
|---|---|
| `02_exploit工程/fusion-s24u/` | exploit 源码工程（CVE-2026-43499，IonStack 参考实现的 S24 版） |
| `.../src/targets/` | **20 个已定标 target**（`target.h` + `p0_fingerprint.h`），索引见 `src/targets/README.md` |
| `.../tools/calibrate_target.py` | **通用自动定标器**（2026-10-24）：符号身份迁移 + 镜像实测 + BTF 结构体核对 + P0 指纹 + 审计报告，一条命令适配一个新内核 |
| `.../build/` | 已编译载荷（按 target 分目录；`*-app.stable.so` 104,128 B 为 App 侧载荷） |
| `02_exploit工程/pipe_test.c` / `ksu_test.c` / `pipe_android61.c` | 设备端诊断工具（F_SETPIPE_SZ 配额 / KernelSU 驱动探测 / 6.1 pipe.c 对照） |
| `02_exploit工程/dirtyfrag-s9280/` | DirtyFrag 引擎调研（6.1 系 MSG_SPLICE_PAGES 不可达，未采用） |
| `02_exploit工程/fusion-s24u/work_W23_offsets/` | W23（5.10）定标实测数据与报告 |

**已定标 target 摘要**（详细见 `02_exploit工程/fusion-s24u/src/targets/README.md`）：

- `e3q-S9280ZCS6DZF2`（国行基线，**真机 ✅**）、`e3q-S9280ZHS6DZE2`（港版 DZE2，**真机 ✅**）
- `e2q-S926USQS6DZE2`（**美版 S24+ DZE2，issue #10 修复**，App v3.5.0-beta.185 发布）
- `e3q-S9280ZCS4CZA1` / `e3q-S9280ZHS4CZA1`（CZA1 国行/港版）、`e3q-S9280ZCS5CZB2`（CZB2）、
  `e3q-S9280ZCS6DZG1`（DZG1，v2.5.6 起并入 DZF2 载荷）、`e3q-S9280ZCS6DZH3`（DZH3，KernelSU 3.3.0 + BakaSU 真机 ✅）
- `e3q-S928USQS6DZF2`（美版 S24U 参考）、`e1q-S9210ZCU4BYH7`（One UI 7）、
  `S9310ZCSCCZG1`（S25 / 6.6）、`cape-W9023ZCSAIZF1`（W23 / 5.10.236）
- **欧版 S928B（EUR/OXM）**：`e3q-S928BXXU6EZIF`（One UI 9.0）、
  `e3q-S928BXXU4AXK5`（One UI 6.1）、`e3q-S928BXXU4BYD9`（One UI 7.0）、`e3q-S928BXXS4CZA1`（One UI 8.0）
  ——后三者 2026-10-24 由 `tools/calibrate_target.py` 自动定标，载荷均 104,128 B，待真机验证

## 三、设备端诊断工具（阶段 4 排坑）

| 文件 | 说明 |
|---|---|
| `02_exploit工程/pipe_test.c` + 二进制 | F_SETPIPE_SZ 行为诊断（配额/限制判定） |
| `02_exploit工程/ksu_test.c` + 二进制 | KernelSU 驱动探测（reboot-magic syscall + ioctl） |
| `02_exploit工程/pipe_android61.c` | Android 6.1 内核 pipe.c 源码（对照反汇编） |
| `01_固件内核/last_kmsg_panic.log` | **关键崩溃日志**：list_del BUG（worklist 竞态证据） |

## 四、参考研究（阶段 0）

| 路径 | 说明 |
|---|---|
| `03_参考研究/Pixel6_5.10_root方案.md` | **Pixel 6（内核 5.10）Root 方案调研**：GhostLock 5.10 移植路线 + Root-My-Pixel 现成方案 + KernelSU 刷入（2026-08-23） |
| `03_参考研究/SM-S9380_RMG_root_experience.md` | SM-S9380 实战经验（boot quiet window / struct page 偏移） |
| `~/rootmygalaxy/Root-My-Galaxy/` | S25U 免解锁 root 参考工程（App 端） |
| `~/rootmygalaxy/Root-My-Galaxy-Payloads/` | 载荷仓库：PORTING.md、S928U1.md、各机型 kdp 模块 |
| `.../kernelsu/` | KernelSU v3.2.5 各机型变体（e3q-S928U1-kdp 等） |
| `~/rootmygalaxy/CyberMeowfia/` | IonStack 源码（漏洞原理） |
| `~/rootmygalaxy/coolapk-s9280-solution/` | 酷安工具（社区有成功案例；其 16/16 失败在 preparing-memory 更可能是环境问题——残留进程污染 pipe_bufs 配额，而非偏移错误） |
| `~/root_research/*.md / *.json` | fusion_s24u.md、od4_*（odin4 分析）、rmgp_*（RMG issues） |

## 五、工具链（阶段 1/3）

| 路径 | 说明 |
|---|---|
| `~/sam85/tools/` | samloader（固件下载）、odin4（Thor 协议刷机，含 4 处本地修复）、magiskboot、adb |
| `~/sam85/scripts/` | flash.sh / repack_kernel.sh / make_abl_only.sh 等 |
| `06_工具链/android-ndk-r29/` | NDK r29（构建 payload / 诊断工具） |
| `06_工具链/android-14/` | build-tools（apksigner 等） |
| `06_工具链/s9280.keystore` | 签名密钥（pass: s9280root） |
| `06_工具链/platform-tools/` | adb / fastboot |
| `06_工具链/vmlinux-to-elf/` | 内核 ELF 恢复工具 |

## 六、发布物

| 路径 | 说明 |
|---|---|
| `~/AndroidStudioProjects/RootMyS9280/` | App 工程（v1.6，已开源） |
| `s9280_port/modules/` | Zygisk-Next / LSPosed / KnoxPatch 模块 |
| `s9280_port/blog_images/` + `blog_s9280_root.md` | 博客与配图 |
| `07_发布物/KernelSU_v3.2.5_32525-release.apk` | KernelSU Manager（官方） |
| `07_发布物/RootMyS24-v3.5.1-release.apk` | **RootMyS24 v3.5.1**（2026-10-18，48,201,754 B，sha256 `54292ce5…`）：韩版 Z Flip6 正式支持 + BakaSU 实验内核 + KernelSU 3.3.0；美版 S24+ DZE2 载荷未包含 |
| `07_发布物/RootMyS24-v3.5.0-beta.185.apk` | RootMyS24 v3.5.0-beta.185（2026-10-17）：BakaSU 实验内核 + 美版 S24+ DZE2 载荷（该载荷未进入 v3.5.1） |
| `07_发布物/bakasu/` | BakaSU late-load 三星适配制品（ksud 35171 / root 守护进程 / 移植记录） |
| `07_发布物/cve-2026-43499-czb2/` | CZB2 载荷归档 |
| `07_发布物/run_logs/` | 运行日志归档（成功/失败样本） |

## 七、运行日志与适配分析

| 路径 | 说明 |
|---|---|
| `RUN_LOG_ANALYSIS.md` | **S9280 DZF2 成功 vs OneUI7 BYH7 失败** 逐行对比分析（2026-08-22） |
| `07_发布物/run_logs/S9280_DZF2_success.txt` | S9280 全链路成功日志（attempt 2/30，root 完成 + KernelSU late-load exit=0） |
| `07_发布物/run_logs/BYH7_e1q_fail.txt` | OneUI7 BYH7 失败日志（CFI 通过，pipe 页 cache gate 失败） |

> BYH7 关键结论：`struct page` 字段偏移错误（`cache08=fffffffe...` vmemmap 地址特征），需按 6.1.99 BTF 核对 `STRUCT_PAGE_SIZE=0x40`、`STRUCT_SLAB_CACHE_OFF=0x08` 等四项偏移；`object_index=28` 超界（max=27）为偶发软性差异，重试可绕过。
> 详见 `03_参考研究/SM-S9380_RMG_root_experience.md` §六（FOPS cache gate 失败判据）与 `RUN_LOG_ANALYSIS.md` §2.3。

## 八、关键结论备忘

1. **S9280 与 S928U1 内核符号 16/17 一致**，唯一差异 `kmalloc_caches`：0x176cbb8（国行）vs 0x176c6f8（美版）
2. **港版 DZE2 构建号 33419968 与美版 S928U1 相同**，`kmalloc_caches=0x176c6f8`（与国行 DZF2 不同，不能用 DZF2 载荷）；其余 19/20 符号与 DZF2 一致。已独立适配并真机验证成功（2026-08-22）
3. **F_SETPIPE_SZ EPERM 不是内核限制**：是残留 `cve43499-hold` 进程污染 uid 2000 的 pipe_bufs 配额（这也解释了酷安工具 preparing-memory 阶段 16/16 失败——同为环境问题而非其偏移错误；社区有成功案例佐证）
4. **worklist 竞态**：注入 workqueue 时显示驱动并发入队 → 孤儿 work → cancel_work_sync 时 `__list_del_entry_valid` BUG → panic（已用"注入前重查"修复）
5. **KNOX 完好的判断依据**：`ro.boot.warranty_bit=0` + `verifiedbootstate=green`（官方固件刷机不熔断）
6. 普通 GKI kernelsu.ko 可在国行加载（version 32525），kdp 变体为备选
7. **S9280 DZF2 成功判定日志**：`pipe page idx=0 ... match=1` → `phys step pipe probe found=1` → `root umh result wake=1 complete=1 retval=0 socket=1` → `pipe physrw done=1 root=1 rw64=1/1 uid=2000->0`
8. **Shell 域 ≠ App 域**：提权逻辑在 Shell 域跑通不保证 App 域能通（SELinux/cgroup/seccomp 差异，cgroup 归属影响 kmalloc 缓存匹配）。BYH7 适配需在 App 域完整验证（源自 SM-S9380 移植经验）
9. **boot quiet window 120 秒**是稳定成功的关键参数（`APP_MIN_BOOT_UPTIME_SEC=120`），fusion-s24u 已是此值；不要为省时间改小（实测 60 秒必失败，120 秒一轮秒杀）
10. **BakaSU（ReSukiSU 系）三星适配版可在 S9280/DZH3 late-load**（2026-10-17 真机验证）：KDP task-scoped RO cred + DEFEX kprobe + RKP 禁 live patch_text（回退 setresuid kretprobe / sucompat 地址级 kprobe）；ksud 须在加载前 staging 到 `/data/adb/ksud`；UAPI 强制按 4 上报对齐 rc3 管理器。见 `devices_ports/dzh3_bakasu_late_load.md`
11. **同一构建号 ≠ 同一字符串布局**：S9280 TGY 与 S926U1 XAA 同为 33419968，代码/数据符号一致，但 `.rodata` 字符串区整体差 0x2e（`nfnetlink_log` 0x016a61e6 vs 0x016a61b8）→ 跨 CSC/区域适配必须按原始 Image 实测字符串偏移，不能直接复用载荷（issue #10 根因）
12. **美版 S24+（e2q）已独立定标**：target `e2q-S926USQS6DZE2`；App v3.5.0-beta.185 起内置独立载荷 `cve-2026-43499-dze2-xaa`
13. **F741N（韩版 Flip6 DZE1）布局≈美版 S24+**：103,520 个 name/type 符号仅 2 个 `.rodata` 标签差 +0x2e；remove_waiter 154 条指令三内核逐字节一致；2026-10-18 正式定标并接入 App（条目 `F741NDZE1` + 专属 KSU 3.3.0 驱动 `ksud-f741n-32601`），beta.191 真机验证通过（issue #16），v3.5.1 正式发布
14. **BakaSU 独立仓库**：<https://github.com/NanoTurtle1145/BakaSU-S9280>（per-boot 脚本 + 三星补丁 + DDK 构建）；App v3.5.0-beta.185 起提供「BakaSU 内核（实验）」开关
15. **欧版 SM-S928B EZIF（One UI 9.0）定标 draft 完成**（2026-10-18）：内核 6.1.162-android14-11-34343818（6.1.145 → 6.1.162 代际跃升），25 项偏移重标（23 项符号身份迁移 + 2 项镜像实测：`nfnetlink_log` `0x016ba45d`、random_table boot_id 槽 `0x02396a98`）；`remove_waiter` 154 条指令序列与港版零差异；P0 指纹全量重生成（vs 旧版 235/256 不同）；载荷 `cve-2026-43499-app.stable.so` 104,128 B 已构建（`e3q-S928BXXU6EZIF`），待真机验证
16. **欧版 SM-S928B 三代固件（AXK5/BYD9/CZA1）自动定标完成**（2026-10-24）：新增通用定标器 `02_exploit工程/fusion-s24u/tools/calibrate_target.py`，一条命令产出 `target.h`/`p0_fingerprint.h`/审计报告；三目标均 0 未解析、载荷 104,128 B。关键结论：**同构建号≠同机型**（CZA1 EUR vs TGY 同 31999054，`SLIDE_NFULNL_LOGGER_OFF` 差 8 B）；**BTF 实测 6.1 KMI 结构体偏移全世代一致**（task_struct/rt_mutex_waiter/file_operations/pool_workqueue/worker_pool/workqueue_struct/slab），故「结构体偏移沿用模板」有据可依；`MM_STRUCT_SZ` 是载荷调优值而非 `sizeof(mm_struct)`（BTF 实测 6 内核均为 0x3c0）
17. **港版 S9260 CZC1（issue #6）定标完成**（2026-11-01）：`S9260ZHS5CZC1`（6.1.128/31999054）与 CZD2 `S9210ZHS5CZD2` 内核 **100,754 符号 100% 同址**、`remove_waiter` 逐字节相同，唯一镜像差 `.rodata`（`SLIDE_NFULNL_LOGGER_OFF` +0x52）；与同为 31999054 的 CZA1 却不同址——**「同构建号」只是必要条件，判定必须比符号表**。target `e2q-S9260ZHS5CZC1`，载荷 104,128 B 已构建，待真机验证

## 2026-11-07 · SM-S9280(S9280ZHU6EZIF) 实机 root 成功

- 方法：**SamTimer v1.3（CVE-2026-98260）UMH 链路 + KSU 32601 多 KMI KDP late-load**
- 结果：`su -c id` → `uid=0 / u:r:ksu:s0`，`kernelsu` 模块 Live，重启失效（临时 root）
- 归档：`07_发布物/samtimer-98260-root/`（README + payloads + SHA256SUMS）
- 自研链路结项：`cve-2026-98260-uaf/FINAL_REPORT.md`（触发/泄漏通，cred 收尾未打通）
- RootMyS24 集成：commit `80c5742`（引擎）/ `560892b`（引擎切换选项卡）
