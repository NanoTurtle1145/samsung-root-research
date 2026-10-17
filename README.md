# Samsung Root Research

Samsung Galaxy 免解锁 bootloader Root 研究 —— 以 **S24 系列（SM-S9210 / SM-S9260 / SM-S9280 / SM-S926U1 等）** 为主线，另含 Pixel 6（5.10）与 W23（5.10.236）跨平台适配。

基于内核漏洞 CVE-2026-43499，在不解锁 bootloader、不熔断 KNOX e-fuse 的前提下实现临时提权，并通过 late-load 加载 **KernelSU / BakaSU** 内核驱动。

---

## 项目背景

Samsung 国行机型解锁 bootloader 的成本极高：解锁即熔断 KNOX e-fuse（不可逆），Secure Folder、Samsung Health、Samsung Pay 等 KNOX 相关功能永久失效。同时 rev bit 机制让降级/自定义内核极其困难——一旦官方新固件将 rev bit 熔到更高位，旧版本 bootloader 无法刷回。

本项目记录从方案选型、内核符号提取、exploit 适配、设备端排坑，到最终落地为 Android App 的完整过程，作为同平台/同系列机型适配的方法论参考。

---

## 目录结构

```
samsung_root_research/
├── 01_固件内核/              # 各机型 boot / 原始内核 / 恢复的符号 ELF / 符号版本
│   ├── vmlinux_dzf2.elf、vmlinux_dzh3.elf、vmlinux_CZB2.elf …
│   ├── p0_fingerprint_*.h    # KASLR 滑动指纹（32 行 × 8 qword）
│   └── Module.symvers.DZH3   # 内核模块符号版本（DDK 重建三星适配 .ko 用）
│
├── 02_exploit工程/           # CVE-2026-43499 利用工程
│   ├── fusion-s24u/          # 主 exploit（C，NDK 构建）
│   │   ├── src/              # main.c / pipe.c / slide.c / root.c / su_daemon.c …
│   │   ├── src/targets/      # 12 个已定标 target（附 README 索引）
│   │   └── build/            # 各 target 已编译载荷（*-app.stable.so 104,128 B）
│   ├── dirtyfrag-s9280/      # DirtyFrag 引擎调研
│   └── pipe_test.c / ksu_test.c / pipe_android61.c
│
├── 03_参考研究/              # 参考项目与社区资料（RMG / IonStack / Pixel6 / 酷安 …）
├── 04_BL分析/                # Bootloader 分析（S9280 永久解锁终局判定等）
├── 05_图标素材/              # App 图标与 UI 素材
├── 06_工具链/                # NDK r29 / build-tools / platform-tools / vmlinux-to-elf / KernelSU 源码
├── 06_运行日志/              # 设备运行日志
├── 07_发布物/                # 发布产物
│   ├── RootMyS24-v3.5.0-beta.185.apk   # 最新 App beta（BakaSU + 美版 S24+）
│   ├── bakasu/               # BakaSU late-load 三星适配制品
│   ├── cve-2026-43499-czb2/  # CZB2 载荷归档
│   ├── run_logs/             # 成功/失败运行日志
│   └── ksud-candidates/      # 各机型 ksud 候选
│
├── devices_ports/            # 逐机型素材 / 定标与分析报告（含 README 索引）
│   ├── dze2_unpacked/ dze2_xaa_unpacked/ f741n_unpacked/ …
│   ├── dzh3_bakasu_late_load.md
│   └── f741n_dze1_analysis.md
│
├── ADAPTATION_GUIDE.md / ADAPTATION_GUIDE_FULL.md / ADAPTATION_PLAYBOOK.md
├── VULNERABILITY_ANALYSIS.md / RUN_LOG_ANALYSIS.md
├── RESEARCH_INDEX.md         # 研究资料全量索引
└── README.md                 # 本文件
```

---

## 核心成果

### 适配固件

| 固件 | 机型 | 内核 | 状态 |
|------|------|------|------|
| S9280ZCS6DZF2（国行 DZF2） | SM-S9280 | 6.1.145 / 3254743 | ✅ 真机 root 成功（基线 target） |
| S9280ZHS6DZE2（港版 DZE2） | SM-S9280 | 6.1.145 / 33419968 | ✅ 真机 root 成功（2026-08-22） |
| S9280ZCS6DZH3（国行 DZH3 线） | SM-S9280 | 6.1.145 | ✅ 真机：KernelSU 3.3.0，且 **BakaSU late-load 验证成功** |
| **S926U1UES6DZE2（美版 S24+ XAA）** | **SM-S926U1** | 6.1.145 / 33419968 | ✅ 已定标（issue #10），App **v3.5.0-beta.185** 发布独立载荷 |
| S9280ZCS4CZA1 / S9280ZHS4CZA1（CZA1） | S24 全系 国行/港版 | 6.1.128 | ✅ 已定标（App 内置） |
| S9280ZCS5CZB2（国行 CZB2） | S24 全系 | 6.1.128 | ✅ 已定标（App 内置） |
| S9280ZCS6DZG1（国行 DZG1） | S24 全系 | 6.1.145 | ✅ 已定标（v2.5.6 起并入 DZF2 载荷） |
| S9210ZCU4BYH7（国行 One UI 7） | SM-S9210 | 6.1.99 | ✅ 已定标，待真机反馈 |
| S9310ZCSCCZG1（国行 S25） | SM-S9310 | 6.6 系列 | ✅ 已定标（App 内置） |
| W9023ZCSAIZF1（W23 / Fold4） | SM-W9023N | 5.10.236 | ✅ 定标 + 编译通过（2026-10-02），待真机 |
| F741NKSS4DZE1（韩版 Z Flip 6） | SM-F741N | 6.1.145 / 33418572 | 🔍 仅内核分析（**暂不接入**） |
| Pixel 6（Android 15） | oriole | 5.10.214 | ✅ 已定标 + 载荷交付，待真机验证 |

> 另有 **BakaSU late-load 路线**（不刷 boot、不动 Knox）：在 S9280/DZH3 上通过
> `ksud late-load` 加载三星适配的 BakaSU LKM，管理器显示「工作中 / LKM / 越狱模式」。
> 见 `devices_ports/dzh3_bakasu_late_load.md`；构建/脚本仓库
> [BakaSU-S9280](https://github.com/NanoTurtle1145/BakaSU-S9280)。

### 近期进展（2026-10）

- **2026-10-17**：美版 S24+（SM-S926U1）DZE2 定标完成（`e2q-S926USQS6DZE2`），
  修复 issue #10 的 `cache gate` 失败根因（美/港版 `.rodata` 字符串区差 0x2e）；
  RootMyS24 **v3.5.0-beta.185** 发布，新增独立载荷 `cve-2026-43499-dze2-xaa`。
- **2026-10-17**：**BakaSU late-load 三星适配**（KDP/RKP/DEFEX）在 DZH3 真机验证通过；
  RootMyS24 增加「BakaSU 内核（实验）」开关；独立仓库
  [BakaSU-S9280](https://github.com/NanoTurtle1145/BakaSU-S9280)（per-boot 脚本 + 补丁 + DDK 构建）。
- **2026-10-18**：韩版 F741N（Z Flip 6）DZE1 内核分析完成 —— 与美版 S24+ 布局几乎全等
  （103,520 个符号仅 2 个 `.rodata` 标签差），target 草案与载荷已构建验证；
  决定**暂不接入**，分析留档 `devices_ports/f741n_dze1_analysis.md`。
- **2026-10-02**：W23（SM-W9023N / cape / 5.10.236）定标完成并编译通过。
- **2026-09**：Pixel 6（5.10.214）跨平台适配交付（载荷 + 诊断工具 + App）。

### 关键结论

- **S9280 与 S928U1 内核符号 16/17 一致**，唯一差异为 `kmalloc_caches` 偏移（0x176cbb8 国行 vs 0x176c6f8 美版）
- **F_SETPIPE_SZ EPERM 不是内核限制**，是残留进程污染 uid 2000 的 pipe_bufs 配额
- **worklist 竞态导致随机 panic**，修复方式为注入前重查链表为空 + 运行期间熄屏
- **KNOX 完好判断依据**：`ro.boot.warranty_bit=0` + `verifiedbootstate=green`
- 普通 GKI kernelsu.ko 可在国行加载（version 32525），kdp 变体为备选
- **同一构建号 ≠ 同一字符串布局**：S9280 TGY 与 S926U1 XAA 同为 33419968，代码/数据符号一致，
  但 `.rodata` 字符串区整体差 0x2e（`nfnetlink_log` 0x016a61e6 vs 0x016a61b8）——
  issue #10 的 `cache gate` 失败根因，跨 CSC 适配必须按原始 Image 实测字符串偏移
- **BakaSU 三星适配要点**：KDP task-scoped cred、DEFEX kprobe、RKP 禁 live patch_text
  （回退 setresuid kretprobe + sucompat 地址级 kprobe）、ksud 加载前 staging、UAPI 4 对齐
- **F741N（韩版 Flip6）≈ 美版 S24+**：布局几乎全等，可作为后续适配储备


### 文档导航

| 文档 | 内容 |
|------|------|
| [VULNERABILITY_ANALYSIS.md](./VULNERABILITY_ANALYSIS.md) | **漏洞原理剖析**：rtmutex UAF 成因、利用链全景、防护绕过路径、worklist 竞态（研究笔记） |
| [ADAPTATION_GUIDE.md](./ADAPTATION_GUIDE.md) | 适配方法论与排坑记录（操作流程） |
| [RUN_LOG_ANALYSIS.md](./RUN_LOG_ANALYSIS.md) | 成功/失败日志逐行对比与失败特征判读 |
| [RESEARCH_INDEX.md](./RESEARCH_INDEX.md) | 研究资料全量索引 |
| [devices_ports/README.md](./devices_ports/README.md) | 机型素材 / 解包内核 / 定标与分析报告索引 |
| [02_exploit工程/fusion-s24u/src/targets/README.md](./02_exploit工程/fusion-s24u/src/targets/README.md) | 12 个已定标 target 一览（机型/固件/内核/状态） |
| [devices_ports/dzh3_bakasu_late_load.md](./devices_ports/dzh3_bakasu_late_load.md) | BakaSU late-load 三星适配落地记录（真机验证） |
| [devices_ports/f741n_dze1_analysis.md](./devices_ports/f741n_dze1_analysis.md) | F741N（韩版 Flip6）DZE1 内核分析（暂不接入） |
| [03_参考研究/SM-S9380_RMG_root_experience.md](./03_参考研究/SM-S9380_RMG_root_experience.md) | SM-S9380 实战经验（boot quiet window / struct page 偏移 / Shell-App 域差异） |

---

## 适配流程（概要）

```
阶段0 情报收集    确定目标/参考/固件，评估可行性
阶段1 提取       固件 -> boot -> 内核 -> 恢复符号 ELF
阶段2 定标       与参考 target.h 逐符号对比，生成目标配置
阶段3 验证       设备上逐阶段跑通 exploit 链路
阶段4 排坑       处理设备特有的环境问题
阶段5 集成       root 持久化 + KernelSU 加载
阶段6 封装       App 化
```

完整的适配方法论与排坑记录见 [ADAPTATION_GUIDE.md](./ADAPTATION_GUIDE.md)。

---

## 相关项目

- [RootMyS24](https://github.com/NanoTurtle1145/root-my-s24) - 基于本研究的 Android App（最终交付物）
- [CVE-2026-43499](https://github.com/IonStack/CVE-2026-43499) - 漏洞安全研究（IonStack / NebuSec）
- [Root-My-Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy) - 参考工程
- [BakaSU-S9280](https://github.com/NanoTurtle1145/BakaSU-S9280) - BakaSU 三星适配（脚本 / 补丁 / DDK 构建）

---

## 安全研究声明

本项目仅用于安全研究与自有设备维护。使用内核漏洞提权存在导致系统崩溃、数据丢失、设备变砖的风险，使用者需自行承担一切后果。请勿用于非法用途。

---

## License

[GNU General Public License v3.0](LICENSE)