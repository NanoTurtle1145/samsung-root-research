# Samsung Root Research

Samsung Galaxy S24 系列（SM-S9210 / S9260 / S9280）免解锁 bootloader Root 研究。

基于内核漏洞 CVE-2026-43499，在不解锁 bootloader、不熔断 KNOX e-fuse 的前提下，实现临时提权并加载 KernelSU 驱动。

---

## 项目背景

Samsung 国行机型解锁 bootloader 的成本极高：解锁即熔断 KNOX e-fuse（不可逆），Secure Folder、Samsung Health、Samsung Pay 等 KNOX 相关功能永久失效。同时 rev bit 机制让降级/自定义内核极其困难——一旦官方新固件将 rev bit 熔到更高位，旧版本 bootloader 无法刷回。

本项目记录从方案选型、内核符号提取、exploit 适配、设备端排坑，到最终落地为 Android App 的完整过程，作为同平台/同系列机型适配的方法论参考。

---

## 目录结构

```
samsung_root_research/
├── 01_固件内核/              # 从固件提取的 boot 分区与内核
│   ├── boot_dzf2.img         # boot 分区镜像（已解压，~100MB）
│   ├── kernel_dzf2_raw       # 原始内核映像（~38MB）
│   ├── vmlinux_dzf2.elf      # 带符号的 ELF（vmlinux-to-elf 恢复，43MB）
│   ├── p0_fingerprint_dzf2.h # KASLR 滑动指纹（32 行 x 8 qword）
│   └── last_kmsg_panic.log   # 关键崩溃日志（worklist 竞态证据）
│
├── 02_exploit工程/           # CVE-2026-43499 利用工程
│   ├── fusion-s24u/          # 主 exploit 源码（C 语言，NDK 构建）
│   │   ├── src/              # 源码：main.c / pipe.c / slide.c / root.c / su_daemon.c
│   │   ├── src/targets/      # 各固件适配配置（target.h + p0_fingerprint.h）
│   │   └── build/            # 已编译产物（覆盖 5 个固件版本）
│   ├── pipe_test.c           # F_SETPIPE_SZ 行为诊断工具
│   ├── ksu_test.c            # KernelSU 驱动探测工具
│   └── pipe_android61.c      # Linux 6.1 pipe.c 源码对照
│
├── 03_参考研究/              # 参考项目存档
│   ├── fusion_a36.md         # IonStack 原理分析
│   ├── fusion_s24u.md        # Root-My-Galaxy 的 S24U 工程笔记
│   ├── od4_readme.md         # Odin4 协议分析
│   └── coolapk免root工具/    # 酷安社区工具存档
│
├── 04_BL分析/                # Bootloader 分析
│   ├── S9280_KEEP_OEM_UNLOCK_分析.md
│   ├── stock/                # 原厂 abl.elf
│   └── patched/              # 补丁后的 abl.elf + vbmeta.img
│
├── 05_图标素材/              # App 图标与 UI 素材
├── 06_工具链/                # 开发工具链（NDK、vmlinux-to-elf、KernelSU 源码等）
├── 07_发布物/                # 最终发布产物
│   ├── modules/              # Zygisk-Next / LSPosed / KnoxPatch 模块
│   ├── blog_s9280_root.md    # 技术博客文章
│   └── S24ultra_s9280*.apk   # 打包好的 App
│
├── devices_ports/            # 其他固件/机型的适配
│   ├── ONEUI7_适配可行性报告.md # BYH7 适配分析（18 个符号已提取）
│   └── dzg1_unpacked/        # DZG1 内核 ELF
│
├── i18n/                     # 多语言翻译（zh/en）
├── ADAPTATION_GUIDE.md       # 适配流程完整复盘（6 阶段, 4 个排坑记录）
├── RESEARCH_INDEX.md         # 研究资料索引
└── README.md                 # 本文件
```

---

## 核心成果

### 适配固件

| 固件 | 机型 | 内核 | 状态 |
|------|------|------|------|
| S9280ZCS6DZF2 (One UI 8.5) | SM-S9280 国行 | 6.1.145 | 已验证，真机 root 成功 |
| S9280ZCS6DZG1 (One UI 8.5) | SM-S9280 国行 | 6.1.145 | 已定标，载荷已编译 |
| S9210ZCU4BYH7 (One UI 7) | SM-S9210 国行 | 6.1.99 | 已定标，待真机验证 |

### 关键结论

- **S9280 与 S928U1 内核符号 16/17 一致**，唯一差异为 `kmalloc_caches` 偏移（0x176cbb8 国行 vs 0x176c6f8 美版）
- **F_SETPIPE_SZ EPERM 不是内核限制**，是残留进程污染 uid 2000 的 pipe_bufs 配额
- **worklist 竞态导致随机 panic**，修复方式为注入前重查链表为空 + 运行期间熄屏
- **KNOX 完好判断依据**：`ro.boot.warranty_bit=0` + `verifiedbootstate=green`
- 普通 GKI kernelsu.ko 可在国行加载（version 32525），kdp 变体为备选

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

---

## 安全研究声明

本项目仅用于安全研究与自有设备维护。使用内核漏洞提权存在导致系统崩溃、数据丢失、设备变砖的风险，使用者需自行承担一切后果。请勿用于非法用途。

---

## License

[GNU General Public License v3.0](LICENSE)