# devices_ports —— 机型号文件 / 内核素材 / 定标与可行性报告

> 整理时间：2026-10-18
> 说明：本目录存放**逐机型/逐固件**的 boot 镜像、解包内核、恢复的 ELF、定标/分析报告。
> 通用方法论见根目录 `ADAPTATION_GUIDE.md` / `ADAPTATION_GUIDE_FULL.md`；
> 目标配置（target.h / p0_fingerprint.h）在
> `02_exploit工程/fusion-s24u/src/targets/`。

---

## 1. 原始 boot 镜像

| 文件 | 机型 / CSC | 固件构建 | 内核版本 | 备注 |
|---|---|---|---|---|
| `chc_oneui7_byh7_boot.img` | SM-S9210 国行 CHC | S9210ZCU4BYH7 | 6.1.99 | One UI 7；已定标（e1q-S9210ZCU4BYH7） |
| `chc_oneui8.0_cza1_boot.img.lz4` | S24 全系国行 CHC | S9280ZCS4CZA1 | 6.1.128 | One UI 8.0；已定标（e3q-S9280ZCS4CZA1） |
| `tgy_oneui8.0_cza1_boot.img` | S24 全系港版 TGY | S9280ZHS4CZA1 | 6.1.128 | One UI 8.0；已定标（e3q-S9280ZHS4CZA1） |
| `chc_oneui8.5_dzg1_boot.img` | S24 全系国行 CHC | S9280ZCS6DZG1 | 6.1.145 | One UI 8.5；v2.5.6 起并入 DZF2 载荷 |
| `tgy_oneui8.5_dze2_boot.img` | S24 全系港版 TGY | S9280ZHS6DZE2 | 6.1.145 / 33419968 | **真机验证成功**（2026-08-22） |
| `xaa_oneui8.5_dze2_boot.img` | **SM-S926U1 美版 S24+ XAA** | S926U1UES6DZE2 | 6.1.145 / 33419968 | **issue #10 修复**；e2q target；App v3.5.0-beta.185 已发布 |
| `kss_oneui8.5_dze1_boot.img` | **SM-F741N 韩版 Z Flip 6 KSS** | F741NKSS4DZE1 | 6.1.145 / 33418572 | 仅内核分析（2026-10-18），**暂不接入** |

> 注：`download.img`（`/home/nt/下载/`）= `boot.2.zip` 内 boot.img = SN-F741N
> 韩国固件的 boot 分区；Samsung 签名信息 `SM-F741N_KOR_KX_QKEY2`。

## 2. 解包内核与恢复 ELF

| 目录 | 内容 | ELF 符号数 | 状态 |
|---|---|---|---|
| `unpacked/` | SM-S9210 BYH7：`kernel`(raw) + `vmlinux_byh7.elf` | — | 已定标 |
| `cza1_unpacked/` | S9280 HK CZA1：kernel + `vmlinux_cza1.elf` | — | 已定标 |
| `cza1_chc_unpacked/` | S9280 CN CHC CZA1：kernel + `vmlinux_cza1_chc.elf` | — | 已定标 |
| `dzg1_unpacked/` | S9280 CN DZG1：kernel + `vmlinux_dzg1.elf` | — | 并入 DZF2 载荷 |
| `dze2_unpacked/` | **S9280 HK DZE2**：`kernel` + `vmlinux_dze2.elf` | 107,253 条 | ✅ 真机验证 |
| `dze2_xaa_unpacked/` | **S926U1 US S24+ DZE2**：`kernel` + `vmlinux_dze2_xaa.elf` | 107,253 条 | ✅ 定标（issue #10） |
| `f741n_unpacked/` | **F741N KR Z Flip6 DZE1**：`kernel` + `vmlinux_f741n_dze1.elf` | 107,253 条 | 🔍 仅分析，暂不接入 |
| `rootmygalaxy_v3/` | RMG 参考 ksud/模块产物与机型资料 | — | 参考 |

## 3. 报告

| 文件 | 内容 | 结论/状态 |
|---|---|---|
| `ONEUI7_适配可行性报告.md` | One UI 7（BYH7 / 6.1.99）适配可行性 | 已定标（e1q-S9210ZCU4BYH7），待真机 |
| `dzg1_resukisu_plan.md` | DZG1 线 ReSukiSU/BakaSU 路线规划 | 后续被 DZE2/DZH3 BakaSU 路线接续 |
| `dzh3_bakasu_late_load.md` | **DZH3 BakaSU late-load 三星适配落地记录** | ✅ 2026-10-17 真机验证（管理器「工作中/LKM/越狱模式」） |
| `f741n_dze1_analysis.md` | **F741N（韩版 Flip6）DZE1 内核分析**（符号对比 / nfnetlink_log / P0 指纹 / remove_waiter / 编译验证） | 🔍 分析完成，2026-10-18 决定暂不接入 |
| `f741n_dze1_draft/` | F741N target 草案与构建产物（`target.h.draft`、`p0_fingerprint.h`、`cve-2026-43499-app.stable.so` 104,128 B） | 备查，未进入 App |

## 4. 相关文档

- 目标配置索引：`02_exploit工程/fusion-s24u/src/targets/README.md`
- 总索引：`RESEARCH_INDEX.md`
- App 端定标报告（镜像于 RootMyS24 仓库）：`docs/dze2-target-complete.md`、
  `docs/dze2-xaa-target-complete.md`、`docs/cza1-target-complete.md` 等
