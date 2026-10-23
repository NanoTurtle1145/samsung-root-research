# devices_ports —— 机型号文件 / 内核素材 / 定标与可行性报告

> 整理时间：2026-10-24
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
| `kss_oneui8.5_dze1_boot.img` | **SM-F741N 韩版 Z Flip 6 KSS** | F741NKSS4DZE1 | 6.1.145 / 33418572 | ✅ 已定标并接入（`b6q-F741NKSS4DZE1` / App `F741NDZE1`），beta.191 真机验证通过（issue #16），v3.5.1 正式支持 |
| `eur_oneui9.0_ezif_boot.img` | **SM-S928B 欧版 S24 Ultra（EUR/OXM；签名 `SM-S928B_EUR_XX_QKEY2`）** | S928BXXU6EZIF | 6.1.162 / 34343818 | **One UI 9.0**；已定标（`e3q-S928BXXU6EZIF`，载荷 104,128 B 已构建），待真机验证 |
| `eur_oneui6.1_axk5_boot.img` | **SM-S928B 欧版 S24 Ultra（EUR；签名 `SM-S928B_EUR_XX_QKEY2`）** | S928BXXU4AXK5 | 6.1.75 / 29543898 | 2026-10-24 归档；**One UI 6.1（Android 14）**；✅ 已自动定标（`e3q-S928BXXU4AXK5`，载荷 104,128 B 已构建），待真机验证 |
| `eur_oneui7.0_byd9_boot.img` | SM-S928B 欧版 S24 Ultra（EUR） | S928BXXU4BYD9 | 6.1.99 / 30958380 | 2026-10-24 归档；**One UI 7.0（Android 15）**；✅ 已自动定标（`e3q-S928BXXU4BYD9`，载荷 104,128 B 已构建），待真机验证 |
| `eur_oneui8.0_cza1_boot.img` | SM-S928B 欧版 S24 Ultra（EUR） | S928BXXS4CZA1 | 6.1.128 / 31999054 | 2026-10-24 归档；**One UI 8.0（Android 16）**；✅ 已自动定标（`e3q-S928BXXS4CZA1`）；注意与港版 TGY 同构建号但**非同一机型**，`SLIDE_NFULNL_LOGGER_OFF` 差 8 字节；待真机验证 |

> 注：`download.img`（`/home/nt/下载/`）= `boot.2.zip` 内 boot.img = SN-F741N
> 韩国固件的 boot 分区；Samsung 签名信息 `SM-F741N_KOR_KX_QKEY2`。
>
> 注：`eur_oneui{6.1,7.0,8.0}_*_boot.img` 来自 2026-10-24 下载的 S928B 固件合集
> `/home/nt/下载/s24uboot.img`（RAR5，内含 Android 14 / 15 / 16 三代 boot），
> 已按惯例重命名归档；原始压缩包仍留在下载目录。

## 2. 解包内核与恢复 ELF

| 目录 | 内容 | ELF 符号数 | 状态 |
|---|---|---|---|
| `unpacked/` | SM-S9210 BYH7：`kernel`(raw) + `vmlinux_byh7.elf` | — | 已定标 |
| `cza1_unpacked/` | S9280 HK CZA1：kernel + `vmlinux_cza1.elf` | — | 已定标 |
| `cza1_chc_unpacked/` | S9280 CN CHC CZA1：kernel + `vmlinux_cza1_chc.elf` | — | 已定标 |
| `dzg1_unpacked/` | S9280 CN DZG1：kernel + `vmlinux_dzg1.elf` | — | 并入 DZF2 载荷 |
| `dze2_unpacked/` | **S9280 HK DZE2**：`kernel` + `vmlinux_dze2.elf` | 107,253 条 | ✅ 真机验证 |
| `dze2_xaa_unpacked/` | **S926U1 US S24+ DZE2**：`kernel` + `vmlinux_dze2_xaa.elf` | 107,253 条 | ✅ 定标（issue #10） |
| `f741n_unpacked/` | **F741N KR Z Flip6 DZE1**：`kernel` + `vmlinux_f741n_dze1.elf` | 107,253 条 | ✅ 已定标并接入，真机验证通过 |
| `ezif_unpacked/` | **S928B EU S24U EZIF（One UI 9.0）**：`kernel` + `vmlinux_ezif.elf` | 107,567 条 | 已定标（`e3q-S928BXXU6EZIF`，载荷已构建），待真机验证 |
| `axk5_unpacked/` | **S928B EU S24U AXK5（One UI 6.1）**：`kernel` + `vmlinux_axk5.elf` + `vmlinux_axk5.btf` | 97,796 条 | 已自动定标（`e3q-S928BXXU4AXK5`），待真机验证 |
| `byd9_unpacked/` | **S928B EU S24U BYD9（One UI 7.0）**：`kernel` + `vmlinux_byd9.elf` + `vmlinux_byd9.btf` | 100,386 条 | 已自动定标（`e3q-S928BXXU4BYD9`），待真机验证 |
| `cza1_eur_unpacked/` | **S928B EU S24U CZA1（One UI 8.0）**：`kernel` + `vmlinux_cza1_eur.elf` + `vmlinux_cza1_eur.btf` | 100,747 条 | 已自动定标（`e3q-S928BXXS4CZA1`），待真机验证 |
| `rootmygalaxy_v3/` | RMG 参考 ksud/模块产物与机型资料 | — | 参考 |

## 3. 报告

| 文件 | 内容 | 结论/状态 |
|---|---|---|
| `ONEUI7_适配可行性报告.md` | One UI 7（BYH7 / 6.1.99）适配可行性 | 已定标（e1q-S9210ZCU4BYH7），待真机 |
| `dzg1_resukisu_plan.md` | DZG1 线 ReSukiSU/BakaSU 路线规划 | 后续被 DZE2/DZH3 BakaSU 路线接续 |
| `dzh3_bakasu_late_load.md` | **DZH3 BakaSU late-load 三星适配落地记录** | ✅ 2026-10-17 真机验证（管理器「工作中/LKM/越狱模式」） |
| `f741n_dze1_analysis.md` | **F741N（韩版 Flip6）DZE1 内核分析**（符号对比 / nfnetlink_log / P0 指纹 / remove_waiter / 编译验证） | ✅ 分析完成、定标接入并真机验证（v3.5.1 正式支持） |
| `f741n_dze1_draft/` | F741N target 草案与构建产物（`target.h.draft`、`p0_fingerprint.h`、`cve-2026-43499-app.stable.so` 104,128 B） | 备查（正式 target 已建，构建与草案逐字节一致） |
| `s928b_ezif_analysis.md` | **S928B（欧版 S24 Ultra）EZIF 内核分析**（25 项偏移迁移 / nfnetlink_log / random_table / tracefs / remove_waiter / P0 指纹 / 编译验证） | 定标完成、draft 已构建，待真机验证 |
| `ezif_draft/` | EZIF target 草案与构建产物（`target.h.draft`、`p0_fingerprint.h`、`cve-2026-43499-app.stable.so` 104,128 B、`cve-2026-43499-app.so`、`cve-2026-43499-root`） | 备查（正式 target 已建，构建与草案逐字节一致） |
| `s928b_axk5_analysis.md` | **S928B 欧版 AXK5 内核分析**（20 项符号迁移 / 6 项镜像实测 / 48 项 BTF 核对 / 构建验证 / 真机清单） | 自动定标完成（`e3q-S928BXXU4AXK5`），待真机验证 |
| `s928b_byd9_analysis.md` | **S928B 欧版 BYD9 内核分析**（同上结构） | 自动定标完成（`e3q-S928BXXU4BYD9`），待真机验证 |
| `s928b_cza1_eur_analysis.md` | **S928B 欧版 CZA1 内核分析**（同上结构） | 自动定标完成（`e3q-S928BXXS4CZA1`），待真机验证 |
| `axk5_draft/` `byd9_draft/` `cza1_eur_draft/` | 三个欧版 target 的草案与构建产物（`target.h.draft`、`p0_fingerprint.h`、三件载荷，stable 均 104,128 B） | 备查（正式 target 在 `src/targets/`） |

## 4. 相关文档

- 目标配置索引：`02_exploit工程/fusion-s24u/src/targets/README.md`
- 总索引：`RESEARCH_INDEX.md`
- App 端定标报告（镜像于 RootMyS24 仓库）：`docs/dze2-target-complete.md`、
  `docs/dze2-xaa-target-complete.md`、`docs/cza1-target-complete.md` 等
