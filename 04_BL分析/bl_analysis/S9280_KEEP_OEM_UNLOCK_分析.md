# S9280 KEEP_OEM_UNLOCK 补丁机制分析

> 分析对象：`BL_S9280ZHS6DZE2_BIT_6_KEEP_OEM_UNLOCK_UI_8_5.tar.md5`（社区"保持 OEM 解锁" BL 包）
> 辅助工具：`BL_PATCHER_V1`（JR Kruse，Credit A.S._id）
> 分析日期：2026-08-18
> 结论先行：**这不是"解锁补丁"，是"防重新上锁补丁"。它无法让一台从未解锁的 S9280 获得解锁能力。**

---

## 1. 核心结论

1. **KEEP_OEM_UNLOCK 包的真实机制 = 整体替换旧版 abl.elf**，不是二进制 patch。
   - 包内 xbl/tz/aop/vbmeta 均为 **S9280ZHS6DZE2**（One UI 8.5 / Android 16）
   - 唯独 **abl.elf 是 S9280ZHS4BYH1**（港版 TGY，Android 15 / One UI 7 时代，构建于 2025-08-06）
   - 也就是：**拿 One UI 7 的旧 abl 塞进 One UI 8.5 的 BL 包**。

2. **S9280 的 abl.elf 代码段是加密的**（熵 ~7.95 bits/byte，AES-like），只有尾部证书链/签名块是明文。
   - 社区工具没有解密能力，**无法对 abl 做指令级 patch**，只能整体换文件。
   - 这解释了为什么补丁是"换 abl"而非"改 abl"。

3. **为什么换旧 abl 就能"保持解锁"**：
   - One UI 8.0 起，三星因欧盟新规移除了 OEM 解锁选项（见 §4）
   - 已解锁设备如果刷入 One UI 8.5 的新 abl，bootloader 可能被重新锁定（XDA 有 "Once you update to oneui 8 your bootloader will be locked forever" 的反馈）
   - 旧版（One UI 7）abl 保留了解锁状态读取/保持逻辑 → 换上去后新内核继续以"已解锁"状态启动

4. **对用户（KNOX 0x0、从未解锁的国行 S9280）无解锁能力**：
   - 该补丁只能"保持已解锁状态"，不能凭空产生解锁状态（解锁状态存放在 eFuse/KG 状态，由 abl+XBL 硬件校验链决定）
   - 用户当前靠 CVE-2026-43499 漏洞 root，**不需要也不应**刷这个 BL 包（会引入 DZE2 BL 且无收益）

---

## 2. abl.elf 结构分析（静态）

```
文件：abl.elf（解压后 2441528 字节 = 0x254138）
ELF：ARM 32-bit, statically linked, no section headers
Entry：0x9fa00000

0x000000 - 0x000094  ELF 头 + Program Header 表（3 个 PH）
0x000094 - 0x001000  0x00 填充
0x001000 - 0x001020  16 字节零 + 16 字节 GUID 78e58c8c-3d8a-1c4f-9935-896185c32dd3
0x001020 - 0x001024  u32 0x252000 = PH[1].filesz（疑似加密载荷长度）
0x001000 - 0x0b7000  加密区（熵 ≈ 7.95 bits/byte）
0x0b7000 - 0x253000  0xFF 填充
0x253000 - 0x254138  Samsung 证书链 + 签名块（明文）
```

Program Headers：
| # | type | off | vaddr | filesz | flags |
|---|------|-----|-------|--------|-------|
| 0 | 0x0  | 0x000000 | 0x00000000 | 0x94 | 0x7000000 |
| 1 | 0x1  | 0x001000 | 0x9fa00000 | 0x252000 | 0x7 (RWE) |
| 2 | 0x0  | 0x253000 | 0x00000000 | 0xf38 | 0x2000000 |

尾部明文元数据（0x253f38 起）：

| 偏移 | 内容 | 含义 |
|------|------|------|
| 0x253f38 | `SignerVer02` | 签名格式版本 |
| 0x253f48 | `99507881R` | 签名者/工程号 |
| 0x253f58 | `S9280ZHS4BYH1` | **固件版本：港版 TGY，Android 15 / One UI 7** |
| 0x253f78 | `20250806114901` | 构建时间 2025-08-06 11:49:01 |
| 0x253f88 | `SM-S9280_CHN_TGY_QKEY1` | 中国/港版 QKEY1 密钥标识 |
| 0x253fa8 | `SRPWH02C004` | 项目编号 |
| 0x253fd4 | `abl.elf` | 分区名 |

证书链：ECDSA384 ROOT 1011 ← CA 1011 ← ATTEST 1010v0（Samsung 标准 XBL/ABL 签名链，
`m.sec.key@samsung.com`，2021-07-07 签发，2041-07-02 到期）。

**判定：代码区为 Samsung 私有加密格式**（头部 GUID + 载荷长度，随后整段高熵密文）。
在无 Samsung 私钥/解密例程的前提下，无法反汇编出 OEM-unlock 判断逻辑。

---

## 3. BL_PATCHER 工具本身的问题

BL_PATCHER.bat 逻辑（逐行读完 320 行）：
1. 从用户提供的 stock BL tar.md5 中解出全部文件
2. **删除 stock 的 abl.elf / vbmeta.img**
3. 用 `bin/UI_7_Abl_Files/<MODEL>/` 下**预制的** abl.elf.lz4 + vbmeta.img.lz4 替换
4. 重新打包成 `*_KEEP_OEM_UNLOCK.tar.md5`

**发现的 bug：**
- `bin/UI_7_Abl_Files/S9280/vbmeta.img.lz4` 解压后是 **S918B（S23 Ultra 欧版）** 的 vbmeta
  （内含 `S918BXXS8EYJ1`、`SM-S918B_EUR_XX_QKEY1`）—— 工具自带的 S9280 预制 vbmeta 是**错的文件**
- 但网上流传的 `BL_S9280ZHS6DZE2_BIT_6_KEEP_OEM_UNLOCK_UI_8_5.tar.md5` 成品包内的 vbmeta 是
  正确的 **S9280ZHS6DZE2 / SM-S9280_CHN_TGY_QKEY1** —— 说明成品包是打包者手工修正过的，不能直接用 BL_PATCHER 现场生成
- 两个 vbmeta 均为 avbtool 1.3.0 生成，algorithm_type=0、flags=0（无签名算法、无 AVB flags），
  属 Samsung 魔改 avbtool 产物，descriptors 指向 prism/optics 等 Samsung 私有分区

**结论：如要自制 KEEP_OEM_UNLOCK 包，必须用成品包里的 vbmeta（S9280 正确版），
不要用 BL_PATCHER 自带的 S9280 目录文件。**

---

## 4. 背景：为什么 One UI 8 需要"保持解锁"

- 2025 年 8 月起，三星随 One UI 8.0 移除 OEM bootloader 解锁选项（合规压力，欧盟
  Cyber Resilience Act 相关讨论见 XDA/ithome）
- 后果：
  - 新设备/未解锁设备：系统设置里不再有"OEM 解锁"开关，无法解锁 BL
  - **已解锁设备**：升级 One UI 8.x 新 BL 后 bootloader 可能被重新锁定
    （XDA TWRP S25 帖："Once you update to oneui 8 your bootloader will be locked forever"）
- 社区对策（jrkruse 的 Userdata_AIO 系列 / KEEP_OEM_UNLOCK BL 包）：
  - 用 One UI 7（最后一代带完整解锁逻辑）的 abl.elf 顶替新版 abl
  - 让已解锁设备升级到 One UI 8/8.5 后仍以 unlocked 状态引导，可继续 root

> 用户场景对照：国行 S9280 KNOX 0x0、未解锁、One UI 8.5 (DZF2)。
> 该补丁解决的是"已解锁→升级→保持解锁"，对"未解锁→获得解锁"无效。

---

## 5. 攻击面评估：S9280 还有没有可能"解锁"或"绕过解锁"

按现实可能性从高到低：

1. **维持现状（漏洞 root，不解锁）** — 已实现，无风险，不熔 KNOX。
2. **找新漏洞直接攻 XBL/ABL** — 难度极高：
   - abl 加密 → 无法静态审计 unlock 逻辑
   - XBL 有独立签名链 + QFPROM 硬件锚点
   - 公开渠道无 S24 系 unlock 漏洞（S25 系曾有 firehose 相关讨论，S24 无）
3. **降级/跨版本解锁尝试** — 无效：
   - 解锁判定不在 Android 层，在 abl+XBL+eFuse，降级系统不改变 KG 状态
   - 且 DZF2 BIT6 防降级（sw rev check 在 xbl/vbmeta 链上）
4. **刷 KEEP_OEM_UNLOCK BL** — 对未解锁设备**无解锁效果**，且有风险：
   - 引入 DZE2 BL（BIT6 同 BIT 可刷，但跨版本）
   - 一旦刷入，Odin 校验通过也可能因 KG 状态仍 locked 而开机卡
   - 收益为零，不推荐

**结论：对这台 KNOX 0x0 的国行 S9280，继续走漏洞 root 路线是唯一合理路径；
"解锁 bootloader"这一目标在当前公开技术下不可达，且解锁本身会熔断 KNOX，
与 KnoxPatch/Secure Folder 需求直接冲突。**

---

## 6. 材料清单（供后续研究）

```
/home/nt/下载/Bit_6_UI_8_5/BL_S9280ZHS6DZE2_BIT_6_KEEP_OEM_UNLOCK_UI_8_5.tar.md5  成品补丁 BL
/home/nt/下载/BL_PATCHER_V1/                                                   打包工具（含 S918B 错误 vbmeta）
/home/nt/root_research/bl_analysis/patched/abl.elf                              解压后的 abl（加密）
/home/nt/root_research/bl_analysis/tarmd5_vbmeta.img                            成品包 vbmeta（S9280 DZE2 正确版）
/home/nt/root_research/bl_analysis/blpatcher_vbmeta.img                         工具自带 vbmeta（S918B 错误版）
```

待补：stock DZF2 BL 的 abl.elf（用户固件仍在手机里，可从 DZF2 五件套提取，或 sammobile 下载）
用于和补丁 abl 做字节级 diff，验证"补丁 abl 是否只是旧版换名"。
