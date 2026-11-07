# SM-S928U / S928USQS4AYB3（美版 S24 Ultra，e3q 高通）

来源：GitHub issue [#31](https://github.com/NanoTurtle1145/root-my-s24/issues/31)
（用户 `chinazi`，2026-11-06 提供）

## 文件

| 文件 | 大小 | sha256 |
|---|---|---|
| `S928U_AYB3_boot.img` | 100,663,296 B | `3cd01767981bb99ee88317baae0166ab0b44ddfcc0c5264232c0ca2383a66aac` |
| `S928U_AYB3_kernel.bin`（从 boot.img 提取的 arm64 原始内核） | 35,904,000 B | `faf4b710bd76aae9ab7c09f0288d48a905b25f62b3419797e207b6c68f64577f` |

原始下载 URL：`https://pub-209ca7e9ff734bf9bc920d288d8049eb.r2.dev/boot.img`（2026-11-07 下载）

## 设备信息（来自 issue）

- 型号：SM-S928U（S24 Ultra 美版，平台 e3q / pineapple，Snapdragon 8 Gen 3 for Galaxy）
- 固件：S928USQS4AYB3（bootloader 同）
- 系统：Android 14 / One UI 6.1，安全补丁 2025-03-01
- 内核：`6.1.75-android14-11-29543898-abS928USQS4AYB3`
- 指纹：`samsung/e3qsqw/e3q:14/UP1A.231005.007/S928USQS4AYB3:user/release-keys`
- KNOX：完好（warranty_bit=0, verifiedbootstate=green）

## 注意

- **用户没有提供 sha256**。文件完整性通过内核版本字符串确认（`6.1.75-...-abS928USQS4AYB3`）。
- 参考：同批 issue 中 #32（欧版 S928B EZJ1）用户提供了 sha256
  `54688aff1c242f6fdd92f80b8d4b96917d7abcef89c6bc0210ce803a6f780e4d`，
  但那是**另一个机型（EZJ1）的 boot.img**，与本目录文件无关。
- 该固件是 **6.1.75**（One UI 6.1），与 S9280/S928B 的 EZIF（6.1.162）不是同一代内核，偏移不可复用。
