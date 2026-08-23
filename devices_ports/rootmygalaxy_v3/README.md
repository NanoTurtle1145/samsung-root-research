# RootMyGalaxy v3 载荷库（他人制作，存档分析用）

> **来源**：`RootMyGalaxy-release-v3.apk.1`（下载文件夹，2026-08-24 收到）
> **包名**：`dev.busung.s25uroot`，versionCode 34 / versionName 0.3.0
> **说明**：他人（BuSung-dev 体系）制作的免解锁 root App。本目录仅作**存档与对照分析**，
> 不直接用于发布；与我们自己的 RootMyS9280 载荷同源（CVE-2026-43499 / GhostLock 框架）。

---

## 目录结构

```
devices_ports/rootmygalaxy_v3/
├── README.md                    # 本索引
├── <构建号>/<构建号>.so          # 47 个机型载荷（44 机型，S9280 有 4 个构建号）
├── ksud/                        # KernelSU 内核驱动（4 个版本，按内核系列）
└── ksu-manager/                 # KernelSU 管理器 APK
```

## 关键事实（存档备忘）

- **定标方式**：运行时 KASLR 探测（fops 指针扫描 `kaslr_open_ptr/ioctl_ptr/mmap_ptr/...`），
  非编译期符号偏移表 —— 与我们的 20 符号定标 + BTF 结构验证不同。
- **机型策略**：一机型一载荷（47 个），SHA 全部不同（无重复）。
- **KSU 驱动**：`ksud/ksud-samsung-android14-6.1-kdp`
  SHA `1b92611de62035263f129636270deb9002de42e1d2329460342856243975015b`
  **与我们 `RootMyS9280/assets/ksud-selected` 完全一致**（同源二进制）。
- **缺少的修复**：他们的载荷**不含**我们的 v7–v10 稳定性修复
  （`slide_wait_flag` 超时防冻结、CFI 触发重试、KernelSnitch futex_hashsize roundup 对齐）。
- **没有 CZA1 港版 One UI 8.0 适配**（最高到港版 DZG1 / 6.1.145）。
- **未 stripped 样本**：`S9480ZCS4AZG1/S9480ZCS4AZG1.so` 保留符号表，可作逆向参考。

---

## 载荷分组（按大小 → 内核/系列）

### 89560B — S23 系列 / Fold5 / Flip5（kernel 6.1 早期）
| 构建号 | SHA256 | 机型 |
|---|---|---|
| F7310TBS9GZF1 | `69ec155663b68c4ec2de582a3de9b08db6401063a1523ef162d65c11f0e86214` | Galaxy Z Fold5 |
| F9460ZCS9GZF1 | `e80a964a3fd97e605ec052ef0346742b843980787fa4d2b5bc41c101a9860497` | Galaxy Z Flip5 |
| S9110ZCS8FZE3 | `6514c7209a9bbc37a09288b6427ed81ae07837ce1e824db4fece048dd3088c26` | S23 国行 |
| S9110ZCS8FZG1 | `ab7ab50c6a4d5204207016cb309f18ffd5d279d5526a18ad98496ebbc8d3885d` | S23 国行 |
| S9160ZCS8FZE3 | `27d11820a5d763d6c40e55418084dbf14d770332629b3ebcf257af6947eb6ece` | S23+ 国行 |
| S9160ZCS8FZG1 | `a9de85462409fa2bee0b4d561b7ab8c33af79fe0652c37f6dc8fe4c2b6c359b7` | S23+ 国行 |
| S9160ZHS8FZE3 | `95ec2a8c7c48641e844e123bebba4c3856f61c50a7d469c1559ce1128656b409` | S23+ 港版 |
| S9180ZCS8FZE3 | `d4cfb163792aa14f5e36ea58f055a5a0a7a673cecca6192c4b0f60f02f7e9bbd` | S23 Ultra 国行 |
| S9180ZCS8FZG1 | `612ecf6a02fab815035b7abc61f1d12c4ddf0c4585d4949110b7a8e6ba65bc23` | S23 Ultra 国行 |

### 89624B — S25 系列 / Fold7 / Flip7 / 心系天下（kernel 6.6）
| 构建号 | SHA256 | 机型 |
|---|---|---|
| F7660ZCSBBZG3 | `e59404316ae4d6fde1028e0259b18a4be76ed9ff8936df28dd80d065e53e04f5` | Galaxy Z Fold7 |
| F9660ZCSBBZG3 | `5aadb4ec56c62b555dabcfaad09a14b112040b0de7e7e7ee3246442330c9bbff` | Galaxy Z Flip7 |
| F9660ZCU9BZDP | `da9a2f921bef70ebb1d30ea38a1af33d427c90e28bae51a15e9e7c21c07de1ba` | Galaxy Z Flip7 |
| F966BXXSBBZG3 | `2624dfcaf0e7b64dcba19d8fcc35bb7a3675fc3adb59b6337d83a51d992eb4cf` | Galaxy Z Flip7（欧版） |
| S9310ZCSCCZG1 | `6e88cf76fda54527b8f3c7239e098d549e1d51bd089c7f5be8c92ef99248445a` | S25 国行 |
| S9360ZCSCCZG1 | `f49a404c15b31b2c0454e8f600a39a9a641f72b9d9995f34a53ef510a8003538` | S25+ 国行 |
| S9370ZCS9CZG1 | `6ae91faa6c9e869b3fa5dea75b97585bbaed97c114f39d1e571f35ec6e4069a5` | S25 Ultra 国行 |
| S9370ZCU8CZF1 | `4ef65806fc82388f388de28533f830709748adf06d734056a558de2d6e302816` | S25 Ultra 国行 |
| S9370ZHS9CZG1 | `3ccdfcacab6cee67cd70b20f366a10bd741d330e1d5432bef69153df92178bb7` | S25 Ultra 港版 |
| S9380ZCS8BZA1 | `7a74c35b8feee5fbc7888b76e64e59504a3cf2be2c9fe56f20130261a4ce8278` | S25 Ultra（SM-S9380） |
| S9380ZCS9BZC1 | `1c24ae8831bb5e93fcaff70bad4c5a301bde59c6ba9b0eed6e194dba6e6f5732` | S25 Ultra（SM-S9380） |
| S9380ZCSCCZG1 | `92c92dcfabb891c0db5abcbece41242c815fdcf0c07ccfff317de4907a6d3f19` | S25 Ultra 国行 |
| S9380ZCUBCZF1 | `79602f2e9cc559d39f07020ff6701906385a3b538e8f8daafd150ce07d175249` | S25 Ultra 国行 |
| W9026ZCS8BZG3 | `761b9670127e46e1248b1f860828842fcae18391dc823bcdfa9f548e104ae1b6` | 心系天下 W26 |
| W9026ZCU7BZF1 | `49588efab911eee76fa1b15e27e34f146b3e620803f4d4dc0f35441483a34fcb` | 心系天下 W26 |

### 99776B — S24 系列（非 Ultra）/ Fold6 / Flip6 / 心系天下（kernel 6.1.145）
| 构建号 | SHA256 | 机型 |
|---|---|---|
| F7410ZCS4DZF2 | `136de27903b8a0d0f8504a49fb84789ae384543506606612a57993cc964ec9db` | Galaxy Z Fold6 国行 |
| F7410ZCS4DZG3 | `650cf035003aee8ed29c4afb99a174a59f56b6900c84d74cd9beed2ab16d61b5` | Galaxy Z Fold6 国行 |
| F9560ZCS4DZG3 | `95ff128083b3d1b5c811f4968d35f27b71319df6cadda6d54a485d61bc4591dc` | Galaxy Z Flip6 国行 |
| F956USQS4DZG3 | `7c8642a38a53c6cd871d82f203fbbb51905bc6ef3ee26049fe5f299ae83de9bc` | Galaxy Z Flip6 美版 |
| S9210ZCS6DZE2 | `df8f5f7fda8a08cbe67b1935eac6d1bef7654ff15bb5763b64cde7d06b6280fa` | S24 国行 DZE2 |
| S9210ZCS6DZF2 | `6bc6d7ff9159f68f1595dc36a46d23d3619391db59634d263d4a6fa609874006` | S24 国行 DZF2 |
| S9210ZCS6DZG1 | `5fe3feef28053006a0d891344077a096c508827f3e89737c3f7c0cee8ce3c434` | S24 国行 DZG1 |
| S9210ZHS6DZG1 | `c8990bdaacefb5874730ae4561ba1c4a17fdfcb5f75866938f0f645812b87306` | S24 港版 DZG1 |
| S9260ZCS6DZE2 | `81b6d16214e273388f16d176aa1a46e522edf596ad0d5308328850fc642ccc53` | S24+ 国行 DZE2 |
| S9260ZCS6DZF2 | `f0dbd2a398d9f4be8ccae9c6f84d72be39f751e5c80a4dd33efb50bdde1125cd` | S24+ 国行 DZF2 |
| S9260ZCS6DZG1 | `751eadf3d16b94c5c15610c4d0b99a6e74460a2de45d08a77c59743c781bb240` | S24+ 国行 DZG1 |
| W9025ZCS4DZF2 | `e33b33cc381edf1e4a10f82fcb61a01c9ac4713a558b61b50634afba90928888` | 心系天下 W25 |
| W9025ZCS4DZG3 | `8c92b9e040220b912d096edad0a05e3f384bb48e4883d4083d9490ab36d133ed` | 心系天下 W25 |

### 99792B — S24 Ultra（SM-S9280, kernel 6.1.145）
| 构建号 | SHA256 | 机型 |
|---|---|---|
| S9280ZCS6DZE2 | `1bbe272e39785f77ea23c9a963d68b6a88915cf16cfe31163acb45a34b7f8b47` | S24 Ultra 国行 DZE2 |
| S9280ZCS6DZF2 | `8937a216d3ff2241d2f2516e7b519b8426a03d80ae1e20079c4c55733dc4715b` | S24 Ultra 国行 DZF2 |
| S9280ZCS6DZG1 | `3c5fe9de3b5729ce068e431013fd4adf256f3d09a696c1b5d914c20b4f8b7932` | S24 Ultra 国行 DZG1 |
| S9280ZHS6DZG1 | `4e1810726bdd1cf40e103859e2d39452de7807b4ab9c83fd8bf6f24aaa36b7f5` | S24 Ultra 港版 DZG1 |

### 160104B — S26 系列（kernel 6.12）
| 构建号 | SHA256 | 机型 |
|---|---|---|
| S9420ZCS4AZG1 | `773c17141146861d56a93f2fe6044f3f64e8245bfc69d7ee3901ecb447685d3d` | S26（SM-S9420）国行 |
| S9470ZCS4AZG1 | `3f24ccd4a124e798b3b00c02463206ddb006e3e6eac5df3d3fab6d44901328ca` | S26+（SM-S9470）国行 |
| S9480ZCS4AZG1 | `a9a3424b9b77eca7faa2f57fb2f48c2ba9f6049f58129d2f0fe0d85ef7f26c93` | S26 Ultra（SM-S9480）国行 |

---

## ksud（KernelSU 内核驱动，按内核系列）

| 文件 | SHA256 | 大小 | 内核系列 |
|---|---|---|---|
| ksud-samsung-android13-5.15-kdp | `11329c52adf28130d75290bd095fb6831c0682f85817534a531c773933aefe8e` | 6756208 | Android 13 / 5.15 |
| ksud-samsung-android14-6.1-kdp | `1b92611de62035263f129636270deb9002de42e1d2329460342856243975015b` | 4879856 | Android 14 / 6.1 ⭐ |
| ksud-samsung-android15-6.6-kdp | `99133461028ef90b1cc9d3e5651ef483ac11004306e72a2930d03a621cc27a8e` | 6415632 | Android 15 / 6.6 |
| ksud-samsung-android16-6.12-kdp | `80d69d87835835c1bd00d5e40e0a7c4cd05f9fb1de1f1d6b109400a150ee7175` | 3506520 | Android 16 / 6.12 |

> ⭐ `android14-6.1-kdp` 与我们 `RootMyS9280/assets/ksud-selected` **二进制完全一致**。

## ksu-manager

| 文件 | SHA256 | 大小 |
|---|---|---|
| KernelSU_v3.2.5_32525-release.apk | `1417081413bf7ab1de8e440ecbcb62685037c8f28f048f0f8b79e305b31ab916` | 9083665 |

---

## 与我们 RootMyS9280 的对照速查

| 机型/构建号 | 他们的载荷（SHA 前 16） | 我们的载荷 | 备注 |
|---|---|---|---|
| S9280 国行 DZF2 | `8937a216d3ff2241` | `cve-2026-43499`（e9baa068843b372c） | 同 exploit 不同构建；我们含 v7–v10 修复 |
| S9280 国行 DZG1 | `3c5fe9de3b5729ce` | `cve-2026-43499`（DZF2 共用） | 我们按构建号分组共用 |
| S9280 港版 DZG1 | `4e1810726bdd1cf4` | `cve-2026-43499-dzg1` | 他们无港版 CZA1/One UI 8 |
| S9210 国行 BYH7 | 无（S9210ZCS6DZE2 `df8f5f7f...`） | `cve-2026-43499-byh7` | One UI 7 专用，我们独有 |
| S9280 港版 CZA1 | **无** | `cve-2026-43499-cza1`（2a6f101f） | One UI 8.0，我们独有且真机成功 |

## 使用场景备忘

1. **逆向参考**：`S9480ZCS4AZG1/S9480ZCS4AZG1.so` 未 stripped，可作新内核定标时的对照样本。
2. **机型覆盖扩展**：他们的 S23/S25/S26/折叠屏/心系天下载荷，可作为我们 FirmwareVersion
   分组扩展的候选（用我们的定标流程重编，而非直接复用二进制）。
3. **KSU 驱动**：android13/15/16 的 KDP 可补充我们目前只有 6.1 驱动的缺口。
