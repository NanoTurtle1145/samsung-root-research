# Pixel 6 (内核 5.10) Root 方案调研

> 调研日期：2026-08-23
> 目标：Google Pixel 6 / 6 Pro / 6a（oriole / raven / bluejay），内核 5.10（Android 12 / 13 停留版）
> 结论先行：**CVE-2026-43499 (GhostLock) 可移植到 5.10 内核**——已有多个 5.10 先例（Amazon Fire / Xiaomi XIG04 / Honor 80 GT / MediaTek MT6983V）。Pixel 6 5.10 尚无现成 profile，需按 5.10 定标流程自行移植（与 S24 6.1 定标流程同源，但 rt_mutex_waiter 布局、BTF 可用性、物理基址来源不同）。

---

## 一、背景：Pixel 6 的内核版本史

| Android 版本 | 内核 | KMI | 说明 |
|---|---|---|---|
| Android 12（出厂） | 5.10.x-android12-9 | `android12-5.10` | Tensor GS101 出厂内核 |
| Android 13 | 5.10.x-android13 | `android13-5.10` | 停留 5.10 |
| Android 14+ | 6.1.157-android14-11 | `android14-6.1` | **内核随大版本升级到 6.1**（Google 提供升级） |

> 关键点：**Root-My-Pixel 的 Pixel 6 profile 用的是 6.1.157-android14-11（Android 14 后的内核），不是 5.10**。
> 若设备停留在 Android 12/13（5.10 内核），Root-My-Pixel 的现成 profile 不适用，需要 5.10 内核移植。

## 二、方案总览

| 方案 | 内核 | 是否需解锁 BL | 现成度 | 适用场景 |
|---|---|---|---|---|
| **A. 升级系统后用 Root-My-Pixel** | 6.1（Android 14+） | 否（锁 BL 可） | **现成** | 愿意升级系统、锁 BL |
| **B. GhostLock 5.10 移植** | 5.10（Android 12/13） | 否 | 需自行定标 | 必须停留 5.10、锁 BL |
| **C. 解锁 BL + KernelSU 刷入** | 5.10 / 6.1 均可 | **是** | 现成 | BL 可解锁（非 Verizon 版） |
| **D. 旧漏洞方案（历史）** | 5.10（Android 12/13） | 否 | 已过期 | 仅研究参考 |

## 三、方案 B 详解：CVE-2026-43499 移植到 5.10 内核

### 3.1 漏洞适用性

CVE-2026-43499 是 `kernel/locking/rtmutex.c` `remove_waiter()` 的 use-after-free（`futex_requeue` 代理锁回滚路径误用 `current` 而非 `waiter->task`）。**影响 Linux 2.6.39 – 6.18.x**，5.10.136 在范围内（`CONFIG_FUTEX_PI=y` + `CONFIG_RT_MUTEXES=y`）。

### 3.2 已有 5.10 先例（按相关性排序）

| 项目 | 设备 | 内核 | 平台 | 状态 |
|---|---|---|---|---|
| [CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle) | Xiaomi XIG04（au/KDDI） | **5.10.136-android12-9** | MediaTek，Android 12 | 代码完成，硬件未验证 |
| [GhostLock-5.10](https://github.com/R0rt1z2/GhostLock-5.10) | Amazon Fire Max 11 / Fire TV Stick 4K Max 2nd | 5.10（Fire OS 8） | 多设备 target | 可用 |
| [GhostLock-H80GT](https://github.com/yakidango-official/GhostLock-H80GT) | Honor 80 GT | 5.10.168 | MagicOS 8.0 | PoC |
| [GhostLock_MT6983V_5.10](https://github.com/SetsuNeko/GhostLock_MT6983V_5.10) | MediaTek MT6983V 设备 | 5.10 | Dimensity 9000 | PoC |

### 3.3 5.10 与 6.1（S24 定标基准）的关键差异

| 差异项 | 5.10（Pixel 6 场景） | 6.1（S24 DZF2 场景） |
|---|---|---|
| **rt_mutex_waiter 布局** | 旧的**扁平布局**：13 words → **10 words**（无嵌套 `rt_waiter_node`、无 `wake_state`/`ww_ctx`） | 新嵌套布局 |
| **BTF** | 5.10 GKI **可能无 BTF**（aristotle 即无）→ 结构体偏移需**反汇编恢复**后硬编码 | 有 BTF 可反推 |
| **KASLR 锚点** | 无 `xbl_config` → 动态 info-leak（`slide.c`）+ 静态 DRAM 基址（device tree）+ 运行时 `memstart_addr`/`kimage_voffset` | tracefs / boot_id 双路径 |
| **物理基址** | 5.10 场景 `P0_PHYS_OFFSET` 视平台（MediaTek 0x40000000；Pixel GS101 需从 dts 取） | 0x80000000 |
| **API level** | 编译需 `API=31`（Android 12） | API 34+ |

### 3.4 定标流程（Pixel 6 5.10）

参照 aristotle 移植流程（`ARISTOTLE_CVE43499_PORT.md`）：

```sh
# 1. 提取 boot.img（Pixel 官方 factory image / OTA）
#    解包 payload.bin → boot.img → 提取 vmlinux（vmlinux-to-elf）

# 2. 反推偏移（无 BTF 时反汇编；有 BTF 直接用 pahole）
#    关键符号：init_task / init_cred / kmalloc_caches / ashmem_fops /
#    anon_pipe_buf_ops / nfulnl_logger / selinux 相关

# 3. 生成 target.h（aristotle 生成器，无 --xbl-config）
python3 gen_aristotle_target.py \
  --boot boot.img \
  --pselect-shift 0 \
  --loggers <LOGERS_RVA> \
  --boot-id-data <BOOTID_RVA> \
  --kernel-phys-load <PHYS_LOAD> \
  -o src/target.h

# 4. 编译（API=31 关键）
make -C src clean preload API=31

# 5. 运行
adb push src/build/bin/preload.so /data/local/tmp/preload.so
adb shell 'chmod 0644 /data/local/tmp/preload.so'
adb shell 'LD_PRELOAD=/data/local/tmp/preload.so /system/bin/true'
adb shell '/data/local/tmp/su -c id'
# 成功标志: uid=0(root) ... context=u:r:kernel:s0
#           direct-root-summary root=1 id=1 su=1/... selinux=1->0 uid=0
```

### 3.5 Pixel 6 特有的定标注意点

1. **内核版本**：Pixel 6 出厂 `android12-5.10`，Android 13 为 `android13-5.10`——两者 GKI 构建号不同，偏移需分别定标；Pixel 6a（bluejay）与 6/6 Pro 内核不同。
2. **Tensor GS101 的物理内存布局**：`P0_PHYS_OFFSET` / `P0_KERNEL_PHYS_LOAD` 需从 Pixel 6 的 dts 或 XBL/abl 分区读取（不可套用 MediaTek 的 0x40000000）。
3. **硬编码结构体**：若内核无 BTF，`task_struct` / `pipe_buffer` / `rt_mutex_waiter` 布局须按 5.10 源码 + 反汇编核对（我们的 BYH7 经验：struct page 偏移错误特征 = `cache08/cache10` 读到 vmemmap 地址 `fffffffe` 前缀）。
4. **API=31**：Android 12 需要 `API=31` 编译，否则 payload 加载失败。

## 四、方案 A 详解：升级后直接用 Root-My-Pixel

[Root-My-Pixel](https://github.com/alex193a/Root-My-Pixel)（alex193a）已支持 Pixel 6：

```json
{
  "profileId": "oriole-CP2A.260705.006",
  "codename": "oriole",
  "kernelRelease": "6.1.157-android14-11",
  "buildDisplay": "CP2A.260705.006",
  "exploitAsset": "exploits/oriole-CP2A.260705.006.so",
  "kmi": "android14-6.1"
}
```

- 前置：Pixel 6 升级到 Android 14+（内核升为 6.1）、安装 Shizuku（ADB/无线调试授权）
- 流程：App 内检测设备 → 匹配 profile → 推送 payload → exploit → KernelSU/ReSukiSU late-load
- 优点：**开箱即用、锁 BL 可**；缺点：必须升级系统（放弃 5.10）

## 五、方案 C：解锁 BL + KernelSU

- Pixel 6 除 Verizon 版外 BL 可解锁（`fastboot flashing unlock`，会清数据）
- 解锁后刷入带 KernelSU 的 5.10 内核（[KernelSU](https://github.com/tiann/KernelSU) 支持 5.10）
- 最省事、最稳定；缺点是熔断？——Pixel 无 e-fuse，解锁 BL 永久可重锁，无 KNOX 类顾虑

## 六、方案 D：历史漏洞（仅研究参考）

- [Bad Spin (CVE-2022-20421)](https://github.com/0xkol/badspin)：Binder LPE，Pixel 6 Android 12 时代
- Black Hat 演讲「Two Bugs With One PoC - Rooting Pixel 6 from Android 12 to Android 13」：两个漏洞组合 PoC
- CVE-2023-45798 / CVE-2023-45799：Pixel 6 Android 14（2023-12 安全补丁修复）

> 以上均已被安全补丁修复，仅作原理参考。

---

## 七、建议路线

1. **若可接受升级系统**：方案 A（Root-My-Pixel 现成）最快，锁 BL 无风险
2. **若必须停留 Android 12/13（5.10 内核）且锁 BL**：方案 B（GhostLock 5.10 移植）——参照 aristotle 流程，需 Pixel 6 内核提取与 5.10 定标（估计 20 个符号 + 4 个结构体布局）
3. **若 BL 可解锁**：方案 C（KernelSU 刷入）最稳，推荐

## 八、参考链接

- [Root-My-Pixel](https://github.com/alex193a/Root-My-Pixel)（Pixel 现成 profile，6.1 内核）
- [GhostLock-5.10](https://github.com/R0rt1z2/GhostLock-5.10)（Amazon 5.10 内核）
- [CVE-2026-43499-aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle)（XIG04，5.10.136-android12，MediaTek——与 Pixel 6 场景最接近）
- [CVE-2026-43499-4.19-k40](https://github.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40)（Qualcomm 4.19，LD_PRELOAD 形式）
- [GhostLock-SELinux-Disabler](https://github.com/PeronGH/ghostlock-selinux-disabler)
- [rmx3888-cve-2026-43499-config](https://github.com/Bailan766/rmx3888-cve-2026-43499-config)（20 个已验证偏移示例）
- [NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)（漏洞原发）
- [GhostLock 4.19 README](https://raw.githubusercontent.com/yijiacloud/ghostlock-cve-2026-43499-4.19-k40/main/README.md)（原理）
- [Black Hat: Two Bugs With One PoC](https://www.classcentral.com/course/youtube-two-bugs-with-one-poc-rooting-pixel-6-from-android-12-to-android-13-250998)（历史方案）
- [Android 官方内核构建文档](https://source.android.com/docs/setup/build/building-kernels)（boot.img 提取与 vmlinux 构建）
