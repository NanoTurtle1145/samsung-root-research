# BakaSU late-load 三星适配落地（SM-S9280 · DZH3）

> 报告日期：2026-10-17
> 目标设备：SM-S9280（S24 Ultra 国行），固件 `S9280ZCS6DZH3`，内核 `6.1.145-android14-11-3254743-abS9280ZCS6DZH3`
> 上游：BakaSU（`Baka-SU/BakaSU`，ReSukiSU 系）分支 `samsung-port`：`02a11f6e`（KDP/RKP/DEFEX 适配）+ `3befe299`（版本/UAPI 覆盖），基线 `d7260ca1`
> 管理器：`com.resukisu.resukisu` v4.2.0-rc3（versionCode 35171）
> 承接：`dzg1_resukisu_plan.md`（ReSukiSU 调研）——本次以 BakaSU 在 DZH3 落地，该技术路线已真机证实
> 独立仓库（补丁/脚本/构建）：<https://github.com/NanoTurtle1145/BakaSU-S9280>

## 结论：真机验证通过（不写 boot）

CVE-2026-43499 → 临时 root → `ksud late-load` 加载**按 DZH3 精确构建 + 三星 KDP/RKP/DEFEX 适配**的 BakaSU 内核模块：

- `/proc/modules` 中 `kernelsu ... Live`；`ksud debug info`：`version 35171`、`lkm: true`、`late_load: true`、`uapi_version: 4`；
- BakaSU 管理器显示「工作中 / LKM / 越狱模式」（内核 35171/5 ↔ 管理器 35171/4）；
- 识别到原有 10 个超级用户、9 个模块，SELinux 强制模式下正常；
- 与 RootMyS9280 相同为 per-boot 模型（重启后重跑），不写 boot、不熔断 Knox。

## 适配要点（相对上游）

| 组件 | 处理 | 说明 |
|---|---|---|
| KDP 凭据 | `prepare_ro_creds` + `kdp_assign_pgd`（root workqueue 上 task-scoped 安装）；`kdp_usecount_dec_and_test` + `__put_cred` 释放 | 运行时符号解析，无需 DDK 导出 CRC |
| DEFEX | kprobe `task_defex_enforce`（仅 current / uid 0 / KSU 域放行）+ UID 切换同步凭据三元组 | 绕过 Safeplace kill |
| RKP | `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT`：`ksu_patch_text()` 直返 `-EOPNOTSUPP` | fixmap 写代码/只读表会触发 RKP RAMDUMP |
| 回退 hook | dispatcher 不可用时：`__arm64_sys_setresuid` kretprobe（管理器 fd 下发）+ execve/newfstatat/faccessat/statx/faccessat2 地址级 kprobe（sucompat） | 注意 BakaSU 的 `ksu_handle_setuid(new_uid, old_uid)` 为两参数语义 |
| ksud staging | 加载**前**把 ksud 从 `/data/local/tmp/.ksud-stage` 落到 `/data/adb/ksud`；加载后 `finish_install()` | 加载后进程上下文变 `u:r:ksu:s0`，再写会被拒绝 / DEFEX kill |
| 版本 / UAPI | `KSU_VERSION_OVERRIDE=35171`；`KSU_FORCE_UAPI_VERSION=4` | 管理器按「内核 UAPI == 管理器 UAPI」显示模块页；UAPI 5 仅新增 EVENT_SERVICES 事件（向后兼容） |

补丁全文：`BakaSU-S9280/patches/0001..0002`；完整移植记录：`07_发布物/bakasu/BAKASU_SAMSUNG_PORT_NOTES.md`。

## 归档制品（本仓库 `07_发布物/bakasu/`）

| 文件 | 说明 | sha256（前 20） |
|---|---|---|
| `ksud-e3q-S9280ZCS6DZH3-samsung-35171` | 内嵌 DZH3 模块的 ksud（与 App 资产 `ksud-bakasu-dzh3` 同文件） | `909c8265724350ea1cac` |
| `cve-2026-43499-root-bakasu` | BakaSU 环境适配的 root 守护进程（与 App 资产同文件） | `6f096da08f853c91d72f` |
| `su_daemon_bakasu.c` | 上述守护进程源码（= `fusion-s24u/src/su_daemon.c` + 小补丁：loader 环境变量传递、ksud 前台运行修 verify 竞态，diff 23 行） | `359907f7441d9d745993` |
| `BAKASU_SAMSUNG_PORT_NOTES.md` | 移植完整记录（含构建、使用、限制） | `691ddbc7a9ff0850ed04` |

> 内核模块 `android14-6.1_kernelsu-e3q-S9280ZCS6DZH3-samsung-35171.ko`（484,912 B，`module_layout` CRC `0xea759d7f`）按本仓库 `.gitignore`（`*.ko`）惯例不入库；可由 `BakaSU-S9280/scripts/build-samsung-module.sh`（DDK `ghcr.io/ylarod/ddk-min:android14-6.1-20260313`）重建，且已内嵌于上面的 ksud 中。

## App 集成

RootMyS24 **v3.5.0-beta.185** 起内置：设置 →「BakaSU 内核（实验）」（载荷 `ksud-bakasu-dzh3` + `cve-2026-43499-root-bakasu` + BakaSU 管理器 APK）。

本机命令行使用流程（`bakasu_dl/scripts/`，每次开机重跑）：

```bash
./scripts/01-exploit.sh     # CVE-2026-43499 临时 root（屏幕保持熄灭，约 1–3 分钟）
./scripts/02-late-load.sh   # late-load 加载 + 完整安装（约 10 秒）
```

## 已知限制

- `selinux_hide` feature 不可用（依赖 live patch_text，被 RKP 禁止；日志一条 `Failed to set feature selinux_hide`，不影响 root）；
- 内核 full_version 显示 `v4.1.0-unknown-dirty@BakaSU`（git tag 问题，纯显示）；
- 机器上并存 KernelSU 管理器 v3.3.0（32601）时会提示版本不匹配，以 BakaSU 管理器为准；
- BakaSU 管理器提示升级 beta 35229：**不要升级**（内核按 35171 对齐）；
- 回滚：管理器装回 `ReSukiSU_v4.1.0_34893`（APK 在本机 `bakasu_dl/`）；内核侧重启即恢复干净。

## 证据（本机 `bakasu_dl/logs/`，含序列号，未入库）

- `lateload-20261017-123517.log`：`ksud staged` → `kernelsu.ko loaded successfully`（退出码 0）→ 验证全绿；
- `kmsg-20261017-115030.log`：`Samsung KDP task-scoped credential and native PGD path enabled`、`Samsung DEFEX credential synchronization ... enabled`、`Samsung setresuid kretprobe registered`、`Samsung sucompat kprobes registered`；
- `last_kmsg-*.log`：适配前 RKP/KDP 崩溃对比（排查用）。
