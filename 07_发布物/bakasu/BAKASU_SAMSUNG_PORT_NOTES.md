# BakaSU 内核移植到 Samsung SM-S9280 (DZH3) — 成功记录

日期：2026-10-17
目标设备：SM-S9280，固件 `S9280ZCS6DZH3`，内核
`6.1.145-android14-11-3254743-abS9280ZCS6DZH3`

## 结论

BakaSU v4.2.0-rc3 管理器 + 按 DZH3 精确构建的 BakaSU 内核模块（含三星
KDP/RKP/DEFEX 适配）已在本机 **真机验证成功**：

- late-load 加载成功，`/proc/modules` 中 `kernelsu` Live；
- `ksud debug info`：version `35171`、`lkm: true`、`late_load: true`；
- BakaSU 管理器显示 **「工作中」/「LKM」/「越狱模式」**，
  内核驱动版本 `35171/5` 与管理器 `35171/4` 匹配；
- 识别到原有 10 个超级用户、9 个模块，SELinux 强制执行下正常。

## 实现要点（对 BakaSU 源码的改动）

分支：`/home/nt/项目/bakasu`，commit `02a11f6e` (`samsung-port`)

1. **KDP 凭据**（`kernel/compat/samsung_kdp.c`）
   - 用 `prepare_ro_creds` + `kdp_assign_pgd` 做 root workqueue 上的
     task-scoped cred 安装；
   - `kdp_usecount_dec_and_test` + `__put_cred` 释放 KDP 保护的 cred；
   - 通过 `ksu_resolve_symbol_for_functable_hook` 运行时解析（无需 DDK 导出 CRC）。
2. **DEFEX**（`kernel/compat/samsung_defex.c`）
   - kprobe `task_defex_enforce`，仅对 `current`、uid 0、KSU 域放行；
   - UID 切换后同步 DEFEX 凭据三元组。
3. **RKP / no-patch-text**
   - `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT`：`ksu_patch_text()` 直接返回
     `-EOPNOTSUPP`，避免 fixmap 写内核代码/只读表触发 RKP RAMDUMP；
   - `ksu_syscall_table_hook()` 改为返回 int，只有实际写入成功才把
     dispatcher 记为已安装（失败时 `ksu_dispatcher_nr = -1`）。
4. **RKP 回退 hook**（`kernel/hook/syscall_hook_manager.c`）
   - dispatcher 不可用时：
     - `__arm64_sys_setresuid` kretprobe → 管理器 fd 下发；
     - execve/newfstatat/faccessat/statx/faccessat2 地址级 kprobe →
       sucompat；
     - 用 `syscallno = -2` 防止嵌套重入。
   - 注意：BakaSU 的 `ksu_handle_setuid(new_uid, old_uid)` 是两参数语义，
     回退里必须调它（不要调三参数的 `ksu_handle_setresuid`）。
5. **ksud 用户态 staging**
   - `utils::stage_daemon_from("/data/local/tmp/.ksud-stage")` 在加载模块
     **之前**把 ksud 落到 `/data/adb/ksud`（模块加载后进程上下文变为
     `u:r:ksu:s0`，再写会被拒绝/DEFEX kill）；
   - 加载完成后调用 `utils::finish_install()` 解压 assets/建链接；
   - `scripts/02-late-load.sh` 会在运行前自动把 ksud 复制到暂存路径。
6. **版本对齐**：Kbuild 增加 `KSU_VERSION_OVERRIDE`；本构建用
   `KSU_VERSION_OVERRIDE=35171` 与 BakaSU 管理器 v4.2.0-rc3 对齐。
7. **UAPI 对齐**：管理器用 `isFullFeatured = 是管理器 && 内核UAPI == 管理器UAPI`
   决定是否显示「超级用户/模块」页面。BakaSU HEAD 是 UAPI 5，而 rc3 管理器是 4，
   导致模块页被隐藏（表现为「没法安装模块」）。UAPI 5 只新增了 EVENT_SERVICES
   事件、向后兼容，因此构建时用 `KCFLAGS=-DKSU_FORCE_UAPI_VERSION=4` 让内核
   按 4 上报即可（已在 uapi/supercall.h 加了覆盖开关）。

## 构建（可复现）

```bash
cd /home/nt/项目/bakasu_dl
./scripts/build-samsung-module.sh
```

产物：

- `release/android14-6.1_kernelsu-e3q-S9280ZCS6DZH3-samsung-35171.ko`
  （vermagic 精确 DZH3，`__versions` 含 `module_layout` CRC `0xea759d7f`）
- `release/ksud-e3q-S9280ZCS6DZH3-samsung-35171`（内嵌上述模块）

DDK 镜像：`ghcr.io/ylarod/ddk-min:android14-6.1-20260313`（docker）

## 每次开机使用流程（当前为 late-load 越狱模式，不写 boot）

```bash
cd /home/nt/项目/bakasu_dl
./scripts/01-exploit.sh     # CVE-2026-43499 拿临时 root（屏幕保持熄灭，约 1-3 分钟）
./scripts/02-late-load.sh   # 加载 BakaSU 内核模块 + 完整安装（约 10 秒）
```

完成后打开 **BakaSU 管理器**（`com.resukisu.resukisu` v4.2.0-rc3）即可看到
「工作中 / LKM / 越狱模式」。重启后需重跑一次（与 RootMyS9280 的 per-boot
root 模型相同）。

## 已验证 / 已知限制

- ✅ 加载、fd 下发（管理器能拿到 ksu fd，`blocked by seccomp` 归零）、
  超级用户/模块识别、SELinux 强制下工作；
- ⚠️ `selinux_hide` feature 无法开启（依赖 live patch_text，三星 RKP 禁止），
  日志中会有一条 `Failed to set feature selinux_hide`；
- ⚠️ 内核 full_version 字符串仍是 `v4.1.0-unknown-dirty@BakaSU`（git tag/深度
  问题），不影响功能；
- ⚠️ 机器上同时装着 KernelSU 管理器 v3.3.0（32601），它会提示版本不匹配；
  以 BakaSU 管理器为准，可自行卸载旧管理器；
- ⚠️ BakaSU 管理器提示可升级到 beta 35229：不要升级，当前内核按 35171 对齐；
- 回滚：`adb install -r -d bakasu_dl/ReSukiSU_v4.1.0_34893_installed-rollback.apk`
  （管理器），内核侧重启即恢复干净。

## 关键日志/证据

- `logs/lateload-20261017-121*.log`：`ksud staged ... loaded successfully`
- `logs/kmsg-20261017-115030.log`：Samsung KDP/DEFEX 初始化、dispatcher
  不可用回退、sucompat kprobes/setresuid kretprobe 注册
- `logs/last_kmsg-*.log`：移植前崩溃对比（RKP/KDP）
