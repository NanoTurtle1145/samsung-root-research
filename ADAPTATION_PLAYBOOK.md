# 适配流程总结（历代复盘）

> 把"已验证的参考 exploit"移植到新固件的完整套路。这份是 `ADAPTATION_GUIDE.md`（DZF2 那一代的逐坑记录）的**跨代归纳版**：
> 规则、流水线、历代结果、失败分类、以及还没做完的部分。

---

## 一、三条不变规则

| 规则 | 含义 | 依据 |
| --- | --- | --- |
| **按内核构建定标** | 载荷与 `target.h` 对应的是**内核镜像**，不是机型 | 跨国行/港版同为 DZF2，`kmalloc_caches` 分别是 `0x0176cbb8` / `0x0176c6f8` |
| **S24 全系同构建通用** | S9210 / S9260 / S9280（e1q/e2q/e3q）软件通用，**同一构建号跨机型、跨地区（外版内）都能用** | 云端实测：S9280 与 S9210 的 DZH3 都用国行 DZF2 载荷成功 |
| **国行与外版不通用** | 只分「国行」「外版」两套；港台与欧美外版之间可互串 | 同上 |

推论：**判断能不能用，只看构建号**（固件串后 4 位），不看机型。App 从 v3.2.1 起启动前会校验这一点。

> ⚠️ **2026-11-01 修正（CZC1 定标实测）**：构建号**不唯一标识镜像**。CZA1（S9280，2026-01-15 构建）、
> CZC1（S9260，2026-03-12）、CZD2（S9210，2026-04-08）内核串里都是 `31999054`，但 CZC1/CZD2 符号表
> **100,754 项 100% 同址**，而 CZA1 与之**不同址**（text ≈ +0x800、data ≈ +0x10000）。
> 所以「同构建号可互串」只在**镜像确实相同**时成立；可靠判据是 `llvm-nm` 比符号地址，而不是看构建号。
> 详见 `RESEARCH_INDEX.md` §1h、`devices_ports/s9260_czc1_analysis.md`。

---

## 二、标准流水线（7 步）

### 阶段 0：情报
收集：固件串（`S9280ZCS6DZH3`）、内核版本（`6.1.145-android14-11-3254743`）、bootloader、安全补丁、机型代号（`e3q`）。
来源：设置 → 关于，或 App 日志头部（`◆ 设备/系统/固件/指纹`）。

### 阶段 1：取内核镜像
```sh
# AP 四件套（AP/BL/CP/CSC），从 AP 里解出 boot 分区
# AP 是 LZ4 tar，需按条目偏移提取；boot 再用 magiskboot 拆出 kernel
# 内核本身可能还是 LZ4 压缩的
```
关键一步：**恢复带符号的 ELF** —— `vmlinux-to-elf`，没有符号后面无从定标。

### 阶段 2：定标（生成 target.h）
逐个符号对比参考 target.h（通常拿最接近的已有目标做基线）：

```sh
llvm-nm vmlinux_dzh3.elf | grep -E "kmalloc_caches|init_task|nfnetlink_log|pipe_fcntl"
```

需要对齐的量（按重要性）：
- `KMALLOC_CACHES_OFF`（页面/管道 oracle 的锚点）
- `SLIDE_NFULNL_LOGGER_OFF`（KASLR slide 预判）
- `INIT_TASK_OFF` / `ROOT_TG_OFF` / `SYSCTL_BOOTID_OFF`
- `ASHMEM_MISC_FOPS_OFF`、`P0_ORACLE_PROBE_OFFSET`、`P0_KERNEL_PHYS_LOAD`

### 阶段 3：生成 KASLR 指纹
```sh
perl generate_p0_fingerprint.pl <kernel_raw> 0x1f0000 p0_fingerprint_<build>.h
# 32 行 × 8 qword；判据是设备实测命中数（DZF2 时 32/32）
```

### 阶段 4：构建
```sh
ANDROID_NDK_HOME=.../android-ndk-r29 TARGET=<target> make release   # App 用
ANDROID_NDK_HOME=.../android-ndk-r29 TARGET=<target> make stable    # 真机稳版
# 产物固定 104128 B（大小受限），与 App 资产一致
```

### 阶段 5：真机验证（按阶段地图逐行核对）
```sh
adb shell 'cd /data/local/tmp && \
  EXPLOIT_ATTEMPTS=24 P0_ATTEMPT_TIMEOUT_SEC=45 EXPLOIT_ATTEMPT_TIMEOUT_SEC=120 \
  CVE43499_ROOT_HELPER=/data/local/tmp/cve-2026-43499-root \
  LD_PRELOAD=/data/local/tmp/cve-2026-43499 /system/bin/sh -c true'
```
阶段地图（每行代表一个里程碑，卡在哪一行一目了然）：
```
[+] slide-kaslr-ok              ← KASLR 恢复
[*] fresh physrw pipe page      ← 管道内存就绪
[*] mm leaked=… object_index=N  ← mm_struct 泄漏
[*] sk_buff reclaim sends=16/16 ← SKB 回收
[*] kernel page prepare …       ← 可控内核页
[*] app fops slide route …      ← fops 路由（竞态，概率性触发）
[*] cfi write/read ret=35       ← 任意读写打通
[*] pipe caches … selected=…    ← kmalloc 缓存定位
[*] phys step pipe probe …      ← pipe_buffer 定位
[*] root umh result … socket=1  ← ★ root 成功
[+] exploit completed
```

### 阶段 6：回馈社区
提交到 [Root-My-Galaxy-Payloads](https://github.com/BuSung-dev/Root-My-Galaxy-Payloads)：
`src/targets/<target>/`（target.h + p0_fingerprint.h + README）、`artifacts/<target>/cve-2026-43499-app.so`、
`kernelsu/`（ksud + .ko）、`support/targets-v3.json`、`docs/SM-<机型>-<构建>.md`。

---

## 三、历代目标与结果

| 目标 | 内核 | 结果 | 备注 |
| --- | --- | --- | --- |
| S9280 国行 DZF2 | 6.1.145 | ✅ 基线，已实测 | 首个完成目标，坑最全 |
| S9280 国行 DZG1 | 6.1.145 | ✅ 并入 DZF2 载荷 | 同系偏移，直接可用 |
| S9280 港台 CZA1 | 6.1.128 | ✅ 已定标 | 与国行 CZA1 数据段差 +0x10000 |
| S9280 国行 CZA1 (CHC) | 6.1.128 | ⚠️ 定标完成但实测卡在 P0 泄漏 | 见"失败分类" |
| S9280 港台 DZE2 | 6.1.145 | ✅ 已实测 | 港台共用 |
| S9210 国行 BYH7 | 6.1.99 | ⚠️ 定标完成，待真机 | One UI 7 |
| S25 国行 CZG1 | 6.6.98 | ⚠️ 定标完成 | 关键差异：`struct page` slab_cache 偏移 0x08，KSU 用 6.6 模块 |
| **S9280 / S9210 国行 DZH3** | 6.1.145 | ✅ **云端实测成功**（用 DZF2 载荷） | 未做独立定标，属"运气可用" |
| 台版 S9260 DZG1 | 6.1.145 | ✅ 单设备实测（用港台 DZE2 载荷） | issue #3 |
| **外版 S9260 CZC1** | 6.1.128 / 31999054 | ⚠️ 定标完成，待真机 | issue #6；2026-11-01 独立定标（`e2q-S9260ZHS5CZC1`，载荷 104,128 B 已构建） |
| Z Fold6 国行 F9580 | 同 GKI | ✅ 社区实测（共用 DZF2） | — |

> "运气可用"= 构建号不同但偏移足够接近，能跑通；**不代表可以长期依赖**（见下一节）。

---

## 四、失败分类（来自云端 87 条真实日志）

| 类别 | 特征 | 性质 |
| --- | --- | --- |
| **未进入 exploit** | 无 `exploit attempt=`；多因 Shizuku 未启动 / 无线调试未连 | 环境问题，**不是利用失败**（统计已单列，不计成功率） |
| **P0 泄漏失败** | `pipe KernelSnitch sk_buff page leak failed`，30~60 次全一样 | 载荷与内核不匹配（如 CZA1 国行、CZC1 外版） |
| **physrw 建立不了** | `app fops slide triggered=1 verified=0 step=8` + `pipe physrw done=0` | **开机运气**：分配器没给出可配对的页 → 这次开机怎么试都不行，**重启换一次开机** |
| **竞态没触发** | `triggered=0` | 概率性，重试即可 |
| **physrw 挂住** | 走到 `fresh physrw pipe page` 后无输出，耗到 15 分钟超时 | 需看门狗主动中止重试（待做） |
| **模块/环境** | `wait_requeue_pi ret=-1 errno=110` | futex 等超时，多见于非 S24 载荷 |

**结论**：成功率波动主要来自"physrw 能不能建立"，而不是"竞态运气"。所以**连续多次卡在 `verified=0 step=8` 时，重启比继续重试有效**。

---

## 五、可复用的四个坑（已填）

1. **F_SETPIPE_SZ EPERM = 配额污染**：残留 keeper 进程握着已扩容管道。先查同 uid 残留进程，再怀疑内核。
2. **worklist 孤儿 work**：往共享 worklist 注入前**重查是否仍为空**，被真实 work 占用就回滚放弃。屏幕亮着=显示驱动活跃=必中，所以运行期间熄屏。
3. **SELinux 反复**：exploit 置 0 → late-load 后 KernelSU 恢复 Enforcing → su socket 断开属正常。
4. **模块选型**：国行普通 GKI `android14-6.1_kernelsu.ko` 可加载；kdp 变体是绕 Samsung KDP/RKP/DEFEX 的备选。**ksud 内嵌模块**，必须与目标 vermagic 匹配。

---

## 六、待办

- [ ] **DZH3 独立定标**（当前靠 DZF2 载荷"运气可用"；用户主力机就是这版）
- [x] **CZC1 外版定标**（issue #6）——2026-11-01 完成：`e2q-S9260ZHS5CZC1`（模板 CZD2，内核 100% 同址），载荷 104,128 B 已构建，待真机验证
- [ ] CZA1 国行 P0 泄漏失败定位
- [ ] physrw 卡死看门狗（App 侧，替代 15 分钟干等）
- [ ] ksud 升级到 v3.3.0（见 `KSUD_UPGRADE.md`）
