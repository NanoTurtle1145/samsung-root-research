# V2111 (vivo Y21 2021) CVE-2026-43499 可行性评估

> 分析日期：2026-08-22
> 固件：`PD2139F_EX_A_36.22.2-update-full_1671788190.zip`（vivo 印度官网，MD5 校验通过）
> 分析产物：`~/下载/PD2139F_unpacked/boot_extract/vmlinux.elf`（64,850 符号）

---

## 〇、结论先行

**漏洞疑似存在，但利用链需大幅重写，可行性中等偏低。**

三个关键判断：

1. **内核 rtmutex 是 5.x rbtree 后移版**（不是 4.19 上游的 plist 版），与 6.1 同源
2. **`remove_waiter` 反汇编与 CVE-2026-43499 漏洞模式一致**（误用 current 而非 waiter->task 清 pi_blocked_on）
3. 但整条 exploit 链（KASLR 恢复 / struct page / pipe 物理读写 / fops 定位 / workqueue 注入）全部绑定 Samsung 6.1，**需针对 4.19 重做**

---

## 一、设备与固件确认

| 项 | 值 |
|---|---|
| 型号 | V2111 = **vivo Y21 (2021)** |
| 固件型号 | PD2139F（`PD2139F_EX_A_36.22.2`，海外版 EX） |
| SoC | **MediaTek Helio P35 (MT6765)** |
| Android | 12.0.0（SP1A.210812.003） |
| 安全补丁 | 2022-12 |
| 内核 | **Linux 4.19.191**-gd3561e24e2af-dirty（clang 11.0.1，SMP PREEMPT，2022-12-15 编译） |
| boot | Android bootimg v2，kernel 0x40080000，gzip 压缩 |

> 注意：之前下载的 `Vivo_Y21_PD1309CW_MT6580` 是 2016 年初代 Y21（MT6580 32 位），**型号不符已弃用**。

---

## 二、漏洞面判定（关键发现）

### 2.1 rtmutex 是 5.x rbtree 后移版

4.19 上游 rtmutex 用 **plist**（prio list）；但本内核存在：

```
rt_mutex_enqueue        (0xffffff800812142c)   ← 5.x rbtree API
rt_mutex_enqueue_pi     (0xffffff80081214dc)
rt_mutex_wait_proxy_lock (0xffffff800812130c)   ← 5.x proxy lock API
rt_mutex_cleanup_proxy_lock
rb_erase_cached
```

这些是 **Linux 5.15+ rbtree rtmutex** 的 API。vivo 将新版 rtmutex 后移到 4.19——**与 S24 6.1 的 rtmutex 代码同源**，CVE-2026-43499 的漏洞路径在结构上成立。

### 2.2 remove_waiter 反汇编 = 漏洞模式

`remove_waiter` @ `0xffffff800812115c`，关键指令：

```asm
; x19 = lock, x22 = waiter, x20 = current (SP_EL0)
0x117c: ldr x23, [x19, #0x10]      ; owner
0x1184: ldr x8, [x23, #0x38]       ; owner->pi_blocked_on
0x1188: cmp x8, x19
0x1194: mrs x20, SP_EL0            ; current
0x1198: add x21, x20, #0x83c       ; &current->pi_lock
0x11a0: bl _raw_spin_lock
0x11a4: ldr x8, [x22]              ; waiter list
0x11b8: bl rb_erase_cached         ; 从等待树移除 waiter
0x11c4: str xzr, [x20, #0x860]     ; ★ current->pi_blocked_on = NULL
0x11c8: bl _raw_spin_unlock
...
0x11e8: ldr x8, [x22, #0x18]       ; waiter->task 只被读用于 prio 链
```

**关键观察**：`pi_blocked_on` 清零用的是 `[x20, #0x860]`（**current**），整个函数内**没有** `str xzr, [waiter->task->pi_blocked_on]` 的序列。

对照 CVE-2026-43499 漏洞语义：
- 正确路径：清 `waiter->task->pi_blocked_on`
- 漏洞路径：误用 `current->pi_blocked_on = NULL`（x20+0x860），waiter 任务残留悬垂指针 → 内核栈 UAF

`task_blocks_on_rt_mutex`（0xffffff8008120f30）中同样出现 `[x23, #0x860]`（x23 即 current 路径），偏移 0x860 与 `task_struct.pi_blocked_on` 一致。

### 2.3 触发路径完整

```
futex_requeue (0xffffff800815f82c)
  → rt_mutex_start_proxy_lock (0xffffff80081210f0)   ← FUTEX_CMP_REQUEUE_PI 路径
  → rt_mutex_wait_proxy_lock / proxy 语义存在
```

PI futex 链构造所需的 `futex_lock_pi` / `futex_requeue` / `cmpxchg_futex_value_locked` 全部存在。

---

## 三、移植障碍清单（每项都要重做）

现有 exploit（fusion-s24u / Root-My-Galaxy）以下假设全部按 Samsung 6.1 定制：

| 环节 | Samsung 6.1 假设 | 4.19 (MT6765) 现状 | 工作量 |
|---|---|---|---|
| KASLR 恢复 | p0 oracle / tracefs 泄露 / `slide_logger` 等 Samsung 符号 | KASLR 已开（`kaslr_early_init` 存在），但泄露路径未知，需新找 | **高** |
| struct page 布局 | `STRUCT_PAGE_SIZE=0x40` 等四项 | 4.19 的 struct page 布局不同，需 BTF/手工推导 | 高 |
| pipe 物理读写 | 4K 页内 pipe_buffer 特征匹配 | 4.19 pipe 结构不同（无 anon_pipe_buf_ops 符号） | 高 |
| fops / CFI | misc_fops 定位 + CFI 验证 | 4.19 无 CFI（SCS 时代前），fops 结构不同 | 中 |
| 物理内存映射 | `phys_offset=0x80000000` `kernel_phys_load=0xa8000000` | MT6765 内存映射不同，需实测 | 中 |
| workqueue 注入 | Samsung 符号 + worklist 布局 | 4.19 workqueue 结构差异 | 高 |
| KernelSU late-load | Samsung 模块加载 | 4.19 + MTK 可加载 ko，但路径不同 | 中 |
| **BTF** | 6.1 有 BTF | **4.19 无 BTF**（readelf 无 BTF 段）→ 结构体偏移全靠人工 | 全局 |

> 无 BTF 是最大工程障碍：所有结构体偏移（task_struct/pipe_buffer/rt_mutex_waiter/work_struct）需逐个从反汇编 + kallsyms 推导。

---

## 四、可行性结论与建议

### 可行点
- 漏洞代码模式与 6.1 同源（rbtree rtmutex 后移 + remove_waiter 误用 current），**研究价值高**
- 64,850 符号可恢复，`init_task` / `call_usermodehelper` 均存在
- 触发路径（futex_requeue → proxy lock）完整

### 不可行点（当前状态）
- 整条利用链按 Samsung 6.1 硬编码，直接跑必然失败
- 4.19 无 BTF，移植需要"从零推导"级别的工程量
- KASLR 泄露路径在 MTK 4.19 上是全新问题（Samsung 的泄露方法不可复用）

### 建议路径（如要推进）
1. **先证漏洞**：手工构造 PI futex 三线程链，验证 waiter 任务是否残留悬垂 `pi_blocked_on`（不需要完整 exploit，纯触发验证）
2. **找 KASLR 泄露**：4.19 + MTK 的可用泄露面（/proc 接口、sysfs、tracefs、dmesg 时序）
3. **逐环节移植**：struct page → pipe 原语 → fops → workqueue，无 BTF 前提下以反汇编为准

### 工作量评级
**比 BYH7 移植难一个数量级**。BYH7 至少是同内核代（6.1）、有 BTF、复用整条链；V2111 是跨内核代 + 无 BTF + 全链重写。除非 V2111 是唯一目标且时间充裕，否则不建议作为主线。

---

## 附：关键符号表

```
remove_waiter           0xffffff800812115c
rt_mutex_wait_proxy_lock 0xffffff800812130c
rt_mutex_start_proxy_lock 0xffffff80081210f0
rt_mutex_enqueue_pi     0xffffff80081214dc
rt_mutex_slowlock       0xffffff8009226678
task_blocks_on_rt_mutex 0xffffff8008120f30
futex_requeue           0xffffff800815f82c
futex_lock_pi           0xffffff80081602b4
rb_erase_cached         0xffffff800921614c
init_task               (kallsyms 有，ELF 未导出)
call_usermodehelper     (kallsyms 有，ELF 未导出)
KASLR 基址              0xffffff8008080000
```
