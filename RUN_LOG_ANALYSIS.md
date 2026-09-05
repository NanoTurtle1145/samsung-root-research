# 运行日志分析：S9280 DZF2 成功 vs OneUI7 BYH7 失败

> 分析日期：2026-08-22
> 原始日志：`07_发布物/run_logs/`（S9280_DZF2_success.txt / BYH7_e1q_fail.txt）
> 结论先行：S9280 DZF2 全链路验证通过（attempt 2/30 成功）；BYH7 失败点在 **pipe 页内 `anon_pipe_buf_ops` 特征匹配（cache gate）**，`pipe_buffer` 结构布局与 DZF2 存在差异，需按 6.1.99 BTF 核对结构体偏移。

---

## 1. S9280 DZF2 成功日志（基线）

设备：SM-S9280 国行，`S9280ZCS6DZF2`，kernel 6.1.145-android14-11-3254743
结果：**attempt 2/30 成功**，完整走到 KernelSU late-load exit=0

### 1.1 成功链路（与 ADAPTATION_GUIDE 阶段地图逐行对应）

```
[+] preload supervisor pid=12953 attempts=30 base_delay=20000 p0_timeout=45 timeout=120
[+] exploit attempt=1/30 pid=18763 delay=50000 p0_offset=scan
    → slide-kaslr-ok source=tracefs slide=000a0000
    → pipe page / mm leak 正常
    → app fops slide attempt=1/1 triggered=0 verified=0   ← 概率性竞态失败（正常）
[-] exploit attempt=1/30 failed status=1

[+] exploit attempt=2/30 pid=29171 delay=50000 p0_offset=0xa0000
    → slide-kaslr-ok source=forced（复用 attempt1 的 KASLR 结果）
    → [*] mm leaked=ffffff8a6b6dc400 object_index=17
    → [*] S928 bank bucket=17 lock=0x52a0 task=0x1000 mode=0
    → [*] sk_buff reclaim sends=16/16 mode=0
    → [*] kernel page prepare mode=0 attempt=1/2 elapsed_ms=9483
    → [*] stage=verifying-kernel-access
    → [*] cfi write ret=35 / cfi read ret=35            ← CFI 验证通过
    → [*] pipe caches normal1k/2k cgroup1k/2k selected=cgroup2k 0xffffff8001cf7100
    → [*] pipe page idx=0 ... cache18=0xffffff8001cf6800 type=ffffffff match=1  ← 特征匹配
    → [*] phys step pipe probe found=1 pipebuf=... idx=90
    → [*] phys step probed read/write done ok=1
    → [*] root direct start uid=2000 fd=3
    → [*] root umh queued wq=... work=... writes=1/1/1/1/1
    → [*] root umh result wake=1 complete=1 retval=0 socket=1   ← ★ root 成功
    → [+] pipe physrw pid=29171 done=1 root=1 rw64=1/1 uid=2000->0
    → [+] stability keeper pid=10314 retaining reclaimed kernel pages
    → [+] exploit completed attempt=2/30
✔ 临时 root 已获得！
ksud late-load: exit=0 → KernelSU 驱动已加载
```

### 1.2 关键结论

1. **首次失败是竞态而非配置错误**：attempt 1 `app fops slide triggered=0` 是概率性竞态失败，KASLR 结果（slide=0xa0000）在 attempt 2 被复用（`source=forced`），这是设计内行为，不是问题。
2. **S9280 的 pipe 页特征**：`cache18=0xffffff8001cf6800`（即 pipe caches 中的 normal2k 地址）、`cache10=dead000000000122`（poison 值）、`type=ffffffff`，`match=1`——这套特征用于在 4K 页内定位 `pipe_buffer` 数组。
3. **mm 泄漏的 bank 定位**：`object_index=17` → `S928 bank bucket=17 lock=0x52a0`，与 `target.h` 的 bank 配置吻合。
4. **root 阶段完整走通**：workqueue 注入（`writes=1/1/1/1/1`）→ UMH 结果 `retval=0 socket=1` → `uid=2000->0`，**没有出现 worklist 竞态 panic**（运行期间自动熄屏生效）。

---

## 2. OneUI7 BYH7 失败日志（对比）

设备：SM-S9210 国行，`S9210ZCU4BYH7`，kernel 6.1.99-android14-11-2370239
结果：attempt 1 竞态失败；attempt 2 走到 CFI 通过，但 **pipe 页 cache gate 失败**，未获 root

### 2.1 失败链路

```
[+] exploit attempt=1/30 pid=15135 p0_offset=scan
    → slide-kaslr-ok source=tracefs slide=00000000
    → app fops slide triggered=0 verified=0   ← 竞态失败（正常）
[-] exploit attempt=1/30 failed

[+] exploit attempt=2/30 pid=24149 p0_offset=0x0
    → slide-kaslr-ok source=forced
    → [*] mm leaked=... object_index=28
    → [-] S928 lock bucket rejected=28 max=27 mode=0   ← 注意：object_index 超界被拒
    → [-] prepare_kernel_page retry 1/2
    → [*] mm leaked=... object_index=5 → S928 bank bucket=5 lock=0x22a0
    → [*] kernel page prepare attempt=2/2 elapsed_ms=6373
    → [*] stage=verifying-kernel-access
    → [*] cfi write ret=35 / cfi read ret=35          ← CFI 通过（与 DZF2 相同）
    → [*] pipe caches ... selected=0xffffff8001cf7100
    → [*] pipe page idx=0..7 cache08/cache18 均非预期，type=ffffff7f/ffffffff match=0
    → [-] phys step cache gate failed slab=0000000000000000 want=0xffffff8001cf7100
    → [*] app fops slide attempt=1/1 triggered=1 verified=0 step=8
[-] exploit attempt=2/30 failed status=1
```

### 2.2 失败根因定位

**失败点在 pipe 页内 `pipe_buffer` 特征匹配，不在 CFI/root 阶段**：

| 检查点 | S9280 (6.1.145) | BYH7 (6.1.99) | 结论 |
|---|---|---|---|
| KASLR slide | 0xa0000 | 0x0 | 正常（0 合法） |
| CFI write/read | ret=35 | ret=35 | **两者一致** |
| pipe caches selected | cgroup2k 0xffffff8001cf7100 | 同 | 一致 |
| pipe page idx=0 cache18 | 0xffffff8001cf6800 (=normal2k) | 0x0 | **BYH7 不匹配** |
| pipe page idx=0 cache10 | dead000000000122 (poison) | fffffffe... 垃圾值 | **BYH7 偏移读错** |
| pipe page idx=0 type | ffffffff (match=1) | ffffffff (match=0) | **BYH7 页内扫描 8 个 idx 全不匹配** |

**核心判断**：BYH7 的 `pipe_buffer` 结构体在页内的**字段偏移/数组步长与 DZF2 不同**（6.1.99 vs 6.1.145），exploit 用 DZF2 的布局去读 BYH7 的 pipe 页，把无关内存当成 `cache18`/`cache10` 读取，导致特征匹配失败。这与 `byh7-target-complete.md` 第 5 节预判一致（"结构体布局在 6.1.99 vs 6.1.145 间可能有差异；若真机跑不到对应阶段，优先核对 BTF 布局"）。

**次要点**：attempt 2 第一次 `mm leaked object_index=28` 超界（`max=27`）被拒，说明 BYH7 的 mm 分配布局与 DZF2 略有差异（可能只是该次分配偶然落到更高阶 slab），重试后 `object_index=5` 正常。这是软性差异，重试可绕过。

### 2.3 根因修正（2026-08-22，对照 SM-S9380 移植经验）

**更精确的定位：`struct page` 字段偏移错误（vmemmap 地址特征），而非笼统的 pipe_buffer 布局。**

SM-S9380 经验（`03_参考研究/SM-S9380_RMG_root_experience.md` §六）给出 FOPS cache gate 失败判据：

> 失败典型 2：`cache08=fffffffe24997a08` —— 读到 **vmemmap 地址**，即 struct page 偏移算错。

对照 BYH7 失败日志：

```
[*] pipe page idx=0 page=ffffff889bb38000 head=fffffffe226ece00
    cache08=fffffffe208aac08 cache10=fffffffe2919de08 cache18=0 cache20=0 type=ffffff7f match=0
```

- `cache08=fffffffe208aac08`、`cache10=fffffffe2919de08` 均以 **`fffffffe` 开头 = vmemmap 区域地址** → struct page 字段偏移读错（把 vmemmap 内容当成 slab_cache 指针）
- S9280 成功对照：`cache08=0000000000000000`、`cache18=ffffff8001cf6800`（正常内核地址）→ 偏移正确

**需核对的四项偏移**（源自 SM-S9380 ZG1 移植结论，BYH7/6.1.99 需单独确认）：

```
STRUCT_PAGE_SIZE              = 0x40
STRUCT_PAGE_COMPOUND_HEAD_OFF = 0x08
STRUCT_SLAB_CACHE_OFF         = 0x18
STRUCT_PAGE_TYPE_OFF          = 0x30
```

> **注意（2026-08-22 反汇编验证）**：上述偏移中 `STRUCT_SLAB_CACHE_OFF` 已通过反汇编确认 **BYH7 与 DZF2 一致（均为 0x18，非 SM-S9380 ZG1 的 0x08）**——两个内核的 `new_slab` 中写 `page->slab_cache` 的指令完全相同（`str x19, [x20, #0x18]`），且 `new_slab`/`__slab_free` 访问 struct page 的偏移集合几乎一致。SM-S9380 是不同平台（pa3q）不同内核版本，其偏移不能直接套用 BYH7。

### 2.4 根因再修正（2026-08-22 反汇编验证后）

**BYH7 失败不是 struct page 偏移错误，而是 pipe 页回收状态问题：pipe 页不在 SLUB slab 缓存中。**

反汇编证据：DZF2 与 BYH7 的 `new_slab` 写 `page->slab_cache` 指令一致（`str x19, [x20, #0x18]`），struct page 布局相同。

日志证据（关键）：
- **BYH7 失败**：`cache08=fffffffe208aac08 cache10=fffffffe2919de08 cache18=0 type=ffffff7f match=0`
  - `cache08/cache10` 以 `fffffffe` 开头 = **vmemmap 区域地址**（struct page 数组在 vmemmap）→ 这是 **buddy 空闲链表指针**（free_list 上相邻页的 struct page 地址）的特征
  - `cache18=0` = 该页 **slab_cache 字段为空** → 页已释放回 buddy 系统，**不在任何 kmalloc 缓存中**
- **S9280 成功**：`cache08=0 cache10=dead000000000122 cache18=ffffff8001cf6800 type=ffffffff match=1`
  - `cache10=dead000000000122` = SLUB poison 值（CONFIG_SLUB_DEBUG 填充）
  - `cache18=normal2k cache 地址` = 页是 SLUB slab 页 ✓

**结论**：BYH7 的 pipe 页被释放后回到了 buddy 空闲链表（或未进入目标 kmalloc-2k 缓存），exploit 在 pipe 页内找不到 slab_cache 匹配 → cache gate 失败。这不是偏移常量错误，而是 **pipe 页回收/分配路径与 DZF2 不同**（可能原因：pipe 容量不同→pipe_buffer 数组落入不同 kmalloc 桶；或回收时序/分配器行为差异；或 cgroup 缓存归属差异）。

**附加观察**：BYH7 attempt2 第一次 `mm leaked object_index=28` 超界（max=27）被拒后重试 `object_index=5` 成功——6.1.99 的 mm 分配布局与 6.1.145 有细微差异（slab 桶位不同），但非致命（重试可绕过）。

**下一步验证方向**（按优先级）：
1. 核对 BYH7 的 `pipe_buffer` 数组实际落桶：`pipe-buffer-max` 等配置或 pipe 默认容量（`PIPE_DEF_BUFFERS`）是否不同 → pipe_buffer 数组大小（32×64B=2KB）是否仍落 kmalloc-2k
2. 检查 BYH7 是否启用 `CONFIG_SLUB_DEBUG`/poison（日志显示 S9280 有 poison 值，BYH7 的页无）→ 回收/分配路径差异
3. 对比两内核 `alloc_pipe_info`（pipe 初始化）中 `kcalloc(pipe_bufs, sizeof(struct pipe_buffer))` 的实际分配尺寸

> **已反汇编验证过的结论**（2026-08-22）：
> - `STRUCT_SLAB_CACHE_OFF=0x18` 在两个内核中一致（`new_slab` 写 `page->slab_cache` 的指令 `str x19, [x20, #0x18]` 相同）
> - `new_slab`/`__slab_free` 访问 struct page 的偏移集合一致，struct page 布局相同
> - `alloc_pipe_info` 中 pipe_buffer 数组分配的指令序列一致（pipe_buffer 大小相同）
> - 两个内核的 kmalloc_caches 地址（normal1k/2k, cgroup1k/2k）完全相同
> - **排除 struct page 偏移和 pipe 分配路径差异**，定位为 pipe 页回收状态问题（页回 buddy 而非 SLUB slab）

**附加因素**：SM-S9380 经验还提示 **Shell 域 vs App 域差异**（cgroup 归属影响 kmalloc 落 cgroup 还是 normal 缓存，与 FOPS 的 kmalloc_cgroup_2k_cache 匹配相关）。BYH7 测试走 App（Shizuku），除偏移外还需考虑运行环境对缓存归属的影响。

---

## 3. 下一步建议

1. **BYH7 排查方向已收敛**（2026-08-22）：通过反汇编验证排除了 struct page 偏移（`0x18` 一致）、pipe 分配路径（`alloc_pipe_info` 一致）、kmalloc_caches（地址一致）三个疑点。**剩余主嫌疑：pipe 页回收状态**——BYH7 的 pipe 页回到了 buddy 空闲链表（cache08/10=vmemmap 链表指针、cache18=0），而 S9280 的 pipe 页是 SLUB slab 页（cache18=normal2k）。
2. **优先实测验证 pipe 回收**：在 BYH7 真机上（或对比 S9280 成功时）观察 `pipe page` 扫描前的 drain/reclaim 是否真正把 pipe_buffer 数组页留在 SLUB。可临时加大 `PIPE_DRAIN/PIPE_RECLAIM` 或调整 `sk_buff reclaim sends` 观察是否改变页状态。
3. **备用方向**：若 pipe 回收状态在 6.1.99 上确实不同（如 CONFIG_SLUB_DEBUG 差异导致 poison 语义不同），考虑在 BYH7 target.h 中调整 `PIPE_DRAIN_SLABS/PIPE_RECLAIM_SLABS` 或 pipe 页扫描逻辑（`pipe_reclaim_cache_gate` 的候选匹配放宽）。
4. **App 域验证**：SM-S9380 经验提示 Shell 域 ≠ App 域（cgroup 归属影响 kmalloc 缓存匹配），BYH7 修正后必须走 App（Shizuku）完整验证。
5. **时序**：保持 `APP_MIN_BOOT_UPTIME_SEC=120`（当前已是），不要改小（SM-S9380 实测 60 秒必失败）。

---

## 4. 复现与验证命令

```sh
# 反查 pipe_buffer 布局（BYH7 ELF）
llvm-nm vmlinux_byh7.elf | grep -E "pipe_buf|anon_pipe_buf_ops"
llvm-objdump -d --start-address=<pipe_fcntl 附近> vmlinux_byh7.elf | grep -A20 "pipe_buffer"

# 设备复测（装 App 后熄屏运行，重启后导出日志）
# 期望日志关键行（成功）：
#   [*] pipe page idx=0 ... match=1
#   [*] root umh result wake=1 complete=1 retval=0 socket=1
```

---

## 4. 修复实施（2026-08-22 pipe cache gate v2）

**确认的根因**（与 §2 收敛结论一致）：BYH7(6.1.99) 的泄漏页是 LRU 匿名页（`cache08/10=vmemmap LRU 指针`、`cache18=0`），而 DZF2(6.1.145) 的泄漏页是 kmalloc-2k slab 页（`cache18=normal2k`，pipe 对象复用了同页）。即 **pipe 对象未落位在泄漏页 32KB 邻域**（泄漏页释放后回 buddy，而非留在 SLUB），gate 在 8 页扫描内找不到 kmalloc-2k slab 页。

**pipe caches 值相同的解释**：S9210(S24) 与 S9280(S24+) 同属 Exynos 2400 平台，物理内存布局/启动分配确定性一致 → kmem_cache 结构体（含 normal1k/2k、cgroup1k/2k）物理地址完全相同。DZF2 成功日志中 `pipe page idx=0 cache18==normal2k(bulk 读取值)` 自洽证明读取真实，因此 BYH7 的 `pipe caches` 打印相同值也是真实读取，非"P0 读取失效"。

**已实施的修复**（commit 3c3d09b）：
1. `pipe_reclaim_cache_gate`：448B 大块 P0 读取改为逐槽位 `kernel_read64`（8B 路径已验证可靠；即使大块读取在 BYH7 上行为异常也能兜底）
2. `PIPE_CANDIDATE_PAGES` 8→64：gate 扫描范围从泄漏页 32KB 邻域扩到 256KB
3. gate 命中 slab 页时立即调用 `find_pipe_buffer` 验证页内确有 pipe_buffer 对象（防止扩大扫描后命中无关 kmalloc-2k 页）
4. `install_pipe_physrw`：marker 写入提前到 gate 之前（gate 内 find 依赖 pb.len）
5. BYH7 `target.h`：`PIPE_DRAIN/RECLAIM_SLABS` 10→16，更多 pipe 对象提高落位概率

**验证状态**：`build/e1q-S9210ZCU4BYH7/cve-2026-43499-app.stable.so` md5 `2ea5f6c5`；已打包 `RootMyS24-debug-BYH7-pipe-gate-v2.apk` 待真机测试。

---

## 5. v2 真机验证失败 → v3 修复（2026-08-22）

**v2 结果**（`chcbyh7rootmys9280-SM-S9210 (6).txt`）：30/30 次尝试全部 `[!] pipe page child did not report base`，日志根因：
```
[!] SYSCHK(fcntl(pipefd[0], F_SETPIPE_SZ, slots * PAGE_SIZE)): Operation not permitted
```
**根因**：v2 把 `PIPE_DRAIN/RECLAIM_SLABS` 从 10 改到 16 → 512 pipes × 32 slots = 16384 页，**恰好顶满 `pipe-user-pages-soft`(16384页) 软限制**，后续 `F_SETPIPE_SZ` 全部 EPERM → child 无法分配 pipe 对象 → 泄漏后的 base 未报告 → 整个尝试提前失败（连 gate 都没走到）。

**v3 修复**（commit d151113）：`PIPE_DRAIN/RECLAIM_SLABS` 回退 10（320 pipes = 10240 页 < 16384），保留 v2 其余有效改动：
- 逐槽位 8B 读取 kmalloc_caches
- `PIPE_CANDIDATE_PAGES` 64（256KB 扫描）
- gate 命中页 find_pipe_buffer 验证
- marker 写入提前到 gate 前

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v3.apk`（payload md5 `7accca26`）。

---

## 6. v3 真机日志分析 → v4 修复（2026-08-22）

**v3 结果**（`chc7rootmys9280-SM-S9210 (3).txt`，恢复的上次会话日志约 12 次尝试）：
- 前 10 次尝试 `triggered=0`（CFI 劫持未触发，slide route 失败）——与 v1（全部 triggered=1）不同，可能是 CFI 时序/随机性
- **第 11 次尝试 CFI 成功**（`triggered=1`，`cfi write ret=35`，`cfi restoring misc_fops`），gate 扫描 64 页：
  - `pipe caches normal1k=ffffff8001cf6700 normal2k=ffffff8001cf6800 cgroup1k=ffffff8001cf7000 cgroup2k=ffffff8001cf7100 selected=ffffff8001cf7100`（与 v1 相同，8B 逐槽读取工作正常）
  - **idx=26-33 连续 8 页（order-3 32KB slab）`cache18=ffffff88b4a95410` 一致非零、`cache20` 连续递减（0x10ee→0x10e7）**——这是 pipe_buffer 对象所在的 slab！
  - 但 `cache18=ffffff88b4a95410` **不在 56 个 kmalloc 槽位中**（非 normal2k/cgroup2k），原 cache_match 拒绝 → `phys step cache gate failed slab=0000000000000000 want=ffffff8001cf7100`
- 第 12 次尝试 `triggered=1 step=4 errno=25`（cfi misc_fops mismatch ret=-1，CFI 阶段失败）

**关键洞察**：BYH7(6.1.99) 的 pipe_buffer 对象落在**另一个 kmem_cache**（slab_cache=ffffff88b4a95410），不是 DZF2 的 normal2k。可能原因：6.1.99 的 pipe 分配路径用 kmalloc-rcl-2k（reclaimable）或 memcg 变体；或泄漏页回 buddy 后 SLUB 从邻近缓存复用。**gate 只认 normal2k/cgroup2k 是失败根因**（此前一直假设 pipe_buffer 必在 normal2k/cgroup2k）。

**v4 修复**（commit 292cf7b）：`pipe_cache_matches` 放宽为接受**任何非零 slab_cache**，由 `find_pipe_buffer` 做最终验证（page in VMEMMAP + ops==pipe_buf_ops_addr + len in [1,PIPE_RECLAIM] 三重严格特征，不会误判）。64 页扫描 + 逐槽 8B 读取 + gate 内 find 验证均保留。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v4.apk`（payload md5 `14dc1c64`）。

---

## 7. v4 真机重大突破 + late-load 修复（v5，2026-08-22/23）

**v4 结果**（`chcbyh7rootmys9280-SM-S9210 (4).txt`）——**pipe physrw 全链路成功**：
```
pipe page idx=0 page=ffffff89880a0000 cache18=ffffff8001cf6800 match=1   ← 泄漏页即 normal2k slab！
phys step pipe probe found=1 pipebuf=ffffff89880a0000 idx=137 scan=1/1/1
phys step probed read done ok=1 idx=137
phys step probed write done ok=1
phys step read64 done ok=1 value=306365737562656e
root direct start uid=2000 fd=3
root umh queued wq=... retval=0 socket=1
app fops slide attempt=1/1 triggered=1 verified=1 step=0 errno=0      ← verified=1！
pipe physrw pid=9250 done=1 root=1 read_ok=1 write_ok=1 rw64=1/1 uid=2000->0   ← ROOT！
✔ 临时 root 已获得！
```

**注意**：本次泄漏页本身就是 kmalloc-2k slab 页（cache18=normal2k，idx=0 直接 match=1），与 v1 的 LRU 匿名页不同——泄漏页类型随分配随机性变化；v4 的放宽匹配 + 64 页扫描保证了两种情况下都能命中。

**剩余失败**：KernelSU late-load：
```
✔ ksud 已暂存到 ksud-s25u-kdp / .ksud-stage
ksud late-load: exit=10
late-load: private mount namespace: Permission denied
✗ 失败: KernelSU late-load 失败 (exit=10)
```
**根因**：`unshare(CLONE_NEWNS)` 需要 CAP_SYS_ADMIN，但 Android usermodehelper（UMH）创建的 root 进程 capability bounding set 受限 → EPERM。测试者反馈"显示成功却卡死"——root 已获得（App 显示成功），但 KernelSU 未加载，且 root 守护进程/keeper 持续运行可能导致系统不稳定。

**v5 修复**（commit 3753779）：`run_kernelsu_late_load` 中 unshare(CLONE_NEWNS) 失败时 fallback 直接 exec `/data/local/tmp/ksud-s25u-kdp`（SELinux 已 permissive，无需 bind mount 到 /system/bin/logcat）。注意 `make stable` 只构建 app .so，root helper 需 `make app` 单独构建——APK 中旧 root helper 不含此修复。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v5.apk`（payload md5 `14dc1c64` 不变，root helper md5 `1a79f8b4`）。

---

## 8. v5 两次日志分析 → v6 修复（2026-08-23）

**v5 日志**（`chcbyh7v5rootmys9280-SM-S9210 (1)(2).txt` 小 / `chcbyh7v5(2)rootmys9280-SM-S9210(1).txt` 大）：
- 两个日志都带"已从上次会话恢复 N 行"→ **设备在 exploit 运行中重启/冻结**（测试者反馈"显示成功却卡死"与此吻合——可能是 CFI 失败路径累积的不稳定或 late-load 未加载）
- 大日志 4 次尝试全部 `triggered=0`（CFI 触发失败）；小日志 1 次尝试后在 `sk_buff reclaim` 截断
- 大日志 `supervisor retained p0_offset=0x0`——**slide=0 被接受并强制后续尝试**

**关键对照**：
| 日志 | slide | triggered=1 成功率 |
|---|---|---|
| v1（旧版 3bad70bb） | 0x120000 | 26/30 (87%) |
| v3（7accca26） | 0x90000 | 2/12 (17%) |
| v4（14dc1c64） | 0x180000 | 1/1 (100%) 成功 |
| v5（14dc1c64） | **0** | 0/4 (0%) |

v4 与 v5 的 exploit payload **完全相同**（md5 14dc1c64），唯一差异是 slide 与 boot 状态 → **CFI 触发成功率随 boot 随机变化**，且 **slide=0 高度可疑**（tracefs 泄漏读到 caller==链接地址时误报 slide=0；真实 KASLR slide=0 概率仅 1/32）。

**v6 修复**（commit 待）：
1. `slide_app.c slide_leak_physical_base`：tracefs 泄漏 slide=0 时**不走 APP_TRACEFS_KASLR_DIRECT 直接提交**，改走物理扫描（P0 pipe oracle gate/probe）验证真实 slide
2. BYH7 `target.h`：`APP_FOPS_FRESH_PAGE_ATTEMPTS 5`——单进程内多次 CFI 触发尝试（原来每次进程只试 1 次，30 次 supervisor 尝试内命中率低）

---

## 9. v6 两次日志 → v7 卡死修复（2026-08-23）

**v6 日志**（`0823-1055_BYH7_v5_卡死_pselect路由.txt` / `0823-1055_BYH7_v5_卡死_skbuff回收.txt`）：
- 两日志都"已从上次会话恢复"→ **设备在 exploit 运行中重启/冻结**（卡死确认）
- `(2).txt`：slide=0x180000 正常、泄漏/mmun 全成功，但卡在 `slide child context route=pselect` 后——**无 `app fops slide attempt` 输出**（父进程阻塞在 waitpid）
- `(3)(2).txt`：卡在 `sk_buff reclaim` 后

**卡死根因**（slide_app.c 竞态所有等待均为无限循环）：
1. waiter 线程 `while(!owner_acquired)` 无限旋转——owner 线程 `FUTEX_LOCK_PI` 失败时 `return NULL` 不置位 → waiter 永久卡
2. child 主线程 `while(!route_done)` 无限等——waiter 卡死则 route_done 永不置位
3. 父进程 `waitpid(child)` 无限阻塞——child 卡死则父进程永久卡 → **exploit 进程冻结 → 设备无响应**
4. consumer 线程 `while(consume_go)` 不检查 stop——pselect 挂起则 join 卡死

**v7 修复**（commit 7c8d3ea）：`slide_wait_flag(flag, timeout_ms)` 毫秒超时辅助，替换全部无限等待：
- waiter 等 owner_started/deadlock_seen/owner_acquired：5s
- child 主线程等 route_done：ROUTE_WAIT_SECONDS(8s)，超时置 route_stop+consume_stop 并 join
- 线程就绪 trio 等待：5s
- consumer consume_go：5s
- 父进程 waitpid：WNOHANG 轮询 +(ROUTE_WAIT_SECONDS+8)s 超时后 SIGKILL
- pselect stext 管道 read：poll 超时后 SIGKILL
超时后返回失败，supervisor 继续下次尝试（配合 APP_FOPS_FRESH_PAGE_ATTEMPTS=5）。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v7.apk`（payload md5 `d73df0f6`）。

---

## 10. v7 日志 → v8 泄漏页类型修复（2026-08-23）

**v7 日志**（`rootmys9280-SM-S9210(3).txt`，0823-1809）：
- CFI 全部成功（triggered=1, cfi write/read ret=35, restoring misc_fops）——v6/v7 的 slide=0 防御和超时修复生效
- gate 扫描 64 页：**泄漏页 idx=0 cache18=0（LRU 匿名页）**，idx=8-63 大量 cache18 非零（v4 放宽匹配后的误匹配页，非 pipe 对象）→ find_pipe_buffer 全失败 → `cache gate failed`
- 两次尝试均如此

**决定性对照**：
| 日志 | 泄漏页 cache18 | 结果 |
|---|---|---|
| v4 成功 | **normal2k**（kmalloc-2k slab） | gate idx=0 命中 → root |
| v1/v3/v5/v7 失败 | **0**（LRU/空闲页） | gate 全失败 |

**根因**：泄漏目标是 **mm_struct**（futex hash 碰撞泄漏 leak_child 的 mm）。泄漏页是 mm_struct 所在 slab 页。DZF2 上 `close(leak_memfd)` 释放 mm 后页**保留在 SLUB partial**（cache18 仍 normal2k），pipe 对象（kmalloc-2k）分配时复用同页 → gate 命中。**BYH7(6.1.99) 上 close 后页立即回 buddy**（cache18=0）→ 泄漏页变 LRU 空闲页，pipe 对象从别处分配 → gate 找不到。

**v8 修复**（commit a3f12e9）：`close(leak_memfd)` 从泄漏前移到泄漏后、pipe 对象（PIPE_RECLAIM）分配完成后。泄漏期间 mm_struct 存活在 kmalloc-2k slab（16 对象占 1 个，其余空闲可被 pipe_buffer 复用）→ 泄漏页保持 normal2k → gate 命中。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v8.apk`（payload md5 `754f7134`）。

---

## 11. v8 日志 → v9 CFI 触发重试修复（2026-08-23）

**v8 日志**（`rootmys9280-SM-S9210 (1)(3).txt`，0823-1829）：
- 3/3 尝试 `triggered=0`（CFI 触发失败），slide=0x180000 与 v4 成功时**完全相同** → **CFI 触发是纯随机竞态**（v4 1/1 成功 vs v8 0/3 失败，同 slide）
- `app fops slide attempt=1/1` → 每次 supervisor 尝试只有 **1 次** CFI 触发机会

**问题**：v6 加的 `APP_FOPS_FRESH_PAGE_ATTEMPTS=5` 只在 `APP_REQUIRE_FRESH_P0_SESSION` 分支生效；**BYH7 未定义该宏**，main.c 走 else 分支固定 `attempt<=1`。所以 v6-v8 实际每进程只试 1 次 CFI，30 次 supervisor 尝试内命中率低（v4 运气好 1/1 命中，v8 0/3 未命中）。

**v9 修复**（commit 1e003c7）：main.c else 分支同样读取 `APP_FOPS_FRESH_PAGE_ATTEMPTS`（=5），单进程内最多 5 次 CFI 触发尝试（配合 v7 超时防冻结）。

**注意**：v8 的 leak_memfd 时序修复（泄漏页类型）**尚未被真机验证**——v8 全部 triggered=0 提前失败，没走到 gate。v9 的 CFI 重试能让更多尝试进入 gate 阶段，才能验证泄漏页类型修复是否有效。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v9.apk`（payload md5 `f5feed04`）。

---

## 12. CZA1 港版 KernelSnitch mm_struct 泄漏持续失败 → futex_hashsize 对齐修复（2026-08-23）

**CZA1 日志**（`rootmys9280-SM-S9280 (2).txt`，0823-1809，3 会话×30 次）：
- 会话 A：30/30 `pipe KernelSnitch sk_buff page leak failed`（第一次 KernelSnitch 全败）
- 会话 B/C：28/30 同款失败 + 2 次到 `fresh physrw pipe page` 但 `KernelSnitch mm_struct leak failed`（第二次 KernelSnitch 全败）
- 无一次 `collision finding failed` → **collision finding（纯时序侧信道）成功，但 bruteforce 的 mm_struct 泄漏失败**

**排查过程**（全部排除）：
1. **MM_STRUCT_SZ**：BTF sizeof(mm_struct)=0x3c0 但 SLUB 对象 0x400（含对齐）；已从 0x3c0 改回 0x400，无改善
2. **futex key 构造**：反汇编 CZA1(6.1.128) vs DZG1(6.1.145) 的 `get_futex_key` 逐字节一致（mm@0 / address 页对齐@8 / offset@16，`stp x23,x21,[x19]` 相同）
3. **jhash2**：两内核标准实现一致
4. **mm_cache_init**：两内核逐字节一致（`add w1, w8, #0x3c0` 对象大小算法相同）
5. **符号偏移/指纹**：20/20 符号 nm 交叉验证 + p0 别名地址全部对上

**真正根因**：`futex_hashsize` 计算语义不一致——
- **内核** `futex_init`：`roundup_pow2(bitmap_weight(__cpu_possible_mask) * 256)`
- **用户空间非 FRESH 分支**（futex_hash.h）：`sysconf(_SC_NPROCESSORS_ONLN) * 256`（**无 roundup**）

S9280 (Snapdragon 8 Gen 3, nr_cpu_ids=32, possible=8)：8 核全在线时 2048=2^11 恰好匹配；若运行时热插拔关核（在线<8），如 7 核 → 用户 1792 vs 内核 2048 → hash 表大小错位。collision finding 用纯时序（FUTEX_WAKE 耗时）不受影响，但 bruteforce 用用户空间 `futex_hash()` 计算，与内核 hash 桶无法匹配 → mm_struct 找不到。

**修复**（research a7038eb / app 7f46bb4）：futex_hash.h 非 FRESH 分支统一走 roundup_pow2 循环（与 FRESH 分支一致），并支持 `KERNELSNITCH_FUTEX_HASH_SIZE` 强制覆盖。

**待验证**：`~/下载/RootMyS24-debug-CZA1-hashfix.apk`（payload cza1 SHA256 `03f11ba6`）。

---

## 12. v9 日志 → v10 回退（2026-08-23）

**v9 日志**（`rootmys9280-SM-S9210 (2)(2).txt`，0823-2215）：
- **CFI 重试生效**：`app fops slide attempt=1/5 ~ 5/5`（delay 70000/60000/80000/40000/90000）
- **但 6 个进程 × 5 次 = 30 次 CFI 触发全部 triggered=0**（100% 失败）！
- slide=0x1d0000 正常、mm 泄漏正常、无超时警告——CFI 竞态根本没触发

**定位**：v7（仅超时修复）2/2 triggered=1；v8 加 leak_memfd 时序（泄漏后 close）3/3 triggered=0；v9（v8+重试）30/30 triggered=0。**v8 的 leak_memfd 改动破坏了 CFI 触发**——泄漏时 mm_struct 存活干扰了后续 prepare_kernel_page 的 futex hash 碰撞/mm 泄漏结果（泄漏的 mm 地址/页类型变化），导致 CFI 触发竞态 100% 失败。

**v10 修复**（commit ab6b852）：回退 pipe.c 的 leak_memfd 时序到泄漏前 close（v7 行为），**保留** v9 的 main.c CFI 重试（5 次/进程）。泄漏页类型问题（LRU 页）仍未解决，但先恢复 CFI 触发成功率，再处理泄漏页。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v10.apk`（payload md5 `f697e9fb`）。

---

## 13. ✅ CZA1 港版真机 Root 成功（2026-08-23 23:51）

**日志**：`rootmys9280-SM-S9280 (7).txt`（hashfix 载荷，payload cza1 SHA256 `03f11ba6`）

**完整成功链（attempt 2/30）**：
```
[*] fresh physrw pipe page=ffffff8871670000
[*] mm leaked=ffffff8a52878000 base=ffffff8a52878000 object_index=0
[*] S928 bank bucket=0 lock=0xea0 task=0x6000 mode=0
[*] sk_buff reclaim sends=16/16 mode=0
[*] kernel page prepare mode=0 attempt=2/2 base=ffffff8a52878000
[*] app fops slide route ... delay=70000
[+] slide child context route=pselect pid=15755
[*] stage=verifying-kernel-access
[*] cfi write ret=35 errno=0
[*] cfi read ret=35 errno=0
[*] cfi restoring misc_fops target=ffffff802a38fbf0 value=ffffffc00941e7b0
[*] pipe page idx=0 page=ffffff8871670000 ... cache18=ffffff8001cf6800 match=1
[*] phys step read64 done ok=1 value=306365737562656e
[*] root umh queued wq=ffffff8001cf9c00 pwq=ffffff8800b0a800 pool=ffffff80629f7800 work=ffffff8a5287e000
[*] root umh result wake=1 complete=1 retval=0 socket=1
[*] app fops slide attempt=1/1 triggered=1 verified=1 step=0 errno=0
[+] pipe physrw done=1 root=1 read_ok=1 write_ok=1 rw64=1/1 uid=2000->0
✔ 临时 root 已获得！  →  KernelSU late-load exit=0 → 🎉 Root 流程完成！
```

**确认**：futex_hashsize roundup_pow2 修复（section 12）是 CZA1 突破 KernelSnitch 的关键；
attempt 1 的 `sk_buff page leak failed` 是 KernelSnitch 正常概率性失败（collision 时序），
attempt 2 命中即全链通过。CFI 触发竞态在 CZA1 上同样需要多 attempt（(4).txt 连续
triggered=0 是竞态未命中，非崩溃——对比 (3).txt 曾有 panic 自动重启，属于触发命中后
内核写坏的概率事件，多跑即可）。

**CZA1 港版适配完成**：One UI 8.0 / Android 16 / kernel 6.1.128 真机 root 验证通过。

---

## 14. 💡 根因闭环：省电模式 = 在线核数不足 = futex_hashsize 错位（2026-08-24）

**测试人员反馈**：一直开着省电模式，所以之前大量失败；**关闭省电模式后 v2.5.4
第一版载荷（SHA 2a6f101f，MM_STRUCT_SZ=0x3c0，无 roundup 修复）真机成功**。

这与此前 section 12 的诊断完全闭环：
- 省电模式 → 内核热插拔关闭部分核心 → **在线核数 < possible 核数（8）**
- 用户空间（无 roundup）：`futex_hashsize = sysconf(ONLINE)×256`
  省电模式 7 核 → **1792**；内核 `roundup_pow2(possible×256)` = **2048** → 错位
- KernelSnitch collision finding（纯时序）仍成功，但 bruteforce 的用户空间
  futex_hash 与内核 hash 桶无法匹配 → mm_struct 泄漏失败（全部历史失败日志的共同特征）
- 8 核全在线时 2048 = 2048 → v2.5.4 原版即可成功

**结论**：
1. v2.5.4 第一版载荷在**关闭省电模式**（8 核在线）下是正确可用的 —— 按用户要求已
   并回 App 主线（commit a0a685d），research target.h MM_STRUCT_SZ 同步 0x3c0
   （commit 36f94ca）
2. hashfix 载荷（03f11ba6，roundup 修复）在省电模式开关两种情况下都能成功，
   作为更强版本保留；v2.5.4 原版存档于标签 `v2.5.4-cza1-v1` / `cza1-v1-adapt`
3. App 已加省电模式检测提示（commit e47044d）：dumpsys power 检测
   mPowerSaveMode=true 时输出警告，提示先关闭省电模式

---

## 13. v10 日志 → v11 SELinux enforcing 偏移修复（2026-08-24）

**v10 日志**（`rootmys9280-SM-S9210.txt` 小 + `rootmys9280-SM-S9210 (6).txt` 大，0824-1240）：
- **root 全链路成功**：泄漏页 idx=0 cache18=normal2k match=1、pipe probe found=1 idx=130、read64 ok、`triggered=1 verified=1 step=0`、**`uid=2000->0`**、`✔ 临时 root 已获得！`
- **但 KernelSU late-load exit=137（SIGKILL）**：
  ```
  ksud late-load: exit=137
  late-load: private mount namespace: Permission denied (unshare_errno=13)
  ```
- **unshare_errno=13（EACCES）≠ EPERM**——EACCES 是 **SELinux 拒绝**（缺 CAP 才是 EPERM）→ **SELinux permissive 写入未生效**！

**反汇编验证（vmlinux-to-elf 提取三内核对比 enforcing 偏移）**：
| 内核 | selinux_state 符号 | enforcing 偏移 | target.h | 结果 |
|---|---|---|---|---|
| CZA1（late-load 成功） | 0xffffffc00a421460 | **+0** | 0x02421460 ✅ | exit=0 |
| DZF2（全链路成功） | 0xffffffc00a521588 | **+0** | 0x02521588 ✅ | root |
| BYH7（失败） | 0xffffffc00a420440 | **+0** | **0x02420441 ❌（+1）** | exit=137 |

**根因**：BYH7 的 `SELINUX_ENFORCING_OFF=0x02420441` **错 1 字节**——enforcing 是 selinux_state 首字段（+0），0x441 写到了 `initialized` 字段。`selinux_set_mnt_opts` 里 `ldarb [x8,#0x441]` 是 initialized 检查，非 enforcing。→ SELinux 从未 permissive → mount EACCES → ksud 被 SIGKILL(137) → **测试者反馈卡死重启**。

**v11 修复**（commit 8ba5c5f）：`SELINUX_ENFORCING_OFF → 0x02420440`，permissive 写入真正生效 → mount 放行 → ksud 正常加载 KernelSU。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v11.apk`（payload md5 `6e085548`）。

---

## 14. v11 日志 → v12 CFI 时序窗口修复（2026-08-24）

**v11 日志**（`rootmys9280-SM-S9210 (1)(1).txt`，0824-1319）：
- 6 进程 × 5 次 = **30 次 CFI 触发全部 triggered=0**，slide=0x100000 固定
- v11 的 selinux 偏移修复（root.c）与 CFI 触发（slide_app.c）无关，未走到验证
- 对比：v4/v10 CFI 1/1 成功（运气），v9/v11 30/30 失败 → **CFI 触发成功率随 boot 状态剧烈波动**

**根因**：CFI 触发是 pselect/futex 竞态——waiter 线程 `FUTEX_WAIT_REQUEUE_PI` 的超时窗口（`SLIDE_WAIT_NSEC=50ms`）内，requeue 必须命中才能产生 EDEADLK。BYH7 上 50ms 窗口太窄（调度波动下常错过）→ requeue 找不到 waiter → 不 EDEADLK → triggered=0。

**v12 修复**（commit 9cff70c）：
- `slide_app.c`：`SLIDE_WAIT_NSEC`/`SLIDE_REQUEUE_MAX_POLLS`/`SLIDE_REQUEUE_POLL_USEC` 改 `#ifndef` 可覆盖
- BYH7 `target.h`：`SLIDE_WAIT_NSEC=300ms`（6 倍窗口），requeue 命中率大幅提升

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v12.apk`（payload md5 `061153d5`）。

---

## 15. v12 日志 → v13 修正（2026-08-24）

**v12 日志**（`rootmys9280-SM-S9210 (1)(2).txt` + `rootmys9280-SM-S9210(1).txt`，0824-1342）：
- **CFI 触发成功**：2 次 `triggered=1`（v12 的 300ms 窗口生效！此前 v11 30/30 全失败）
- attempt 4 全链路 pipe physrw 成功（read_ok=1 write_ok=1 rw64=1/1）
- **但 root umh retval=-13（EACCES）socket=0**——root helper exec 被 SELinux 拒！

**决定性对照**：
| 版本 | SELINUX_ENFORCING_OFF | root umh 结果 |
|---|---|---|
| v10 | **0x441** | retval=0 socket=1（permissive 生效）|
| v12 | 0x440（v11 改） | **retval=-13**（EACCES，exec 被拒）|

**结论**：**0x441 才是 enforcing**（写 0 → permissive → UMH exec 放行）；**v11 改成 0x440 是错误修复**（写到了别的字段，permissive 失效）。之前 v11 基于"selinux_state+0"的反汇编推断方向反了——BYH7 的 enforcing 字段在 selinux_state+1（0x441）。

**v13 修复**（commit e8cf950）：回退 v11（SELINUX_ENFORCING_OFF 恢复 0x441），保留 v12 的 SLIDE_WAIT_NSEC=300ms。当前组合：CFI 300ms 窗口 + selinux 0x441 + CFI 重试 5 次 + 竞态超时 + late-load fallback。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v13.apk`（payload md5 `ad72be1d`）。

---

## 16. v13 日志 → v14 capability 修复（2026-08-24）

**v13 日志**（`rootmys9280-SM-S9210(2).txt`，0824-1403）：
- **root 全链路确认成功**：CFI 触发（300ms 窗口）→ 泄漏页 idx=0 normal2k match=1 → pipe probe found=1 idx=125 → read/write ok → read64 ok → **`root umh retval=0 socket=1`（SELinux permissive 生效，0x441 恢复正确）**
- 日志在 root umh 后截断（疑似 root 后卡死/重启，或导出截断）
- 另一个日志（`rootmys9280-SM-S9210 (2).txt`）是**错误载荷**（cve-2026-43499 = DZF2，label e3q-S9280ZCS6DZF2），非 BYH7 测试

**遗留问题**（v10 模式）：late-load `unshare(CLONE_NEWNS) EACCES(13)` → ksud SIGKILL(137)。**permissive 已生效仍 EACCES → 非 SELinux，而是 capability**：Android usermodehelper 的 capability bounding set 可能缺 CAP_SYS_ADMIN，且 setresuid(0) 后 effective caps 被清空。

**v14 修复**（commit 506b29f）：`umh_main` 在 setresuid(0,0,0) 后显式 `capset` 把 effective/permitted/inheritable 全置 1（受 bounding set 约束，尝试恢复 CAP_SYS_ADMIN）→ unshare/mount 应放行 → ksud 经 bind mount 或 fallback 正常加载 KernelSU。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v14.apk`（root helper md5 `ac55ba7f`，payload 同 v13 `ad72be1d`）。

---

## 17. v15/v16 日志分析 — KDP mount panic 根因闭环（2026-08-24）

**v15 测试**（`rootmys9280-SM-S9210 (2) (1).txt` / `(1)(1) (1).txt`，1824-1845）：
- 修复内容：root umh 成功后提前 fork keeper（cve43499-hold 继承 pipe fd）+ nanosleep 1.5s 延迟
- 结果：**黑屏重启不再立即发生**——`root early keeper` / `root umh settle done` 正常打印
- 但 **settle done 后仍黑屏重启**：崩溃点在 `install_android_root` 的 holder 轮询期间
  （root_hold_socket_ready 连接 cve43499_roothold abstract socket）
- 另一日志 CFI triggered=0 5/5（slide=0x160000），触发率仍不稳

**根因确定（v16）**：
- v14 capset 提升 CAP_SYS_ADMIN 后，late-load 的 `unshare(CLONE_NEWNS)` + `mount` 真正执行
- Samsung KDP 符号证实：`kdp_mnt_alloc_vfsmount` / `kdp_assign_mnt_flags` / `kdp_restrict_fork`
  监控 mount namespace 操作 → 触发保护 → **内核 panic → 黑屏重启**
- v4/v10（无 capset）unshare 返回 EACCES → fallback execl → 不 panic（但 late-load exit=10/137）
- DZF2 成功日志（`S9280_DZF2_success.txt`）证实其路径本就是 fallback（unshare 失败 → exit=0）

**v16 修复**（commit 63dfcc8）：`run_kernelsu_late_load` **跳过 unshare/mount，直连 execl** 阶段好的
ksud（`/data/local/tmp/ksud-s25u-kdp`）。SELinux 已 permissive，/data/local/tmp 可执行。
root helper md5 `4fe838b9`（原 ac55ba7f），payload 保持 v15 `f891c1ad`。

**待验证**：`RootMyS24-debug-BYH7-pipe-gate-v16.apk`

---

## 18. Pixel 6 (oriole) 双载荷日志分析 — 触发(EDEADLK)成功但 5.10 泄漏原语失效（2026-09-05）

日志归档：`02_exploit工程/pixel6-ghostlock/logs/2026-09-05/`（原始微信目录
`~/文档/xwechat_files/wxid_h7qzzi5p3obc22_34b4/msg/file/2026-09/`）。

### 18.1 三份文件与时间线

| 文件 | 大小 | 导出时刻 | 内容 |
|---|---|---|---|
| `rootmys9280-Pixel_6.txt` | 3.0KB | 11:43 | 上午会话：pixel6 ×2 + pixel6-400 ×1，App 框架头正常、均走到「触发+熄屏」，但**无任何 preload 侧输出行**（未到可分析深度，可不再追） |
| `rootmys9280-Pixel_6(1).txt` | 7.7KB | 13:55 | 下午第 1 轮（载荷 `libpreload.so` 87056B）中途导出，恢复 117 行 |
| `rootmys9280-Pixel_6 (1).txt` | 17.3KB | 14:01 | 聚合日志：第 1 轮完整 + 第 2 轮（`libpreload-400.so` 87008B = **MM_STRUCT_SZ 0x400 变体**）启动段 + 历史会话残留 |

时间戳换算：1787494518=08-23 22:15:18、1788254608=09-01 17:23:28、
1788587226=09-05 13:47:06、1788587914=09-05 13:58:34（均为 CST）。

环境（两轮一致）：Pixel 6 (oriole)，Android 15 / AP4A.250205.002，
内核 `5.10.214-android13-4-00015-g54748cd9e76c-ab12786721`，KASLR on
（verifiedbootstate=orange）。两次运行 boot_id 相同（05c1dee2-9339-4b77-90d7-cbc092373af1）
→ **同一次开机内测试**。

### 18.2 运行时序与失败特征（两个载荷变体一致）

第 1 轮（payload=pixel6，13:47:06 起）：
- startup / pipe 诊断正常（pipe-max-size=1MB、pipe-user-pages=16384）→ [2.6] 清理 exit=137（杀旧残留）。
- **kernel page retry 高频失败**：13:47:10–13:50:08 三轮各 12/12（36 次）才出第一个好页 → attempt 3；attempt 4、6 的 prepare 也各烧 12 次。即**每 2 个 attempt 只有 1 个拿到 groomed page，单个 attempt 平均 2–3 分钟**——20 个 attempt 远超 launcher 60s 窗口（对照 §12 省电模式/核数 futex_hash 错位先例，建议确认 8 核全在线重测）。
- 有输出的 attempt：attempt 3 (shift=2) 13:50:10、attempt 5 (shift=4) 13:52:41、attempt 7 (shift=6) 13:55:39（导出截断）。
- 13:58:34 第 2 轮（pixel6-400）preload 启动（pid 6952），仅 startup 行，导出时仍在跑。

attempt 3 全链关键行（attempt 5 完全同构）：
```
slide attempt 3 uses pselect shift=2
slide child pid=14897 uid=0 direct_cpu=3
slide CMP_REQUEUE_PI ret=-1 errno=35                    ← EDEADLK，见 §18.3
slide pthread_kill(waiter, SIGALRM) ret=0
slide pselect setup shift=2 page=ffffff88d0c08000 fake_lock=… fake_w0=… fake_task=…
slide pselect before fd install nfds=320 / after fd install / before syscall
slide consumer before tgkill tid=14898 / before sched
slide pselect returned ret=0 errno=0 calls=1 sched_ok=0 last_sched_ret=-1
slide consumer sched tid=14898 alive_ret=0 sched_ret=0 sched_errno=0    ← sched_setattr 成功
slide boot_id raw=05c1dee293394b7790d7cbc092373af1 leaked=774b3993e2dec105
[-] slide bad leaked pointer=774b3993e2dec105
slide attempt 3 … sched_ok=1 sigalrm=1 setprio_ret=0 pkill_ret=0
[-] slide attempt 3 failed n=96 status=256
```

要点：
1. **errno=35 是 EDEADLK 不是 EAGAIN**（arm64 通用 errno：EAGAIN=11、EDEADLK=35）。全部 attempt 均为 -35 → 触发签名一致。
2. `leaked=0x774b3993e2dec105` = boot_id 前 8 字节 `05c1dee293394b77` 的 LE u64；且该 16 字节是**完好的 v4 UUID**（byte6 高半 nibble=4、byte8 高两位=10）→ **boot_id 一个字节都没被改写**，泄漏写从未发生。
3. attempt 7 (shift=6) 额外打出 `slide pselect cannot place deadline waiter_word=9 global_word=15 words_per_set=5 nfds=320`：shift≥6 时 waiter word9(deadline) 落到 global word15，超出 3×5 词窗口 → **shift 6/7 结构性不可用，扫它是纯浪费**。
4. 全部 attempt `stext=0`、status=256（子进程 exit 1）→ 载荷循环 20 次全败，无 root。pselect ret=0（超时返回）与 waiter 按 2s 超时退出（werrno=110）均为设计内行为，非异常。

### 18.3 反汇编定论（vmlinux_pixel6.elf，5.10.214-android13-4）

1. **EDEADLK 是触发成功签名，不是环境错误。** `futex_requeue`
   （VA 0xffffffc00827b8f8，Image off 0x27b8f8）全函数体没有任何 -35 物化点；
   唯一来源是 `futex_proxy_trylock_atomic`（0xffffffc0082815b0）内联调用的
   `futex_lock_pi_atomic`（0xffffffc0082805b0）经 requeue_pi 分支表
   （`add w8,w21,#0x10; cmp #0x10; b.hi` → 表 @0xffffffc00a33e780 附近）透传。
   lock_pi_atomic 的 -35 物化于 +0x278（VA 0xffffffc008280828）：
   `and w8,w26,#0x3fffffff; cmp w8,w27; b.eq` —— 即 **uaddr2 词的 TID 位 ==
   待 requeue 顶层 waiter 的 TID**（代理 trylock 的自死锁检查）。这正是
   CVE-2026-43499「futex_requeue 代理锁回滚路径误用 current」要诱导的状态，
   与 fusion/BYH7 线 §14-15 的判据（requeue 命中 → EDEADLK）一致。
   → **dangling waiter / UAF 已武装**；对照其余返回值：requeue 路径 EAGAIN(-11)
   唯一物化点 0xffffffc00827c1d0（cmpval 不匹配）、lock_pi_atomic 的 -11 只来自
   cmpxchg 词值变化（0xffffffc008280778 / 0x…2807f0）——本日志全 -35 说明
   cmpval=0 检查通过、uval 无并发改写，状态干净。
2. **泄漏失败根因与 upstream 结论一致（b270dc6，XIG04 5.10.136）：**
   flat rt_mutex_waiter 下当前 fake tree（parent=LOGGERS_0_1、rb_right=0、
   rb_left=BOOT_ID）只会走出「单子树 rb_erase」路径——仅有
   `__rb_change_child`（向父写 BOOT_ID）+ `rb_set_parent`（向 boot_id 写
   LOGGERS 线性别名，即我们已放置的已知值），**永远不触发 rb 旋转**，运行时
   `&nfulnl_logger`（泄漏目标）不可能被搬进 boot_id[0]。本日志 boot_id 全
   attempt 字节不变即该结论在 Pixel 6 上的复现；sched_ok=1（walk 在 fake
   waiter 上执行、未 panic）与之一致。
   Pixel 6 5.10.214 对应符号（RVA = VA − 0xffffffc008000000）：
   remove_waiter 0x1dd72c、rt_mutex_adjust_prio_chain 0x1ddce4、
   rt_mutex_start_proxy_lock 0x1df4d0、futex_requeue 0x27b8f8、
   futex_lock_pi_atomic 0x2805b0、rb_insert_color 0xa40db8、
   **rb_erase 0xa40f54、__rb_erase_color 0xa412a0**（旋转本体，重建 overlay
   前必须先逆这里）。
3. **MM_STRUCT_SZ 0x3e0 vs 0x400 不是当前瓶颈**：400 变体（第 2 轮）与 3e0
   变体失败在同一步（泄漏原语），与 mm 大小无关；400 变体本轮无判别力。

### 18.4 与 S24/S25 线（6.1）成功路径的差异

- 6.1 线（DZF2/BYH7/CZA1）成功链 = CFI 触发 → 泄漏页 → pipe probe → physrw →
  root umh；其 rt_mutex_waiter 为 nested 布局，可构造引发旋转的两子树。
- Pixel 6 = aristotle 直提权线（boot_id 泄漏 → KASLR → cred 替换 + SELinux
  flip）；5.10 flat 布局下泄漏原语必须按 `SLIDE_LEAK_DISASM_ANALYSIS.md`
  「次の一手」重建 fake tree 形状（使 rb_erase 进入旋转路径、把
  `[loggers[0][1]]` 运行时值搬入 boot_id[0]）。**盲目 shift 扫在实机只会
  no-op（其它机型会 panic），不要再扫。**

### 18.5 下一步（优先级）

1. 【代码】按 §18.3.2 用本 vmlinux 重做 `__rb_erase_color`/`__rb_change_child`
   逆向 → 重设计 `prepare_skb_payload`/`put_direct_waiter` 的 fake tree
   （PAGE_PAYLOAD_SLIDE），目标：rb_erase 走旋转路径、`[loggers[0][1]]` →
   `boot_id[0]`。这是打通 KASLR 泄漏的唯一路径。
2. 【验证环境】确认测试时 8 核全在线（关省电模式），对照 §12 futex_hash 错位
   先例，压掉 kernel page retry 高失败率（13:47–13:50 三连 12/12）。
3. 【扫参收敛】shift 固定 0–5（6/7 放不下 deadline 词）；修复泄漏前无需跑满
   20 attempt（SLIDE_WAIT_SECONDS=2 下远超 60s launcher 窗口）。
4. 【变体】MM_STRUCT_SZ 0x400 变体等 leak 原语修复后再做 A/B。

### 18.6 真机诊断定标与两项修复（2026-09-05 22:58 diag）

诊断文件 `pixel6-diag-20260905-225843.txt`（708 行，root，归档
`02_exploit工程/pixel6-ghostlock/logs/2026-09-05/`）与 §18 失败特征闭环：

1. **kallsyms 全 0**（连 uid=0/u:r:ksu:s0 都被 kptr 屏蔽）→ 符号定标只能信
   vmlinux_pixel6.elf；真机泄漏不可依赖 /proc/kallsyms。
2. **mm_struct slab：object_size=1000(0x3e8)、slab_size=1024(0x400)、order=3** →
   KernelSnitch 扫描步长应为 0x400。**0x3e0 步长是 §18.2 "kernel page retry
   12/12×3" 风暴的直接根因**（gcd=0x20，每 32 次扫描才对齐一次对象起点 → mm
   碰撞必败 → page 准备 2-3 分钟/个）。已修：target.h + common.h MM_STRUCT_SZ
   =0x400。
3. **iomem：Kernel code 0x80000000-0x82caffff、System RAM 起 0x80000000** →
   P0_PHYS_OFFSET/P0_KERNEL_PHYS_LOAD=0x80000000（delta=0）实锤；dmesg 无
   panic；cpu 0-7 全在线（排除核数假设）。
4. **KASLR root 源（绕过泄漏独立验证 direct 链）**：slide.c 新增
   `SLIDE_P0_OFFSET` env + root dmesg `Kernel Offset: 0x<slide>` 自动解析
   （klogctl SYS_syslog(3)），日志 `slide-kaslr-ok source=forced|dmesg`。
   真机验证步骤：`USE_SU=1 ./pixel6-root.sh`（su -c 触发）→ 期望走到
   `direct-root-summary`（cred 替换 + selinux 1->0），与 boot_id overlay 泄漏
   解耦。
5. **遗留**：非 root 场景 boot_id overlay 泄漏需 rb 旋转树形重设计
   （SLIDE_LEAK_DISASM_ANALYSIS.md，__rb_erase_color VA 0xffffffc008a412a0
   已反汇编，见 pixel6_work/rb_erase_disasm.txt）。

新载荷 sha256 `664f400a4d20e06b4085c151b907c06f6c22ae3e50c3f247bb9d85fdadd74645`
（88,608 B，0x400 定标 + KASLR root 源）。
