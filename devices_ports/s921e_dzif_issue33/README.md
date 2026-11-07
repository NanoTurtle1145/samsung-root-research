# SM-S921E（国际版 S24 / E1Q）S921EXXU3DZIF —— issue #33

- 来源：<https://github.com/NanoTurtle1145/root-my-s24/issues/33>（2026-11-07）
- 设备：SM-S921E，`samsung/e1qxins/e1q:17/CP2A.260605.016/S921EXXU3DZIF:user/release-keys`
- 内核：`6.1.162-android14-11-34343818`（与 SM-S9280 EZIF 同构建号）
- App：RootMyS24 v3.6.0-s24 (build 263)
- 实际生效：**引擎 98260 UAF + KSU 3.2.5 驱动（ksud-32525）**（日志头 `引擎: SAMTIMER_98260 · 载荷: 98260 UAF · KSU: 32525`）
- 结果：root 成功，KNOX 完好（warranty_bit=0）
- 结论：E1Q 与 E3Q 同 34343818 构建，98260 链路直接可用；已加入 App 机型表 `S921EDZIF`
- 日志：`rootmys9280-S921EXXU3DZIF.txt`（原样归档）
