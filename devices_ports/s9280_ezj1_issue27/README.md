# SM-S9280 港版 / S9280ZHS6EZJ1（S24 Ultra，e3q）诊断归档

来源：GitHub issue [#27](https://github.com/NanoTurtle1145/root-my-s24/issues/27)
用户通过 RootMyS24 App 上传的运行日志（已从服务端 `run_logs` 导出）。

## 设备信息（日志内）

- 型号：SM-S9280（港版）
- 固件：`S9280ZHS6EZJ1`
- 系统：Android 17 / One UI 9（`CP2A.260605.016`）
- 内核：`6.1.162-android14-11-34343818-abS9280ZHS6EZJ1`
- 指纹：`samsung/e3qzhx/e3q:17/CP2A.260605.016/S9280ZHS6EZJ1:user/release-keys`

## 关键发现

日志里实际使用的载荷是 **`e3q-S928BXXU6EZIF`（S928B 欧版 EZIF 的载荷）**，
不是 S9280 EZJ1 自己的载荷 → p0 阶段失败、无法 root。

即：**EZJ1（港版 S9280）没有适配载荷，App 回退到了 S928B 的载荷**。
这与 issue #28（S24 专用版）暴露的"载荷选择回退"问题可能同源：
机型/固件匹配不到专用条目时，退到了同一平台的其它机型载荷。

## 文件

- `log_1.txt` ~ `log_3.txt`：App 上传的运行日志原文（含 header）
