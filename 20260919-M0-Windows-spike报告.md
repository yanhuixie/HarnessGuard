# M0 Windows spike 报告

> 对应：技术设计 §11 M0 验收项（Win=ETW 三 provider 事件速率/RSS、FileObject→Name 关联成功率）。
> 日期：2026-09-19。环境：Windows 11 内部版本 26200，rustc 1.98.1，ferrisetw 1.2.0，
> 管理员权限（UAC 提权运行）。
> 代码：`crates/hg-plat-win/examples/etw_spike.rs`（可复跑，5 轮原始输出存于 `target/spike_out*.txt`，
> 未入 git）。

## 结论速览（对应 M0 三个验收项）

| 验收项 | 结果 | 结论 |
|---|---|---|
| 三 provider 可用性与事件速率 | Process 1.3–1.9 启动/s、TCP-IP 25–42 事件/s、Dns-Client 正常出流；File 25–26.5k 事件/s | ✅ 可用；File 事件量证实"按 harness 身份早过滤"是硬要求 |
| FileObject→Name 关联成功率 | **55.4%–62.9%**（unknown 37.1%–44.6%，两轮波动） | ⚠️ 可用但 unknown 率高，须缓存 + 容忍 + UI 披露（设计预判正确） |
| 实测 RSS 对照 §10（30–55MB） | **33.5–34.3 MB**（私有提交 22.5MB） | ✅ 落在区间内 |

## 五轮运行明细

| 轮次 | 模式 | 关键数据 |
|---|---|---|
| 1 | KernelTrace：PROCESS + FILE_IO + FILE_IO_INIT + TCP_IP（30s） | 进程启动 60（1.9/s）；文件 790,868（25.4k/s）；Name 事件 39,106、缓存命中 221,396、unknown 130,396（**37.07%**）；网络 791 事件、daddr 解析 791/791、size 累计 3.5MB；RSS 34.3MB。ImageName 解析 **0**（经典事件无此字段）；Dns-Client `by_name` 失败（PlaError::NotFound） |
| 2 | UserTrace + manifest Kernel-Process + Dns-Client by GUID（30s，系统空闲） | Kernel-Process manifest **0 事件**；DNS 74 事件、QueryName 成功 68 |
| 3 | 同 2 + 并发 200 次进程 churn + 10 次 nslookup（判定性验证） | churn 期间 DNS 流入正常（90 事件），Kernel-Process manifest 仍 **0** → 与"没有进程活动"无关，是该 provider 在普通 UserTrace 不出事件 |
| 4 | KernelTrace（SYSTEM_LOGGER 模式）+ manifest Kernel-Process + Dns-Client | manifest Kernel-Process 仍 **0**；DNS 也变 0（kernel 会话收不了用户态 provider） |
| 5 | KernelTrace：PROCESS + FILE_IO + FILE_IO_INIT + TCP_IP + **IMAGE_LOAD**（30s + churn） | Image-Load Load(op10) FileName 解析 **998/998**，样例输出完整 NT 路径（如 `\Device\HarddiskVolume3\Program Files\Git\cmd\git.exe`）；文件 827,504（26.5k/s）、unknown 44.55%；网络 1,313、解析 100%；RSS 33.5MB |

## 对技术设计 §5.1 的校准（M1 落地依据）

1. **进程事件选型修正**：manifest 版 `Microsoft-Windows-Kernel-Process`（GUID 22FB2CD6-…）
   在本机（Win11 26200）无论挂 UserTrace 还是带 SYSTEM_LOGGER 模式的 KernelTrace 均不出事件
   （轮 2–4），**放弃**；采用经典 kernel logger flags 组合：
   - `EVENT_TRACE_FLAG_PROCESS` → start/stop + ProcessId/ParentId（轮 1/5 验证）；
   - `EVENT_TRACE_FLAG_IMAGE_LOAD` → Load 事件携带完整 exe NT 路径（FileName，轮 5 验证 100%）。
     进程身份 = start 事件建立 pid/ppid + 该 pid 首个（或 ImageBase 匹配的）Load 事件给 exe 路径。
   - NT 设备路径（`\Device\HarddiskVolume3\...`）需 `QueryDosDevice` 转盘符路径后再做特征库匹配
     （M1 实现，纯用户态调用）。
2. **CommandLine 缺口**：内核 ETW（经典与 manifest）均不提供命令行（轮 1/2：CommandLine 解析 0）。
   M1 降级链：Exec 事件后由 SYSTEM 服务 `NtQueryInformationProcess` 读目标 PEB 的
   ProcessParameters→CommandLine（SYSTEM + SeDebugPrivilege 可行，短命进程有竞态）；
   读取失败 → cmdline 置空，`[commands].blocked` 命令封堵对该进程退化为按 exe 判定，
   并在 UI/日志显式披露可见性缺口。备选：启用 4688 进程创建审计（重，M4 再评估）。
3. **DNS 观测**：`Microsoft-Windows-Dns-Client` **必须按 GUID**（1C95126E-7EEA-49A9-A3FE-A378B03DDB4D）
   挂独立 UserTrace；`by_name` 在本机返回 NotFound。事件 3006/3008 携带 QueryName
   （解析成功 68/74、84/90，约 92–95%；失败部分为 1001 等无 QueryName 的事件，属正常）。
   3008 的 QueryResults 样例为空串，M1 需从 3008/3011 解析应答 IP 列表。
4. **文件事件与关联率**：25–26.5k 事件/s 全量解析不可取，M1 回调内**第一步按 pid 查 ProcTable**，
   非监控树进程即读即弃（设计 §5.1 原文即此意图，实测数据确认其为硬要求）。
   FileObject→Name unknown 率 37–45%（含缓存未命中与 Name 事件缺失），落在设计预判的
   "经典坑"内：缓存（轮 5 仅 2,918 条即支撑 209,670 次命中）+ unknown 容忍 + UI 披露
   unknown 比例；约 50% 事件（op76 等）天然无 FileObject（目录枚举类），不参与关联统计。
5. **网络观测**：TCP-IP 经典 provider 的 daddr/saddr/dport/size/PID 字段解析 100% 成功，
   按 opcode 分布（10=send、11=recv、16=connect 等）足以构建 ConnOpen/ConnTx 事件。
6. **内存**：5 个 kernel flags 会话 + DNS 会话 + FileObject 缓存全部在跑的 spike 进程
   RSS 33.5–34.3MB。对照 §10：平台事件源行预估 5–15MB 偏乐观（实测含 ferrisetw 运行时
   与 schema 缓存约 33MB 含基础运行时），但合计预算 30–55MB 区间仍成立；
   最终 daemon = spike 同级事件源 + core/store/web ≈ 预计 45–60MB，100MB 预算余量充足。
   超支预案（§10）无需启用。

## 事件速率参考（空闲桌面 + 少量后台负载）

- 文件：25,000–26,500 事件/s（全系统）；仅 harness 树子集时预计 <100/s（早过滤后）。
- 网络：25–42 事件/s；进程启动 1.3–1.9/s；DNS 2–3 查询/s。
- Spike 自身 CPU 未测（M1 有早过滤后无对照意义）；RSS 已实测。

## 风险与遗留

- FileObject→Name unknown 率波动（37%↔45%）与工作负载相关，M1 需在 UI 呈现实时 unknown 比例。
- CommandLine 的 PEB 读取对短命进程存在竞态（读取前进程已退出），影响面=命令封堵规则命中率，
  按设计"显式失败"原则披露。
- UDP/QUIC 未启用（设计已标注盲区，M4 后调研）。
