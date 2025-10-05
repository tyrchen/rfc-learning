# 教程要求

所有涉及的 RFC 文件请参考 sources/ 目录下的文件。

1. 风格与语言
语言: 全程使用简体中文。

风格: 采用教程风格，语言力求通俗易懂、清晰易读。对于复杂概念，请使用恰当的比喻或类比来帮助理解（例如，将滑动窗口比作“寄送包裹的流水线”）。

结构: 教程应有清晰的逻辑结构，从基础概念到高级主题，循序渐进。建议章节划分如下：

TCP 核心概念 (RFC 9293): 连接、端口、可靠性、TCP 报文段结构。

连接管理 (RFC 9293): 详细讲解三次握手和四次挥手的每一个步骤、状态转换以及相关字段（SYN, ACK, FIN）。

可靠数据传输 (RFC 9293): 深入解释序列号（SEQ）、确认号（ACK）、超时重传（RTO）和滑动窗口机制。

拥塞控制 (RFC 5681): 专门讲解慢启动、拥塞避免、快速重传和快速恢复四大核心算法。

高性能扩展 (RFC 7323 & RFC 2018): 介绍 TCP 如何应对“长肥网络”，包括窗口缩放选项、时间戳选项以及选择性确认（SACK）的工作原理。

2. 连接 Linux 实际实现

这是本教程的核心要求。请将 RFC 中的抽象理论与 Linux 内核的实际实现紧密结合，让读者看到“活的” TCP。

系统参数: 在讲解相关概念时，引用 Linux 中的 sysctl 参数。例如：

讲解 SACK 时，提及 net.ipv4.tcp_sack。

讲解窗口缩放时，提及 net.ipv4.tcp_window_scaling。

讲解拥塞控制算法时，提及 net.ipv4.tcp_congestion_control，并可以简要介绍几种常见的算法（如 Reno, Cubic）。

命令行工具: 使用 tcpdump、ss 或 netstat 等工具的输出来作为实例。例如：

使用 tcpdump 抓包展示三次握手过程中 TCP 头部 Flags 和 Options 的变化。

使用 ss -it 命令的输出展示一个真实 TCP 连接的拥塞窗口（cwnd）、慢启动阈值（ssthresh）和 RTT 等信息。

代码/伪代码: 在适当的地方，可以用简单的伪代码来描述算法逻辑，帮助读者理解实现细节。

3. 使用 Mermaid 图表进行可视化

请为所有关键流程和复杂概念配上 Mermaid 图表，图文并茂地进行解释。必须包含但不限于以下图表：

TCP 报文段结构图 (graph TD)

三次握手时序图 (sequenceDiagram)

四次挥手时序图 (sequenceDiagram)

TCP 完整状态机图 (stateDiagram-v2)

滑动窗口工作原理示意图 (sequenceDiagram 或 graph LR)

拥塞窗口（cwnd）在慢启动和拥塞避免阶段的变化曲线图 (xychart-beta)

快速重传和快速恢复的流程示意图 (sequenceDiagram)

SACK 选项如何工作的示例图 (sequenceDiagram)

4. 深度与细节

请确保教程内容详尽，覆盖上述 RFC 的所有核心知识点。

对于重要字段（如 Sequence Number, Acknowledgment Number, Window Size, Flags, Options），请务必解释其确切含义和作用。

解释各种机制（如超时重传、拥塞控制）是为了解决什么具体问题而设计的。

5. 输出格式
请将所有内容生成为 Markdown (.md) 格式。

请将教程组织到 rfcs/tcp/ 文件夹下。考虑到内容会非常多，建议将教程拆分为多个文件，例如：

rfcs/tcp/01-introduction.md

rfcs/tcp/02-connection-management.md

rfcs/tcp/03-reliable-data-transfer.md

rfcs/tcp/04-congestion-control.md

rfcs/tcp/05-high-performance.md
