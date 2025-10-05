# TCP 协议完整教程

> **基于 RFC 9293, RFC 5681, RFC 7323, RFC 2018 的深度学习指南**

本教程系统讲解 TCP（Transmission Control Protocol）协议，从基础概念到高级特性，结合 Linux 实现和实战演练，帮助你全面掌握 TCP 的工作原理。

## 📚 教程结构

### [第一章：TCP 核心概念与报文段结构](./01-core-concepts.md)
- TCP 的核心特性与设计理念
- TCP 报文段格式详解
- 端口、序列号、确认号、标志位
- 窗口大小、校验和、选项字段
- tcpdump 抓包分析实战

**核心知识点**：
- ✅ TCP 提供可靠、有序、面向连接的字节流服务
- ✅ 报文段包含 20-60 字节头部和可变长度数据
- ✅ 序列号和确认号是可靠性的基础
- ✅ 标志位（SYN/ACK/FIN/RST）控制连接状态

**实战技能**：
- 使用 `ss`、`netstat` 查看连接状态
- 使用 `tcpdump` 抓包分析报文段结构
- 通过 `sysctl` 调整 TCP 参数

---

### [第二章：TCP 连接管理](./02-connection-management.md)
- 三次握手：建立连接的完整过程
- 四次挥手：优雅关闭连接
- TCP 状态机：11 种状态的转换逻辑
- TIME-WAIT 状态的作用与问题
- 连接复位（RST）与异常处理

**核心知识点**：
- ✅ 三次握手同步序列号，确认双向通信能力
- ✅ 四次挥手支持全双工的独立关闭
- ✅ TIME-WAIT 持续 2MSL，确保可靠关闭
- ✅ TCP 状态机覆盖连接的完整生命周期

**实战技能**：
- 使用 `ss -tan` 查看连接状态统计
- 诊断半连接队列、全连接队列问题
- 防御 SYN 洪水攻击（SYN Cookies）
- 优化 TIME-WAIT 连接数（`tcp_tw_reuse`）

---

### [第三章：可靠数据传输机制](./03-reliable-data-transfer.md)
- 序列号与确认号的详细运作
- 超时重传（RTO）与 Jacobson/Karels 算法
- 滑动窗口流量控制
- 快速重传（3 个重复 ACK）
- 零窗口探测与糊涂窗口综合症

**核心知识点**：
- ✅ 累积确认：确认号表示期待接收的下一个字节
- ✅ RTO 动态计算：SRTT + 4 × RTTVAR
- ✅ 滑动窗口 = min(接收窗口, 拥塞窗口)
- ✅ 快速重传：收到 3 个重复 ACK 立即重传

**实战技能**：
- 使用 `ss -tino` 查看 RTT、RTO、窗口大小
- 观察序列号和确认号的变化
- 模拟丢包触发快速重传（`tc netem`）
- 监控零窗口和窗口探测

---

### [第四章：TCP 拥塞控制](./04-congestion-control.md)
- 拥塞控制的四大算法
  - 慢启动（Slow Start）
  - 拥塞避免（Congestion Avoidance）
  - 快速重传（Fast Retransmit）
  - 快速恢复（Fast Recovery）
- 拥塞窗口（cwnd）与慢启动阈值（ssthresh）
- Linux 拥塞控制算法：Reno、Cubic、BBR
- 算法对比与场景选择

**核心知识点**：
- ✅ 慢启动：指数增长，快速探测网络容量
- ✅ 拥塞避免：线性增长，谨慎增加窗口
- ✅ 发送窗口 = min(rwnd, cwnd)
- ✅ Cubic：高带宽网络优化，Linux 默认
- ✅ BBR：基于 RTT 和带宽，适合高延迟/丢包网络

**实战技能**：
- 实时监控 `cwnd` 和 `ssthresh` 变化
- 对比 Reno、Cubic、BBR 的性能（`iperf3`）
- 模拟丢包观察拥塞控制响应
- 启用和配置 BBR 算法

---

### [第五章：TCP 高性能扩展](./05-high-performance-extensions.md)
- 长肥网络（LFN）的挑战
- 窗口缩放选项（Window Scale）
  - 支持 > 64 KB 窗口
  - 最大 1 GB 窗口
- 时间戳选项（Timestamps）
  - RTT 测量（RTTM）
  - 防止序列号回绕（PAWS）
- 选择性确认（SACK）
  - 减少不必要的重传
  - D-SACK：检测重复接收

**核心知识点**：
- ✅ 窗口缩放：实际窗口 = 窗口字段 × 2^缩放因子
- ✅ 时间戳：精确 RTT 测量 + PAWS 保护
- ✅ SACK：接收方明确告知已收到的非连续数据块
- ✅ D-SACK：检测不必要的重传，优化 RTO

**实战技能**：
- 观察窗口缩放协商（`tcpdump`）
- 查看时间戳值和 RTT（`ss -tino`）
- 对比启用/禁用 SACK 的性能差异
- 分析 SACK 块和 D-SACK 统计

---

## 🎯 学习路径

### 初学者路径
1. **基础入门**：第一章（报文段结构） → 第二章（连接管理）
2. **核心机制**：第三章（可靠传输） → 第四章（拥塞控制）
3. **进阶优化**：第五章（高性能扩展）

### 实践者路径
1. **抓包分析**：学习 tcpdump/Wireshark 分析 TCP 流
2. **性能调优**：调整 Linux TCP 参数，优化应用性能
3. **问题诊断**：排查连接问题、丢包、拥塞、TIME-WAIT

### 系统设计师路径
1. **协议深度理解**：掌握所有章节的理论和实现
2. **场景化应用**：不同网络环境的 TCP 优化策略
3. **协议扩展设计**：理解 TCP 扩展的设计思路

---

## 🛠️ 实战工具速查

### 抓包分析
```bash
# 捕获三次握手
sudo tcpdump -i any -nn 'tcp[tcpflags] & tcp-syn != 0' -vv -c 3

# 捕获特定连接的所有包
sudo tcpdump -i any -nn host example.com and port 80 -w capture.pcap

# 分析 SACK 选项
sudo tcpdump -i any -nn 'tcp' -vv | grep -E 'sack|SACK'
```

### 连接状态监控
```bash
# 查看所有连接状态
ss -tan

# 查看 ESTABLISHED 连接详情
ss -tino state established

# 实时监控 TIME-WAIT 连接数
watch -n 1 'ss -tan | grep TIME-WAIT | wc -l'
```

### TCP 参数查看
```bash
# 查看拥塞控制算法
sysctl net.ipv4.tcp_congestion_control

# 查看窗口缩放、SACK、时间戳状态
sysctl net.ipv4.tcp_window_scaling
sysctl net.ipv4.tcp_sack
sysctl net.ipv4.tcp_timestamps

# 查看连接的详细信息（cwnd, rtt, rto）
ss -tino | grep -A 3 ESTAB
```

### 性能测试
```bash
# 使用 iperf3 测试吞吐量
iperf3 -c example.com -t 30

# 模拟丢包（5%）
sudo tc qdisc add dev eth0 root netem loss 5%

# 模拟延迟（100ms）
sudo tc qdisc add dev eth0 root netem delay 100ms

# 恢复网络
sudo tc qdisc del dev eth0 root
```

---

## 📊 核心概念速查表

### TCP 报文段标志位
| 标志位 | 含义 | 典型组合 |
|--------|------|----------|
| SYN | 同步序列号 | SYN=1, ACK=0（连接请求） |
| ACK | 确认号有效 | SYN=1, ACK=1（连接确认） |
| FIN | 结束连接 | FIN=1, ACK=1（连接关闭） |
| RST | 重置连接 | RST=1（异常终止） |
| PSH | 推送数据 | PSH=1, ACK=1（数据传输） |

### TCP 状态机关键状态
| 状态 | 含义 | 触发条件 |
|------|------|----------|
| LISTEN | 监听状态 | 服务器等待连接 |
| SYN-SENT | 发送 SYN | 客户端发起连接 |
| ESTABLISHED | 连接建立 | 三次握手完成 |
| FIN-WAIT-1 | 发送 FIN | 主动关闭 |
| TIME-WAIT | 等待 2MSL | 主动关闭，收到 FIN |
| CLOSE-WAIT | 等待关闭 | 被动关闭，收到 FIN |

### 拥塞控制关键变量
| 变量 | 含义 | 典型值 |
|------|------|--------|
| cwnd | 拥塞窗口 | 初始 10 MSS，动态调整 |
| ssthresh | 慢启动阈值 | 初始 65535，丢包后 cwnd/2 |
| MSS | 最大报文段大小 | 1460 字节（以太网） |
| RTT | 往返时间 | 动态测量（ms 级） |
| RTO | 重传超时 | SRTT + 4 × RTTVAR |

### 高性能扩展选项
| 选项 | Kind | 长度 | 作用 |
|------|------|------|------|
| MSS | 2 | 4 | 协商最大报文段大小 |
| Window Scale | 3 | 3 | 窗口缩放因子（0-14） |
| SACK-Permitted | 4 | 2 | 支持选择性确认 |
| SACK | 5 | 可变 | 选择性确认块 |
| Timestamps | 8 | 10 | 时间戳（RTTM + PAWS） |

---

## 🔬 高级主题

### 长肥网络优化
- **带宽延迟乘积（BDP）**：带宽 × RTT
- **窗口缩放**：支持 > 64 KB 窗口（最大 1 GB）
- **SACK**：减少重传，提升丢包恢复速度
- **BBR 算法**：基于 RTT 和带宽，适合高延迟网络

### 特殊网络场景
- **数据中心网络**（低延迟、高带宽）
  - 使用 DCTCP 或 Cubic
  - 调大初始拥塞窗口
  - 启用 ECN（显式拥塞通知）

- **移动网络**（高延迟、丢包）
  - 使用 BBR 算法
  - 启用 SACK 和时间戳
  - 调整 RTO 参数

- **卫星网络**（极高延迟）
  - 窗口缩放因子 ≥ 10
  - 初始 ssthresh 设置很大
  - 使用 PEP（性能增强代理）

---

## 📖 参考资料

### RFC 文档
- [RFC 9293](../sources/rfc9293.txt): Transmission Control Protocol (TCP)
- [RFC 5681](../sources/rfc5681.txt): TCP Congestion Control
- [RFC 7323](../sources/rfc7323.txt): TCP Extensions for High Performance
- [RFC 2018](../sources/rfc2018.txt): TCP Selective Acknowledgment Options

### Linux 文档
- [tcp(7) man page](https://man7.org/linux/man-pages/man7/tcp.7.html)
- [ip-sysctl.txt](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

### 推荐书籍
- *TCP/IP Illustrated, Volume 1: The Protocols* by W. Richard Stevens
- *High Performance Browser Networking* by Ilya Grigorik

### 在线资源
- [Wireshark TCP Analysis](https://wiki.wireshark.org/TCP_Analyze_Sequence_Numbers)
- [BBR Congestion Control](https://queue.acm.org/detail.cfm?id=3022184)

---

## ✅ 学习检查清单

### 基础掌握
- [ ] 能够解释 TCP 报文段的每个字段
- [ ] 理解三次握手和四次挥手的完整过程
- [ ] 掌握 TCP 状态机的 11 种状态
- [ ] 理解序列号和确认号的工作原理

### 进阶理解
- [ ] 能够计算 RTO（SRTT + 4 × RTTVAR）
- [ ] 理解滑动窗口的流量控制机制
- [ ] 掌握慢启动和拥塞避免算法
- [ ] 理解快速重传和快速恢复

### 高级应用
- [ ] 能够使用 tcpdump 分析 TCP 流
- [ ] 会调整 Linux TCP 参数优化性能
- [ ] 理解窗口缩放、时间戳、SACK 的作用
- [ ] 能够对比不同拥塞控制算法

### 实战能力
- [ ] 能够诊断 TIME-WAIT 过多问题
- [ ] 会模拟网络条件测试 TCP 性能
- [ ] 能够分析 SACK 块和 D-SACK
- [ ] 掌握不同网络场景的 TCP 优化策略

---

## 🙏 致谢

本教程基于 IETF RFC 文档编写，结合 Linux 内核实现和实战经验，感谢以下资源：
- IETF TCP 工作组的标准文档
- Linux 内核开发者的实现
- 开源社区的工具和文档

---

**祝你学习愉快！掌握 TCP，成为网络协议专家！** 🚀
