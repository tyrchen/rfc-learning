# Linux 内核中的 IPv4 实现概览

本章从工程角度梳理 Linux 的 IPv4 路径，帮助将 RFC 语义与实际代码建立联系。以下路径仅概览核心节点，具体细节会因内核版本与配置有所差异。

接收路径（RX）：

```mermaid
flowchart TB
  A[NIC 收到帧] --> B[驱动/IRQ -> NAPI]
  B --> C[软中断 -> 报文上交]
  C --> D[以太网解封装 (eth_type_trans)]
  D --> E[ip_rcv() 校验首部/IHL/长度]
  E --> F{目的为本机?}
  F -- 是 --> G[ip_local_deliver() 递交上层(udp_rcv/tcp_v4_rcv/...)]
  F -- 否 --> H[ip_forward() TTL--, 查FIB, 可能分片]
  H --> I[ip_output()/邻居子系统 ARP 解析 -> 发送]
```

发送路径（TX）：

```mermaid
flowchart LR
  A[套接字写 send()/sendto()] --> B[传输层 tcp_transmit_skb/udp_sendmsg]
  B --> C[ip_local_out() 填首部/校验]
  C --> D[ip_output() 路由/分片]
  D --> E[邻居子系统 neigh_output -> dev_queue_xmit]
  E --> F[NIC 发送]
```

关键文件与函数（典型位置）：

- 输入：`net/ipv4/ip_input.c` 中的 `ip_rcv()`, `ip_local_deliver()`。
- 输出：`net/ipv4/ip_output.c` 中的 `ip_local_out()`, `ip_output()`。
- 转发：`net/ipv4/ip_forward.c` 中的 `ip_forward()`。
- 分片：`net/ipv4/ip_fragment.c` 中的 `ip_do_fragment()`, `ip_defrag()`。
- 路由：`net/ipv4/fib_*`（如 `fib_trie.c`）实现最长前缀匹配与 FIB 维护。
- 邻居/ARP：`net/ipv4/arp.c` 与通用邻居子系统 `net/core/neighbour.c`。
- 校验和：`include/net/ip.h` 宏与 `arch/*/lib/checksum*`。

Netfilter 钩子（影响路径）：

- `NF_INET_PRE_ROUTING`：`ip_rcv()` 之后，路由判定之前。
- `NF_INET_LOCAL_IN`：递交本机前。
- `NF_INET_FORWARD`：转发路径上。
- `NF_INET_LOCAL_OUT`：本机发包路径。
- `NF_INET_POST_ROUTING`：离开主机前。

GSO/GRO 与性能：

- GRO（接收合并）在 Rx 合并多个小报文，减少上送次数；
- GSO（发送分段）将大报文在栈末或 NIC 处分段；
- 与 IP 分片不同，GSO/GRO 面向主机内部栈优化，外部看到仍是合法 MTU 大小的 IP 包。

安全与健壮性：

- 重叠分片、畸形选项、异常 TTL 等路径均有健壮性检查与速率限制；
- rp_filter、反射攻击防护、RPF 检查等在策略层面加强安全；
- sysctl 提供大量可调参数（如 `ip_forward`, `ipfrag_*`, `icmp_*`）。
