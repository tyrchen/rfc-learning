# 参考与延伸阅读

- RFC 791: Internet Protocol
- RFC 1122: Requirements for Internet Hosts — Communication Layers
- RFC 1191: Path MTU Discovery
- RFC 5722: Handling of Overlapping IPv6 Fragments（IPv4 安全实践亦受其影响）
- RFC 6864: Updated Specification of the IPv4 ID Field
- RFC 1812: Requirements for IP Version 4 Routers
- RFC 2474/3168: Differentiated Services 和 ECN（与 TOS 关系）

实现与工具：

- Linux 源码：`net/ipv4/`（`ip_input.c`, `ip_output.c`, `ip_forward.c`, `ip_fragment.c`, `fib_*` 等）
- 邻居与 ARP：`net/core/neighbour.c`, `net/ipv4/arp.c`
- `iproute2`：`ip(8)`, `tc(8)`；抓包：`tcpdump(8)`, `wireshark`

推荐书籍：

- TCP/IP 详解（卷一：协议）
- 计算机网络：自顶向下方法（理解分层与设计权衡）

