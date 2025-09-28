# 实验与练习

本章提供可操作的实践，帮助加深对 RFC 791 与 Linux 实现的理解。

实验 1：观察 TTL 与转发

- 使用 `traceroute` 或 `mtr` 观察不同 TTL 下的跳数与 ICMP Time Exceeded。
- 对本机发出的包抓包（`tcpdump -ni any icmp or ip`），观察每跳返回的 ICMP。

实验 2：PMTUD 与 DF 行为

- 在一台 Linux 主机上降低某接口 MTU：`ip link set dev eth0 mtu 1200`。
- 使用 `ping -M do -s 1472 <目标>` 强制 DF，观察是否收到 “Frag Needed” 的 ICMP；
- 抓包确认 ICMP 包内携带的 Next-Hop MTU 信息。

实验 3：IP 分片与重组

- 发送大包但允许分片：`ping -s 4000 <目标>`（某些实现需 `-M want`）。
- 在接收端抓包，观察多片（MF=1/0）、Fragment Offset 与 Identification。
- 调整 `sysctl -w net.ipv4.ipfrag_time=10`，模拟重组超时丢弃行为（实验环境谨慎）。

实验 4：IP 选项（在受控网络）

- 使用 scapy 构造带 RR/TS 的 IP 包，验证中间节点是否记录或直接丢弃。
- 对比不同设备/系统的默认策略（多数生产网络会丢弃源路由选项）。

实验 5：校验和与硬件卸载

- 使用 `ethtool -k eth0` 查看 checksum offload；
- 开关卸载后抓包对比首部校验和是否由主机/网卡计算。

参考抓包表达式：

```bash
tcpdump -ni any 'ip[6:2] & 0x3fff != 0'   # 有分片的 IPv4
tcpdump -ni any 'icmp'                    # ICMP 差错
tcpdump -ni any 'ip and not tcp and not udp' # 观察非典型流量
```

注意：请在测试环境操作，避免影响生产网络。

