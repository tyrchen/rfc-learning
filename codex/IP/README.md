# IP 协议教程（基于 RFC 791）

本教程系统讲解 IPv4（RFC 791）协议，采用循序渐进的教学风格，结合 Linux 内核实现细节，帮助你从规范到工程实现地理解 IP。全篇包含示意图、流程图与实践建议，可作为学习与查阅手册。

- 目标读者：具备基础网络常识的工程师或学生
- 参考标准：RFC 791（IPv4），并适度对比现代实现
- 实践平台：Linux（内核路径以 `net/ipv4/*` 为主）

目录：

1. [总览与定位](./01-overview.md)
2. [IP 首部结构与字段](./02-header.md)
3. [路由、TTL 与转发](./03-routing-ttl-forwarding.md)
4. [分片与重组](./04-fragmentation-reassembly.md)
5. [IP 选项（Options）](./05-options.md)
6. [校验和与差错处理](./06-checksum.md)
7. [Linux 内核中的 IPv4 实现](./07-implementation-linux.md)
8. [实验与练习](./08-examples-labs.md)
9. [参考与延伸阅读](./99-references.md)

建议按顺序阅读；也可按需跳转到特定主题。

