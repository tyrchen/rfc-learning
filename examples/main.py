from scapy.all import *

def main():
    send_ip()

def send_ip():
    # 构造IP数据包
    ip_packet = IP(
        version=4,
        ihl=5,
        tos=0x10,  # 低延迟
        id=12345,
        flags="DF",  # 不分片
        ttl=64,
        proto=1,  # ICMP
        src="192.168.1.100",
        dst="8.8.8.8"
    )

    # 添加ICMP载荷
    icmp_packet = ICMP(type=8, code=0)  # Echo Request

    # 组合并发送
    packet = ip_packet/icmp_packet
    send(packet)

    # 查看数据包详情
    packet.show()

    # 查看原始字节
    hexdump(packet)


if __name__ == "__main__":
    main()
