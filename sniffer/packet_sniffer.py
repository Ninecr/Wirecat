import scapy.all as scapy
from time import sleep
from concurrent.futures import ThreadPoolExecutor

class PacketSniffer:
    def __init__(self, interface = None, filter = None, packet_callback = None):
        self.interface = interface
        self.filter = filter  # 过滤器
        self.packet_count = 0
        self.packet_callback = packet_callback
        self.stop_sniff = False
        self.captured_packets = []


    def start_sniffing(self):
        scapy.sniff(iface=self.interface, prn=self.process_packet, stop_filter=self.should_stop, filter=self.filter)

    def sniff_from_pacp(self, pacp_file):
        scapy.sniff(offline=pacp_file, prn=self.process_packet, filter=self.filter)

    def process_packet(self, packet):
        # 增加数据包计数
        self.packet_count += 1
        # 将数据包添加到列表中
        self.captured_packets.append(packet)
        # sleep(1)
        if self.packet_callback:
            self.packet_callback(packet)


    def should_stop(self, packet):
        return self.stop_sniff

    def stop_sniffing(self):
        # 停止嗅探逻辑，例如关闭捕获线程或执行清理操作
        self.stop_sniff = True


