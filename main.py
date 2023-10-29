import sys
from scapy.layers.inet import *
from scapy.layers.l2 import *
import scapy.all as scapy
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QWidget, QMainWindow, QVBoxLayout, QLabel, QComboBox, QPushButton, QTableWidget, QTableWidgetItem, QTextEdit, QMessageBox, QFileDialog, QSplitter, QTreeWidget, QHeaderView, QAbstractItemView,QTreeWidgetItem, QHBoxLayout, QLineEdit
from PySide6.QtGui import QFont

from sniffer.packet_sniffer import PacketSniffer
import threading
from decimal import Decimal

class SnifferUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.sniffer = None
        self.setWindowTitle("Wirecat Sniffer")
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        # self.setGeometry(100, 100, 500, 300)
        self.layout = QVBoxLayout()
        self.label = QLabel("请选择需要捕获的接口：")
        self.buttons_layout = QHBoxLayout()
        self.start_button = QPushButton("开始捕获")
        self.stop_button = QPushButton("停止捕获")
        self.save_button = QPushButton("保存")
        self.open_button = QPushButton("打开")
        self.comboBox = QComboBox()

        self.buttons_layout2 = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("捕获过滤器：")

        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.save_button.clicked.connect(self.save_captured_packets)
        self.open_button.clicked.connect(self.open_pcap_file)

        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(False)

        self.packet_list_table = QTableWidget()
        self.packet_list_table.cellClicked.connect(self.display_hex_data)
        self.packet_list_table.setSortingEnabled(True)
        self.packet_list_table.verticalHeader().setVisible(False)

        self.packet_list_table.setShowGrid(False)
        self.packet_list_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.hex_display = QTextEdit()
        self.hex_display.setReadOnly(True)
        self.hex_display.setLineWrapMode(QTextEdit.NoWrap)
        self.main_splitter = QSplitter(Qt.Vertical)
        self.bottom_splitter = QSplitter(Qt.Horizontal)
        self.packet_analysis = QTreeWidget()
        self.packet_analysis.setHeaderHidden(True)
        self.init_ui()

    def init_ui(self):
        self.layout.addWidget(self.label)
        self.buttons_layout.addWidget(self.comboBox)
        self.buttons_layout2.addWidget(self.filter_edit)
        self.buttons_layout.addWidget(self.start_button)
        self.buttons_layout.addWidget(self.stop_button)
        self.buttons_layout2.addWidget(self.save_button)
        self.buttons_layout2.addWidget(self.open_button)
        self.layout.addLayout(self.buttons_layout)
        self.layout.addLayout(self.buttons_layout2)

        self.central_widget.setLayout(self.layout)
        self.packet_list_table.setColumnCount(7)
        self.packet_list_table.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.packet_list_table.setColumnWidth(0, 80)
        self.packet_list_table.setColumnWidth(1, 180)
        self.packet_list_table.setColumnWidth(2, 250)
        self.packet_list_table.setColumnWidth(3, 250)
        self.packet_list_table.setColumnWidth(4, 150)
        self.packet_list_table.setColumnWidth(5, 80)
        self.packet_list_table.setColumnWidth(6, 1000)
        self.packet_list_table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft)
        # self.layout.addWidget(self.packet_list_table)
        self.main_splitter.addWidget(self.packet_list_table)
        self.bottom_splitter.addWidget(self.packet_analysis)
        self.bottom_splitter.addWidget(self.hex_display)
        self.main_splitter.addWidget(self.bottom_splitter)
        self.layout.addWidget(self.main_splitter)
        self.populate_interface_list()

    def populate_interface_list(self):
        for interface in scapy.get_working_ifaces():
            self.comboBox.addItem(interface.name)

    def save_packets(self):
        # Ask the user to choose the save path and filename
        file_dialog = QFileDialog()
        file_dialog.setAcceptMode(QFileDialog.AcceptSave)
        file_dialog.setNameFilter("PCAP Files (*.pcap)")
        file_dialog.setDefaultSuffix("pcap")
        file_dialog.setFileMode(QFileDialog.AnyFile)

        if file_dialog.exec():
            selected_files = file_dialog.selectedFiles()
            if selected_files:
                file_path = selected_files[0]
                # save_packets(file_path)
                scapy.wrpcap(file_path,self.sniffer.captured_packets)  # Implement save_packets to save the captured packets

    def show_save_dialog(self):
        msg_box = QMessageBox()
        msg_box.setWindowTitle("Save Captured Packets")
        msg_box.setText("Do you want to save the captured packets?")
        msg_box.setStandardButtons(QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel)
        msg_box.setDefaultButton(QMessageBox.Save)
        ret = msg_box.exec()
        if ret == QMessageBox.Save:
            self.save_packets()
            self.sniffer.captured_packets.clear()
            self.packet_list_table.clearContents()
            self.packet_list_table.setRowCount(0)
            return True
        elif ret == QMessageBox.Discard:
            self.sniffer.captured_packets.clear()
            self.packet_list_table.clearContents()
            self.packet_list_table.setRowCount(0)
            return True
        else:
            return False

    def start_capture(self):
        start_flag = True

        selected_interface = self.comboBox.currentText()
        if selected_interface:
            print(f"Selected interface: {selected_interface}")

            if self.sniffer and self.sniffer.captured_packets:
                start_flag = self.show_save_dialog()
            if start_flag:
                self.start_button.setEnabled(False)
                self.stop_button.setEnabled(True)
                self.save_button.setEnabled(False)
                filter_text = self.filter_edit.text().strip()
                self.sniffer = PacketSniffer(selected_interface, filter_text or None, self.add_packet_to_table)
                # self.sniffer.start_sniffing()
                # Start packet capture in a separate thread
                capture_thread = threading.Thread(target=self.sniffer.start_sniffing)
                capture_thread.daemon = True
                capture_thread.start()

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop_sniffing()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.save_button.setEnabled(True)

    def save_captured_packets(self):
        if self.sniffer and self.sniffer.captured_packets:
            self.save_packets()

    def open_pcap_file(self):
        if self.sniffer and self.sniffer.captured_packets:
            start_flag = self.show_save_dialog()
            if start_flag:
                file_dialog = QFileDialog()
                file_dialog.setAcceptMode(QFileDialog.AcceptOpen)
                file_dialog.setNameFilter("PCAP Files (*.pcap)")
                file_dialog.setFileMode(QFileDialog.ExistingFile)

                if file_dialog.exec():
                    selected_files = file_dialog.selectedFiles()
                    if selected_files:
                        file_path = selected_files[0]
                        filter_text = self.filter_edit.text().strip()
                        self.packet_list_table.clearContents()
                        self.packet_list_table.setRowCount(0)

                        self.sniffer = PacketSniffer(filter=filter_text or None, packet_callback=self.add_packet_to_table)
                        capture_thread = threading.Thread(target=self.sniffer.sniff_from_pacp(file_path))
                        capture_thread.daemon = True
                        capture_thread.start()


    def add_packet_to_table(self, packet):
        row_position = self.packet_list_table.rowCount()
        self.packet_list_table.insertRow(row_position)

        self.packet_list_table.setItem(row_position, 0, QTableWidgetItem(str(row_position + 1)))
        self.packet_list_table.setItem(row_position, 1, QTableWidgetItem(str(timestamp2time(packet.time))))
        src = packet[Ether].src
        dst = packet[Ether].dst
        type = packet[Ether].type
        types = {0x0800:'IPv4',0x0806:'ARP',0x86dd:'IPv6',0x88cc:'LLDP',0x891D:'TTE'}
        if type in types:
            proto = types[type]
        else:
            proto = 'LOOP'  # 协议
        # IP
        if proto == 'IPv4':
            # 建立协议查询字典
            protos = {1: 'ICMP', 2: 'IGMP', 4: 'IP', 6: 'TCP', 8: 'EGP', 9: 'IGP', 17: 'UDP', 41: 'IPv6', 50: 'ESP', 89:'OSPF'}
            src = packet[IP].src
            dst = packet[IP].dst
            proto=packet[IP].proto
            if proto in protos:
                proto=protos[proto]
        # tcp
        if TCP in packet:
            protos_tcp = {80: 'Http', 443: 'Https', 23: 'Telnet', 21: 'Ftp', 20: 'ftp_data', 22: 'SSH', 25: 'SMTP'}
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            if sport in protos_tcp:
                proto = protos_tcp[sport]
            elif dport in protos_tcp:
                proto = protos_tcp[dport]
        elif UDP in packet:
            if packet[UDP].sport == 53 or packet[UDP].dport == 53:
                proto = 'DNS'
        self.packet_list_table.setItem(row_position, 2, QTableWidgetItem(src))
        self.packet_list_table.setItem(row_position, 3, QTableWidgetItem(dst))
        self.packet_list_table.setItem(row_position, 4, QTableWidgetItem(proto))
        self.packet_list_table.setItem(row_position, 5, QTableWidgetItem(str(len(packet))))
        self.packet_list_table.setItem(row_position, 6, QTableWidgetItem(str(packet.summary())))
        self.packet_list_table.scrollToBottom()


    def display_hex_data(self, row, col):
    # When a cell is clicked, get the corresponding packet and display its hexadecimal data
        if row >= 0 and col >= 0:
            packet_no = int(self.packet_list_table.item(row, 0).text()) - 1
            if 0 <= packet_no < len(self.sniffer.captured_packets):
                packet = self.sniffer.captured_packets[packet_no]  # Adjust as needed to access your captured packets
                hex_data = hexdump(packet, dump=True)
                self.hex_display.setPlainText(hex_data)

                # Create a top-level item for the Ethernet header
                self.packet_analysis.clear() # Clear
                self.add_packet_layers_to_tree(packet)

    def add_packet_layers_to_tree(self, packet_layer):
        if packet_layer is None:
            return

        # Create an item for the current layer
        layer_item = QTreeWidgetItem(self.packet_analysis)
        layer_item.setText(0, packet_layer.name)

        # Add fields of the current layer as child items
        for field in packet_layer.fields_desc:
            field_item = QTreeWidgetItem(layer_item)
            field_value = packet_layer.getfieldval(field.name)
            field_item.setText(0, f"{field.name}: {field_value}")

        # Recursively process the next layer
        payload = packet_layer.payload
        if payload:
            self.add_packet_layers_to_tree(payload)

def timestamp2time(timestamp):
    if isinstance(timestamp, float):
        # 处理正常抓包时的时间戳格式
        time_array = time.localtime(timestamp)
        mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    elif isinstance(timestamp, Decimal):
        # 处理从文件读取时的时间戳格式
        timestamp_str = str(timestamp)
        if '.' in timestamp_str:
            seconds, milliseconds = timestamp_str.split('.')
            seconds = int(seconds)
            milliseconds = int(milliseconds)
        else:
            seconds = int(timestamp_str)
            milliseconds = 0

        time_array = time.localtime(seconds)
        mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
        mytime += f".{milliseconds:03}"  # 添加毫秒部分

    return mytime


if __name__ == "__main__":
    app = QApplication(sys.argv)
    # Set the Consolas font for the entire UI
    font = QFont("Consolas")
    app.setFont(font)
    window = SnifferUI()
    window.show()
    sys.exit(app.exec())
