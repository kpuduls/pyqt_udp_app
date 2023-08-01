import sys
import socket
import threading
import queue
from PyQt5.QtCore import pyqtSignal, QObject
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QPushButton, QLineEdit

MESSAGE_SIZE_IN_BYTES = 5  # Assuming each message has a fixed size of 5 bytes


class Message:
    def __init__(self, header, data_length, data_payload, crc):
        self.header = header
        self.data_length = data_length
        self.data_payload = data_payload
        self.crc = crc


class UDPSocket:
    def __init__(self, ip='192.168.10.10', port=14002):
        self.ip = ip
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.ip, self.port))


class UDPTx:
    def __init__(self, udp_socket, ip, port):
        self.ip = ip
        self.port = port
        self.udp_socket = udp_socket

    def send(self, data):
        self.udp_socket.sock.sendto(bytearray.fromhex(data), (self.ip, self.port))


class UDPRx(QObject):
    received_data = pyqtSignal(str)

    def __init__(self, udp_socket):
        super().__init__()
        self.udp_socket = udp_socket
        self.queue = queue.Queue()

    def _receive_data(self):
        while True:
            data, addr = self.udp_socket.sock.recvfrom(1024)
            self.queue.put(data)
            self.received_data.emit(f'Received data: {data} from {addr}')

    def start_receiving(self):
        self.thread = threading.Thread(target=self._receive_data)
        self.thread.daemon = True
        self.thread.start()


class DataProcessor(QObject):
    def __init__(self, data_queue):
        super().__init__()
        self.data_queue = data_queue
        self.valid_message_flag = False

    def process_data(self, message_length_in_bytes):
        while not self.data_queue.empty():
            data = self.data_queue.get()
            try:
                if len(data) >= message_length_in_bytes:
                    # Extract a potential message from the front of the queue
                    message_bytes = data[:message_length_in_bytes]

                    # Parse the message bytes
                    header = message_bytes[0]
                    data_length = int.from_bytes(message_bytes[1:3], byteorder='big')
                    data_payload = message_bytes[3:-1]
                    crc = message_bytes[-1]

                    message = Message(header, data_length, data_payload, crc)
                    self.process_message(message)

                    self.valid_message_flag = True

            except Exception as e:
                print(f"Error processing data: {e}")

    def process_message(self, message):
        # Implement your processing logic here based on the message content
        print(
            f"Received message with header: {message.header}, data length: {message.data_length}, and CRC: {message.crc}")
        print(f"Data payload: {message.data_payload}")


class UDPApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle('UDP App')

        self.server_ip = '192.168.10.100'
        self.client_ip = '192.168.10.10'

        self.client_port = 14002
        self.server_port = 14001

        self.udp_socket = UDPSocket(ip=self.client_ip, port=self.client_port)
        self.tx = UDPTx(self.udp_socket, ip=self.server_ip, port=self.server_port)
        self.rx = UDPRx(self.udp_socket)
        self.data_processor = DataProcessor(self.rx.queue)

        self.rx.received_data.connect(self.on_received_data)
        self.rx.start_receiving()

        self.data_label = QLabel('Enter data to send:')
        self.data_entry = QLineEdit()
        self.send_button = QPushButton('Send')
        self.send_button.clicked.connect(self.send_data)

        self.receive_label = QLabel('Received data:')
        self.receive_text = QTextEdit()
        self.receive_text.setReadOnly(True)

        self.parse_button = QPushButton('Parse')
        self.parse_button.clicked.connect(self.parse_data)

        self.message_length_label = QLabel('Message Length in Bytes:')
        self.message_length_entry = QLineEdit()
        self.message_length_entry.setText(str(MESSAGE_SIZE_IN_BYTES))

        # vertical layout
        vlayout = QVBoxLayout()
        vlayout.addWidget(self.data_label)
        vlayout.addWidget(self.data_entry)
        vlayout.addWidget(self.send_button)
        vlayout.addWidget(self.receive_label)
        vlayout.addWidget(self.receive_text)

        # Add a horizontal layout
        hbox_layout = QHBoxLayout()
        hbox_layout.addWidget(self.message_length_label)
        hbox_layout.addWidget(self.message_length_entry)
        hbox_layout.addWidget(self.parse_button)

        vlayout.addLayout(hbox_layout)


        self.setLayout(vlayout)

    def send_data(self):
        data = self.data_entry.text()
        self.tx.send(data)

    def parse_data(self):
        message_length_in_bytes = int(self.message_length_entry.text())
        self.data_processor.process_data(message_length_in_bytes)

    def on_received_data(self, data_str):
        self.receive_text.append(data_str)


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = UDPApp()
    window.show()

    sys.exit(app.exec_())
