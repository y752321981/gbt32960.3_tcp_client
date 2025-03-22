import socket
import threading
from typing import Callable, Optional
from src.protocol.Gbt32960_packet import GBT32960Packet


class Gbt32960Client:
    def __init__(self, server_ip: str, server_port: int, vin: str):
        self.server_ip = server_ip
        self.server_port = server_port
        self.vin = vin.ljust(17, '0')
        self.sock: Optional[socket.socket] = None
        self.alarm = 0x00000000
        self.status = 0xFF
        self.callback: Optional[Callable[[GBT32960Packet], None]] = None
        self.receive_thread: Optional[threading.Thread] = None
        self.is_connected = False

    def connect(self):
        """建立TCP连接并启动接收线程"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.server_ip, self.server_port))
        self.is_connected = True
        print(f"Connected to {self.server_ip}:{self.server_port}")

        # 启动接收线程
        self.receive_thread = threading.Thread(target=self._receive_loop, daemon=True)
        self.receive_thread.start()

    def disconnect(self):
        """断开连接并清理资源"""
        if self.sock:
            self.is_connected = False
            self.sock.close()
            if self.receive_thread and self.receive_thread.is_alive():
                self.receive_thread.join(timeout=2)
            print("Connection closed")

    def register_callback(self, callback: Callable[[GBT32960Packet], None]):
        """注册数据接收回调函数"""
        self.callback = callback

    def send(self, packet: GBT32960Packet):
        """发送协议数据包"""
        if self.sock:
            data = packet.to_protocol_bytes()
            self.sock.sendall(data)

    def _receive_loop(self):
        """接收数据的线程循环"""
        buffer = bytearray()
        header_size = 4  # ##(2字节) + 数据单元长度(2字节)

        while self.is_connected:
            try:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break

                buffer.extend(chunk)

                # 处理完整报文
                while len(buffer) >= header_size:
                    # 验证起始标识
                    if buffer[0] != 0x23 or buffer[1] != 0x23:
                        buffer.pop(0)
                        continue

                    # 获取数据单元长度
                    data_unit_length = (buffer[2] << 8) | buffer[3]
                    total_length = header_size + data_unit_length + 1  # 总长度 = 头 + 数据单元 + 校验码

                    if len(buffer) < total_length:
                        break  # 等待更多数据

                    # 提取完整报文
                    full_packet = bytes(buffer[:total_length])
                    del buffer[:total_length]

                    # 解析数据包
                    packet = self._parse_packet(full_packet)
                    if packet and self.callback:
                        self.callback(packet)

            except (ConnectionResetError, BrokenPipeError):
                print("Connection lost")
                self.disconnect()
            except Exception as e:
                print(f"Receive error: {str(e)}")
                self.disconnect()

    def _parse_packet(self, data: bytes) -> Optional[GBT32960Packet]:
        """解析接收到的原始数据"""
        try:
            # 基本验证
            if len(data) < GBT32960Packet.MIN_LENGTH:
                return None

            # 提取校验码
            received_checksum = data[-1]
            calculated_checksum = self._calculate_checksum(data[:-1])

            if received_checksum != calculated_checksum:
                print("Checksum mismatch")
                return None

            # 构建数据包对象
            packet = GBT32960Packet()
            # 根据协议结构解析各个字段...
            # 这里需要根据实际协议结构实现具体解析逻辑

            return packet

        except Exception as e:
            print(f"Parse error: {str(e)}")
            return None

    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """计算异或校验码"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        return checksum & 0xFF
