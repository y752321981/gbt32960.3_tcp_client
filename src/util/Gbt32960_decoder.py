import struct
from loguru import logger
from typing import List

from src.protocol.Gbt32960_packet import GBT32960Packet


class GBT32960Decoder:
    def __init__(self):
        self.buffer = bytearray()
        self.START_BYTES = b'##'
        self.MIN_LENGTH = 25

    def feed_data(self, data: bytes):
        """接收原始字节数据并存入缓冲区"""
        self.buffer.extend(data)

    def parse_packets(self) -> List['GBT32960Packet']:
        """尝试从缓冲区解析完整数据包"""
        packets = []

        while len(self.buffer) >= self.MIN_LENGTH:
            # 查找起始标识
            start_pos = self.buffer.find(self.START_BYTES)
            if start_pos == -1:
                self.buffer.clear()
                break

            if start_pos > 0:
                # 丢弃起始标识前的无效数据
                del self.buffer[:start_pos]
                continue

            # 检查最小可用长度
            if len(self.buffer) < self.MIN_LENGTH:
                break

            # 读取命令标识 (位置2)
            cmd_flag = self.buffer[2]
            ack_flag = self.buffer[3]

            # 读取VIN (位置4-20)
            vin_bytes = self.buffer[4:21]
            vin = vin_bytes.decode('utf-8', errors='ignore').strip('\x00')

            # 加密方式 (位置21)
            encrypt_mode = self.buffer[21]

            # 数据单元长度 (位置22-23)
            data_length = struct.unpack('>H', self.buffer[22:24])[0]

            # 总包长度 = 24(头) + data_length + 1(校验)
            total_length = 24 + data_length + 1

            if data_length > 400:
                logger.warning("Invalid data length: %d", data_length)
                del self.buffer[:total_length]
                continue

            if len(self.buffer) < total_length:
                break  # 等待完整数据包

            # 提取完整数据包
            packet_bytes = bytes(self.buffer[:total_length])
            del self.buffer[:total_length]

            # 解析数据单元
            data_start = 24
            data_end = data_start + data_length
            data = list(packet_bytes[data_start:data_end])

            # 校验码
            received_checksum = packet_bytes[-1]

            # 构建数据包对象
            packet = GBT32960Packet(
                command_flag=cmd_flag,
                ack_flag=ack_flag,
                vin=vin,
                encrypt_mode=encrypt_mode,
                data_length=data_length,
                data=data,
                verify=received_checksum
            )

            # 校验验证
            calculated_checksum = self._calculate_checksum(packet_bytes[:-1])
            if calculated_checksum != received_checksum:
                logger.warning("Checksum mismatch")
                continue

            packets.append(packet)

        return packets

    @staticmethod
    def _calculate_checksum(data: bytes) -> int:
        """计算异或校验码"""
        checksum = 0
        for byte in data:
            checksum ^= byte
        return checksum & 0xFF
