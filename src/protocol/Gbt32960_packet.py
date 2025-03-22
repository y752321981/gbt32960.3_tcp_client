from dataclasses import dataclass, field
import struct
from datetime import datetime
from typing import List, ClassVar

from src.enums.AckEnum import AckEnum
from src.enums.DataDecodeEnum import DataDecodeEnum


@dataclass
class GBT32960Packet:
    """GBT32960.3 协议数据包"""
    MIN_LENGTH: ClassVar[int] = 25

    command_flag: int = 0
    ack_flag: int = 0
    vin: str = '0' * 17
    encrypt_mode: int = DataDecodeEnum.NONE
    data_length: int = 0
    data: List[int] = field(default_factory=list)
    verify: int = 0

    def __init__(self, **kwargs):
        self.command_flag = kwargs.get('command_flag', 0)
        self.ack_flag = kwargs.get('ack_flag', 0)
        self.vin = kwargs.get('vin', '')
        self.encrypt_mode = kwargs.get('encrypt_mode', 0)
        self.data_length = kwargs.get('data_length', 0)
        self.data = kwargs.get('data', [])
        self.verify = kwargs.get('verify', 0)

    def __str__(self) -> str:
        data_hex = [f"{x:02x}" for x in self.data]
        return (
            f"commandFlag={self.command_flag:02x}, ackFlag={self.ack_flag:02x}, "
            f"VIN={self.vin}, encryptMode={self.encrypt_mode:02x}, "
            f"dataLength={self.data_length}, data={data_hex}, verify={self.verify:02x}"
        )

    def make_response(self, ack_flag: AckEnum) -> 'GBT32960Packet':
        """生成响应数据包"""
        self.ack_flag = ack_flag.value
        self.data = self._get_current_time_bytes()
        self.data_length = len(self.data)
        self.encrypt_mode = DataDecodeEnum.NONE.value
        self.verify = self.calc_verify_code()
        return self

    def calc_verify_code(self) -> int:
        """计算异或校验码"""
        verify_code = self.command_flag
        verify_code ^= self.ack_flag

        # 处理VIN码
        for c in self.vin.encode('utf-8'):
            verify_code ^= c

        verify_code ^= self.encrypt_mode
        verify_code ^= (self.data_length >> 8) & 0xFF  # 高字节
        verify_code ^= self.data_length & 0xFF  # 低字节

        # 处理数据单元
        for byte in self.data:
            verify_code ^= byte

        return verify_code & 0xFF  # 确保结果为单字节

    def to_protocol_bytes(self) -> bytes:
        """转换为协议字节流"""
        header = b'##'  # 0x23 0x23

        # 数据单元长度 = 命令标识(1) + 应答标识(1) + VIN(17) + 加密(1) + 数据长度(2) + 数据(N)
        data_unit_length = 1 + 1 + 17 + 1 + 2 + self.data_length
        length_bytes = struct.pack('>H', data_unit_length)

        # 构建数据单元
        data_unit = bytes([
            self.command_flag,
            self.ack_flag,
            *self.vin.encode('utf-8'),
            self.encrypt_mode,
            (self.data_length >> 8) & 0xFF,
            self.data_length & 0xFF,
            *self.data
        ])

        # 完整报文 = 头(2) + 长度(2) + 数据单元 + 校验码(1)
        full_packet = (
                header +
                length_bytes +
                data_unit +
                bytes([self.verify])
        )
        return full_packet

    @staticmethod
    def _get_current_time_bytes() -> List[int]:
        """获取当前时间的BCD编码字节（6字节 YYMMDDHHMMSS）"""
        now = datetime.now()
        time_str = now.strftime("%y%m%d%H%M%S")
        return [int(time_str[i:i + 2], 16) for i in range(0, 12, 2)]