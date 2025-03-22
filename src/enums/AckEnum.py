from enum import Enum

class AckEnum(Enum):
    SUCCESS = 1
    FAIL = 2
    NOT_ACK = 0xfe
