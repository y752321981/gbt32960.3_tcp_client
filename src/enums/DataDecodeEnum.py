from enum import Enum

class DataDecodeEnum(Enum):
    NONE = 1
    RSA = 2
    AES = 3
    ERROR = 0xfe
    INVALID = 0xff
    
