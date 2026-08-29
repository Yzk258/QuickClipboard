import struct
import json
from dataclasses import dataclass

# 本文件为项目所用协议的完整定义代码

VERSION = 1               # 协议版本号，目前固定为1，后续版本可以在此基础上进行扩展

MSG_TYPE_LOGIN = 0x01     # 登录操作
MSG_TYPE_PUT = 0x02       # 上传剪贴板数据
MSG_TYPE_GET = 0x03       # 获取剪贴板数据
MSG_TYPE_RESP = 0x04      # 服务器响应
MSG_TYPE_PING = 0x05      # 心跳
MSG_TYPE_EXIT = 0x06      # 退出连接

STATUS_OK = 200           # 成功
STATUS_BAD_REQUEST = 400  # 请求错误，例如缺少必要字段、数据格式错误等
STATUS_UNAUTHORIZED = 401 # 未授权，例如登录失败、未登录等
STATUS_NOT_FOUND = 404    # 未找到，例如请求的资源不存在、用户不存在等
STATUS_TOO_LARGE = 413    # 请求体过大，例如上传的剪贴板数据超过限制等
STATUS_INTERNAL_ERROR = 500 # 服务器内部错误，例如处理请求时发生异常等
STATUS_UNKNOWN_ERROR = 114514 # 未知错误，例如发生了未预料的情况等

MAX_BODY_SIZE = 64 * 1024  # 64 KB

HEADER_FORMAT = "!BBHII"  # 协议头格式：按照大端序，version(1 byte), msg_type(1 byte), status(2 bytes), body_len(4 bytes), reserved(4 bytes)
HEADER_SIZE = struct.calcsize(HEADER_FORMAT) # 12 bytes


@dataclass
class ProtocolHeader:  # 协议头数据类
    version: int       # 协议版本
    msg_type: int      # 消息类型
    status: int        # 状态码
    body_len: int      # 协议体长度
    reserved: int = 0  # 保留字段，暂未使用，默认为0

    def pack(self) -> bytes: # 将协议头打包成字节数据

        return struct.pack(
            HEADER_FORMAT,
            self.version,
            self.msg_type,
            self.status,
            self.body_len,
            self.reserved
        ) 
    
    @staticmethod
    def unpack(data: bytes): # 从字节数据中解析协议头
        
        if len(data) != HEADER_SIZE:
            raise ValueError("首部长错误！")

        header = struct.unpack(HEADER_FORMAT, data)

        return ProtocolHeader(*header)
    

def encode_body(data: dict) -> bytes: # 将字典数据编码成字节数据，使用JSON格式进行序列化
    
    data_str = json.dumps(data)
    return data_str.encode("utf-8")

def decode_body(data_bytes: bytes) -> dict: # 将字节数据解码成字典数据，使用JSON格式进行反序列化

    data_str = data_bytes.decode("utf-8")
    return json.loads(data_str)


def make_packet( # 构造协议数据包
    msg_type: int,
    status: int = STATUS_OK,
    body: dict = None
) -> bytes:
    
    if body is None:
        body = {}

    body_bytes = encode_body(body)

    if len(body_bytes) > MAX_BODY_SIZE:
        raise ValueError("数据量过大！请减小数据量！")
    
    header = ProtocolHeader( # 构造协议头
        version = VERSION,
        msg_type = msg_type,
        status = status,
        body_len = len(body_bytes),
        reserved = 0
    )

    return header.pack() + body_bytes


def recv_exact(sock, size: int) -> bytes: # 从套接字中接收指定大小的字节数据，直到接收完成或连接断开

    data = b""

    while len(data) < size:
        chunk = sock.recv(size - len(data))

        if not chunk:
            return None
        
        data += chunk
    
    return data

def recv_packet(sock): # 从套接字中接收一个完整的协议数据包，返回协议头和协议体

    header_data = recv_exact(sock, HEADER_SIZE)

    if header_data is None:
        return None, None
    
    header = ProtocolHeader.unpack(header_data)

    if header.body_len > MAX_BODY_SIZE:
        raise ValueError("数据量过大！请减小数据量！")
    
    body_data = recv_exact(sock, header.body_len)

    if body_data is None:
        return None, None
    
    body = decode_body(body_data)

    return header, body




