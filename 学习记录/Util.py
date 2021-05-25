#! /usr/bin/env python
import socket
import struct
import random
import re
class Util(object):
    """docstring for Util"""
    def __init__(self, arg):
        super(Util, self).__init__()
        self.arg = arg
        self.head_oonc=[
                      0x4f, 0x4f, 0x4e, 0x43, 0x00, 0x00, 0x01, 0x00,
                      0x10, 0x00, 0x00, 0x00, 0x19, 0x6d, 0x6a, 0xf9,
                      0x29, 0x5b, 0xb9, 0x46, 0xab, 0x95, 0x8a, 0x14,
                      0x3e, 0xcd, 0xdc, 0x26, 0xc0, 0xa8, 0x1f, 0x0b,
                      0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                      0x9a, 0x0a, 0x00, 0x00
                      ]
        self.canc =[  
                      0x43, 0x41, 0x4e, 0x43, 0x00, 0x00, 0x01, 0x00,
                      0x54, 0x00, 0x00, 0x00, 0x19, 0x6d, 0x6a, 0xf9,
                      0x29, 0x5b, 0xb9, 0x46, 0xab, 0x95, 0x8a, 0x14,
                      0x3e, 0xcd, 0xdc, 0x26, 0x01, 0x00, 0x0e, 0x00,
                      0xc0, 0xa8, 0x1f, 0x0b, 0x01, 0x00, 0x00, 0x00,
                      0x01, 0x00, 0x00, 0x00, 0x54, 0x00, 0x65, 0x00,
                      0x61, 0x00, 0x63, 0x00, 0x68, 0x00, 0x65, 0x00,
                      0x72, 0x00, 0x00, 0x00
                      ]

    # 格式化要发送的消息
    def format_b4_send(content):
        arr = []
        for ch in content:
            tmp = ''.join(list(map(lambda x: hex(ord(x)), ch)))
            if int(tmp, 16) > 0xff:
                tmp = tmp[2:]
                high = int((tmp[0] + tmp[1]), 16)
                low = int((tmp[2] + tmp[3]), 16)
                arr.append(low)
                arr.append(high)
            else:
                high = 0
                low = int((tmp[2] + tmp[3]), 16)
                arr.append(low)
                arr.append(high)
        return arr
    #16进制'0x00'形式输出bytes
    def print_hex(bytes):
        l = [hex(int(i)) for i in bytes]
        print(" ".join(l))
     #16进制 00 形式输出bytes
    def print_hex2(bytes):
        l = [(''.join(hex(int(i))).replace("0x",'').zfill(2)) for i in bytes]  
        print(' '.join(l))

        #计算UDP/TCP/IP检验和
    def checksum(data):
        s = 0
        n = len(data) % 2
        for i in range(0, len(data)-n, 2):
            s+=  (data[i]) + ((data[i+1]) << 8)
        if n:
            s+= (data[i+1])
        while (s >> 16):
            s = (s & 0xFFFF) + (s >> 16)
        s = ~s & 0xffff
        return s
     #将字符串以 00 00 格式输出
    def mySplit2(str):
        t = str.upper()
        p = re.compile('.{1,2}')  # 匹配任意字符1-2次
        return ' '.join(p.findall(t))
    #将字符串以 00 00 格式输出
    def mySplit3(str):
        t = str.upper()
        return ' '.join([t[2*i:2*(i+1)] for i in range(len(t)/2)])
    def format16(str):
      l = []
      for i in range(len(str)):
        if i % 2 ==0:
          q = int('0x' + (str[i:i+2]),16)
          l.append(q)
      return l

    def gethostip():
      return socket.gethostbyname(socket.gethostname())
