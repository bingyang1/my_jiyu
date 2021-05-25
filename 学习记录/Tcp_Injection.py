#! /usr/bin/env python
import socket
import struct
import random


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
 
class ip():
    def __init__(self, source, destination):
        self.version = 4
        self.ihl = 5          # Internet Header Length
        self.tos = 0          # Type of Service
        self.tl = 0           # total length will be filled by kernel
        self.id = random.randint(0, 65535)
        self.flags = 0        # More fragments
        self.offset = 0       # Data offset: 5x4 = 20 bytes 数据偏移，4位，该字段的值是TCP首部（包括选项）长度乘以4。
        self.ttl = 255
        self.protocol = socket.IPPROTO_IP
        self.checksum = 0 # will be filled by kernel
        self.source = socket.inet_aton(source)
        self.destination = socket.inet_aton(destination)

    def pack(self):
        ver_ihl = (self.version << 4) + self.ihl
        flags_offset = (self.flags << 13) + self.offset
        ip_header = struct.pack("!BBHHHBBH4s4s",
                    ver_ihl,
                    self.tos,
                    self.tl,
                    self.id,
                    flags_offset,
                    self.ttl,
                    self.protocol,
                    self.checksum,
                    self.source,
                    self.destination)
        return ip_header
 
class tcp():
    def __init__(self, srcp, dstp,payload=''):
        self.srcp = srcp #source port  源端口，16位。
        self.dstp = dstp #destination_port  目的端口，16位。
        self.seqn = 0    #Sequence   Number 发送数据包中的第一个字节的序列号，32位。    
        self.ackn = 0    #Acknowledgment Number 是确认序列号，32位。     
        self.offset = 5  # Data offset: 5x4 = 20 bytes 数据偏移，4位，该字段的值是TCP首部（包括选项）长度乘以4。
        self.reserved = 0
        #标志位： 6位
        self.urg = 0     
        self.ack = 0     # ACK表示Acknowledgment Number字段有意义
        self.psh = 1     # PSH表示Push功能，RST表示复位TCP连接
        self.rst = 0     # 
        self.syn = 0     # SYN表示SYN报文（在建立TCP连接的时候使用）
        self.fin = 0     # FIN表示没有数据需要发送了（在关闭TCP连接的时候使用）
        self.window = socket.htons(5840) # Window表示接收缓冲区的空闲空间，16位，用来告诉TCP连接对端自己能够接收的最大数据长度。
        self.checksum = 0 # Checksum是校验和，16位。
        self.urgp = 0    #Urgent Pointers 是紧急指针，16位，只有URG标志位被设置时该字段才有意义，表示紧急数据相对序列号（Sequence Number字段的值）的偏移。
        self.payload = payload #data 要发送的数据
 
    def pack(self, source, destination):
        data_offset = (self.offset << 4) + 0
        flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
        tcp_header = struct.pack("!HHLLBBHHH",
                     self.srcp,
                     self.dstp,
                     self.seqn,
                     self.ackn,
                     data_offset,
                     flags, 
                     self.window,
                     self.checksum,
                     self.urgp)
        #pseudo header fields 构造TCP伪头部字段
        source_ip = source
        destination_ip = destination
        reserved = 0
        protocol = socket.IPPROTO_TCP
        total_length = len(tcp_header) + len(self.payload)
        # Pseudo header 构造TCP头部
        psh = struct.pack("!4s4sBBH",
              source_ip,
              destination_ip,
              reserved,
              protocol,
              total_length)
        psh = psh + tcp_header + self.payload.encode()
        tcp_checksum = checksum(psh)
        tcp_header = struct.pack("!HHLLBBH",
                  self.srcp,
                  self.dstp,
                  self.seqn,
                  self.ackn,
                  data_offset,
                  flags,
                  self.window)
        tcp_header+= struct.pack("H", tcp_checksum) + struct.pack("!H", self.urgp)
        return tcp_header
 
class UDP(object):
    def __init__(self, source,destination,sport,dport,data=''):
        super(UDP, self).__init__()
        self.source = source             # 源地址
        self.destination = destination   # 目的地址
        self.data = data                 # 数据段
        self.sport =sport                # arbitrary source port
        self.dport = dport               # arbitrary destination port
        self.length = 8+len(data);       # UDP 头部长度
        self.checksum =0                 #检验和


    def create_udp_header(self,proto=socket.IPPROTO_UDP):
        n=0
        pseudo_header = struct.pack('!4s4sBBH',
                                    socket.inet_aton(self.source), socket.inet_aton(self.destination), 0,
                                    proto, self.length)
        self.checksum = checksum(pseudo_header)
        udp_header = struct.pack('!HHHH', self.sport, self.dport, self.length, self.checksum)
        return packet
           
    def send(self): 
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        
        data = bytes(self.data)
        udp_header = struct.pack('!HHHH', self.sport, self.dport, self.length, self.checksum)
        packet = udp_header+data
        s.sendto(packet, (self.destination, self.dport));
        s.close()

def test(source,destination,sport,dport,data):
    s = socket.socket(socket.AF_INET,
                  socket.SOCK_RAW,
                  socket.IPPROTO_RAW)
    # IP Header
    ipobj=ip(source,destination)
    iph=ipobj.pack()
    # TCP Header
    tcpobj=tcp(sport,dport)
    tcpobj.data_length=len(data)
    tcph=tcpobj.pack(ipobj.source,ipobj.destination)
    # Injection
    packet=iph+tcph+bytes(data)
    s.sendto(packet,(destination,dport))
    s.close()
 
if __name__ == '__main__':

  source_ip = "10.0.0.1"
  destination_ip = "6.6.6.6"
  source_prot =random.randint(1, 65535)
  destination_port = 6666

  try:
    UDP(source_ip,destination_ip,source_prot,destination_port,"This is TCP Data".encode()).send() 
  except Exception as e:
    print(e)
  else:
    print("UDP数据发送成功")
    
