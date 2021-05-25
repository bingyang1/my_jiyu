# 极域杀手(Python)脚本版

##  写在前面

写这个最初是源于兴趣.开始的时候接触到极域杀手，感觉挺有趣的。查阅相了关资料，便开始搭建环境对极域电子教室进行抓包分析。原来是不太想写记录的，嫌太麻烦，但是后来想想觉得不能让我的辛苦白费，好歹写个记录表示一下存在感。虽然吧，这个脚本也差不多是我东拼西凑的。

## 正式开始

### 0x00 实验环境

1.   Windows XP 虚拟机 * 5
2.  极域电子教室2016豪华版
3.  WireShark 抓包工具

### 0x01 实验原理

#### 1. UDP

**1.1 UDP数据包首部**

![image-20201204193633422](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201204193633422.png)

**1.2 IP分包UDP数据包**

![image-20201204194449827](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201204194449827.png)

#### 2.  cmd操作防火墙

```powershell
Windows防火墙cmd
os.system("netsh firewall set opmode mode=disable")

命令：netsh firewall 

　　参数： 

　　? // 显示命令列表 

　　add // 添加防火墙配置 

　　delete // 删除防火墙配置 

　　dump // 显示一个配置脚本 

　　help // 显示命令列表 

　　reset // 将防火墙配置重置为默认值。 

　　set // 设置防火墙配置 

　　show // 显示防火墙配置 

　　add allowedprogram // 添加防火墙允许的程序配置。 

　　add portopening // 添加防火墙端口配置 

　　delete allowedprogram // 删除防火墙允许的程序配置 

　　delete portopening // 删除防火墙端口配置 

　　set allowedprogram // 设置防火墙允许的程序配置 

　　set icmpsetting // 设置防火墙 ICMP 配置 

　　set logging // 设置防火墙记录配置 

　　set multicastbroadcastresponse // 设置防火墙多播/广播响应配置 

　　set notifications // 设置防火墙通知配置 

　　set opmode // 设置防火墙操作配置 

　　set portopening // 设置防火墙端口配置 

　　set service // 设置防火墙服务配置 

　　show allowedprogram // 显示防火墙允许的程序配置 

　　show config // 显示防火墙配置。 

　　show currentprofile // 显示当前防火墙配置文件 

　　show icmpsetting // 显示防火墙 ICMP 配置 

　　show logging // 显示防火墙记录配置 

　　show multicastbroadcastresponse // 显示防火墙多播/广播响应配置 
　　show notifications // 显示防火墙操作配置 

　　show opmode // 显示防火墙端口配置 

　　show portopening // 显示防火墙端口配置 

　　show service // 显示防火墙服务配置 

　　show state // 显示当前防火墙状态　　 

　　例如： 

　　命令：netsh firewall show allowedprogram //查看防火墙放行的程序 

　　netsh firewall set portopening TCP 445 ENABLE //打开445端口 

　　netsh firewall set portopening TCP 3389 ENABLE // 

　　netsh firewall delete allowedprogram C:\A.exe //删除放行程序A.exe 

　　netsh firewall set allowedprogram C:\A.exe A ENABLE //添加程序C盘下的A.exe并放行 

　　netsh firewall add allowedprogram C:\A.exe A ENABLE //添加程序C盘下的A.exe并放行

    netsh firewall set icmpsettting type=ALL mode=enable //开启ICMP协议 

    netsh firewall set icmpsettting type=2 mode=enable  //允许出站数据包太大
```

以上命令执行完会提示

重要信息: 已成功执行命令。
但是，"netsh firewall" 已弃用；
请改用 "netsh advfirewall firewall" 。
有关使用 "netsh advfirewall firewall" 命令
而非 "netsh firewall" 的详细信息，请参阅
 https://go.microsoft.com/fwlink/?linkid=121488 上的 KB 文章 947709。

故使用这个

```powershell
netsh advfirewall firewall add rule name="Chrome"  dir=out  program="Chrome.exe"  action=block      #新建防火墙规则

netsh advfirewall firewall set rule name='Chrome' new enable=no    #禁用指定规则

netsh advfirewall firewall set rule name='Chrome' new enable=yes     #开启指定规则
```

#### 3. os.popen()与os.system()的区别

os.system()是简单粗暴的执行cmd指令无法获取在cmd输出的内容

os.popen() 会以文件的形式返回输出结果

![image-20201204225357225](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201204225357225.png)

### 0x02 实验过程

#### 1.构造UDP数据包

```python
class UDP(object):
    '''
    构建UDP数据包
    '''
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
```

计算校验和

```python
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
```

测试构造的TCP数据包

```python
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
    UDP(source_ip,destination_ip,source_prot,destination_port,"This is TCP Data").send() 
  except Exception as e:
    print(e)
  else:
    print("UDP数据发送成功")
```

测试结果:![image-20201204200012353](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201204200012353.png)

![image-20201204200126205](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201204200126205.png)

#### 2.  抓包分析各个功能数据包

通过抓取完整的登录退出过程,对抓取到的数据包进行分析,我们锁定了一个数据包,通过重发数据包,发现,只要持续重发这个数据包,教师端就会与学生端断开连接.

![image-20201209151730492](C:/Users/55037/AppData/Roaming/Typora/typora-user-images/image-20201209151730492.png)

```bash
464e58540000010014000000a03a43ce447d6542a22134b6be1a615d0a0a550f01000000000c29f67de6000042006900
```



#### 3.  编写完善脚本

### 实验总结

## 参考资料

https://www.52pojie.cn/forum.php?mod=viewthread&tid=1092295&highlight=%BC%AB%D3%F2 抓包思路

https://www.52pojie.cn/forum.php?mod=viewthread&tid=1188109&highlight=%BC%AB%D3%F2 功能参考

https://github.com/ht0Ruial/Jiyu_udp_attack 代码参考

https://blog.csdn.net/sinat_25449961/article/details/88353378  tcp/ip 

https://www.cnblogs.com/linuxbug/p/4906000.html udp

https://www.cnblogs.com/gtea/p/12672813.html python 下 cmd操作防火墙

https://blog.csdn.net/weixin_43625577/article/details/88258369 cmd 建立防火墙规则

https://www.cnblogs.com/yoyoketang/p/9083932.html os.system与 os.popen的区别