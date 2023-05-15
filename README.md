# A-Lightweight-Firewall
基于Linux、Netfilter框架的轻量级防火墙

基于Linux中的Netfilter框架，实现了一个轻量级防火墙，支持基于IP地址、端口、协议五元组的访问控制，支持基于MAC地址的访问控制，支持用户自定义访问控制策略，支持封禁PING、HTTP/HTTPS等功能，支持设置和修改防火墙启用时间，支持新增、删除、查看防火墙过滤规则，支持记录和查看防火墙日志文件。

一键使用：

    cd /home/ubuntu/Firewall/kernel_module/
  
    make testload
  
    cd ..
  
    cd user/
  
    sudo gcc fwcontroller.c -o fwcontroller
  
    sudo ./fwcontroller

操作系统：Ubuntu 20.04

内核版本：Linux 5.4.0-148-generic

编译环境：gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)

小提示：记得在头文件 myfirewall.h 中修改一下防火墙日志文件的路径 LOG_FILE，我的路径是 /home/ubuntu/Firewall/log.txt。
