# A-Lightweight-Firewall

基于Linux、Netfilter框架的轻量级防火墙。

基于Linux中的Netfilter框架，实现了一个轻量级防火墙，支持基于IP地址、端口、协议五元组的访问控制，支持基于MAC地址的访问控制，支持封禁PING、HTTP/HTTPS等功能，支持用户自定义安全策略，支持新增、删除、查看防火墙过滤规则。

一键使用：
  
    cd Firewall/kernel_module/
  
    make testload
  
    cd ..
  
    cd user/
  
    sudo gcc fwcontroller.c -o fwcontroller
  
    sudo ./fwcontroller
