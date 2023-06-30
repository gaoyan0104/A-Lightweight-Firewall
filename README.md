# A-Lightweight-Firewall
基于Linux、Netfilter框架的轻量级状态检测防火墙

基于 Linux 中的 Netfilter 框架，实现了一个轻量级状态检测防火墙，支持对数据包的状态检测和过滤，支持基于 IP 地址、端口、协议五元组的访问控制，支持基于 MAC 地址的访问控制，支持基于用户自定义策略的访问控制，支持封禁 PING 、 HTTP/HTTPS 等功能，支持设置和修改防火墙启用时间，支持查看和修改防火墙过滤规则，支持查看和记录防火墙日志文件。

操作系统：Ubuntu 20.04

内核版本：Linux 5.4.0-148-generic

编译环境：gcc version 9.4.0 (Ubuntu 9.4.0-1ubuntu1~20.04.1)

一键使用：

    cd Firewall/kernel_module/
  
    make load
  
    cd ..
  
    cd user/
  
    sudo gcc fwcontroller.c -o fwcontroller -D _XOPEN_SOURCE
  
    sudo ./fwcontroller

小提示：记得在头文件 myfirewall.h 中修改一下防火墙日志文件的路径 LOG_FILE，我的路径是 /home/ubuntu/Firewall/log.txt。


Netfilter框架：

Netfilter 是 Linux 内核中进行数据包过滤，连接跟踪（Connect Track），网络地址转换（NAT）等功能的主要实现框架；该框架在网络协议栈处理数据包的关键流程中定义了一系列钩子点（Hook 点），并在这些钩子点中注册一系列函数对数据包进行处理。这些注册在钩子点的函数即为设置在网络协议栈内的数据包通行策略，也就意味着，这些函数可以决定内核是接受还是丢弃某个数据包，换句话说，这些函数的处理结果决定了这些网络数据包的“命运”。

<img src="https://github.com/gaoyan0104/A-Lightweight-Firewall/blob/master/img/netfilter.jpg" width="700px">

其中，矩形方框中的即为 Netfilter 的钩子节点。从图中可以看到，三个方向的数据包需要经过的钩子节点不完全相同：

发往本地：NF_INET_PRE_ROUTING-->NF_INET_LOCAL_IN

转发：NF_INET_PRE_ROUTING-->NF_INET_FORWARD-->NF_INET_POST_ROUTING

本地发出：NF_INET_LOCAL_OUT-->NF_INET_POST_ROUTING


sk_buff 结构：

在 Linux 内核中，系统使用 sk_buff 数据结构对数据包进行存储和管理。在数据包接收过程中，该数据结构从网卡驱动收包开始，一直贯穿到内核网络协议栈的顶层，直到用户态程序从内核获取数据。使用图形表示 sk_buff 的结构如下：
<img src="https://github.com/gaoyan0104/A-Lightweight-Firewall/blob/master/img/sk_buff.jpg" width="700px">
在 sk_buff 数据结构中包含了诸多关于数据包存储，定位和管理的指针，数据包在网络协议栈各层次之间进行传输的过程中，内核通过操作指针的方式对数据包进行逐层解析，避免频繁的大数据段拷贝操作，从而提高数据包处理效率。
