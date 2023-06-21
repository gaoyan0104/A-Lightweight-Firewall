#include <linux/module.h>
#include <linux/init.h> 
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include "myfirewall.h"

static DEFINE_SPINLOCK(log_lock);               // 定义静态自旋锁

static struct nf_hook_ops nfhoLocalIn;  	    // 在数据路由后处理本机数据包的钩子
static struct nf_hook_ops nfhoLocalOut;  	    // 在本地数据未路由之前的钩子
static struct nf_hook_ops nfhoPreRouting;     	// 在数据路由之前的钩子
static struct nf_hook_ops nfhoForwarding;     	// 在数据路由后处理转发数据包的钩子
static struct nf_hook_ops nfhoPostRouting;      // 在本地数据路由之后的钩子
static struct nf_sockopt_ops nfhoSockopt;       // 处理内核和用户间通信钩子

// 防火墙过滤规则
ban_status rules, recv;

// 定时器变量
static struct timer_list connect_timer;

// 状态连接链表的表头和表尾
Connection connHead, connEnd;

// 状态检测Hash表
time_t hashTable[TABLE_SIZE] = {0};

// HASH锁
char hashLock = 0;

// 声明延迟 work，设置回调函数为 wirte_log，
void wirte_log(struct work_struct *work);
static DECLARE_DELAYED_WORK(my_work, wirte_log);

// 日志表
static Log logs[LOG_NUM_MAX] = {0};

// 未写入日志文件的日志数
static int log_num = 0;

// Hash函数
static unsigned get_hash(int k) 
{
	unsigned a, b, c = 4;
    a = b = 0x9e3779b9;
    a += k;
	a -= b; a -= c; a ^= (c >> 13); 
	b -= c; b -= a; b ^= (a << 8); 
	c -= a; c -= b; c ^= (b >> 13); 
	a -= b; a -= c; a ^= (c >> 12);  
	b -= c; b -= a; b ^= (a << 16); 
	c -= a; c -= b; c ^= (b >> 5); 
	a -= b; a -= c; a ^= (c >> 3);  
	b -= c; b -= a; b ^= (a << 10); 
	c -= a; c -= b; c ^= (b >> 15); 

    return c % TABLE_SIZE;
}

// 检测该数据包的连接是否已建立
bool check_conn(struct sk_buff *skb) 
{
	struct iphdr *ip = ip_hdr(skb);
	unsigned int src_ip = ntohl(ip->saddr);
	unsigned int dst_ip = ntohl(ip->daddr);

	int src_port;
	int dst_port;
	int protocol;
	unsigned int scode;
	unsigned int pos;    

	if (!skb) return true;

	if (ip->protocol == IPPROTO_TCP) 
	{
		struct tcphdr *tcp = tcp_hdr(skb);
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		protocol = TCP;
	}
	else if (ip->protocol == IPPROTO_UDP) 
	{
		struct udphdr *udp = udp_hdr(skb);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		protocol = UDP;
	}
	else if (ip->protocol == IPPROTO_ICMP)
	{
		src_port = -1;
		dst_port = -1;
		protocol = ICMP;
	}
	else 
	{
		// 不记录状态
		return false;
	}

	scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
	pos = get_hash(scode);

	while(hashLock);  
	hashLock = 1;     

	if (hashTable[pos])
	{
		// 更新连接时间
		hashTable[pos] = CONNECT_TIME;
		// 开锁
		hashLock = 0;
		return true;
	}

	hashLock = 0;
	return false;
}

// 更新状态检测连接哈希表
void update_hashTable(struct sk_buff *skb) 
{
	struct iphdr *ip = ip_hdr(skb);
	unsigned int src_ip = ntohl(ip->saddr);
	unsigned int dst_ip = ntohl(ip->daddr);

	int src_port;
	int dst_port;
	int protocol;
	unsigned int scode;
	unsigned int pos;   
	Connection *conn_node;

	if (rules.connNum < CONN_NUM_MAX)
	{
		// 区分协议类型
		if (ip->protocol == IPPROTO_TCP) 
		{
			struct tcphdr *tcp = tcp_hdr(skb);
			src_port = ntohs(tcp->source);
			dst_port = ntohs(tcp->dest);
			protocol = TCP;
		}
		else if (ip->protocol == IPPROTO_UDP) 
		{
			struct udphdr *udp = udp_hdr(skb);
			src_port = ntohs(udp->source);
			dst_port = ntohs(udp->dest);
			protocol = UDP;
		}
		else if (ip->protocol == IPPROTO_ICMP) 
		{
			src_port = -1;
			dst_port = -1;
			protocol = ICMP;
		}

		scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
		pos = get_hash(scode);

		while(hashLock);  
		hashLock = 1;	  

		hashTable[pos] = CONNECT_TIME;
		// 开锁
		hashLock = 0;

		++rules.connNum;
		conn_node = (Connection *)kmalloc(sizeof(Connection), GFP_ATOMIC);
		conn_node->src_ip = src_ip;
		conn_node->dst_ip = dst_ip;
		conn_node->src_port = src_port;
		conn_node->dst_port = dst_port;
		conn_node->protocol = protocol;
		conn_node->index = pos;

		// printk("Add connnection. src IP: %d.%d.%d.%d\n", 
		// (src_ip & 0x000000ff) >> 0, (src_ip & 0x0000ff00) >> 8,
		// (src_ip & 0x00ff0000) >> 16, (src_ip & 0xff000000) >> 24);

		// 头插法
		conn_node->next = connHead.next;  
		connHead.next = conn_node;	
	}
	else
	{
		printk("The number of connections exceeds the maximum.\n");
	}
}

// 定时器回调函数
void time_out(struct timer_list *timer)
{
	Connection *p = connHead.next, *pre = &connHead;

	while(hashLock);
	hashLock = 1;    // 加锁
	
	while(p != &connEnd) 
	{
		hashTable[p->index]--;
		if (hashTable[p->index] == 0) 
		{
			// 连接超时
			pre->next = p->next;
			kfree(p);
			p = pre->next;
			rules.connNum--;
		}
		else 
		{
			pre = p;
			p = p->next;
		}
	}
            
	hashLock = 0; // 开锁
	connect_timer.expires = jiffies + HZ;  	// 重新设置过期时间为1s后
	add_timer(&connect_timer);
}

// 获取系统当前时间
void get_time(char *time_buf, int len)
{
	ktime_t k_time;
	struct rtc_time tm;  

	k_time = ktime_get_real();
	tm = rtc_ktime_to_tm(k_time);  

	snprintf(time_buf, len, "%d-%d-%d %d:%d:%d", 
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour + 8, tm.tm_min, tm.tm_sec);
}

// 清空链表
void release_list(Connection *head, Connection *tail) 
{
    Connection *p = head->next;
    while (p != tail) 
	{
        Connection *temp = p;
        p = p->next;
        kfree(temp);
    }
    head->next = tail;
    tail->next = NULL;
}

// IP地址格式转换
void convert_ip(unsigned int ip, char* ip_str, size_t size)
{
	snprintf(ip_str, size, "%u.%u.%u.%u", 
	(ip & 0x000000ff) >> 0,(ip & 0x0000ff00) >> 8,(ip & 0x00ff0000) >> 16,(ip & 0xff000000) >> 24);
}

// 增加日志到数组中
bool add_log(struct sk_buff* skb, char *rule_str)
{
	struct iphdr *iph = ip_hdr(skb);                    
	char time_buf[64]; 
	get_time(time_buf, sizeof(time_buf)); 

	if (log_num == LOG_NUM_MAX)
	{
		printk("The currently retained logs have reached the maximum value.\n");
		return false;
	}
	
	logs[log_num].src_ip = iph->saddr;
	logs[log_num].dst_ip = iph->daddr;

	if (iph->protocol == IPPROTO_TCP)
	{
		struct tcphdr *tcph = tcp_hdr(skb);    
		logs[log_num].src_port = ntohs(tcph->source);
		logs[log_num].dst_port = ntohs(tcph->dest);    
		strcpy(logs[log_num].protocol, "TCP");
	}
	else if (iph->protocol == IPPROTO_UDP)
	{
		struct udphdr *udph = udp_hdr(skb);     
		logs[log_num].src_port = ntohs(udph->source); 
		logs[log_num].dst_port = ntohs(udph->dest);
		strcpy(logs[log_num].protocol, "UDP");    
	}
	else if (iph->protocol == IPPROTO_ICMP)
	{
		logs[log_num].src_port = -1; 
		logs[log_num].dst_port = -1;       
		strcpy(logs[log_num].protocol, "ICMP");		
	}
	else
	{
		strcpy(logs[log_num].protocol, "ELSE");	
	}

	memcpy(logs[log_num].curr_time, time_buf, sizeof(time_buf)); 
	memcpy(logs[log_num].filter_rule, rule_str, sizeof(logs[log_num].filter_rule)); 
	log_num++;
	
	return true;
}

// 写防火墙日志文件
void wirte_log(struct work_struct *work)
{
	static mm_segment_t old_fs;
	struct file *fp;
	int len;         
	char buf[256]; 
	int i;
	int err;
	
	spin_lock(&log_lock);    // 加锁
	fp = filp_open(LOG_FILE, O_WRONLY|O_CREAT|O_APPEND, 0644);
	err = PTR_ERR(fp);
	if (IS_ERR(fp))
	{
		if (err == -ENOENT) 
		{
			printk("Failed to open file: file not found.\n");
		} 
		else if (err == -EACCES) 
		{
			printk("Failed to open file: permission denied.\n");
		} 
		else if (err == -ENOSPC) 
		{
			printk("Failed to open file: file system is full.\n");
		} 
		else 
		{
			printk("Failed to open file: error code %d\n", err);
		}

        spin_unlock(&log_lock);
		printk("无法打开文件，已解锁...\n");
		return;
	}

	// 移动内核堆栈指针到内核数据空间
    old_fs = get_fs();  
    set_fs(KERNEL_DS); 

	for (i = 0; i < log_num; i++)
	{
		len = snprintf(buf, sizeof(buf), "Time: %s\t\tProtocol: %s\t\tSrc IP: %d.%d.%d.%d\t\tDst IP: %d.%d.%d.%d\t\tSrc Port: %d\t\tDst Port: %d\t\tFilter Rule: %s\t\tAction：Deny\n", logs[i].curr_time, logs[i].protocol, 
		(logs[i].src_ip & 0x000000ff) >> 0,(logs[i].src_ip & 0x0000ff00) >> 8,(logs[i].src_ip & 0x00ff0000) >> 16,(logs[i].src_ip & 0xff000000) >> 24, 
		(logs[i].dst_ip & 0x000000ff) >> 0,(logs[i].dst_ip & 0x0000ff00) >> 8,(logs[i].dst_ip & 0x00ff0000) >> 16,(logs[i].dst_ip & 0xff000000) >> 24, logs[i].src_port, logs[i].dst_port, logs[i].filter_rule);
		
		kernel_write(fp, buf, len, &fp->f_pos);
	}
	// printk("A total of %d logs were written...\n", log_num);
	
	// 把内核堆栈指针恢复到原来的值
    set_fs(old_fs);

	filp_close(fp, NULL);
	spin_unlock(&log_lock);    // 解锁

	log_num = 0;
	memset(&logs, 0, sizeof(logs));
		
    // 重新设置 work 延时执行
    queue_delayed_work(system_wq, &my_work, msecs_to_jiffies(10000));
}

// 判断是否为PING包
bool is_PING(struct iphdr *iph)
{
	if (iph->protocol == IPPROTO_ICMP)
	{
		return true;
	}
	return false;
}

// 判断是否为HTTP/HTTPS包
bool is_HTTP(struct iphdr *iph, struct tcphdr *tcph)
{
	if (iph->protocol == IPPROTO_TCP)
	{		
		if ((tcph->dest == htons(80)) || (tcph->dest == htons(443)) || (tcph->dest == htons(8080)) 
		|| (tcph->source == htons(80)) || (tcph->source == htons(443)) || (tcph->source == htons(8080)))
		{
			return true;	
		}
	}
	return false;
}

// 判断是否为Telnet包
bool is_TELNET(struct iphdr *iph, struct tcphdr *tcph)
{
	if (iph->protocol == IPPROTO_TCP && tcph->dest == htons(23))
	{
		return true;
	}
	return false;
}

unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb);                    
	struct tcphdr *tcph = tcp_hdr(skb);    
	struct udphdr *udph = udp_hdr(skb); 

	char src_ip_str[16];
	char dst_ip_str[16];
	char time_buf[64]; 

	convert_ip(iph->saddr, src_ip_str, sizeof(src_ip_str));
	convert_ip(iph->daddr, dst_ip_str, sizeof(dst_ip_str));
	get_time(time_buf, sizeof(time_buf)); 

	if (rules.open_status == 0)
	{
		 return NF_ACCEPT;  
	} 

	if (rules.settime_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("current date： %ld  Start date： %ld  end date： %ld\n", current_time, rules.start_date, rules.end_date);
		if (current_time < rules.start_date || current_time >= rules.end_date)
		{
			printk("Time: %s. The firewall is not in effect at the current time\n", time_buf);
			return NF_ACCEPT;
		}
	}

	if (rules.inp_status == 1)            
	{
		// 状态检测
		if (check_conn(skb)) 
		{
			// printk("status check passed\n");
			return NF_ACCEPT;  
		}
	}

	// 基于源IP地址访问控制
	if (rules.sip_status == 1)
	{
		int sip_number;
		for (sip_number = 0; sip_number < rules.sipNum; sip_number++)
		{
			// printk("Src IP: %d.%d.%d.%d\n",
			// (rules.ban_dip[sip_number] & 0x000000ff) >> 0, (rules.ban_dip[sip_number] & 0x0000ff00) >> 8,
			// (rules.ban_dip[sip_number] & 0x00ff0000) >> 16, (rules.ban_dip[sip_number] & 0xff000000) >> 24);
			
			if (rules.ban_sip[sip_number] == iph->saddr)
			{  	
				printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\n\n", time_buf, src_ip_str, dst_ip_str);
				add_log(skb, "Source IP");
				return NF_DROP;
			}
		}
	}

	// 基于目的IP地址访问控制
	if (rules.dip_status == 1)
	{
		int dip_number;
		for (dip_number = 0; dip_number < rules.dipNum; dip_number++)
		{
			if (rules.ban_dip[dip_number] == iph->daddr)
			{  
				printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\n\n", time_buf, src_ip_str, dst_ip_str);
				add_log(skb, "Destination IP");
				return NF_DROP;
			}
		}
	}

	// 基于源端口的访问控制
	if (rules.sport_status == 1)
	{
		switch(iph->protocol)  
		{          
			case IPPROTO_TCP:
			{
				int sport_numberi;
				for (sport_numberi = 0; sport_numberi < rules.sportNum; sport_numberi++)
				{
					unsigned short sport = ntohs(rules.ban_sport[sport_numberi]);
					if (tcph->source == sport)
					{
						printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\tSrc port: %hu\n\n", time_buf, src_ip_str, dst_ip_str, rules.ban_sport[sport_numberi]);
						add_log(skb, "Source port");
						return NF_DROP;
					}
				}
				break;
			}
			case IPPROTO_UDP:
			{
				int sport_numberj;
				for (sport_numberj = 0; sport_numberj < rules.sportNum; sport_numberj++)
				{
					unsigned short sport = ntohs(rules.ban_sport[sport_numberj]);
					if (udph->source == sport)
					{
						printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\tSrc port: %hu\n\n", time_buf, src_ip_str, dst_ip_str, rules.ban_sport[sport_numberj]);
						add_log(skb, "Source port");
						return NF_DROP;
					}
				}
				break;
			}
		}
	}

	// 基于目的端口的访问控制
	if (rules.dport_status == 1)
	{
		// int i;
		// for (i = 0; i < rules.dportNum; i++){
		// 	unsigned short dport = ntohs(rules.ban_dport[i]);
		// 	printk("Host endianness port number received by kernel space：%hu\n", dport);
		// }
		switch(iph->protocol)  
		{           
			case IPPROTO_TCP:
			{
				int dport_numberi;
				for (dport_numberi = 0; dport_numberi < rules.dportNum; dport_numberi++)
				{
					unsigned short dport = ntohs(rules.ban_dport[dport_numberi]);
					if (tcph->dest == dport)
					{	
						printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\tDest port: %hu\n\n", time_buf, src_ip_str, dst_ip_str, rules.ban_dport[dport_numberi]);
						add_log(skb, "Destination port");
						return NF_DROP;
					}
				}
				break;
			}
			case IPPROTO_UDP:
			{
				int dport_numberj;
				for (dport_numberj = 0; dport_numberj < rules.dportNum; dport_numberj++)
				{
					unsigned short dport = ntohs(rules.ban_dport[dport_numberj]);
					if (udph->dest == dport)
					{
						printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\tDest port: %hu\n\n", time_buf, src_ip_str, dst_ip_str, rules.ban_dport[dport_numberj]);
						add_log(skb, "Destination port");
						return NF_DROP;
					}
				}
				break;
			}
		}
	}
	
	// PING功能的控制
	if (rules.ping_status == 1)
	{
		if (is_PING(iph))
		{
			printk("Time: %s. PING from %s is deny\n", time_buf, src_ip_str);
			add_log(skb, "PING Disabled");
			return NF_DROP;
		}
	}

	// HTTP/HTTPS功能的控制
	if (rules.http_status == 1)
	{
		if (is_HTTP(iph, tcph))
		{
			printk("Time: %s. HTTP/HTTPS request is deny\n", time_buf);
			add_log(skb, "HTTP/HTTPS Disabled");
			return NF_DROP;		
		}
	}

	// Telnet功能的控制
	if (rules.telnet_status == 1)
	{
		if (is_TELNET(iph, tcph))
		{
			printk("Time: %s. Telnet request is deny\n", time_buf);
			add_log(skb, "Telnet Disabled");
			return NF_DROP;
		}
	}

	// 基于协议类型的访问控制                       
	if (rules.protocol_status == 1)
	{
		switch(iph->protocol)
		{
			case IPPROTO_TCP:         
				if (rules.protocol_type[0])
				{
					printk("Time: %s. TCP request is deny\n", time_buf);
					add_log(skb, "Protocol");
					return NF_DROP;
				}
				break;
			case IPPROTO_UDP:         
				if (rules.protocol_type[1])
				{
					printk("Time: %s. UDP request is deny\n", time_buf);
					add_log(skb, "Protocol");
					return NF_DROP;
				}				
				break;
			case IPPROTO_ICMP:         
				if (rules.protocol_type[2])
				{
					printk("Time: %s. ICMP request is deny\n", time_buf);
					add_log(skb, "Protocol");
					return NF_DROP;
				}						
				break;
			default:
				break;	
		}
	}
	
	// 关闭所有连接功能的控制
	if (rules.close_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("curr: %ld\n", current_time);
		// printk("start: %ld\n", rules.start_time);
		// printk("end: %ld\n", rules.end_time);
		if (rules.start_time <= current_time && rules.end_time >= current_time)
		{
			printk("Time: %s. Request is deny. \nSrc IP: %s\tDest IP: %s\n\n", time_buf, src_ip_str, dst_ip_str);
			add_log(skb, "Close all connections");
			return NF_DROP;
		}
		// else
		// {
		// 	printk("This function is not enabled at the current time\n");
		// }
	}

	if (rules.inp_status == 1)
	{
		update_hashTable(skb);    // 更新状态连接表
	}

	return NF_ACCEPT;
}

unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	return NF_ACCEPT;
}

unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb); 	                    
	struct tcphdr *tcph = tcp_hdr(skb);    
	struct udphdr *udph = udp_hdr(skb);   
	struct ethhdr *ethhdr = eth_hdr(skb);

	unsigned short sport, dport;            // 存储当前数据包的源端口号和目的端口号
	unsigned char mac_source[ETH_ALEN];     // 存储当前数据包的MAC地址
	char src_ip_str[16];
	char dst_ip_str[16];
	char time_buf[64]; 

	convert_ip(iph->saddr, src_ip_str, sizeof(src_ip_str));
	convert_ip(iph->daddr, dst_ip_str, sizeof(dst_ip_str));
	get_time(time_buf, sizeof(time_buf)); 
	memcpy(mac_source, ethhdr->h_source, ETH_ALEN);  

	if (rules.open_status == 0)
	{
		return NF_ACCEPT;
	}   

	if (rules.settime_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("current date： %ld  start date： %ld  end date： %ld\n", current_time, rules.start_date, rules.end_date);
		if (current_time < rules.start_date || current_time >= rules.end_date)
		{
			printk("Time: %s. The firewall is not in effect at the current time\n", time_buf);
			return NF_ACCEPT;
		}
	}

	// 区分协议类型
	switch(iph->protocol)  
	{          
		case IPPROTO_TCP:
		{
			sport = tcph->source;
			dport = tcph->dest;
			break;
		}
		case IPPROTO_UDP:
		{
			sport = udph->source;
			dport = udph->dest;
			break;
		}
	}  

	// 基于MAC地址的访问控制
	if (rules.mac_status == 1)
	{					
		int mac_number;
		for (mac_number = 0; mac_number < rules.macNum; mac_number++)
		{
			if ((rules.ban_mac[mac_number][0] ==	mac_source[0]) && (rules.ban_mac[mac_number][1] == mac_source[1]) &&
		   	(rules.ban_mac[mac_number][2] == mac_source[2]) && (rules.ban_mac[mac_number][3] == mac_source[3]) &&
		   	(rules.ban_mac[mac_number][4] == mac_source[4]) && (rules.ban_mac[mac_number][5] == mac_source[5]))
			{
				// struct iphdr *iph = ip_hdr(skb); 
				printk("Time: %s. Request is deny. \nMAC: %02X:%02X:%02X:%02X:%02X:%02X\tSrc IP: %s\n\n", time_buf,
				mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5], src_ip_str);
				add_log(skb, "MAC");
				return NF_DROP;
			}	
			// else
			// {
			// 	printk("MAC: %02X:%02X:%02X:%02X:%02X:%02X \n filter MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
			// 	mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5],
			// 	rules.ban_mac[mac_number][0], rules.ban_mac[mac_number][1], rules.ban_mac[mac_number][2], rules.ban_mac[mac_number][3], rules.ban_mac[mac_number][4], rules.ban_mac[mac_number][5]);
			// }	
		}
	}
	
	// 基于用户自定义策略的访问控制
	if (rules.combin_status == 1)
	{
		int combin_numberi;
		for (combin_numberi = 0; combin_numberi < rules.combineNum; combin_numberi++)      	// 遍历每一个自定义的访问控制策略
		{			
			int flag_banSip = !rules.ban_combin[combin_numberi].banSip_status;
			int flag_banDip = !rules.ban_combin[combin_numberi].banDip_status;
			int flag_banSport = !rules.ban_combin[combin_numberi].banSport_status;
			int flag_banDport = !rules.ban_combin[combin_numberi].banDport_status;
			int flag_banMAC = !rules.ban_combin[combin_numberi].banMac_status;

			if (rules.ban_combin[combin_numberi].banSip_status == 1 && rules.ban_combin[combin_numberi].banSip == iph->saddr)
			{
				flag_banSip = 1;
			}
			if (rules.ban_combin[combin_numberi].banDip_status == 1 && rules.ban_combin[combin_numberi].banDip == iph->daddr)
			{
				flag_banDip = 1;
			}
			if (rules.ban_combin[combin_numberi].banSport_status == 1 && ntohs(rules.ban_combin[combin_numberi].ban_sport) == sport)
			{
				flag_banSport = 1;
			}
			if (rules.ban_combin[combin_numberi].banDport_status == 1 && ntohs(rules.ban_combin[combin_numberi].ban_dport) == dport)
			{
				flag_banDport = 1;
			}
			if (rules.ban_combin[combin_numberi].banMac_status == 1)
			{
				if ((rules.ban_combin[combin_numberi].banMac[0] == mac_source[0]) && (rules.ban_combin[combin_numberi].banMac[1] == mac_source[1]) &&
		 	 	(rules.ban_combin[combin_numberi].banMac[2] == mac_source[2]) && (rules.ban_combin[combin_numberi].banMac[3] == mac_source[3]) &&
		 	 	(rules.ban_combin[combin_numberi].banMac[4] == mac_source[4]) && (rules.ban_combin[combin_numberi].banMac[5] == mac_source[5]))
				{
					flag_banMAC = 1;
				}
			}

			if (flag_banSip && flag_banDip && flag_banSport && flag_banDport && flag_banMAC == 1)
			{
				printk("Time: %s. Custom filter rules hits, request is deny.\nSrc IP: %s\tDest IP: %s\tMAC: %02X:%02X:%02X:%02X:%02X:%02X\n\n", 
				time_buf, src_ip_str, dst_ip_str, mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5]);
				add_log(skb, "Customized filter rules");
				return NF_DROP;
			}
		}
	}

	return NF_ACCEPT;
}

unsigned int hookPostRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	return NF_ACCEPT;
}

unsigned int hookForwarding(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	return NF_ACCEPT;
}

int hookSockoptSet(struct sock* sock, int cmd, void __user* user, unsigned int len)
{
	int ret;
	
	// 将用户空间的rules拷贝到内核空间，使用recv接收，保证用户和内核空间过滤规则的一致性
	ret = copy_from_user(&recv, user, sizeof(recv));

	switch(cmd)
	{
		case OPENSTATE:           // 改变防火墙开启状态
			rules.open_status = recv.open_status;
			break;
		case INPSTATE:            // 改变防火墙状态检测功能开启状态
			rules.inp_status = recv.inp_status;
			rules.connNum = recv.connNum;
			memcpy(rules.connNode, recv.connNode, sizeof(rules.connNode));  
			release_list(&connHead, &connEnd);
			memset(&hashTable, 0, sizeof(hashTable));
			break;
		case SETTIME:             // 改变防火墙开启时间段
			rules.settime_status = recv.settime_status;
			rules.start_date = recv.start_date;
			rules.end_date = recv.end_date;
			break;
		case BANSIP:              // 基于源IP地址的访问控制
			rules.sip_status = recv.sip_status;
			rules.sipNum = recv.sipNum;
			memcpy(rules.ban_sip, recv.ban_sip, sizeof(rules.ban_sip));  
			break;
		case BANDIP:              // 基于目的IP地址的访问控制
			rules.dip_status = recv.dip_status;
			rules.dipNum = recv.dipNum;
			memcpy(rules.ban_dip, recv.ban_dip, sizeof(rules.ban_dip));  
			break;
		case BANSPORT:            // 基于源头端口的访问控制 
			rules.sport_status = recv.sport_status;
			rules.sportNum = recv.sportNum;    
			memcpy(rules.ban_sport, recv.ban_sport, sizeof(rules.ban_sport));  
			break;
		case BANDPORT:            // 基于目的端口的访问控制 
			rules.dport_status = recv.dport_status;
			rules.dportNum = recv.dportNum;   
			memcpy(rules.ban_dport, recv.ban_dport, sizeof(rules.ban_dport)); 
			break;
		case BANPROTOCOL:         // 基于协议类型的访问控制 
			rules.protocol_status = recv.protocol_status;
			memcpy(rules.protocol_type, recv.protocol_type, sizeof(rules.protocol_type)); 
			break;
		case BANMAC:              // 基于MAC地址的访问控制
			rules.mac_status = recv.mac_status;
			rules.macNum = recv.macNum;
			memcpy(rules.ban_mac, recv.ban_mac, sizeof(rules.ban_mac)); 
			break;
		case BANCOMBIN:           // 基于用户自定义策略的访问控制
			rules.combin_status = recv.combin_status;
			rules.combineNum = recv.combineNum; 
			memcpy(rules.ban_combin, recv.ban_combin, sizeof(rules.ban_combin)); 
			break;
		case BANALL:              // 关闭所有连接功能的控制
			rules.close_status = recv.close_status;
			rules.start_time = recv.start_time;
			rules.end_time = recv.end_time;
			break;
		case BANPING:             // PING功能的控制 
			rules.ping_status = recv.ping_status;
			break;
		case BANHTTP:             // HTTP/HTTPS功能的控制
			rules.http_status = recv.http_status;
			break;
		case BANTELNET:           // TELNET功能的控制
			rules.telnet_status = recv.telnet_status;
			break;
		case RESTORE:             // 恢复默认设置的控制
			memset(&rules, 0, sizeof(rules));	
			release_list(&connHead, &connEnd);
			memset(&hashTable, 0, sizeof(hashTable));
			rules.open_status = 1;
			break;
		default:
			break;
	}

	if (ret != 0)
	{
		ret = -EINVAL;
		printk("Error copying from user space to kernel space");
	}
	return ret;
}

int hookSockoptGet(struct sock* sock, int cmd, void __user* user, int* len)
{
	int ret;

	if (cmd == CONNGET)
	{
		int i = 0;
		Connection *p = connHead.next;
		while (p != &connEnd)
		{
			rules.connNode[i++] = *p;
			p = p->next;
		}
	}

	// 将内核空间的rules拷贝到用户空间，保证用户和内核空间过滤规则的一致性
	ret = copy_to_user(user, &rules, sizeof(rules));
	if (ret != 0)
	{
		ret = -EINVAL;
		printk("Error copying from kernel space to user space");
	}

	return ret;
}

// 初始化模块 
int myfirewall_init(void)
{
    timer_setup(&connect_timer, time_out, 0);   // 初始化定时器，设置回调函数为time_out
    connect_timer.expires = jiffies + HZ;       // 过期时间为1s后
    add_timer(&connect_timer);   

    // 提交 work 到 workqueue
    queue_delayed_work(system_wq, &my_work, msecs_to_jiffies(10000));

	rules.open_status = 1;          // 初始化防火墙的状态为开启
	rules.inp_status = 0;           // 初始化防火墙状态检测功能为关闭
	rules.sip_status = 0;           // 初始化基于源IP访问控制功能为关闭 
	rules.dip_status = 0;           // 初始化基于目的IP访问控制功能为关闭 
	rules.sport_status = 0;         // 初始化基于源端口访问控制功能为关闭  
	rules.dport_status = 0;         // 初始化基于目的端口访问控制功能为关闭 
	rules.settime_status = 0;	    // 初始化防火墙时间段功能为关闭
	rules.ping_status = 0;          // 初始化不封禁PING功能
	rules.http_status = 0;          // 初始化不封禁HTTP/HTTPS功能
	rules.telnet_status = 0;        // 初始化不封禁TELNET功能
	rules.protocol_status = 0;      // 初始化基于协议类型访问控制功能为关闭 
	rules.mac_status = 0;		    // 初始化基于MAC地址访问控制功能为关闭 
	rules.close_status = 0;         // 初始化开启所以连接
	rules.combin_status = 0; 	    // 初始化基于用户自定义策略访问控制功能为关闭

	// 初始化状态连接链表
	connHead.next = &connEnd;
	connEnd.next = NULL;

	// 初始化状态连接存储结构 
	rules.connNum = 0;		     
	memset(rules.connNode, 0, sizeof(rules.connNode));   

	nfhoLocalIn.hook = hookLocalIn;         
	nfhoLocalIn.pf = PF_INET;
	nfhoLocalIn.hooknum = NF_INET_LOCAL_IN;
	nfhoLocalIn.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalIn);

	nfhoLocalOut.hook = hookLocalOut;
	nfhoLocalOut.pf = PF_INET;
	nfhoLocalOut.hooknum = NF_INET_LOCAL_OUT;
	nfhoLocalOut.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoLocalOut);

	nfhoPreRouting.hook = hookPreRouting;
	nfhoPreRouting.pf = PF_INET;
	nfhoPreRouting.hooknum = NF_INET_PRE_ROUTING;
	nfhoPreRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPreRouting);

	nfhoForwarding.hook = hookForwarding;
	nfhoForwarding.pf = PF_INET;
	nfhoForwarding.hooknum = NF_INET_FORWARD;
	nfhoForwarding.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoForwarding);

	nfhoPostRouting.hook = hookPostRouting;
	nfhoPostRouting.pf = PF_INET;
	nfhoPostRouting.hooknum = NF_INET_POST_ROUTING;
	nfhoPostRouting.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfhoPostRouting);

	nfhoSockopt.pf = PF_INET;
	nfhoSockopt.set_optmin = SOE_MIN;  
	nfhoSockopt.set_optmax = SOE_MAX;  
	nfhoSockopt.set = hookSockoptSet;
	nfhoSockopt.get_optmin = SOE_MIN;
	nfhoSockopt.get_optmax = SOE_MAX;
	nfhoSockopt.get = hookSockoptGet;

	nf_register_sockopt(&nfhoSockopt);

	printk("Firewall kernel module loaded successfully!\n");
	return 0;
}

// 清理模块 
void myfirewall_exit(void)
{
	// 删除定时器
	del_timer(&connect_timer);

    // 取消 work 的延时执行
    cancel_delayed_work_sync(&my_work);

	// 注销钩子 
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForwarding);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);
	
	// 注销通信的钩子
	nf_unregister_sockopt(&nfhoSockopt);

	printk("Firewall kernel module unloaded successfully!\n");
}

module_init(myfirewall_init);
module_exit(myfirewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GY");
MODULE_DESCRIPTION("Netfilter Firewall v2.0");