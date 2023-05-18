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
#include "myfirewall.h"

static DEFINE_SPINLOCK(log_lock);               //定义静态自旋锁变量

static struct nf_hook_ops nfhoLocalIn;  	    //在数据路由后处理本机数据包的钩子
static struct nf_hook_ops nfhoLocalOut;  	    //在本地数据未路由之前的钩子
static struct nf_hook_ops nfhoPreRouting;     	//在数据路由之前的钩子
static struct nf_hook_ops nfhoForwarding;     	//在数据路由后处理转发数据包的钩子
static struct nf_hook_ops nfhoPostRouting;      //在本地数据路由之后的钩子
static struct nf_sockopt_ops nfhoSockopt;       //处理内核和用户间通信钩子

// 存储防火墙过滤规则
ban_status rules, recv;
// 状态检测Hash表
time_t hashTable[TABLE_SIZE]={0};
// HASH锁
char hashLock = 0;

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

// 检测该数据包是否在状态检测哈希数组中
bool check_conn(struct sk_buff *skb) 
{
	struct iphdr *ip = ip_hdr(skb);
	unsigned int src_ip = ntohl(ip->saddr);
	unsigned int dst_ip = ntohl(ip->daddr);

	int src_port;
	int dst_port;
	int protocol;
	unsigned int scode;
	unsigned int pos;    // 状态表的位置

	if(!skb) return true;

	if (ip->protocol == IPPROTO_TCP) 
	{
		struct tcphdr *tcp = tcp_hdr(skb);
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		protocol = 1;
	}
	else if (ip->protocol == IPPROTO_UDP) 
	{
		struct udphdr *udp = udp_hdr(skb);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		protocol = 2;
	}
	else if (ip->protocol == IPPROTO_ICMP)
	{
		src_port = -1;
		dst_port = -1;
		protocol = 3;
	}
	else 
	{
		// 不记录状态
		return false;
	}

	scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
	pos = get_hash(scode);

	while(hashLock);  // 等待开锁
	hashLock = 1;     // 上锁

	//当前时间戳减Hash表中的时间戳为间隔时间
	if (hashTable[pos] && get_seconds() - hashTable[pos] < 10) 
	{
		// printk("状态检测通过  pos:%d   hash:%ld\n", pos, hashTable[pos]);
		// 更新时间为当前时间戳
		hashTable[pos] = get_seconds();
		hashLock = 0;   // 开锁
		return true;
	}
	// 连接不存在，返回插入位置
	else 
	{
		hashLock = 0;	// 开锁
	}

	// printk("状态检测不通过\n");
	return false;
}

// 更新状态检测哈希数组
void update_hashTable(struct sk_buff *skb) 
{
	struct iphdr *ip = ip_hdr(skb);
	unsigned int src_ip = ntohl(ip->saddr);
	unsigned int dst_ip = ntohl(ip->daddr);

	int src_port;
	int dst_port;
	int protocol;
	unsigned int scode;
	unsigned int pos;    // 状态表的位置

	if (ip->protocol == IPPROTO_TCP) 
	{
		struct tcphdr *tcp = tcp_hdr(skb);
		src_port = ntohs(tcp->source);
		dst_port = ntohs(tcp->dest);
		protocol = 1;
	}
	else if (ip->protocol == IPPROTO_UDP) 
	{
		struct udphdr *udp = udp_hdr(skb);
		src_port = ntohs(udp->source);
		dst_port = ntohs(udp->dest);
		protocol = 2;
	}
	else if (ip->protocol == IPPROTO_ICMP) 
	{
		src_port = -1;
		dst_port = -1;
		protocol = 3;
	}

	scode = src_ip ^ dst_ip ^ src_port ^ dst_port ^ protocol;
	pos = get_hash(scode);

	while(hashLock);  // 等待开锁
	hashLock = 1;	  // 上锁

	// 更新为当前时间戳
	hashTable[pos] = get_seconds(); 
	
	hashLock = 0;	  // 开锁
	// printk("更新哈希表 pos:%d  zhi: %ld\n", pos, hashTable[pos]);
}

//获取系统当前时间
struct rtc_time get_time(void)
{
	ktime_t k_time;
	struct rtc_time tm;  
	k_time = ktime_get_real();
	tm = rtc_ktime_to_tm(k_time);  
	return tm;
}

// 转换IP地址格式
void convert_ip(unsigned int ip, char* ip_str, size_t size)
{
	snprintf(ip_str, size, "%u.%u.%u.%u", 
	(ip & 0x000000ff) >> 0,(ip & 0x0000ff00) >> 8,(ip & 0x00ff0000) >> 16,(ip & 0xff000000) >> 24);
}

// 写防火墙日志文件
void wirte_log(struct iphdr *iph, char *rule_str)
{
	struct file *f;
	int len;         
	char buf[256]; 
	struct rtc_time tm = get_time();  //获取系统当前时间

	spin_lock(&log_lock);    //加锁

	f = filp_open(LOG_FILE, O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (IS_ERR(f))
	{
        // printk("Failed to open file\n");
        spin_unlock(&log_lock);
        return;
    }

	len = snprintf(buf, sizeof(buf), "Time: %d-%d-%d %d:%d:%d\t\tSource IP: %d.%d.%d.%d\t\tDestination IP: %d.%d.%d.%d\t\tFilter Rule: %s\t\tAction：Deny\n", 
	tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour + 8, tm.tm_min, tm.tm_sec, 
	(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
	(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24, rule_str);
	
	kernel_write(f, buf, len, &f->f_pos);

	filp_close(f, NULL);
	spin_unlock(&log_lock);    //解锁
}

unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb);                    
	struct tcphdr *tcph = tcp_hdr(skb);    
	struct udphdr *udph = udp_hdr(skb); 
	char src_ip_str[16];
	char dst_ip_str[16];
	convert_ip(iph->saddr, src_ip_str, sizeof(src_ip_str));
	convert_ip(iph->daddr, dst_ip_str, sizeof(dst_ip_str));

	if(rules.open_status == 0) return NF_ACCEPT;   //防火墙为关闭状态，直接放包

	if(rules.settime_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("当前日期： %ld  开始日期： %ld  结束日期： %ld\n", current_time, rules.start_date, rules.end_date);
		if(current_time < rules.start_date || current_time >= rules.end_date)
		{
			printk("当前时间不在防火墙生效时间段内，放包\n");
			return NF_ACCEPT;
		}
	}

	// if(check_conn(skb)) return NF_ACCEPT;   //状态检测

	//基于源ip地址访问控制，若rules.ip_status为1并且源ip地址与禁用的ip地址相同，丢弃该数据包 
	if (rules.sip_status == 1)
	{
		int sip_number;
		for(sip_number = 0; sip_number < rules.sipNum; sip_number++)
		{
			if (rules.ban_sip[sip_number] == iph->saddr)
			{  	
				printk("源ip: %s\t目的ip: %s 的访问已拒绝\n", src_ip_str, dst_ip_str);
				wirte_log(iph, "源IP");
				return NF_DROP;
			}
		}
	}

	//基于目的ip地址访问控制，若rules.ip_status为1并且源ip地址与禁用的ip地址相同，丢弃该数据包 
	if (rules.dip_status == 1)
	{
		int dip_number;
		for(dip_number = 0; dip_number < rules.dipNum; dip_number++)
		{
			if (rules.ban_dip[dip_number] == iph->daddr)
			{  
				printk("源ip: %s\t目的ip: %s 的访问已拒绝\n", src_ip_str, dst_ip_str);
				wirte_log(iph, "目的IP");
				return NF_DROP;
			}
		}
	}

	//基于源端口的访问控制，若rules.sport_status为1并且目的端口与禁用的端口相同则丢弃该数据包 
	if(rules.sport_status == 1)
	{
		switch(iph->protocol)  // 区分tcp和udp
		{          
			case IPPROTO_TCP:
			{
				int sport_numberi;
				for(sport_numberi = 0; sport_numberi < rules.sportNum; sport_numberi++)
				{
					// 遍历端口数组中的每一个端口进行对比
					unsigned short sport = ntohs(rules.ban_sport[sport_numberi]);
					if(tcph->source == sport)
					{
						printk("源ip: %s\t目的ip: %s\t源端口: %hu 的访问已拒绝\n", src_ip_str, dst_ip_str, sport);
						wirte_log(iph, "源端口");
						return NF_DROP;
					}
				}
				break;
			}
			case IPPROTO_UDP:
			{
				int sport_numberj;
				for(sport_numberj = 0; sport_numberj < rules.sportNum; sport_numberj++)
				{
					// 遍历端口数组中的每一个端口进行对比
					unsigned short sport = ntohs(rules.ban_sport[sport_numberj]);
					if(udph->source == sport)
					{
						printk("源ip: %s\t目的ip: %s\t源端口: %hu 的访问已拒绝\n", src_ip_str, dst_ip_str, sport);
						wirte_log(iph, "源端口");
						return NF_DROP;
					}
				}
				break;
			}
		}
	}

	//基于目的端口的访问控制，若rules.dport_status为1并且目的端口与禁用的端口相同则丢弃该数据包 
	if(rules.dport_status == 1)
	{
		// int tooli;
		// for(tooli = 0; tooli < rules.dportNum; tooli++){
		// 	unsigned short dport = ntohs(rules.ban_dport[tooli]);
		// 	printk("内核空间接收的主机字节序端口号：%hu\n", dport);
		// }
		switch(iph->protocol)  // 区分tcp和udp
		{           
			case IPPROTO_TCP:
			{
				int dport_numberi;
				for(dport_numberi = 0; dport_numberi < rules.dportNum; dport_numberi++)
				{
					// 遍历端口数组中的每一个端口进行对比
					unsigned short dport = ntohs(rules.ban_dport[dport_numberi]);
					if(tcph->dest == dport)
					{	
						printk("源ip: %s\t目的ip: %s\t目的端口: %hu 的访问已拒绝\n", src_ip_str, dst_ip_str, dport);
						wirte_log(iph, "目的端口");
						return NF_DROP;
					}
				}
				break;
			}
			case IPPROTO_UDP:
			{
				int dport_numberj;
				for(dport_numberj = 0; dport_numberj < rules.dportNum; dport_numberj++)
				{
					// 遍历端口数组中的每一个端口进行对比
					unsigned short dport = ntohs(rules.ban_dport[dport_numberj]);
					if(udph->dest == dport)
					{
						printk("源ip: %s\t目的ip: %s\t目的端口: %hu 的访问已拒绝\n", src_ip_str, dst_ip_str, dport);
						wirte_log(iph, "目的端口");
						return NF_DROP;
					}
				}
				break;
			}
		}
	}

	//PING功能的控制，如果数据包协议是ICMP且rules.ping_status为1则丢弃数据包 
	if(iph->protocol == IPPROTO_ICMP && rules.ping_status == 1)
	{
		printk("来自%s的PING已拒绝\n", src_ip_str);
		wirte_log(iph, "PING禁用");
		return NF_DROP;
	}

	//HTTP/HTTPS功能的控制
	if(rules.http_status == 1)
	{
		if(iph->protocol == IPPROTO_TCP)
		{
			// tcph = tcp_hdr(skb);                      
			if((tcph->dest == htons(80)) || (tcph->dest == htons(443)) || (tcph->dest == htons(8080)) 
			|| (tcph->source == htons(80)) || (tcph->source == htons(443)) || (tcph->source == htons(8080)))
			{
				//如果rules.http_status为1，数据包是tcp并且目的端口号80或443，丢弃该数据包
				printk("HTTP/HTTPS请求已拒绝\n");
				wirte_log(iph, "HTTP/HTTPS禁用");
				return NF_DROP;		
			}
		}
	}

	//Telnet功能的控制
	if(rules.telnet_status == 1)
	{
		if(iph->protocol == IPPROTO_TCP && tcph->dest == htons(23))
		{
			printk("TELNET请求已拒绝\n");
			wirte_log(iph, "Telnet禁用");
			return NF_DROP;
		}
	}

	//关闭所有连接功能的控制
	if(rules.close_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("curr: %ld\n", current_time);
		// printk("start: %ld\n", rules.start_time);
		// printk("end: %ld\n", rules.end_time);
		if(rules.start_time <= current_time && rules.end_time >= current_time)
		{
			printk("源ip: %s\t目的ip: %s 的访问已拒绝\n", src_ip_str, dst_ip_str);
			wirte_log(iph, "关闭所有连接");
			return NF_DROP;
		}
		else
		{
			printk("不在防火墙生效时间段，放包\n");
		}
	}

	//如果以上情况都不符合，则不应拦截该数据包，返回NF_ACCEPT
	// update_hashTable(skb);   //更新状态检测哈希表
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
	unsigned short sport, dport;            //存储当前数据包的源端口号和目的端口号
	unsigned char mac_source[ETH_ALEN];     //存储当前数据包的MAC地址
	char src_ip_str[16];
	char dst_ip_str[16];
	convert_ip(iph->saddr, src_ip_str, sizeof(src_ip_str));
	convert_ip(iph->daddr, dst_ip_str, sizeof(dst_ip_str));

	if(rules.open_status == 0) return NF_ACCEPT;   //防火墙为关闭状态，直接放包

	if(rules.settime_status == 1)
	{
		time_t current_time = get_seconds();
		// printk("当前日期： %ld  开始日期： %ld  结束日期： %ld\n", current_time, rules.start_date, rules.end_date);
		if(current_time < rules.start_date || current_time >= rules.end_date)
		{
			printk("当前时间不在防火墙生效时间段内，放包\n");
			return NF_ACCEPT;
		}
	}

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

	memcpy(mac_source, ethhdr->h_source, ETH_ALEN);    

	if(rules.mac_status == 1)
	{					
		int mac_number;
		for(mac_number = 0; mac_number < rules.macNum; mac_number++)
		{
			if((rules.ban_mac[mac_number][0] ==	mac_source[0]) && (rules.ban_mac[mac_number][1] == mac_source[1]) &&
		   	(rules.ban_mac[mac_number][2] == mac_source[2]) && (rules.ban_mac[mac_number][3] == mac_source[3]) &&
		   	(rules.ban_mac[mac_number][4] == mac_source[4]) && (rules.ban_mac[mac_number][5] == mac_source[5]))
			{
				// struct iphdr *iph = ip_hdr(skb); 
				printk("已拒绝来自MAC地址: %02X:%02X:%02X:%02X:%02X:%02X 的访问  IP地址为: %s\n",
				mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5], src_ip_str);
				wirte_log(iph, "MAC地址");
				return NF_DROP;
			}	
			// else
			// {
			// 	printk("当前数据包MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n需过滤的MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
			// 	mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5],
			// 	rules.ban_mac[mac_number][0], rules.ban_mac[mac_number][1], rules.ban_mac[mac_number][2], rules.ban_mac[mac_number][3], rules.ban_mac[mac_number][4], rules.ban_mac[mac_number][5]);
			// 	printk("放包\n");
			// }	
		}
	}
	
	if(rules.combin_status == 1)
	{
		int combin_numberi;
		for(combin_numberi = 0; combin_numberi < rules.combineNum; combin_numberi++)      	//遍历每一个自定义的访问控制策略
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
				if((rules.ban_combin[combin_numberi].banMac[0] == mac_source[0]) && (rules.ban_combin[combin_numberi].banMac[1] == mac_source[1]) &&
		 	 	(rules.ban_combin[combin_numberi].banMac[2] == mac_source[2]) && (rules.ban_combin[combin_numberi].banMac[3] == mac_source[3]) &&
		 	 	(rules.ban_combin[combin_numberi].banMac[4] == mac_source[4]) && (rules.ban_combin[combin_numberi].banMac[5] == mac_source[5]))
				{
					flag_banMAC = 1;
				}
			}

			if(flag_banSip && flag_banDip && flag_banSport && flag_banDport && flag_banMAC == 1)
			{
				//满足自定义的访问控制规则，拦截该数据包
				printk("自定义访问控制策略命中，该数据包已拦截\n源ip: %s\t目的ip: %s\tMAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n", 
				src_ip_str, dst_ip_str, mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5]);
				wirte_log(iph, "用户自定义");
				return NF_DROP;
			}
		}
	}

	//如果以上情况都不符合，则不应拦截该数据包，返回NF_ACCEPT
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
	
	//将用户空间的rules拷贝到内核空间，使用recv接收，保证用户和内核空间过滤规则的一致性
	ret = copy_from_user(&recv, user, sizeof(recv));

	switch(cmd)
	{
		case OPENSTATE:           //改变防火墙开启状态
			rules.open_status = recv.open_status;
			break;
		case SETTIME:             //改变防火墙开启时间段
			rules.settime_status = recv.settime_status;
			rules.start_date = recv.start_date;
			rules.end_date = recv.end_date;
			break;
		case BANSIP:              //基于源IP地址的访问控制
			rules.sip_status = recv.sip_status;
			rules.sipNum = recv.sipNum;
			memcpy(rules.ban_sip, recv.ban_sip, sizeof(rules.ban_sip));  
			break;
		case BANDIP:              //基于目的IP地址的访问控制
			rules.dip_status = recv.dip_status;
			rules.dipNum = recv.dipNum;
			memcpy(rules.ban_dip, recv.ban_dip, sizeof(rules.ban_dip));  
			break;
		case BANSPORT:            //基于源头端口的访问控制 
			rules.sport_status = recv.sport_status;
			rules.sportNum = recv.sportNum;    
			memcpy(rules.ban_sport, recv.ban_sport, sizeof(rules.ban_sport));  
			break;
		case BANDPORT:            //基于目的端口的访问控制 
			rules.dport_status = recv.dport_status;
			rules.dportNum = recv.dportNum;   
			memcpy(rules.ban_dport, recv.ban_dport, sizeof(rules.ban_dport)); 
			break;
		case BANMAC:              //基于MAC地址的访问控制
			rules.mac_status = recv.mac_status;
			rules.macNum = recv.macNum;
			memcpy(rules.ban_mac, recv.ban_mac, sizeof(rules.ban_mac)); 
			break;
		case BANCOMBIN:           //基于用户自定义策略的访问控制
			rules.combin_status = recv.combin_status;
			rules.combineNum = recv.combineNum; 
			memcpy(rules.ban_combin, recv.ban_combin, sizeof(rules.ban_combin)); 
			break;
		case BANALL:              //关闭所有连接功能的控制
			rules.close_status = recv.close_status;
			rules.start_time = recv.start_time;
			rules.end_time = recv.end_time;
			break;
		case BANPING:             //PING功能的控制 
			rules.ping_status = recv.ping_status;
			break;
		case BANHTTP:             //HTTP/HTTPS功能的控制
			rules.http_status = recv.http_status;
			break;
		case BANTELNET:           //TELNET功能的控制
			rules.telnet_status = recv.telnet_status;
			break;
		case RESTORE:             //恢复默认设置的控制
			memset(&rules, 0, sizeof(rules));	
			rules.open_status = 1;
			break;
		default:
			break;
	}

	if (ret != 0)
	{
		ret = -EINVAL;
		printk("从用户空间拷贝到内核空间错误");
	}
	return ret;
}

int hookSockoptGet(struct sock* sock, int cmd, void __user* user, int* len)
{
	int ret;
	//将内核空间的rules拷贝到内核空间，保证用户和内核空间过滤规则的一致性
	ret = copy_to_user(user, &rules, sizeof(rules));

	if (ret != 0)
	{
		ret = -EINVAL;
		printk("从内核空间拷贝到用户空间错误");
	}
	return ret;
}

//初始化模块 
int myfirewall_init(void)
{
	rules.open_status = 1;       //初始化防火墙的状态为开启
	rules.sip_status = 0;        //初始化基于源IP访问控制的状态为不封禁 
	rules.dip_status = 0;        //初始化基于目的IP访问控制的状态为不封禁 
	rules.sport_status = 0;      //初始化基于源端口访问控制的状态为不封禁 
	rules.dport_status = 0;      //初始化基于目的端口访问控制的状态为不封禁 
	rules.settime_status = 0;	 //初始化关闭防火墙时间段功能
	rules.ping_status = 0;       //初始化不封禁PING功能
	rules.http_status = 0;       //初始化不封禁HTTP/HTTPS功能
	rules.telnet_status = 0;     //初始化不封禁TELNET功能
	rules.mac_status = 0;		 //初始化基于MAC地址访问控制的状态为不封禁 
	rules.close_status = 0;      //初始化开启所以连接
	rules.combin_status = 0; 	 //初始化基于用户自定义策略访问控制的状态为不封禁 

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

	printk("防火墙内核模块加载成功\n");
	return 0;
}

//清理模块 
void myfirewall_exit(void)
{
	//注销钩子 
	nf_unregister_net_hook(&init_net, &nfhoLocalIn);
	nf_unregister_net_hook(&init_net, &nfhoLocalOut);
	nf_unregister_net_hook(&init_net, &nfhoPreRouting);
	nf_unregister_net_hook(&init_net, &nfhoForwarding);
	nf_unregister_net_hook(&init_net, &nfhoPostRouting);
	
	//注销通信的钩子
	nf_unregister_sockopt(&nfhoSockopt);

	printk("防火墙内核模块已卸载\n");
}

module_init(myfirewall_init);
module_exit(myfirewall_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GY");
