#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "myfirewall.h"

static struct nf_hook_ops nfhoLocalIn;  	//在数据路由后处理本机数据包的钩子
static struct nf_hook_ops nfhoLocalOut;  	//在本地数据未路由之前的钩子
static struct nf_hook_ops nfhoPreRouting;  	//在数据路由之前的钩子
static struct nf_hook_ops nfhoForwarding;  	//在数据路由后处理转发数据包的钩子
static struct nf_hook_ops nfhoPostRouting;  //在本地数据路由之后的钩子
static struct nf_sockopt_ops nfhoSockopt;   //处理内核和用户间通信钩子

ban_status rules, recv;
 
unsigned int hookLocalIn(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct iphdr *iph = ip_hdr(skb);                    
	struct tcphdr *tcph = tcp_hdr(skb);    
	struct udphdr *udph = udp_hdr(skb);    

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
						printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n源端口: %hu 的访问已拒绝\n------------------\n", 
						(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
						(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24, sport);
						// printk("源端口 %hu 的访问已拒绝", sport);
						return NF_DROP;
						break;
					}
				}
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
						printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n源端口: %hu 的访问已拒绝\n------------------\n", 
						(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
						(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24, sport);
						// printk("源端口 %hu 的访问已拒绝", sport);
						return NF_DROP;
						break;
					}
				}
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
						printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n目的端口: %hu 的访问已拒绝\n------------------\n", 
						(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
						(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24, dport);

						return NF_DROP;
						break;
					}
				}
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
						printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n目的端口: %hu 的访问已拒绝\n------------------\n", 
						(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
						(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24, dport);

						return NF_DROP;
						break;
					}
				}
			}
		}
	}

	//基于源ip地址访问控制，若rules.ip_status为1并且源ip地址与禁用的ip地址相同，丢弃该数据包 
	if (rules.sip_status == 1)
	{
		int sip_number;
		for(sip_number = 0; sip_number < rules.sipNum; sip_number++)
		{
			if (rules.ban_sip[sip_number] == iph->saddr)
			{  
				printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n的访问已拒绝\n------------------\n", 
				(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
				(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24);

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
				printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n的访问已拒绝\n------------------\n", 
				(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
				(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24);

				return NF_DROP;
			}
		}
		
	}

	//ping功能的控制，如果数据包协议是ICMP且rules.ping_status为1则丢弃数据包 
	if(iph->protocol == IPPROTO_ICMP && rules.ping_status == 1)
	{
		printk("来自%d.%d.%d.%d的PING已拒绝\n", 
		(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24);
		
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
			return NF_DROP;
		}
	}

	//关闭所有连接功能的控制
	if(rules.close_status == 1)
	{
		printk("------------------\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\n的访问已拒绝\n------------------\n", 
		(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
		(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24);
		return NF_DROP;
	}

	//如果以上情况都不符合，则不应拦截该数据包，返回NF_ACCEPT
	return NF_ACCEPT;
}

unsigned int hookLocalOut(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	return NF_ACCEPT;
}
unsigned int hookPreRouting(void* priv, struct sk_buff* skb, const struct nf_hook_state* state)
{
	struct ethhdr *ethhdr = eth_hdr(skb);
	struct iphdr *iph = ip_hdr(skb); 			
	unsigned char mac_source[ETH_ALEN];    //存储MAC地址

	memcpy(mac_source, ethhdr->h_source, ETH_ALEN);    

	if(rules.mac_status == 1)
	{					
		if((rules.ban_mac[0] ==	mac_source[0]) && (rules.ban_mac[1] == mac_source[1]) &&
		   (rules.ban_mac[2] == mac_source[2]) && (rules.ban_mac[3] == mac_source[3]) &&
		   (rules.ban_mac[4] == mac_source[4]) && (rules.ban_mac[5] == mac_source[5]))
		{
			// struct iphdr *iph = ip_hdr(skb); 
			printk("已拒绝来自MAC地址: %02X:%02X:%02X:%02X:%02X:%02X 的访问\n其IP地址为: %d.%d.%d.%d\n",
			mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5],
			(iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24);

			return NF_DROP;
		}
		// else
		// {
		// 	printk("当前数据包MAC地址: %02X:%02X:%02X:%02X:%02X:%02X \n需过滤的MAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n",
		// 	mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5],
		// 	rules.ban_mac[0], rules.ban_mac[1], rules.ban_mac[2], rules.ban_mac[3], rules.ban_mac[4], rules.ban_mac[5]);
		// 	printk("放包\n");
		// }
	}

	if(rules.combin_status == 1)
	{
		if(rules.ban_combin.banSip == iph->saddr && rules.ban_combin.banDip == iph->daddr &&
		  (rules.ban_combin.banMac[0] == mac_source[0]) && (rules.ban_combin.banMac[1] == mac_source[1]) &&
		  (rules.ban_combin.banMac[2] == mac_source[2]) && (rules.ban_combin.banMac[3] == mac_source[3]) &&
		  (rules.ban_combin.banMac[4] == mac_source[4]) && (rules.ban_combin.banMac[5] == mac_source[5]))
		{
			//满足自定义的访问控制规则，拦截该数据包
			printk("自定义访问控制拦截成功\n源ip: %d.%d.%d.%d\n目的ip: %d.%d.%d.%d\nMAC地址: %02X:%02X:%02X:%02X:%02X:%02X\n该数据包已拦截\n", 
		    (iph->saddr & 0x000000ff) >> 0,(iph->saddr & 0x0000ff00) >> 8,(iph->saddr & 0x00ff0000) >> 16,(iph->saddr & 0xff000000) >> 24, 
		  	(iph->daddr & 0x000000ff) >> 0,(iph->daddr & 0x0000ff00) >> 8,(iph->daddr & 0x00ff0000) >> 16,(iph->daddr & 0xff000000) >> 24,
			mac_source[0], mac_source[1], mac_source[2], mac_source[3], mac_source[4], mac_source[5]);

			return NF_DROP;
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
		case BANPING:             //PING功能的控制 
			rules.ping_status = recv.ping_status;
			break;
		case BANHTTP:             //HTTP/HTTPS功能的控制
			rules.http_status = recv.http_status;
			break;
		case BANTELNET:           //TELNET功能的控制
			rules.telnet_status = recv.telnet_status;
			break;
		case BANMAC:              //基于MAC地址的访问控制
			rules.mac_status = recv.mac_status;
			memcpy(rules.ban_mac, recv.ban_mac, sizeof(rules.ban_mac)); 
			break;
		case BANALL:              //关闭所有连接功能的控制
			rules.close_status = recv.close_status;
			break;
		case BANCOMBIN:           //基于用户自定义策略的访问控制
			rules.combin_status = recv.combin_status;
			rules.ban_combin.banSip = recv.ban_combin.banSip;
			rules.ban_combin.banDip = recv.ban_combin.banDip;
			memcpy(rules.ban_combin.banMac, recv.ban_combin.banMac, sizeof(rules.ban_combin.banMac));  
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
	// printk("hookSockoptGet");

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
	rules.sip_status = 0;        //初始化基于源IP访问控制的状态为不封禁 
	rules.dip_status = 0;        //初始化基于目的IP访问控制的状态为不封禁 
	rules.sport_status = 0;      //初始化基于源端口访问控制的状态为不封禁 
	rules.dport_status = 0;      //初始化基于目的端口访问控制的状态为不封禁 
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