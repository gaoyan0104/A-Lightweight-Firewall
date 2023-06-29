#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <errno.h>  
#include "../kernel_module/myfirewall.h"

void open_firewall(int sockfd, socklen_t len);              /*功能函数:开启/关闭防火墙*/
void open_stateInp(int sockfd, socklen_t len);              /*功能函数:开启/关闭状态检测功能*/
void set_opentime(int sockfd, socklen_t len);               /*功能函数:设置防火墙开启时间段*/
void get_status();                                          /*功能函数:获取当前防火墙过滤规则*/
void change_status(int sockfd, socklen_t len);              /*功能函数:改变防火墙过滤规则*/
void change_ping(int sockfd, socklen_t len);                /*功能函数:改变PING规则*/
void change_nat(int sockfd, socklen_t len);                 /*功能函数:开启/关闭防火墙NAT功能*/
void change_ip(int sockfd, socklen_t len);                  /*功能函数:改变IP过滤规则*/
void change_sip(int sockfd, socklen_t len);                 /*功能函数:改变源IP过滤规则*/
void change_dip(int sockfd, socklen_t len);                 /*功能函数:改变目的IP过滤规则*/
void change_port(int sockfd, socklen_t len);                /*功能函数:改变端口过滤规则*/
void change_sport(int sockfd, socklen_t len);               /*功能函数:改变源端口过滤规则*/
void change_dport(int sockfd, socklen_t len);               /*功能函数:改变目的端口过滤规则*/
void change_http(int sockfd, socklen_t len);                /*功能函数:改变HTTP/HTTPS规则*/
void change_telnet(int sockfd, socklen_t len);              /*功能函数:改变Telnet规则*/
void change_protocol(int sockfd, socklen_t len);            /*功能函数:改变协议类型过滤规则*/
void change_mac(int sockfd, socklen_t len);                 /*功能函数:改变MAC地址过滤规则*/		
void change_close(int sockfd, socklen_t len);               /*功能函数:改变关闭所有连接规则*/
void change_combin(int sockfd, socklen_t len);              /*功能函数:改变自定义过滤规则*/
void mac_format(char *mac_str, unsigned char *mac_addr);    /*功能函数:分割MAC地址*/
void show_log();                                            /*功能函数:查看日志*/
void restore_default(int sockfd, socklen_t len);            /*功能函数:恢复默认设置*/
void printError(char *msg);                                 /*功能函数:打印错误信息*/

// 防火墙过滤规则
ban_status rules; 

int main(void)
{
	int sockfd;
	socklen_t len;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printError("create socket");
	}
	else
	{
		len = sizeof(rules);
		if (getsockopt(sockfd, IPPROTO_IP, NOWRULE, (void *)&rules, &len))
		{
			printError("get filtering rules from kernel space");
		}
		else
		{
			while(1)
			{
				if (rules.open_status == 1)             // 防火墙状态为开启
				{
					get_status();                       // 循环打印当前防火墙过滤规则
					change_status(sockfd, len);         // 循环打印规则菜单,直至用户层选择退出
				}
				else
				{
					printf("防火墙当前状态:关闭\n");
					printf("是否开启防火墙（1 开启  0 exit）\n");
					int choice;
					scanf("%d", &choice);
					if (choice == 1)
					{
						open_firewall(sockfd, len);    // 开启防火墙
					} 
					else if (choice == 0)
					{
						exit(0);                       // 退出
					}
					else
					{
						printf("Bad parameter.\n");
					} 
				}
			}
		}
	}
	return 0;
}

// 功能函数:获取当前防火墙过滤规则
void get_status() 
{	
	printf("-------------------------------------------------------------------------------\n");
	if (rules.settime_status == 1)
	{
		// 将时间戳转换为tm结构体
		struct tm start_date, end_date;	
    	localtime_r(&rules.start_date, &start_date);     
    	localtime_r(&rules.end_date, &end_date);

		// printf("%ld ~ %ld", rules.start_date, rules.end_date);
		printf("防火墙启用时间段: %d-%d-%d 00:00:00  ~  %d-%d-%d 23:59:59\n", start_date.tm_year + 1900, 
		start_date.tm_mon + 1, start_date.tm_mday + 1, end_date.tm_year + 1900, end_date.tm_mon + 1, end_date.tm_mday);
	}
	
	printf("当前防火墙功能:\n");
	printf("--------------------------------------\n");

	printf("防火墙状态检测功能: \t\t");
	if (rules.inp_status == 1)
	{
		printf("开启\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("防火墙NAT功能: \t\t\t");
	if (rules.nat_status == 1)
	{
		printf("开启\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据源IP过滤功能: \t\t");
	if (rules.sip_status == 1)
	{
		printf("开启\n");
		for (int i = 0; i < rules.sipNum; i++)
		{
			printf("过滤源IP地址: %d.%d.%d.%d\n", 
			(rules.ban_sip[i] & 0x000000ff) >> 0,
			(rules.ban_sip[i] & 0x0000ff00) >> 8,
			(rules.ban_sip[i] & 0x00ff0000) >> 16,
			(rules.ban_sip[i] & 0xff000000) >> 24);
		}
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据目的IP过滤功能: \t\t");
	if (rules.dip_status == 1)
	{
		printf("开启\n");
		for (int i = 0; i < rules.dipNum; i++)
		{
			printf("过滤目的IP地址: %d.%d.%d.%d\n", 
			(rules.ban_dip[i] & 0x000000ff) >> 0,
			(rules.ban_dip[i] & 0x0000ff00) >> 8,
			(rules.ban_dip[i] & 0x00ff0000) >> 16,
			(rules.ban_dip[i] & 0xff000000) >> 24);
		}
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据源端口过滤功能: \t\t");
	if (rules.sport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for (int i = 0; i < rules.sportNum; i++)
		{
			printf("%hu ", rules.ban_sport[i]);   
		}
		printf("\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据目的端口过滤功能: \t\t");
	if (rules.dport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for (int i = 0; i < rules.dportNum; i++)
		{
			printf("%hu ", rules.ban_dport[i]);   
		}
		printf("\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据MAC过滤功能: \t\t");
	if (rules.mac_status == 1)
	{
		printf("开启\n");
		for (int i = 0; i < rules.macNum; i++)
		{
			printf("过滤MAC地址:%02X:%02X:%02X:%02X:%02X:%02X\n",
			rules.ban_mac[i][0], rules.ban_mac[i][1], rules.ban_mac[i][2], 
			rules.ban_mac[i][3], rules.ban_mac[i][4], rules.ban_mac[i][5]);
		}
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("自定义访问控制策略功能: \t");
	if (rules.combin_status == 1)
	{
		printf("开启\n");
		printf("共%d个自定义访问控制策略\n", rules.combineNum);
		for (int i = 0; i < rules.combineNum; i++)
		{
			printf("\n第%d个自定义访问控制策略:\n", i + 1);
			if (rules.ban_combin[i].banSip_status == 1)
			{
				printf("源IP地址: \t%d.%d.%d.%d\n", 
				(rules.ban_combin[i].banSip & 0x000000ff) >> 0,
				(rules.ban_combin[i].banSip & 0x0000ff00) >> 8,
				(rules.ban_combin[i].banSip & 0x00ff0000) >> 16,
				(rules.ban_combin[i].banSip & 0xff000000) >> 24);
			}

			if (rules.ban_combin[i].banDip_status == 1)
			{
				printf("目的IP地址: \t%d.%d.%d.%d\n", 
				(rules.ban_combin[i].banDip & 0x000000ff) >> 0,
				(rules.ban_combin[i].banDip & 0x0000ff00) >> 8,
				(rules.ban_combin[i].banDip & 0x00ff0000) >> 16,
				(rules.ban_combin[i].banDip & 0xff000000) >> 24);
			}	

			if (rules.ban_combin[i].banSport_status == 1)
			{
				printf("源端口号: \t%hu\n", rules.ban_combin[i].ban_sport);
			}	

			if (rules.ban_combin[i].banDport_status == 1)
			{
				printf("目的端口号: \t%hu\n", rules.ban_combin[i].ban_dport);
			}	

			if (rules.ban_combin[i].banMac_status == 1)
			{
				printf("MAC地址:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
				rules.ban_combin[i].banMac[0], rules.ban_combin[i].banMac[1], rules.ban_combin[i].banMac[2], 
				rules.ban_combin[i].banMac[3], rules.ban_combin[i].banMac[4], rules.ban_combin[i].banMac[5]);
			}
		}
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------------------\n");

	printf("关闭所有连接功能: \t\t");
	if (rules.close_status == 1)
	{
		printf("开启\n");		
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------------------\n");

	printf("禁用PING功能: \t\t\t");
	if (rules.ping_status == 1)
	{
		printf("开启\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("禁用HTTP/HTTPS功能: \t\t");
	if (rules.http_status == 1)
	{
		printf("开启\n");		
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------------------\n");

	printf("禁用Telnet功能: \t\t");
	if (rules.telnet_status == 1)
	{
		printf("开启\n");		
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------------------\n");

	printf("根据协议类型过滤功能: \t\t");
	if (rules.protocol_status == 1)
	{
		printf("开启\n");
		printf("禁用协议: ");
		if (rules.protocol_status == 1)
		{
			if (rules.protocol_type[0])
			{
				printf("TCP ");
			}
			if (rules.protocol_type[1])
			{
				printf("UDP ");
			}
			if (rules.protocol_type[2])
			{
				printf("ICMP ");
			}
			printf("\n");
		}
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	time_t timer0;
	timer0= time(NULL);
	struct tm* tm = localtime(&timer0);
	printf("Time:%d-%d-%d %d:%d:%d\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour + 8, tm->tm_min, tm->tm_sec);
}

// 功能函数:改变防火墙过滤规则
void change_status(int sockfd, socklen_t len)
{
	int choice;
	printf("\n选择需要设置的防火墙功能:\n");
	printf("1.开启/关闭防火墙\t2.查看日志\t\t3.状态检测功能\t\t4.NAT功能\n");
	printf("5.IP过滤功能\t\t6.端口号过滤功能\t7.协议类型过滤功能\t8.MAC地址过滤功能\n"); 
	printf("9.自定义访问控制策略\t10.PING功能\t\t11.HTTP/HTTPS功能\t12.Telnet功能\n");
	printf("13.关闭所有连接\t\t14.防火墙生效时间\t15.恢复默认设置\t\t0.exit\n");
	printf("-------------------------------------------------------------------------------\n");
	// printf("选项:\t");

	scanf("%d", &choice);
	switch (choice)
	{
		case 1:   
			open_firewall(sockfd, len);
			break;	
		case 2:   
			show_log();
			break;
		case 3:   
			open_stateInp(sockfd, len);	
			break;
		case 4:
			change_nat(sockfd, len);
			break;
		case 5:   
			change_ip(sockfd, len);
			break;
		case 6:
			change_port(sockfd, len);   
			break;
		case 7:
			change_protocol(sockfd, len);   
			break;
		case 8:
			change_mac(sockfd, len);
			break;
		case 9:   
			change_combin(sockfd, len); 
			break;
		case 10:
			change_ping(sockfd, len);
			break;
		case 11:
			change_http(sockfd, len);	
			break;
		case 12:
			change_telnet(sockfd, len);
			break;
		case 13:
			change_close(sockfd, len);
			break;
		case 14:
			set_opentime(sockfd, len);
			break;
		case 15:
			restore_default(sockfd, len);
			break;
		case 0:
			printf("Exit the fwcontroller...\n");
			exit(0);
		default:
			printf("Bad parameter.\n");
	}
}

// 功能函数:开启/关闭防火墙
void open_firewall(int sockfd, socklen_t len)
{
	rules.open_status = !rules.open_status;     

	if (rules.open_status == 1)
	{
		printf("防火墙已开启!\n");
	}
	else
	{
		printf("防火墙已关闭!\n");
	}

	if (setsockopt(sockfd, IPPROTO_IP, OPENSTATE, &rules, len))
	{
		printf("Filter rule synchronization to kernel space failed\n");
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:开启/关闭防火墙状态检测功能
void open_stateInp(int sockfd, socklen_t len)
{
	int choice;
	printf("1. 开启/关闭状态检测功能   2. 查看当前连接   3. 清空当前连接\n");
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.inp_status = !rules.inp_status;     
		if (rules.inp_status == 1)
		{
			printf("防火墙状态检测已开启!\n");
		}
		else
		{
			printf("防火墙状态检测已关闭!\n");
		}

		rules.connNum = 0;
		memset(rules.connNode, 0, sizeof(rules.connNode));   
		if (setsockopt(sockfd, IPPROTO_IP, INPSTATE, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else if (choice == 2)
	{
		if (getsockopt(sockfd, IPPROTO_IP, CONNGET, (void *)&rules, &len))
		{
			printError("get filtering rules from kernel space");
		}

		if (rules.inp_status == 1)
		{
			if (rules.connNum == 0)
			{
				printf("当前无连接\n");
			}
			else
			{
				printf("当前共%d个连接,分别为:\n", rules.connNum);
				for (int i = 0; i < rules.connNum; i++)
				{
					printf("源IP: %d.%d.%d.%d  \t目的IP: %d.%d.%d.%d  \t源端口: %d  \t目的端口: %d  \t协议:", 
					(rules.connNode[i].src_ip & 0x000000ff) >> 0, (rules.connNode[i].src_ip & 0x0000ff00) >> 8,
					(rules.connNode[i].src_ip & 0x00ff0000) >> 16, (rules.connNode[i].src_ip & 0xff000000) >> 24, 
					(rules.connNode[i].dst_ip & 0x000000ff) >> 0, (rules.connNode[i].dst_ip & 0x0000ff00) >> 8,
					(rules.connNode[i].dst_ip & 0x00ff0000) >> 16, (rules.connNode[i].dst_ip & 0xff000000) >> 24,
					 rules.connNode[i].src_port, rules.connNode[i].dst_port);

					switch (rules.connNode[i].protocol)
					{
					case 1:
						printf("TCP\n");
						break;
					case 2:
						printf("UDP\n");
						break;
					case 3:
						printf("ICMP\n");
						break;				
					default:
						break;
					}
				}
			}	
		}
		else
		{
			printf("状态检测功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.inp_status == 1)
		{
			rules.inp_status = 1;    
			rules.connNum = 0;
			memset(rules.connNode, 0, sizeof(rules.connNode));   

			if (setsockopt(sockfd, IPPROTO_IP, INPSTATE, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
			printf("连接已清空\n");
		}
		else
		{
			printf("状态检测功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:开启/关闭防火墙NAT功能
void change_nat(int sockfd, socklen_t len)
{
	char str_ip[20];
	unsigned short port;
	int choice;
	
	printf("1. 开启/关闭NAT功能   2. 查看NAT转换表   3. 新增NAT转换   4. 删除NAT转换   5. 清空NAT转换表\n");
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.nat_status = !rules.nat_status;     
		if (rules.nat_status == 1)
		{
			printf("NAT功能已开启\n");
			for (int i = 0; i < NAT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要NAT转换的组合（退出: 0）:\n", i + 1);
				printf("请输入内网源IP:");
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.natTable[i].firewall_ip = inet_addr(str_ip);

				printf("请输入内网源端口号:");
				scanf("%hu", &port);
				rules.natTable[i].firewall_port = port;

				printf("请输入对应的外网源IP:");
				scanf("%s", str_ip);
				rules.natTable[i].nat_ip = inet_addr(str_ip);

				printf("请输入对应的外网源端口号:");
				scanf("%hu", &port);
				rules.natTable[i].nat_port = port;

				rules.natNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, NATSTATE, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("NAT功能已关闭\n");
			rules.nat_status = 0;
			memset(rules.natTable, 0, sizeof(rules.natTable));   
			rules.natNum = 0;

			if (setsockopt(sockfd, IPPROTO_IP, NATSTATE, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
	}
	else if (choice == 2)
	{
		if (rules.nat_status == 1)
		{
			if (rules.natNum == 0)
			{
				printf("尚未设置NAT\n");
			}
			else
			{
				printf("内网地址\t\t外网地址\n");
				for (int i = 0; i < rules.natNum; i++)
				{
					printf("%d.%d.%d.%d:%hu\t\t",(rules.natTable[i].firewall_ip & 0x000000ff) >> 0, (rules.natTable[i].firewall_ip & 0x0000ff00) >> 8,
					(rules.natTable[i].firewall_ip & 0x00ff0000) >> 16, (rules.natTable[i].firewall_ip & 0xff000000) >> 24, rules.natTable[i].firewall_port);

					printf("%d.%d.%d.%d:%hu\n",(rules.natTable[i].nat_ip & 0x000000ff) >> 0, (rules.natTable[i].nat_ip & 0x0000ff00) >> 8,
					(rules.natTable[i].nat_ip & 0x00ff0000) >> 16, (rules.natTable[i].nat_ip & 0xff000000) >> 24, rules.natTable[i].nat_port);
				}
			}
		}
		else
		{
			printf("NAT功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.nat_status == 1)
		{
			for (int i = rules.natNum; i < NAT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要NAT转换的组合（退出: 0）:\n", i + 1);
				printf("请输入内网源IP:");
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.natTable[i].firewall_ip = inet_addr(str_ip);

				printf("请输入内网源端口号:");
				scanf("%hu", &port);
				rules.natTable[i].firewall_port = port;

				printf("请输入对应的外网源IP:");
				scanf("%s", str_ip);
				rules.natTable[i].nat_ip = inet_addr(str_ip);

				printf("请输入对应的外网源端口号:");
				scanf("%hu", &port);
				rules.natTable[i].nat_port = port;

				rules.natNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, NATSTATE, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("NAT功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.nat_status == 1)
		{

			int pos;
			printf("请输入需要删除的NAT转化编号: ");
			scanf("%d", &pos);

			if (pos < 0 || pos > rules.natNum) 
			{ 
        		printf("Invalid position!\n");
    		}
			else
			{
				for (int i = pos - 1; i < rules.natNum - 1; i++)
				{ 
					memcpy(&rules.natTable[i], &rules.natTable[i + 1], sizeof(rules.natTable[i]));
				}
				rules.natNum--; 

				if (setsockopt(sockfd, IPPROTO_IP, NATSTATE, &rules, len))
				{
					printf("Filter rule synchronization to kernel space failed\n");
				}
			}
		}
		else
		{
			printf("NAT功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.nat_status == 1)
		{
			memset(rules.natTable, 0, sizeof(rules.natTable));   
			rules.natNum = 0;
			printf("NAT转化表已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, NATSTATE, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("NAT功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:设置防火墙开启时间段
void set_opentime(int sockfd, socklen_t len)
{
	rules.settime_status = !rules.settime_status;
	if (rules.settime_status == 1)
	{
		struct tm start_date, end_date;
		char start_date_str[32];
		char end_date_str[32];	

		printf("请输入防火墙开始日期（格式:YYYY-MM-DD）:\n");
		scanf("%s", start_date_str);
		printf("请输入防火墙结束日期（格式:YYYY-MM-DD）:\n");
		scanf("%s", end_date_str);

		if (!strptime(start_date_str, "%Y-%m-%d", &start_date)) 
		{
			printf("输入格式有误,请重新设置！\n");
			rules.settime_status = 0;
			printf("Press enter to continue...\n");
			getchar(); 
			getchar(); 
			return;
		}
		start_date.tm_hour = 0 - 8;
		start_date.tm_min = 0;
		start_date.tm_sec = 0;
		start_date.tm_isdst = -1;  // 自动判断夏令时

		if (!strptime(end_date_str, "%Y-%m-%d", &end_date)) 
		{
			printf("输入格式有误,请重新设置！\n");
			rules.settime_status = 0;
			printf("Press enter to continue...\n");
			getchar(); 
			getchar(); 
			return;
		}
		end_date.tm_hour = 23 - 8;
		end_date.tm_min = 59;
		end_date.tm_sec = 59;
		end_date.tm_isdst = -1;    // 自动判断夏令时

		printf("防火墙启用时间段: %d-%d-%d %d:%d:%d  ~  %d-%d-%d %d:%d:%d\n", start_date.tm_year+1900, start_date.tm_mon + 1, start_date.tm_mday, start_date.tm_hour + 8, 
		start_date.tm_min, start_date.tm_sec, end_date.tm_year+1900, end_date.tm_mon + 1, end_date.tm_mday, end_date.tm_hour + 8, end_date.tm_min, end_date.tm_sec);

		rules.start_date = mktime(&start_date);
		rules.end_date = mktime(&end_date);
	}

	if (setsockopt(sockfd, IPPROTO_IP, SETTIME, &rules, len))
	{
		printf("Filter rule synchronization to kernel space failed\n");
	}
    printf("Press enter to continue...\n");
	getchar(); 
	getchar(); 
}

// 功能函数:改变IP过滤规则
void change_ip(int sockfd, socklen_t len)                
{
	int choice;
	printf("1. 源IP过滤功能   2. 目的IP过滤功能\n");
	scanf("%d", &choice);
	if (choice == 1) 
	{
		change_sip(sockfd, len);
	}
	else if (choice == 2)
	{
		change_dip(sockfd, len);
	}
	else
	{
		printf("Bad parameter.\n");
	}
}

// 功能函数:改变源IP过滤规则
void change_sip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;
	
	printf("1. 开启/关闭源IP过滤功能   2. 查看过滤的源IP地址   3. 新增源IP地址   4. 删除源IP地址   5. 清空源IP地址\n");
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.sip_status = !rules.sip_status;     
		if (rules.sip_status == 1)
		{
			printf("源IP过滤功能已开启\n");
			for (int i = 0; i < IP_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的IP地址（退出: 0）:", i + 1);
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.ban_sip[i] = inet_addr(str_ip);   // 将字符串形式的IP地址转换为网络字节序
				rules.sipNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("源IP过滤功能已关闭\n");
			rules.sip_status = 0;
			memset(rules.ban_sip, '\0', sizeof(rules.ban_sip));   
			rules.sipNum = 0;

			if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
	}
	else if (choice == 2)
	{
		if (rules.sip_status == 1)
		{
			if (rules.sipNum == 0)
			{
				printf("尚未设置过滤的源IP地址\n");
			}
			else
			{
				for (int i = 0; i < rules.sipNum; i++)
				{
					printf("第%d个过滤的源IP地址为: %d.%d.%d.%d\n", i + 1, 
					(rules.ban_sip[i] & 0x000000ff) >> 0, (rules.ban_sip[i] & 0x0000ff00) >> 8,
					(rules.ban_sip[i] & 0x00ff0000) >> 16, (rules.ban_sip[i] & 0xff000000) >> 24);
				}
			}
		}
		else
		{
			printf("过滤源IP功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.sip_status == 1)
		{
			for (int i = rules.sipNum; i < IP_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的IP地址（退出: 0）:", i + 1);
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.ban_sip[i] = inet_addr(str_ip);   // 将字符串形式的IP地址转换为网络字节序
				rules.sipNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤源IP功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.sip_status == 1)
		{
			for (int i = 0; i < rules.sipNum; i++)
			{
				printf("第%d个过滤的源IP地址为: %d.%d.%d.%d\n", i + 1, 
				(rules.ban_sip[i] & 0x000000ff) >> 0, (rules.ban_sip[i] & 0x0000ff00) >> 8,
				(rules.ban_sip[i] & 0x00ff0000) >> 16, (rules.ban_sip[i] & 0xff000000) >> 24);
			}

			int pos;
			printf("请输入需要删除的IP地址编号: ");
			scanf("%d", &pos);

			if (pos < 0 || pos > rules.sipNum) 
			{ 
        		printf("Invalid position!\n");
    		}
			else
			{
				for (int i = pos - 1; i < rules.sipNum - 1; i++)
				{ 
					rules.ban_sip[i] = rules.ban_sip[i + 1];
				}
				rules.sipNum--; 

				if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
				{
					printf("Filter rule synchronization to kernel space failed\n");
				}
			}
		}
		else
		{
			printf("过滤源IP功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.sip_status == 1)
		{
			memset(rules.ban_sip, '\0', sizeof(rules.ban_sip));   
			rules.sipNum = 0;
			printf("源IP地址已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤源IP功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变目的IP过滤规则
void change_dip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;
	
	printf("1. 开启/关闭目的IP过滤功能   2. 查看过滤的目的IP地址   3. 新增目的IP地址   4. 删除目的IP地址   5. 清空目的IP地址\n");
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.dip_status = !rules.dip_status;     
		if (rules.dip_status == 1)
		{
			printf("目的IP过滤功能已开启\n");
			for (int i = 0; i < IP_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的IP地址（退出: 0）:", i + 1);
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.ban_dip[i] = inet_addr(str_ip);   // 将字符串形式的IP地址转换为网络字节序
				rules.dipNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("目的IP过滤功能已关闭\n");
			rules.dip_status = 0;
			memset(rules.ban_dip, '\0', sizeof(rules.ban_dip));   
			rules.dipNum = 0;

			if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
	}
	else if (choice == 2)
	{
		if (rules.dip_status == 1)
		{
			if (rules.dipNum == 0)
			{
				printf("尚未设置过滤的目的IP地址\n");
			}
			else
			{
				for (int i = 0; i < rules.dipNum; i++)
				{
					printf("第%d个过滤的目的IP地址为: %d.%d.%d.%d\n", i + 1, 
					(rules.ban_dip[i] & 0x000000ff) >> 0, (rules.ban_dip[i] & 0x0000ff00) >> 8,
					(rules.ban_dip[i] & 0x00ff0000) >> 16, (rules.ban_dip[i] & 0xff000000) >> 24);
				}
			}
		}
		else
		{
			printf("过滤目的IP功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.dip_status == 1)
		{
			for (int i = rules.dipNum; i < IP_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的IP地址（退出: 0）:", i + 1);
				scanf("%s", str_ip);
				if (!strcmp(str_ip, "0"))
				{
					// printf("\n输入完毕\n");
					break;
				}
				rules.ban_dip[i] = inet_addr(str_ip);   // 将字符串形式的IP地址转换为网络字节序
				rules.dipNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤目的IP功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.dip_status == 1)
		{
			for (int i = 0; i < rules.dipNum; i++)
			{
				printf("第%d个过滤的目的IP地址为: %d.%d.%d.%d\n", i + 1, 
				(rules.ban_dip[i] & 0x000000ff) >> 0, (rules.ban_dip[i] & 0x0000ff00) >> 8,
				(rules.ban_dip[i] & 0x00ff0000) >> 16, (rules.ban_dip[i] & 0xff000000) >> 24);
			}

			int pos;
			printf("请输入需要删除的IP地址编号: ");
			scanf("%d", &pos);

			if (pos < 0 || pos > rules.dipNum) 
			{ 
        		printf("Invalid position!\n");
    		}
			else
			{
				for (int i = pos - 1; i < rules.dipNum - 1; i++)
				{ 
					rules.ban_dip[i] = rules.ban_dip[i + 1];
				}
				rules.dipNum--; 

				if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
				{
					printf("Filter rule synchronization to kernel space failed\n");
				}
			}
		}
		else
		{
			printf("过滤目的IP功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.dip_status == 1)
		{
			memset(rules.ban_dip, '\0', sizeof(rules.ban_dip));   
			rules.dipNum = 0;
			printf("目的IP地址已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤目的IP功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}
}

// 功能函数:改变端口号过滤规则
void change_port(int sockfd, socklen_t len)                
{
	int choice;
	printf("1. 源端口过滤功能   2. 目的端口过滤功能\n");
	scanf("%d", &choice);
	if (choice == 1) 
	{
		change_sport(sockfd, len);
	}
	else if (choice == 2)
	{
		change_dport(sockfd, len);
	}
	else
	{
		printf("Bad parameter.\n");
	}
}

// 功能函数:改变源端口过滤规则
void change_sport(int sockfd, socklen_t len)
{
	int choice;
	printf("1. 开启/关闭源端口号过滤功能   2. 查看过滤的源端口号   3. 新增源端口号   4. 删除源端口号   5. 清空源端口号\n");
	scanf("%d", &choice);

	if (choice == 1)   
	{
		rules.sport_status = !rules.sport_status;     
		if (rules.sport_status == 1)
		{
			printf("源端口号过滤功能已开启\n");
			for (int i = 0; i < PORT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的端口号 (退出: 0):", i + 1);
				unsigned short sport;
				scanf("%hu", &sport);
				if (sport == 0) break;	        // 0代表输入完成,提前退出循环
				rules.ban_sport[i] = sport;     
				rules.sportNum = i + 1;         
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}

		}
		else
		{
			printf("源端口号过滤功能已关闭\n");
			memset(rules.ban_sport, 0, sizeof(rules.ban_sport));  
			rules.sportNum = 0;

			if (setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}	
		}
	}
	else if (choice == 2)
	{
		if (rules.sport_status == 1)
		{
			if (rules.sportNum == 0)
			{
				printf("尚未设置过滤的源端口号\n");
			}
			else
			{
				printf("过滤的源端口号为: ");
				for (int i = 0; i < rules.sportNum; i++)
				{
					printf("%hu ", rules.ban_sport[i]);   
				}
				printf("\n");
			}
		}
		else
		{
			printf("过滤源端口号功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.sport_status == 1)
		{
			for (int i = rules.sportNum; i < PORT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的端口号 (退出: 0):", i + 1);
				unsigned short sport;
				scanf("%hu", &sport);
				if (sport == 0) break;	        // 0代表输入完成,提前退出循环
				rules.ban_sport[i] = sport;     
				rules.sportNum = i + 1;         
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤源端口号功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.sport_status == 1)
		{
			printf("过滤的源端口号为: ");
			for (int i = 0; i < rules.sportNum; i++)
			{
				printf("%hu ", rules.ban_sport[i]);   
			}
			printf("\n");

			unsigned short del_port;
			printf("请输入需要删除的源端口号: ");
			scanf("%hu", &del_port);

			if (del_port < 1 || del_port > 65535) 
			{ 
        		printf("Illegal port!\n");
    		}
			else
			{
				for (int i = 0; i < rules.sportNum; i++)
				{ 
					if (rules.ban_sport[i] == del_port)
					{
						for (int j = i; j < rules.sportNum - 1; j++)
						{ 
							rules.ban_sport[j] = rules.ban_sport[j + 1];
						}
						rules.sportNum--;
						printf("端口号: %hu 已删除\n", del_port);

						if (setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
						{
							printf("Filter rule synchronization to kernel space failed\n");
						}
						break;
					}
					if (i == rules.sportNum - 1)
					{
						printf("要删除的端口号不存在\n");
					}				
				}
			}
		}
		else
		{
			printf("过滤源端口号功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.sport_status == 1)
		{
			memset(rules.ban_sport, 0, sizeof(rules.ban_sport));  
			rules.sportNum = 0;
			printf("源端口号已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}	
		}
		else
		{
			printf("过滤源端口号功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变目的端口过滤规则
void change_dport(int sockfd, socklen_t len)
{
	int choice;
	printf("1. 开启/关闭目的端口号过滤功能   2. 查看过滤的目的端口号   3. 新增目的端口号   4. 删除目的端口号   5. 清空目的端口号\n");
	scanf("%d", &choice);

	if (choice == 1)   
	{
		rules.dport_status = !rules.dport_status;     
		if (rules.dport_status == 1)
		{
			printf("目的端口号过滤功能已开启\n");
			for (int i = 0; i < PORT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的目的口号 (退出: 0):", i + 1);
				unsigned short dport;
				scanf("%hu", &dport);
				if (dport == 0) break;	        // 0代表输入完成,提前退出循环
				rules.ban_dport[i] = dport;     
				rules.dportNum = i + 1;         
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("目的端口号过滤功能已关闭\n");
			memset(rules.ban_dport, 0, sizeof(rules.ban_dport));  
			rules.dportNum = 0;

			if (setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}	
		}
	}
	else if (choice == 2)
	{
		if (rules.dport_status == 1)
		{
			if (rules.dportNum == 0)
			{
				printf("尚未设置过滤的目的端口号\n");
			}
			else
			{
				printf("过滤的目的端口号为: ");
				for (int i = 0; i < rules.dportNum; i++)
				{
					printf("%hu ", rules.ban_dport[i]);   
				}
				printf("\n");
			}
		}
		else
		{
			printf("过滤目的端口号功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.dport_status == 1)
		{
			for (int i = rules.dportNum; i < PORT_NUM_MAX; i++)
			{
				printf("请输入第 %d 个需要过滤的目的口号 (退出: 0):", i + 1);
				unsigned short dport;
				scanf("%hu", &dport);
				if (dport == 0) break;	        // 0代表输入完成,提前退出循环
				rules.ban_dport[i] = dport;     
				rules.dportNum = i + 1;         
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("过滤目的端口号功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.dport_status == 1)
		{
			printf("过滤的目的端口号为: ");
			for (int i = 0; i < rules.dportNum; i++)
			{
				printf("%hu ", rules.ban_dport[i]);   
			}
			printf("\n");

			unsigned short del_port;
			printf("请输入需要删除的目的端口号: ");
			scanf("%hu", &del_port);

			if (del_port < 1 || del_port > 65535) 
			{ 
        		printf("Illegal port!\n");
    		}
			else
			{
				for (int i = 0; i < rules.dportNum; i++)
				{ 
					if (rules.ban_dport[i] == del_port)
					{
						for (int j = i; j < rules.dportNum - 1; j++)
						{ 
							rules.ban_dport[j] = rules.ban_dport[j + 1];
						}
						rules.dportNum--;
						printf("端口号: %hu 已删除\n", del_port);

						if (setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
						{
							printf("Filter rule synchronization to kernel space failed\n");
						}
						break;
					}
					if (i == rules.dportNum - 1)
					{
						printf("要删除的目的口号不存在\n");
					}				
				}
			}
		}
		else
		{
			printf("过滤目的端口号功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.dport_status == 1)
		{
			memset(rules.ban_dport, 0, sizeof(rules.ban_dport));  
			rules.dportNum = 0;
			printf("目的端口号已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}	
		}
		else
		{
			printf("过滤目的端口号功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变自定义访问控制规则
void change_combin(int sockfd, socklen_t len)
{
	unsigned char mac_str[20];  	// 存储输入的MAC地址字符串
	unsigned char mac_addr[6];      // 存储将字符串分割后的MAC地址
	char str_ip[20];                // 存储输入的IP地址
		
	printf("1. 开启/关闭自定义过滤规则功能   2. 查看自定义规则   3. 新增自定义规则   4. 删除自定义规则   5. 清空自定义规则\n");
	int choice;
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.combin_status = !rules.combin_status;     
		if (rules.combin_status == 1)
		{
			printf("自定义访问控制策略功能已开启\n");
			for (int i = 0; i < COMBINE_NUM_MAX; i++)
			{
				printf("\n请输入第 %d 个自定义访问控制策略 (退出: 0):\n", i + 1);
				int select;
				printf("是否根据源IP地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banSip_status = 1;
					printf("请输入需要过滤的源IP地址:");
					scanf("%s", str_ip);
					rules.ban_combin[i].banSip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banSip_status = 0;
				}
				else if (select == 0)
				{
					break;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据目的IP地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banDip_status = 1;
					printf("请输入需要过滤的目的IP地址:");
					scanf("%s", str_ip);
					rules.ban_combin[i].banDip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banDip_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据源端口过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banSport_status = 1;
					printf("请输入需要过滤的源端口号:");
					scanf("%hu", &rules.ban_combin[i].ban_sport);
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banSport_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据目的端口过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banDport_status = 1;
					printf("请输入需要过滤的目的端口号:");
					scanf("%hu", &rules.ban_combin[i].ban_dport);
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banDport_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据MAC地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banMac_status = 1;
					printf("请输入需要过滤的输入MAC:");
					scanf("%s", mac_str);
					mac_format(mac_str, mac_addr);
					memcpy(rules.ban_combin[i].banMac, mac_addr, sizeof(rules.ban_combin[i].banMac));
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banMac_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				rules.combineNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");			
			}
		}
		else
		{
			printf("自定义访问控制策略功能已关闭\n");
			rules.combin_status = 0;
			rules.combineNum = 0;
			memset(rules.ban_combin, 0, sizeof(rules.ban_combin));  

			if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
	}
	else if (choice == 2)
	{
		if (rules.combin_status == 1)
		{
			if (rules.combineNum == 0)
			{
				printf("尚未设置自定义访问控制策略\n");
			}
			else
			{
				printf("共%d个自定义访问控制策略\n", rules.combineNum);
				for (int i = 0; i < rules.combineNum; i++)
				{
					printf("\n第%d个自定义访问控制策略:\n", i + 1);
					if (rules.ban_combin[i].banSip_status == 1)
					{
						printf("源IP地址: \t%d.%d.%d.%d\n", 
						(rules.ban_combin[i].banSip & 0x000000ff) >> 0, (rules.ban_combin[i].banSip & 0x0000ff00) >> 8,
						(rules.ban_combin[i].banSip & 0x00ff0000) >> 16, (rules.ban_combin[i].banSip & 0xff000000) >> 24);
					}

					if (rules.ban_combin[i].banDip_status == 1)
					{
						printf("目的IP地址: \t%d.%d.%d.%d\n", 
						(rules.ban_combin[i].banDip & 0x000000ff) >> 0, (rules.ban_combin[i].banDip & 0x0000ff00) >> 8,
						(rules.ban_combin[i].banDip & 0x00ff0000) >> 16, (rules.ban_combin[i].banDip & 0xff000000) >> 24);
					}	

					if (rules.ban_combin[i].banSport_status == 1)
					{
						printf("源端口号: \t%hu\n", rules.ban_combin[i].ban_sport);
					}	

					if (rules.ban_combin[i].banDport_status == 1)
					{
						printf("目的端口号: \t%hu\n", rules.ban_combin[i].ban_dport);
					}	

					if (rules.ban_combin[i].banMac_status == 1)
					{
						printf("MAC地址:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
						rules.ban_combin[i].banMac[0], rules.ban_combin[i].banMac[1], rules.ban_combin[i].banMac[2], 
						rules.ban_combin[i].banMac[3], rules.ban_combin[i].banMac[4], rules.ban_combin[i].banMac[5]);
					}
				}
			}
		}
		else
		{
			printf("自定义访问控制策略功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.combin_status == 1)
		{
			for (int i = rules.combineNum; i < COMBINE_NUM_MAX; i++)
			{
				printf("\n请输入第 %d 个自定义访问控制策略 (退出: 0):\n", i + 1);
				int select;
				printf("是否根据源IP地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banSip_status = 1;
					printf("请输入需要过滤的源IP地址:");
					scanf("%s", str_ip);
					rules.ban_combin[i].banSip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banSip_status = 0;
				}
				else if (select == 0)
				{
					break;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据目的IP地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banDip_status = 1;
					printf("请输入需要过滤的目的IP地址:");
					scanf("%s", str_ip);
					rules.ban_combin[i].banDip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banDip_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据源端口过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banSport_status = 1;
					printf("请输入需要过滤的源端口号:");
					scanf("%hu", &rules.ban_combin[i].ban_sport);
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banSport_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据目的端口过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banDport_status = 1;
					printf("请输入需要过滤的目的端口号:");
					scanf("%hu", &rules.ban_combin[i].ban_dport);
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banDport_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				printf("是否根据MAC地址过滤(是:1  否:2):\n");
				scanf("%d", &select);
				if (select == 1)
				{
					rules.ban_combin[i].banMac_status = 1;
					printf("请输入需要过滤的输入MAC:");
					scanf("%s", mac_str);
					mac_format(mac_str, mac_addr);
					memcpy(rules.ban_combin[i].banMac, mac_addr, sizeof(rules.ban_combin[i].banMac));
				}
				else if (select == 2)
				{
					rules.ban_combin[i].banMac_status = 0;
				}
				else
				{
					printf("Bad parameter.\n");
					break;
				}

				rules.combineNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("自定义访问控制策略功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.combin_status == 1)
		{
			for (int i = 0; i < rules.combineNum; i++)
			{
				printf("\n第%d个自定义访问控制策略:\n", i + 1);
				if (rules.ban_combin[i].banSip_status == 1)
				{
					printf("源IP地址: \t%d.%d.%d.%d\n", 
					(rules.ban_combin[i].banSip & 0x000000ff) >> 0, (rules.ban_combin[i].banSip & 0x0000ff00) >> 8,
					(rules.ban_combin[i].banSip & 0x00ff0000) >> 16, (rules.ban_combin[i].banSip & 0xff000000) >> 24);
				}

				if (rules.ban_combin[i].banDip_status == 1)
				{
					printf("目的IP地址: \t%d.%d.%d.%d\n", 
					(rules.ban_combin[i].banDip & 0x000000ff) >> 0, (rules.ban_combin[i].banDip & 0x0000ff00) >> 8,
					(rules.ban_combin[i].banDip & 0x00ff0000) >> 16, (rules.ban_combin[i].banDip & 0xff000000) >> 24);
				}	

				if (rules.ban_combin[i].banSport_status == 1)
				{
					printf("源端口号: \t%hu\n", rules.ban_combin[i].ban_sport);
				}	

				if (rules.ban_combin[i].banDport_status == 1)
				{
					printf("目的端口号: \t%hu\n", rules.ban_combin[i].ban_dport);
				}	

				if (rules.ban_combin[i].banMac_status == 1)
				{
					printf("MAC地址:\t%02X:%02X:%02X:%02X:%02X:%02X\n",
					rules.ban_combin[i].banMac[0], rules.ban_combin[i].banMac[1], rules.ban_combin[i].banMac[2], 
					rules.ban_combin[i].banMac[3], rules.ban_combin[i].banMac[4], rules.ban_combin[i].banMac[5]);
				}
			}

			int pos;
			printf("请输入需要删除的自定义访问控制策略编号: ");
			scanf("%d", &pos);

			if (pos < 0 || pos > rules.combineNum) 
			{ 
        		printf("Invalid position!\n");
    		}
			else
			{
				for (int i = pos - 1; i < rules.combineNum - 1; i++)
				{ 
					rules.ban_combin[i] = rules.ban_combin[i + 1];
				}
				rules.combineNum--; 

				if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
				{
					printf("Filter rule synchronization to kernel space failed\n");
				}
			}
		}
		else
		{
			printf("自定义访问控制策略功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.combin_status == 1)
		{
			rules.combineNum = 0;
			memset(rules.ban_combin, 0, sizeof(rules.ban_combin));  
			printf("自定义访问控制策略已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");
			}
		}
		else
		{
			printf("自定义访问控制策略功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变PING规则
void change_ping(int sockfd, socklen_t len)
{
	rules.ping_status = !rules.ping_status;

	if (setsockopt(sockfd, IPPROTO_IP, BANPING, &rules, len))
	{
		printf("Filter rule synchronization to kernel space failed\n");
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变HTTP/HTTPS规则
void change_http(int sockfd, socklen_t len)
{
	rules.http_status = !rules.http_status;

	if (setsockopt(sockfd, IPPROTO_IP, BANHTTP, &rules, len))  
	{
		printf("Filter rule synchronization to kernel space failed\n");		
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变Telnet规则
void change_telnet(int sockfd, socklen_t len)
{
	rules.telnet_status = !rules.telnet_status;

	if (setsockopt(sockfd, IPPROTO_IP, BANTELNET, &rules, len))  
	{
		printf("Filter rule synchronization to kernel space failed\n");		
	}	
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}     

// 功能函数:改变协议类型过滤规则
void change_protocol(int sockfd, socklen_t len)
{
	rules.protocol_status = !rules.protocol_status;
	if (rules.protocol_status == 1)
	{
		char options[3];
		printf("1.TCP\t2.UDP\t3.ICMP\n请选择一个或多个封禁的协议类型: ");
		scanf("%s", options);

		for (int i = 0; i < strlen(options); i++)
		{
			switch(options[i])
			{
				case '1':
					rules.protocol_type[0] = 1;
					break;
				case '2':
					rules.protocol_type[1] = 1;
					break;
				case '3':
					rules.protocol_type[2] = 1;
					break;
				default:
					printf("您选择了无效的选项 %c\n", options[i]);
			}
		}

		printf("封禁协议类型: ");
		if (rules.protocol_type[0])
		{
			printf("TCP ");
		}
		if (rules.protocol_type[1])
		{
			printf("UDP ");
		}
		if (rules.protocol_type[2])
		{
			printf("ICMP ");
		}
		printf("\n");

		if (setsockopt(sockfd, IPPROTO_IP, BANPROTOCOL, &rules, len))  
		{
			printf("Filter rule synchronization to kernel space failed\n");		
		}	
	}
	else
	{
		printf("根据协议类型过滤功能已关闭\n");
		memset(&rules.protocol_type, 0, sizeof(rules.protocol_type));	

		if (setsockopt(sockfd, IPPROTO_IP, BANPROTOCOL, &rules, len))  
		{
			printf("Filter rule synchronization to kernel space failed\n");		
		}
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 工具函数:将MAC地址分割并存入mac_addr
void mac_format(char *mac_str, unsigned char *mac_addr)
{
    char *ptr = strtok(mac_str, ":");      // 将字符串按“:”分割,返回第一个子字符串的指针
    for (int i = 0; i < 6; i++)
	{
        mac_addr[i] = (unsigned char)strtol(ptr, NULL, 16);    // 将子字符串转换为 unsigned char 类型的数字
        ptr = strtok(NULL, ":");                               // 继续按“:”分割,返回下一个子字符串的指针
    }
}

// 功能函数:改变MAC地址过滤规则	
void change_mac(int sockfd, socklen_t len)
{
	unsigned char mac_str[20];  	// 存储输入的MAC地址字符串
	unsigned char mac_addr[6];      // 存储将字符串分割后的MAC地址

	printf("1. 开启/关闭MAC地址过滤功能   2. 查看过滤的MAC地址   3. 新增MAC地址   4. 删除MAC地址   5. 清空MAC地址\n");
	int choice;
	scanf("%d", &choice);
	if (choice == 1)   
	{
		rules.mac_status = !rules.mac_status;     
		if (rules.mac_status == 1)
		{
			printf("MAC地址过滤功能已开启\n");
			for (int i = 0; i < MAC_NUM_MAX; i++)
			{
				printf("请输入第 %d 个 需要过滤的MAC地址（退出: 0）:", i + 1);
				scanf("%s", mac_str);
				if (!strcmp(mac_str, "0"))
				{
					break;
				}
				mac_format(mac_str, mac_addr);
				memcpy(rules.ban_mac[i], mac_addr, sizeof(rules.ban_mac[i]));
				rules.macNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");			
			}
		}
		else
		{
			printf("MAC地址过滤功能已关闭\n");
			rules.mac_status = 0;
			rules.macNum = 0;
			memset(rules.ban_mac, 0, sizeof(rules.ban_mac));		

			if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len)) 
			{
				printf("Filter rule synchronization to kernel space failed\n");			
			}
		}
	}
	else if (choice == 2)
	{
		if (rules.mac_status == 1)
		{
			if (rules.macNum == 0)
			{
				printf("尚未设置过滤的MAC地址\n");
			}
			else
			{
				for (int i = 0; i < rules.macNum; i++)
				{
					printf("第%d个过滤MAC地址:%02X:%02X:%02X:%02X:%02X:%02X\n", i + 1,
					rules.ban_mac[i][0], rules.ban_mac[i][1], rules.ban_mac[i][2], 
					rules.ban_mac[i][3], rules.ban_mac[i][4], rules.ban_mac[i][5]);
				}
			}
		}
		else
		{
			printf("过滤MAC功能未开启\n");
		}
	}
	else if (choice == 3)
	{
		if (rules.mac_status == 1)
		{
			for (int i = rules.macNum; i < MAC_NUM_MAX; i++)
			{
				printf("请输入第 %d 个 需要过滤的MAC地址（退出: 0）:", i + 1);
				scanf("%s", mac_str);
				if (!strcmp(mac_str, "0"))
				{
					break;
				}
				mac_format(mac_str, mac_addr);
				memcpy(rules.ban_mac[i], mac_addr, sizeof(rules.ban_mac[i]));
				rules.macNum = i + 1;
			}

			if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len))
			{
				printf("Filter rule synchronization to kernel space failed\n");			
			}
		}
		else
		{
			printf("过滤MAC功能未开启\n");
		}
	}
	else if (choice == 4)
	{
		if (rules.mac_status == 1)
		{
			for (int i = 0; i < rules.macNum; i++)
			{
				printf("第%d个过滤MAC地址:%02X:%02X:%02X:%02X:%02X:%02X\n", i + 1,
				rules.ban_mac[i][0], rules.ban_mac[i][1], rules.ban_mac[i][2], 
				rules.ban_mac[i][3], rules.ban_mac[i][4], rules.ban_mac[i][5]);
			}
			
			int pos;
			printf("请输入需要删除的MAC地址编号: ");
			scanf("%d", &pos);

			if (pos < 0 || pos > rules.macNum) 
			{ 
        		printf("Invalid position!\n");
    		}
			else
			{
				for (int i = pos - 1; i < rules.macNum - 1; i++)
				{ 
					memcpy(rules.ban_mac[i], rules.ban_mac[i + 1], sizeof(rules.ban_mac[i]));
				}
				rules.macNum--; 
				printf("删除成功\n");

				if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len))
				{
					printf("Filter rule synchronization to kernel space failed\n");
				}
			}
		}
		else
		{
			printf("过滤MAC功能未开启\n");
		}
	}
	else if (choice == 5)
	{
		if (rules.mac_status == 1)
		{
			memset(rules.ban_mac, 0, sizeof(rules.ban_mac));	
			rules.macNum = 0;	
			printf("MAC地址已清空\n");

			if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len)) 
			{
				printf("Filter rule synchronization to kernel space failed\n");			
			}
		}
		else
		{
			printf("过滤MAC功能未开启\n");
		}
	}
	else
	{
		printf("Bad parameter.\n");
	}

    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变关闭所有连接规则
void change_close(int sockfd, socklen_t len)
{
	rules.close_status = !rules.close_status;
	if (rules.close_status == 1)
	{
		struct tm start_time, end_time;
    	time_t t = time(NULL);            // 获取当前时间的时间戳

		// 将当前时间的时间戳转换为tm结构体并复制给start_time、end_time。
    	localtime_r(&t, &start_time);     
    	localtime_r(&t, &end_time);

		int start_hour, end_hour;

		printf("请输入规则开启时间(h):\n");
		scanf("%d", &start_hour);
		printf("请输入规则结束时间(h):\n");
		scanf("%d", &end_hour);

		// 设置修改后的开始时间
    	start_time.tm_hour = start_hour - 8; 
    	start_time.tm_min = 0;
    	start_time.tm_sec = 0;

		// 设置修改后的结束时间
    	end_time.tm_hour = end_hour - 8; 
    	end_time.tm_min = 59;
    	end_time.tm_sec = 59;

		printf("规则生效时间段: %d-%d-%d %d:%d:%d  ~  %d-%d-%d %d:%d:%d\n", start_time.tm_year+1900, start_time.tm_mon + 1, start_time.tm_mday, start_time.tm_hour + 8, 
		start_time.tm_min, start_time.tm_sec, end_time.tm_year+1900, end_time.tm_mon + 1, end_time.tm_mday, end_time.tm_hour + 8, end_time.tm_min, end_time.tm_sec);

		// 将tm结构体转换为时间戳并存储rules
    	rules.start_time = mktime(&start_time);
    	rules.end_time = mktime(&end_time);
	}
	
	if (setsockopt(sockfd, IPPROTO_IP, BANALL, &rules, len))  
	{
		printf("Filter rule synchronization to kernel space failed\n");		
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:查看当前日志
void show_log()
{
    FILE *fp;
    char log_buf[255];

    fp = fopen(LOG_FILE, "r");
    if (fp == NULL) {
        printf("Failed to open file\n");
        return;
    }

	printf("Firewall access control log content:\n");
    while (fgets(log_buf, 255, fp)) {
        printf("%s", log_buf);
    }

    fclose(fp);
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:恢复默认设置
void restore_default(int sockfd, socklen_t len)
{
	memset(&rules, 0, sizeof(rules));	
	rules.open_status = 1;

	if (setsockopt(sockfd, IPPROTO_IP, RESTORE, &rules, len))  
	{
		printf("Filter rule synchronization to kernel space failed\n");		
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 	
}

// 功能函数:打印错误信息
void printError(char * msg)
{
	printf("%s error %d: %s\n", msg, errno, strerror(errno));
}