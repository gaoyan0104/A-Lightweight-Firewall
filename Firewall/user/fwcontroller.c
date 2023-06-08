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
void change_sip(int sockfd, socklen_t len);                 /*功能函数:改变源IP过滤规则*/
void change_dip(int sockfd, socklen_t len);                 /*功能函数:改变目的IP过滤规则*/
void change_sport(int sockfd, socklen_t len);               /*功能函数:改变源端口过滤规则*/
void change_dport(int sockfd, socklen_t len);               /*功能函数:改变目的端口过滤规则*/
void change_http(int sockfd, socklen_t len);                /*功能函数:改变HTTP/HTTPS规则*/
void change_telnet(int sockfd, socklen_t len);              /*功能函数:改变Telnet规则*/
void change_mac(int sockfd, socklen_t len);                 /*功能函数:改变MAC地址过滤规则*/		
void change_close(int sockfd, socklen_t len);               /*功能函数:改变关闭所有连接规则*/
void change_combin(int sockfd, socklen_t len);              /*功能函数:改变自定义过滤规则*/
void mac_format(char *mac_str, unsigned char *mac_addr);    /*功能函数:将MAC地址分割并存入mac_addr*/
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
		if(getsockopt(sockfd, IPPROTO_IP, NOWRULE, (void *)&rules, &len))
		{
			printError("get filtering rules from kernel space");
		}
		else
		{
			while(1)
			{
				if(rules.open_status == 1)              // 防火墙状态为开启
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
					if(choice == 1) open_firewall(sockfd, len);    // 开启防火墙
					else if(choice == 0) exit(0);                  // 退出
				}
			}
		}
	}
	return 0;
}

// 功能函数:获取当前防火墙过滤规则
void get_status() 
{	
	time_t timer0;
	timer0= time(NULL);
	struct tm* tm = localtime(&timer0);
	printf("\nTime:%d-%d-%d %d:%d:%d\n", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday, tm->tm_hour + 8, tm->tm_min, tm->tm_sec);
	printf("-------------------------------------------------------------------------------\n");
	
	if (rules.settime_status == 1)
	{
		// 将时间戳转换为tm结构体
		struct tm start_date, end_date;	
    	localtime_r(&rules.start_date, &start_date);     
    	localtime_r(&rules.end_date, &end_date);

		// printf("%ld ~ %ld", rules.start_date, rules.end_date);
		printf("防火墙启用时间段: %d-%d-%d 00:00:00  ~  %d-%d-%d 23:59:59\n", start_date.tm_year+1900, 
		start_date.tm_mon + 1, start_date.tm_mday + 1, end_date.tm_year+1900, end_date.tm_mon + 1, end_date.tm_mday);
	}
	
	printf("当前防火墙过滤规则为:\n");
	printf("--------------------------------------\n");

	printf("防火墙状态检测功能:\t\t");
	if(rules.inp_status == 1)
	{
		printf("开启\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------------------\n");

	printf("根据源IP过滤功能:\t\t");
	if(rules.sip_status == 1)
	{
		printf("开启\n");
		for(int i = 0; i < rules.sipNum; i++){
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

	printf("根据目的IP过滤功能:\t\t");
	if(rules.dip_status == 1)
	{
		printf("开启\n");
		for(int i = 0; i < rules.dipNum; i++){
			printf("过滤源IP地址: %d.%d.%d.%d\n", 
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

	printf("根据源端口过滤功能:\t\t");
	if(rules.sport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for(int i = 0; i < rules.sportNum; i++)
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

	printf("根据目的端口过滤功能:\t\t");
	if(rules.dport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for(int i = 0; i < rules.dportNum; i++)
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

	printf("根据MAC过滤功能:\t\t");
	if(rules.mac_status == 1)
	{
		printf("开启\n");
		for(int i = 0; i < rules.macNum; i++)
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

	printf("自定义访问控制策略功能:\t\t");
	if(rules.combin_status == 1)
	{
		printf("开启\n");
		printf("共%d个自定义访问控制策略\n", rules.combineNum);
		for(int i = 0; i < rules.combineNum; i++)
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

			if(rules.ban_combin[i].banMac_status == 1)
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

	printf("关闭所有连接功能:\t\t");
	if(rules.close_status == 1)
	{
		printf("开启\n");		
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------------------\n");

	printf("PING功能:\t\t\t");
	if(rules.ping_status == 1)
	{
		printf("禁用\n");
	}
	else
	{
		printf("不禁用\n");
	}
	printf("--------------------------------------\n");

	printf("HTTP/HTTPS功能:\t\t\t");
	if(rules.http_status == 1)
	{
		printf("禁用\n");		
	}
	else
	{
		printf("不禁用\n");		
	}
	printf("--------------------------------------\n");

	printf("Telnet功能:\t\t\t");
	if(rules.telnet_status == 1)
	{
		printf("禁用\n");		
	}
	else
	{
		printf("不禁用\n");		
	}
	printf("--------------------------------------\n");
}

// 功能函数:改变防火墙过滤规则
void change_status(int sockfd, socklen_t len)
{
	int choice;
	printf("\n选择需要修改的防火墙过滤规则:\n");
	printf("1.开启/关闭防火墙\t2.状态检测功能\t\t3.设置防火墙生效时间\t4.自定义访问控制策略\n");
	printf("5.过滤源IP\t\t6.过滤目的IP\t\t7.过滤源端口\t\t8.过滤目的端口\n"); 
	printf("9.过滤MAC地址\t\t10.PING功能\t\t11.HTTP/HTTPS功能\t12.Telnet功能\n");
	printf("13.查看日志\t\t14.关闭所有连接\t\t15.恢复默认设置\t\t0.exit\n");
	printf("-------------------------------------------------------------------------------\n");
	// printf("选项:\t");

	scanf("%d", &choice);
	switch (choice)
	{
		case 1:   
			open_firewall(sockfd, len);
			break;	
		case 2:
			open_stateInp(sockfd, len);
			break;
		case 3:   
			set_opentime(sockfd, len);
			break;
		case 4:   
			change_combin(sockfd, len); 
			break;
		case 5:   
			change_sip(sockfd, len);
			break;
		case 6:
			change_dip(sockfd, len);   
			break;
		case 7:   
			change_sport(sockfd, len);	
			break;
		case 8:
			change_dport(sockfd, len);
			break;
		case 9:
			change_mac(sockfd, len);
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
			show_log();
			break;
		case 14:
			change_close(sockfd, len);	
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
	if(rules.open_status == 1)
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
	if(choice == 1)   
	{
		rules.inp_status = !rules.inp_status;     
		if(rules.inp_status == 1)
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
	else if(choice == 2)
	{
		if(getsockopt(sockfd, IPPROTO_IP, CONNGET, (void *)&rules, &len))
		{
			printError("get filtering rules from kernel space");
		}

		if(rules.inp_status == 1)
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
					printf("源IP地址: %d.%d.%d.%d\t   目的IP地址: %d.%d.%d.%d\t   源端口: %d\t   目的端口: %d\t   协议:", 
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
	else if(choice == 3)
	{
		if(rules.inp_status == 1)
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

// 功能函数:改变源IP过滤规则
void change_sip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;

	printf("是否开启过滤源IP功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);
	if(choice == 1)   // 1 开启 、 2 关闭
	{
		rules.sip_status = 1;
		for(int i = 0; i < IP_NUM_MAX; i++)
		{
			printf("请输入第 %d 个 需要过滤的IP地址（退出: 0）:", i + 1);
			scanf("%s", str_ip);
			if(!strcmp(str_ip, "0"))
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
	else if(choice == 2)
	{
		rules.sip_status = 0;
		memset(rules.ban_sip, '\0', sizeof(rules.ban_sip));   
		rules.sipNum = 0;

		if(setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else
	{
		// 输入错误
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

		if (strptime(start_date_str, "%Y-%m-%d", &start_date) == NULL) {
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

		if (strptime(end_date_str, "%Y-%m-%d", &end_date) == NULL) {
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

	if(setsockopt(sockfd, IPPROTO_IP, SETTIME, &rules, len))
	{
		printf("Filter rule synchronization to kernel space failed\n");
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
	
	printf("是否开启过滤目的IP功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);
	if(choice == 1)
	{
		rules.dip_status = 1;
		for(int i = 0; i < IP_NUM_MAX; i++)
		{
			printf("请输入第 %d 个 需要过滤的IP地址（退出: 0）:", i + 1);
			scanf("%s", str_ip);
			if(!strcmp(str_ip, "0"))
			{
				// printf("\n输入完毕\n");
				break;
			}
			rules.ban_dip[i] = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
			rules.dipNum = i + 1;
		}

		if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else if(choice == 2)
	{
		rules.dip_status = 0;
		memset(rules.ban_dip, '\0', sizeof(rules.ban_dip));   
		rules.dipNum = 0;

		if(setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else
	{
		// 输入错误
		printf("Bad parameter.\n");
	}
    printf("Press enter to continue...\n");
    getchar(); 
	getchar(); 
}

// 功能函数:改变源端口过滤规则
void change_sport(int sockfd, socklen_t len)
{
	int choice;
	printf("是否开启过滤源端口功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);

	if(choice == 1)
	{
		rules.sport_status = 1;
		int i;
		for(i = 0; i < PORT_NUM_MAX; i++)
		{
			printf("请输入第 %d 个需要过滤的端口号 (退出: 0):", i + 1);
			unsigned short sport;
			scanf("%hu", &sport);
			if(sport == 0) break;	        // 0代表输入完成,提前退出循环
			rules.ban_sport[i] = sport;     
			rules.sportNum = i + 1;         
		}

		if(setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else if(choice == 2)
	{
		rules.sport_status = 0;
		memset(rules.ban_sport, 0, sizeof(rules.ban_sport));  
		rules.sportNum = 0;

		if(setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}	
	}
	else
	{
		// 输入错误
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
	printf("是否开启过滤目的端口功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);

	if(choice == 1)
	{
		// 开启
		rules.dport_status = 1;
		int i;
		for(i = 0; i < PORT_NUM_MAX; i++)
		{
			printf("请输入第 %d 个需要过滤的端口号 (退出: 0):", i + 1);
			unsigned short dport;
			scanf("%hu", &dport);
			if(dport == 0) break;	         // 0代表输入完成,提前退出循环
			rules.ban_dport[i] = dport;      
			rules.dportNum = i + 1;          
		}

		if(setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}
	}
	else if(choice == 2)
	{
		rules.dport_status = 0;
		memset(rules.ban_dport, 0, sizeof(rules.ban_dport));   
		rules.dportNum = 0;

		if(setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");
		}	
	}
	else
	{
		// 输入错误
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

	int choice;
	printf("是否开启自定义访问控制策略功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);

	if(choice == 1)
	{
		// 开启
		rules.combin_status = 1;
		for(int i = 0; i < COMBINE_NUM_MAX; i++)
		{
			printf("\n请输入第 %d 个自定义访问控制策略 (退出: 0):\n", i + 1);
			int select;
			printf("是否根据源IP地址过滤(是:1  否:2):\n");
			scanf("%d", &select);
			if(select == 1)
			{
				rules.ban_combin[i].banSip_status = 1;
				printf("请输入需要过滤的源IP地址:");
				scanf("%s", str_ip);
				rules.ban_combin[i].banSip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
			}
			else if(select == 2)
			{
				rules.ban_combin[i].banSip_status = 0;
			}
			else
			{
				break;
			}

			printf("是否根据目的IP地址过滤(是:1  否:2):\n");
			scanf("%d", &select);
			if(select == 1)
			{
				rules.ban_combin[i].banDip_status = 1;
				printf("请输入需要过滤的目的IP地址:");
				scanf("%s", str_ip);
				rules.ban_combin[i].banDip = inet_addr(str_ip);    // 将字符串形式的IP地址转换为网络字节序
			}
			else if(select == 2)
			{
				rules.ban_combin[i].banDip_status = 0;
			}
			else
			{
				break;
			}

			printf("是否根据源端口过滤(是:1  否:2):\n");
			scanf("%d", &select);
			if(select == 1)
			{
				rules.ban_combin[i].banSport_status = 1;
				printf("请输入需要过滤的源端口号:");
				scanf("%hu", &rules.ban_combin[i].ban_sport);
			}
			else if(select == 2)
			{
				rules.ban_combin[i].banSport_status = 0;
			}
			else
			{
				break;
			}

			printf("是否根据目的端口过滤(是:1  否:2):\n");
			scanf("%d", &select);
			if(select == 1)
			{
				rules.ban_combin[i].banDport_status = 1;
				printf("请输入需要过滤的目的端口号:");
				scanf("%hu", &rules.ban_combin[i].ban_dport);
			}
			else if(select == 2)
			{
				rules.ban_combin[i].banDport_status = 0;
			}
			else
			{
				break;
			}

			printf("是否根据MAC地址过滤(是:1  否:2):\n");
			scanf("%d", &select);
			if(select == 1)
			{
				rules.ban_combin[i].banMac_status = 1;
				printf("请输入需要过滤的输入MAC:");
    			scanf("%s", mac_str);
				mac_format(mac_str, mac_addr);
				memcpy(rules.ban_combin[i].banMac, mac_addr, sizeof(rules.ban_combin[i].banMac));
			}
			else if(select == 2)
			{
				rules.ban_combin[i].banMac_status = 0;
			}
			else
			{
				break;
			}

			rules.combineNum = i + 1;
		}

		if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
		{
			printf("Filter rule synchronization to kernel space failed\n");			
		}
	}
	else if(choice == 2)
	{
		rules.combin_status = 0;
		memset(rules.ban_combin, 0, sizeof(rules.ban_combin));

		if(setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len)) 
		{
			printf("Filter rule synchronization to kernel space failed\n");			
		}
	}
	else
	{
		// 输入错误
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

	if(setsockopt(sockfd, IPPROTO_IP, BANPING, &rules, len))
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

	if(setsockopt(sockfd, IPPROTO_IP, BANHTTP, &rules, len))  
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

	if(setsockopt(sockfd, IPPROTO_IP, BANTELNET, &rules, len))  
	{
		printf("Filter rule synchronization to kernel space failed\n");		
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

	if(rules.mac_status == 0)
	{  
		rules.mac_status = 1;

		for(int i = 0; i < MAC_NUM_MAX; i++)
		{
			printf("请输入第 %d 个 需要过滤的MAC地址（退出: 0）:", i + 1);
			scanf("%s", mac_str);
			if(!strcmp(mac_str, "0"))
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
		rules.mac_status = 0;
		memset(rules.ban_mac, 0, sizeof(rules.ban_mac));		

		if(setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len)) 
		{
			printf("Filter rule synchronization to kernel space failed\n");			
		}
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
	
	if(setsockopt(sockfd, IPPROTO_IP, BANALL, &rules, len))  
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
    char buffer[255];

    fp = fopen(LOG_FILE, "r");
    if (fp == NULL) {
        printf("Failed to open file\n");
        return;
    }

	printf("Firewall access control log content:\n");
    while (fgets(buffer, 255, fp)) {
        printf("%s", buffer);
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

	if(setsockopt(sockfd, IPPROTO_IP, RESTORE, &rules, len))  
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
