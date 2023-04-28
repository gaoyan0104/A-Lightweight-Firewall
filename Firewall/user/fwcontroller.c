#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>  
#include "../kernel_module/myfirewall.h"

ban_status rules;

void printError(char * msg)
{
	printf("%s error %d: %s\n", msg, errno, strerror(errno));
}

void get_status();                                       /*功能函数：获取当前防火墙过滤规则*/
void change_status(int sockfd, socklen_t len);           /*功能函数：改变防火墙过滤规则*/
void change_ping(int sockfd, socklen_t len);             /*功能函数：改变PING规则*/
void change_sip(int sockfd, socklen_t len);              /*功能函数：改变源IP过滤规则*/
void change_dip(int sockfd, socklen_t len);              /*功能函数：改变目的IP过滤规则*/
void change_sport(int sockfd, socklen_t len);            /*功能函数：改变源端口过滤规则*/
void change_dport(int sockfd, socklen_t len);            /*功能函数：改变目的端口过滤规则*/
void change_http(int sockfd, socklen_t len);             /*功能函数：改变HTTP/HTTPS规则*/
void change_telnet(int sockfd, socklen_t len);           /*功能函数：改变Telnet规则*/
void change_mac(int sockfd, socklen_t len);              /*功能函数：改变MAC地址过滤规则*/		
void change_close(int sockfd, socklen_t len);            /*功能函数：改变关闭所有连接规则*/
void change_combin(int sockfd, socklen_t len);           /*功能函数：改变自定义过滤规则*/

int main(void)
{
	int sockfd;
	socklen_t len;
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
	{
		printError("创建套接字");
	}
	else
	{
		len = sizeof(rules);
		if(getsockopt(sockfd, IPPROTO_IP, NOWRULE, (void *)&rules, &len))
		{
			printError("从内核空间获取过滤规则");
		}
		else
		{
			while(1)
			{
				get_status();                  //循环打印当前防火墙过滤规则
				change_status(sockfd, len);    //循环打印规则菜单，直至用户层选择退出
			}
		}
	}
	return 0;
}

void get_status() 
{
	printf("\n\n\n当前防火墙过滤规则为:\n");
	printf("--------------------------\n");

	printf("根据源IP过滤功能： ");
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
	printf("--------------------------\n");

	printf("根据目的IP过滤功能： ");
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
	printf("--------------------------\n");

	printf("根据源端口过滤功能： ");
	if(rules.sport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for(int i = 0; i < rules.sportNum; i++)
		{
			printf("%hu ", rules.ban_sport[i]);   //打印当前所有禁用的源端口号
		}
		printf("\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------\n");

	printf("根据目的端口过滤功能： ");
	if(rules.dport_status == 1)
	{
		printf("开启\n");
		printf("关闭端口: ");
		for(int i = 0; i < rules.dportNum; i++)
		{
			printf("%hu ", rules.ban_dport[i]);   //打印当前所有禁用的目的端口号
		}
		printf("\n");
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------\n");

	printf("PING功能： ");
	if(rules.ping_status == 1)
	{
		printf("禁用\n");
	}
	else
	{
		printf("不禁用\n");
	}
	printf("--------------------------\n");

	printf("HTTP/HTTPS功能： ");
	if(rules.http_status == 1)
	{
		printf("禁用\n");		
	}
	else
	{
		printf("不禁用\n");		
	}
	printf("--------------------------\n");

	printf("Telnet功能： ");
	if(rules.telnet_status == 1)
	{
		printf("禁用\n");		
	}
	else
	{
		printf("不禁用\n");		
	}
	printf("--------------------------\n");

	printf("根据MAC过滤功能： ");
	if(rules.mac_status == 1)
	{
		printf("开启\n");
		printf("过滤MAC地址：%02X:%02X:%02X:%02X:%02X:%02X\n",
		rules.ban_mac[0], rules.ban_mac[1], rules.ban_mac[2], rules.ban_mac[3], rules.ban_mac[4], rules.ban_mac[5]);
	}
	else
	{
		printf("关闭\n");
	}
	printf("--------------------------\n");

	printf("关闭所有连接功能： ");
	if(rules.close_status == 1)
	{
		printf("开启\n");		
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------\n");

	printf("自定义访问控制策略功能： ");
	if(rules.combin_status == 1)
	{
		printf("开启\n");	

		printf("过滤源IP地址: %d.%d.%d.%d\n", 
		(rules.ban_combin.banSip & 0x000000ff) >> 0,
		(rules.ban_combin.banSip & 0x0000ff00) >> 8,
		(rules.ban_combin.banSip & 0x00ff0000) >> 16,
		(rules.ban_combin.banSip & 0xff000000) >> 24);
	
		printf("过滤目的IP地址: %d.%d.%d.%d\n", 
		(rules.ban_combin.banDip & 0x000000ff) >> 0,
		(rules.ban_combin.banDip & 0x0000ff00) >> 8,
		(rules.ban_combin.banDip & 0x00ff0000) >> 16,
		(rules.ban_combin.banDip & 0xff000000) >> 24);

		printf("过滤MAC地址：%02X:%02X:%02X:%02X:%02X:%02X\n",
		rules.ban_combin.banMac[0], rules.ban_combin.banMac[1], rules.ban_combin.banMac[2], 
		rules.ban_combin.banMac[3], rules.ban_combin.banMac[4], rules.ban_combin.banMac[5]);	
	}
	else
	{
		printf("关闭\n");		
	}
	printf("--------------------------\n");
}

void change_status(int sockfd, socklen_t len)
{
	int choice;
	printf("\n选择需要修改的防火墙过滤规则:");
	printf("\n1.过滤源IP          2.过滤目的IP     3.过滤源端口     4.过滤目的端口     5.PING功能");
	printf("\n6.HTTP/HTTPS功能    7.Telnet功能     8.过滤MAC地址    9.关闭所有连接     10.自定义访问控制策略     0.exit \n\n");  //已经对齐
	// printf("选项：");

	scanf("%d", &choice);
	switch (choice)
	{
		case 1:   
			change_sip(sockfd, len);
			break;
		case 2:   
			change_dip(sockfd, len);
			break;
		case 3:   
			change_sport(sockfd, len);
			break;
		case 4:   
			change_dport(sockfd, len);
			break;
		case 5:   
			change_ping(sockfd, len);
			break;
		case 6:   
			change_http(sockfd, len);
			break;
		case 7:   
			change_telnet(sockfd, len);
			break;
		case 8:   
			change_mac(sockfd, len);
			break;
		case 9:
			change_close(sockfd, len);
			break;
		case 10:
			change_combin(sockfd, len);
			break;
		case 0:
			exit(0);
		default:
			printf("选项输入错误\n");
	}
}

// 功能函数：改变源IP过滤规则
void change_sip(int sockfd, socklen_t len)
{
	char str_ip[20];
	int choice;

	printf("是否开启过滤IP功能? (1 开启   2 关闭)\n");
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
			rules.ban_sip[i] = inet_addr(str_ip);   //将字符串形式的IP地址转换为网络字节序
			rules.sipNum = i + 1;
		}
		if (setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else if(choice == 2)
	{
		rules.sip_status = 0;
		memset(rules.ban_sip, '\0', sizeof(rules.ban_sip));   //将存储禁用IP的数组置空
		rules.sipNum = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANSIP, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else
	{
		//输入错误
		printf("选项号有误\n");
	}
}

// 功能函数：改变目的IP过滤规则
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
			rules.ban_dip[i] = inet_addr(str_ip);    //将字符串形式的IP地址转换为网络字节序
			rules.dipNum = i + 1;
		}
		if (setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else if(choice == 2)
	{
		rules.dip_status = 0;
		memset(rules.ban_dip, '\0', sizeof(rules.ban_dip));   //将存储禁用IP的数组置空
		rules.dipNum = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANDIP, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else
	{
		//输入错误
		printf("选项号有误\n");
	}
}

// 功能函数：改变源端口过滤规则
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
			if(sport == 0) break;	        //0代表输入完成，提前退出循环
			rules.ban_sport[i] = sport;     //把每一个端口号写进数组保存
			rules.sportNum = i + 1;         //设置当前禁用端口的总数
		}
		if(setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else if(choice == 2)
	{
		rules.sport_status = 0;
		memset(rules.ban_sport, 0, sizeof(rules.ban_sport));   //将存储禁用端口的数组置空
		rules.sportNum = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANSPORT, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}	
	}
	else
	{
		//输入错误
		printf("选项号有误\n");
	}
}

// 功能函数：改变目的端口过滤规则
void change_dport(int sockfd, socklen_t len)
{
	int choice;
	printf("是否开启过滤目的端口功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);

	if(choice == 1)
	{
		//开启
		rules.dport_status = 1;
		int i;
		for(i = 0; i < PORT_NUM_MAX; i++)
		{
			printf("请输入第 %d 个需要过滤的端口号 (退出: 0):", i + 1);
			unsigned short dport;
			scanf("%hu", &dport);
			// printf("用户层输入的端口号: %hu\n", dport);
			if(dport == 0) break;	      //0代表输入完成 提前退出循环
			rules.ban_dport[i] = dport;   //把每一个端口号写进数组保存
			rules.dportNum = i + 1;       //设置当前禁用的端口总数
		}
		if(setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}
	}
	else if(choice == 2)
	{
		rules.dport_status = 0;
		memset(rules.ban_dport, 0, sizeof(rules.ban_dport));   //将存储禁用端口的数组置空
		rules.dportNum = 0;
		if(setsockopt(sockfd, IPPROTO_IP, BANDPORT, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");
		}	
	}
	else
	{
		//输入错误
		printf("选项号有误\n");
	}

}

// 功能函数：改变PING规则
void change_ping(int sockfd, socklen_t len)
{
	rules.ping_status = !rules.ping_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANPING, &rules, len))
	{
		printf("过滤规则同步至内核空间失败");
	}
}

// 功能函数：改变HTTP/HTTPS规则
void change_http(int sockfd, socklen_t len)
{
	rules.http_status = !rules.http_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANHTTP, &rules, len))  
	{
		printf("过滤规则同步至内核空间失败");		
	}
}

// 功能函数：改变Telnet规则
void change_telnet(int sockfd, socklen_t len)
{
	rules.telnet_status = !rules.telnet_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANTELNET, &rules, len))  
	{
		printf("过滤规则同步至内核空间失败");		
	}	
}     

// 工具函数：分割后的存入mac_addr
void mac_format(char *mac_str, unsigned char *mac_addr)
{
    char *ptr = strtok(mac_str, ":");      // 将字符串按“:”分割，返回第一个子字符串的指针

    for (int i = 0; i < 6; i++)
	{
        mac_addr[i] = (unsigned char)strtol(ptr, NULL, 16);  // 将子字符串转换为 unsigned char 类型的数字
        ptr = strtok(NULL, ":");                            // 继续按“:”分割，返回下一个子字符串的指针
    }

}

// 功能函数：改变MAC地址过滤规则	
void change_mac(int sockfd, socklen_t len)
{
	unsigned char mac_str[20];  	//存储输入的MAC地址字符串
	unsigned char mac_addr[6];      //存储将字符串分割后的MAC地址

	if(rules.mac_status == 0)
	{  
		rules.mac_status = 1;

		printf("请输入需要过滤的MAC地址:\n");
    	scanf("%s", mac_str);
    	// printf("输入的MAC: %s\n", mac_str);

		mac_format(mac_str, mac_addr);
		memcpy(rules.ban_mac, mac_addr, sizeof(rules.ban_mac));

		if (setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len))
		{
			printf("过滤规则同步至内核空间失败");			
		}
	}
	else
	{  
		rules.mac_status = 0;

		memset(rules.ban_mac, 0, sizeof(rules.ban_mac));		

		if(setsockopt(sockfd, IPPROTO_IP, BANMAC, &rules, len)) 
		{
			printf("过滤规则同步至内核空间失败");			
		}
	}
}

// 功能函数：改变关闭所有连接规则
void change_close(int sockfd, socklen_t len)
{
	rules.close_status = !rules.close_status;
	if(setsockopt(sockfd, IPPROTO_IP, BANALL, &rules, len))  
	{
		printf("过滤规则同步至内核空间失败");		
	}
}

// 功能函数：改变自定义访问控制规则
void change_combin(int sockfd, socklen_t len)
{
	unsigned char mac_str[20];  	//存储输入的MAC地址字符串
	unsigned char mac_addr[6];      //存储将字符串分割后的MAC地址
	char str_ip[20];                //存储输入的IP地址

	int choice;
	printf("是否开启过滤MAC地址功能? (1 开启   2 关闭)\n");
	scanf("%d", &choice);

	if(choice == 1)
	{
		//开启
		rules.combin_status = 1;

		printf("请输入需要过滤的源IP地址: ");
		scanf("%s", str_ip);
		rules.ban_combin.banSip = inet_addr(str_ip);    //将字符串形式的IP地址转换为网络字节序

		printf("请输入需要过滤的目的IP地址: ");
		scanf("%s", str_ip);
		rules.ban_combin.banDip = inet_addr(str_ip);    //将字符串形式的IP地址转换为网络字节序

		printf("请输入需要过滤的输入MAC: ");
    	scanf("%s", mac_str);
    	// printf("输入的MAC: %s\n", mac_str);
		
		mac_format(mac_str, mac_addr);
		memcpy(rules.ban_combin.banMac, mac_addr, sizeof(rules.ban_combin.banMac));

		if (setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len))
		{
			printf("setsockopt");			
		}
	}
	else if(choice == 2)
	{
		rules.combin_status = 0;

		rules.ban_combin.banSip = rules.ban_combin.banSip;
		rules.ban_combin.banDip = rules.ban_combin.banDip;
		memset(rules.ban_combin.banMac, 0, sizeof(rules.ban_combin.banMac));		

		if(setsockopt(sockfd, IPPROTO_IP, BANCOMBIN, &rules, len)) 
		{
			printf("setsockopt");			
		}
	}
	else
	{
		//输入错误
		printf("选项号有误\n");
	}
}