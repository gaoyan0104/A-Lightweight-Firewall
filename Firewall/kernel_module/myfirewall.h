#define SOE_MIN		          0x1000                              // 驱动程序处理最小值
#define OPENSTATE             0x1001                              // 改变防火墙开启状态编号 
#define INPSTATE              0x1002                              // 改变防火墙开启状态编号 
#define BANSIP                0x1003                              // 禁源IP功能编号 
#define BANDIP                0x1004                              // 禁目的IP功能编号
#define BANSPORT              0x1005                              // 禁源端口功能编号 
#define BANDPORT              0x1006                              // 禁目的端口功能编号
#define BANPING               0x1007                              // PING功能编号 
#define BANHTTP    	          0x1008                              // HTTP/HTTPS功能编号
#define BANTELNET             0x1009			                  // Telnet功能编号
#define NOWRULE               0x1010                              // 获取防火墙当前规则功能编号
#define BANALL                0x1011                              // 关闭所以连接功能编号
#define BANMAC                0x1012			                  // 禁MAC地址功能编号
#define BANCOMBIN             0x1013                              // 自定义访问控制策略功能编号
#define SETTIME               0x1014                              // 设置防火墙启用时间段功能编号
#define RESTORE               0x1015                              // 恢复默认设置功能编号
#define CONNGET               0x1016                              // 获取状态链接功能编号
#define SOE_MAX		          0x1100                              // 驱动程序处理最大值 
#define CONN_NUM_MAX          100                                 // 保留状态连接的最大值
#define CONNECT_TIME	      60								  // 状态检测连接超时时间
#define TABLE_SIZE            1000001							  // 状态检测哈希表长度
#define IP_NUM_MAX            10                                  // 过滤IP地址个数的最大值
#define PORT_NUM_MAX          10                                  // 过滤端口个数的最大值
#define MAC_NUM_MAX           10                                  // 过滤MAC地址个数的最大值
#define COMBINE_NUM_MAX       10                                  // 用户自定义访问控制策略个数的最大值
#define MAC_LEN               6                                   // MAC地址的字节数
#define LOG_FILE              "/home/ubuntu/Firewall/log.txt"     // 日志文件存储路径

// 用户自定义访问控制策略
typedef struct banCombin{
	int banSip_status;                             			      // 是否根据源IP地址过滤
	int banDip_status;                               		      // 是否根据目的IP地址过滤
	int banSport_status;                            	          // 是否根据源端口过滤
	int banDport_status;                             	          // 是否根据目的端口过滤	       
	int banMac_status;                           	              // 是否根据MAC地址过滤
	unsigned int banSip;                                          // 存储过滤的自定义源IP地址
	unsigned int banDip;                                          // 存储过滤的自定义目的IP地址
	unsigned short ban_sport;                                     // 存储过滤的自定义源端口号
	unsigned short ban_dport;                                     // 存储过滤的自定义目的端口号
	unsigned char banMac[MAC_LEN];                                // 存储过滤的自定义MAC地址
}banCombin;

// 状态检测连接结构
typedef struct conn{
	unsigned int src_ip;                                          // 源IP地址
	unsigned int dst_ip;                                          // 目的IP地址
	int src_port;                                                 // 源端口号
	int dst_port;                                                 // 目的端口号
	int protocol;												  // 协议类型
	int index;                                                    // 状态检测Hash表的指针
	struct conn *next;                                            // next指针
}Connection;

// 防火墙过滤规则，其中 int *_status (1：禁止，0：允许)
typedef struct ban_status{
	int open_status;                                              // 防火墙开启状态
	int inp_status;                                               // 状态检测功能开启状态
	int sip_status;                                               // 源IP控制开启状态
	int dip_status;                                               // 目的IP控制开启状态
	int sport_status;                                             // 源端口控制开启状态
	int dport_status;                                             // 目的端口控制开启状态
	int settime_status;		                                      // 防火墙时间段控制开启状态
	time_t start_date;								              // 防火墙开启时间
	time_t end_date;								              // 防火墙关闭时间
	int ping_status;                                              // PING控制开启状态
	int http_status;  					                          // HTTP/HTTPS控制开启状态
	int telnet_status;  		                                  // Telnet控制开启状态
	int mac_status;                                               // MAC地址控制开启状态
	int close_status; 							                  // 关闭所以连接控制开启状态
    time_t start_time;						           		      // 关闭所有连接开启时间
	time_t end_time;			           					      // 关闭所有连接关闭时间
	int combin_status;	                                          // 自定义访问控制策略控制开启状态
	int sipNum;                                                   // 当前禁用源IP地址的数量
	int dipNum;                                                   // 当前禁用目的IP地址的数量
	int sportNum;                                                 // 当前禁用源端口的数量
	int dportNum;                                                 // 当前禁用目的端口的数量
	int macNum;                                                   // 当前禁用MAC地址的数量
	int combineNum;                                               // 当前用户自定义访问控制策略的数量
	int connNum; 									              // 当前建立状态连接的数量
	unsigned int ban_sip[IP_NUM_MAX];                             // 存储当前禁用源IP地址的数组
	unsigned int ban_dip[IP_NUM_MAX];                             // 存储当前禁用目的IP地址的数组
	unsigned short ban_sport[PORT_NUM_MAX];                       // 存储当前禁用源端口的数组
	unsigned short ban_dport[PORT_NUM_MAX];                       // 存储当前禁用目的端口的数组
	unsigned char ban_mac[MAC_NUM_MAX][MAC_LEN];                  // 存储当前禁用MAC地址的二维数组
	banCombin ban_combin[COMBINE_NUM_MAX];                        // 存储用户自定义的访问控制策略的数组
	Connection connNode[CONN_NUM_MAX];                            // 存储状态检测连接的数组
}ban_status;
