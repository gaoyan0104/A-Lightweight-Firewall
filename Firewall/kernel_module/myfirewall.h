#define SOE_MIN		  0x6000                     //驱动程序处理最小值 
#define BANSIP        0x6001                     //禁源IP功能编号 
#define BANDIP        0x6002                     //禁目的IP功能编号
#define BANSPORT      0x6003                     //禁源端口功能编号 
#define BANDPORT      0x6004                     //禁目的端口功能编号
#define BANPING       0x6005                     //PING功能编号 
#define BANHTTP    	  0x6006                     //HTTP/HTTPS功能编号
#define BANTELNET     0x6007					 //Telnet功能编号
#define NOWRULE       0x6008                     //获取防火墙当前规则功能编号
#define BANALL        0x6009                     //关闭所以连接功能编号
#define BANMAC        0x6010					 //禁MAC地址功能编号
#define BANCOMBIN     0x6011                     //自定义访问控制策略功能编号
#define SOE_MAX		  0x6100                     //驱动程序处理最大值 
#define IP_NUM_MAX    10                         //过滤IP个数的最大值
#define PORT_NUM_MAX  10                         //过滤端口个数的最大值
#define MAC_LEN       6                          //MAC地址的字节数

//存储用户自定义访问控制策略的结构体
typedef struct banCombin{
	unsigned int banSip;                         //存储过滤的自定义源IP地址
	unsigned int banDip;                         //存储过滤的自定义目的IP地址
	unsigned char banMac[MAC_LEN];               //存储过滤的自定义MAC地址
}banCombin;

//存储防火墙过滤规则的结构体，其中 int *_status (1:：禁止，0：允许)
typedef struct ban_status{
	int sip_status;                              //源IP控制开启状态
	int dip_status;                              //目的IP控制开启状态
	int sport_status;                            //源端口控制开启状态
	int dport_status;                            //目的端口控制开启状态
	int ping_status;                             //PING控制开启状态
	int http_status;  					         //HTTP/HTTPS控制开启状态
	int telnet_status;  		                 //Telnet控制开启状态
	int mac_status;                              //MAC地址控制开启状态
	int close_status; 							 //关闭所以连接控制开启状态
	int combin_status;	                         //自定义访问控制策略控制开启状态
	int sipNum;                                  //当前禁用源IP地址的数量
	int dipNum;                                  //当前禁用目的IP地址的数量
	int sportNum;                                //当前禁用源端口的数量
	int dportNum;                                //当前禁用目的端口的数量
	unsigned int ban_sip[IP_NUM_MAX];            //存储当前禁用源IP地址的数组
	unsigned int ban_dip[IP_NUM_MAX];            //存储当前禁用目的IP地址的数组
	unsigned short ban_dport[PORT_NUM_MAX];      //存储当前禁用目的端口的数组
	unsigned short ban_sport[PORT_NUM_MAX];      //存储当前禁用源端口的数组
	unsigned char ban_mac[MAC_LEN];              //存储当前禁用的MAC地址
	banCombin ban_combin;                        //存储用户自定义的访问控制策略
}ban_status;
