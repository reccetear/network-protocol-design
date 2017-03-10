#include "sys/include.h"

extern void tcp_DiscardPkt(char* pBuffer, int type);

extern void tcp_sendIpPkt(unsigned char* pData, UINT16 len, unsigned int  srcAddr, unsigned int dstAddr, UINT8	ttl);

extern int waitIpPacket(char *pBuffer, int timeout);

extern unsigned int getIpv4Address();

extern unsigned int getServerIpv4Address();

#define INPUT 0
#define OUTPUT 1

#define NOT_READY 0
#define READY 1

#define DATA_NOT_ACKED 0
#define DATA_ACKED 1

#define NOT_USED 0
#define USED 1

#define MAX_TCP_CONNECTIONS 5

#define INPUT_SEG 0
#define OUTPUT_SEG 1

typedef int STATE;

int gLocalPort = 2007;
int gRemotePort = 2006;
int gSeqNum = 1234;
int gAckNum = 0;

enum TCP_STATES	//TCP 协议链接状态
{
	CLOSED,		//TCP 状态为CLOSED，表示断开链接
	SYN_SENT,	//TCP 状态为SYN_SENT，表示正在发送SYN报文字段
	ESTABLISHED,//TCP 状态为ESTABLISHED，表示TCP链接已经建立
	FIN_WAIT1,	//TCP状态为FIN_WAIT1，表示等待等待远程TCP的终止链接报文
	FIN_WAIT2,  //TCP状态为FIN_WAIT2，第二次终止报文的握手
	TIME_WAIT,  //TCP状态为TIME_WAIT，表示等待用户端的中止请求
};

struct MyTcpSeg		//TCP报文结构，存储TCP的各个字段
{
	unsigned short src_port;	//表示源端口
	unsigned short dst_port;	//表示目的端口
	unsigned int seq_num;		//表示序列号
	unsigned int ack_num;		//表示ack的序列号
	unsigned char hdr_len;		//表示硬件长度
	unsigned char flags;        //报文控制所需要的各种标识位
	unsigned short window_size;	//TCP流量控制窗口大小
	unsigned short checksum;	//checksum校验和
	unsigned short urg_ptr;     //
	unsigned char data[2048];	//TCP传输数据
	unsigned short len;         //TCP的数据长度
};

struct MyTCB
{
	STATE current_state;		//MyTCP当前的状态
	unsigned int local_ip;		//MyTCP的本地IP地址
	unsigned short local_port;	//MyTCP的本地端口
	unsigned int remote_ip;		//MyTCP的远程IP地址
	unsigned short remote_port;	//MyTCP的远程端口
	unsigned int seq;           //MyTCP的报文序列号
	unsigned int ack;           //MyTCP的ack序列号
	unsigned char flags;        //报文控制的标识位
	int iotype;
	int is_used;
	int data_ack;
	unsigned char data[2048];	//MyTCP的传输数据
	unsigned short data_len;	//MyTCP的数据长度
};

struct MyTCB gTCB[MAX_TCP_CONNECTIONS];
int initialized = NOT_READY;

int convert_tcp_hdr_ntoh(struct MyTcpSeg* pTcpSeg)
//这个函数用来将TCP头部的各个字段字节顺序转化成PC的字节顺序（pTcpSeg是要转化的TCP头，如果成功返回0失败返回-1）
{
	if( pTcpSeg == NULL )
	{
		//TCP头部为空则返回-1
		return -1;
	}
    //ntohs()函数是用来将一个16位数由网络字节顺序转化为主机字节顺序
	pTcpSeg->src_port = ntohs(pTcpSeg->src_port);
	pTcpSeg->dst_port = ntohs(pTcpSeg->dst_port);
	pTcpSeg->seq_num = ntohl(pTcpSeg->seq_num);
	pTcpSeg->ack_num = ntohl(pTcpSeg->ack_num);
	pTcpSeg->window_size = ntohs(pTcpSeg->window_size);
	pTcpSeg->checksum = ntohs(pTcpSeg->checksum);
	pTcpSeg->urg_ptr = ntohs(pTcpSeg->urg_ptr);

	return 0;
}

int convert_tcp_hdr_hton(struct MyTcpSeg* pTcpSeg)
//这个函数用来将MyTCP头部中的各个字段字节顺序转化成网络字节顺序（pTcpSeg是要转化的TCP头，如果成功返回0失败返回-1）
{
	if( pTcpSeg == NULL )
	{
		//MyTCP头部为空返回-1
		return -1;
	}
    //htons是用来将一个16位数由主机字节顺序转化为网络字节顺序
	pTcpSeg->src_port = htons(pTcpSeg->src_port);
	pTcpSeg->dst_port = htons(pTcpSeg->dst_port);
	pTcpSeg->seq_num = htonl(pTcpSeg->seq_num);
	pTcpSeg->ack_num = htonl(pTcpSeg->ack_num);
	pTcpSeg->window_size = htons(pTcpSeg->window_size);
	pTcpSeg->checksum = htons(pTcpSeg->checksum);
	pTcpSeg->urg_ptr = htons(pTcpSeg->urg_ptr);

	return 0;
}

unsigned short tcp_calc_checksum(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//这个函数用来计算MyTCP头部的checksum校验和（pTcp是TCP的报文，pTcpSeg是TCP的头部字段，返回值成功为校验和，失败为-1）
{
	int i = 0;
	int len = 0;
	unsigned int sum = 0;
	unsigned short* p = (unsigned short*)pTcpSeg;

	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return 0;
	}

	for( i=0; i<10; i++)
	{
		sum += p[i];
	}

	sum = sum - p[8] - p[6] + ntohs(p[6]);

	if( (len = pTcpSeg->len) > 20 )
	{
		if( len % 2 == 1 )
		{
			pTcpSeg->data[len - 20] = 0;
			len++;
		}

		for( i=10; i<len/2; i++ )
		{
			sum += ntohs(p[i]);
		}
	}

	sum = sum + (unsigned short)(pTcb->local_ip>>16)
		+ (unsigned short)(pTcb->local_ip&0xffff)
		+ (unsigned short)(pTcb->remote_ip>>16)
		+ (unsigned short)(pTcb->remote_ip&0xffff);
	sum = sum + 6 + pTcpSeg->len;
	sum = ( sum & 0xFFFF ) + ( sum >> 16 );
	sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	return (unsigned short)(~sum);
}

int get_socket(unsigned short local_port, unsigned short remote_port)
//这个函数用来获取TCP的套接字描述符，返回套接字描述符（local_port是本地端口，remote_port是远程端口，返回值是一个TCP类型的套接字描述符）
{
	int i = 1;
	int sockfd = -1;

	for( i=1; i<MAX_TCP_CONNECTIONS; i++ )
	{
		if( gTCB[i].is_used == USED
			&& gTCB[i].local_port == local_port
			&& gTCB[i].remote_port == remote_port )
		{
			sockfd = i;
			break;
		}
	}

	return sockfd;
}

int tcp_init(int sockfd)
//这个函数用来通过套接字类型来初始化TCP报文头部（sockfd是套接字描述符）
{
	if( gTCB[sockfd].is_used == USED )
	{
		return -1;
	}

	gTCB[sockfd].current_state = CLOSED;    //当前sockfd的状态是closed
	gTCB[sockfd].local_ip = getIpv4Address();   // IP地址赋值
	gTCB[sockfd].local_port = gLocalPort + sockfd - 1;
	gTCB[sockfd].seq = gSeqNum;     //序列号赋值
	gTCB[sockfd].ack = gAckNum;     //ACK赋值
	gTCB[sockfd].is_used = USED;
	gTCB[sockfd].data_ack = DATA_ACKED;

	return 0;
}

int tcp_construct_segment(struct MyTcpSeg* pTcpSeg, struct MyTCB* pTcb, unsigned short datalen, unsigned char* pData)
//这个函数用来建立一个新的TCP报文段（pTcpSeg是TCP的头部，pTcp是TCP的报文段，datalen是TCP数据长度，pData是字节数组指针，成功创建TCP报文返回0）
{
	pTcpSeg->src_port = pTcb->local_port;
	pTcpSeg->dst_port = pTcb->remote_port;
	pTcpSeg->seq_num = pTcb->seq;
	pTcpSeg->ack_num = pTcb->ack;
	pTcpSeg->hdr_len = (unsigned char)(0x50);
	pTcpSeg->flags = pTcb->flags;
	pTcpSeg->window_size = 1024;
	pTcpSeg->urg_ptr = 0;

	if( datalen > 0 && pData != NULL )
	{
        //memcpy()函数用来将pData的数组写入到pTcpSeg中
		memcpy(pTcpSeg->data, pData, datalen);
	}

	pTcpSeg->len = 20 + datalen;//这里要加上20字节的头部长度

	return 0;
}

int tcp_kick(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//这个函数用来讲TCP封装好的报文通过IP报文的形式发送出去（两个参数分别是要发送的TCP报文头和数据，成功返回0）
{
	pTcpSeg->checksum = tcp_calc_checksum(pTcb, pTcpSeg);

	convert_tcp_hdr_hton(pTcpSeg);
	
	tcp_sendIpPkt((unsigned char*)pTcpSeg, pTcpSeg->len, pTcb->local_ip, pTcb->remote_ip, 255);

	if( (pTcb->flags & 0x0f) == 0x00 )
	{
		pTcb->seq += pTcpSeg->len - 20;
	}
	else if( (pTcb->flags & 0x0f) == 0x02 )
	{
		pTcb->seq++;
	}
	else if( (pTcb->flags & 0x0f) == 0x01 )
	{
		pTcb->seq++;
	}
	else if( (pTcb->flags & 0x3f) == 0x10 )
	{
	}

	return 0;
}

int tcp_closed(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//第一次握手链接，发送第一个SYN报文，等待回复（成功返回0）
{
	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	if( pTcb->iotype != OUTPUT )
	{
		//to do: discard packet

		return -1;
	}

	pTcb->current_state = SYN_SENT;
	pTcb->seq = pTcpSeg->seq_num ;
    //调用tcp_kick()将TCP的SYN报文发送出去
	tcp_kick( pTcb, pTcpSeg );

	return 0;
}

int tcp_syn_sent(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//第二次握手链接（返回SYN+1报文，两个参数同上，成功返回0）
{
	struct MyTcpSeg my_seg;

	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	if( pTcb->iotype != INPUT )
	{
		return -1;
	}

	if( (pTcpSeg->flags & 0x3f) != 0x12 )
	{
		//to do: discard packet

		return -1;
	}

	pTcb->ack = pTcpSeg->seq_num + 1;
	pTcb->flags = 0x10;
    //这里建立一个新的报文段然后发送
    tcp_construct_segment( &my_seg, pTcb, 0, NULL );
	tcp_kick( pTcb, &my_seg );
    //将当前状态改为ESTABLISHED状态
	pTcb->current_state = ESTABLISHED;

	return 0;
}

int tcp_established(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//第三次握手链接，收到ACK报文，并再次回复以完成链接（参数同上）
{
	struct MyTcpSeg my_seg;

	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	if( pTcb->iotype == INPUT )
	{
		if( pTcpSeg->seq_num != pTcb->ack )
		{
			tcp_DiscardPkt((char*)pTcpSeg, TCP_TEST_SEQNO_ERROR);
			//to do: discard packet
            //如果收到的TCP报文的ACK码不正确证明这个报文很有可能是假的或者过期的要舍弃
			return -1;
		}

		if( (pTcpSeg->flags & 0x3f) == 0x10 )
		{
			memcpy(pTcb->data, pTcpSeg->data, pTcpSeg->len - 20);
			pTcb->data_len = pTcpSeg->len - 20;

			if( pTcb->data_len == 0 )
			{
			}
			else
			{
				pTcb->ack += pTcb->data_len;
				pTcb->flags = 0x10;
				tcp_construct_segment(&my_seg, pTcb, 0, NULL);
				tcp_kick(pTcb, &my_seg);
			}
		}
	}
	else
	{
		if( (pTcpSeg->flags & 0x0F) == 0x01 )
		{
			pTcb->current_state = FIN_WAIT1;
		}

		tcp_kick( pTcb, pTcpSeg );
	}

	return 0;
}

int tcp_finwait_1(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//链接完成进入等待状态（等待远程TCP发送关闭链接的请求）
{
	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	if( pTcb->iotype != INPUT )
	{
		return -1;
	}

	if( pTcpSeg->seq_num != pTcb->ack )
	{
		tcp_DiscardPkt((char*)pTcpSeg, TCP_TEST_SEQNO_ERROR);

		return -1;
	}

	if( (pTcpSeg->flags & 0x3f) == 0x10 && pTcpSeg->ack_num == pTcb->seq )
	{
        //这个状态表示本服务器已经关闭TCP链接，等待另一个远程TCP端口关闭链接的返回信息
		pTcb->current_state = FIN_WAIT2;
	}

	return 0;
}

int tcp_finwait_2(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//关闭链接的第二次握手，返回本地TCP已经关闭链接的信息
{
	struct MyTcpSeg my_seg;

	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	if( pTcb->iotype != INPUT )
	{
		return -1;
	}

	if( pTcpSeg->seq_num != pTcb->ack )
	{
		tcp_DiscardPkt((char*)pTcpSeg, TCP_TEST_SEQNO_ERROR);

		return -1;
	}

	if( (pTcpSeg->flags & 0x0f) == 0x01 )
	{
		pTcb->ack++;
		pTcb->flags = 0x10;

		tcp_construct_segment( &my_seg, pTcb, 0, NULL );
		tcp_kick( pTcb, &my_seg );
        //这里将TCP状态改为CLOSED表示已经断开连接
		pTcb->current_state = CLOSED;
	}
	else
	{
		//to do
	}

	return 0;
}

int tcp_time_wait(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//等待用户端关闭TCP链接的信息（参数同上）
{
	pTcb->current_state = CLOSED;
	//to do
    //将TCP状态改为CLOSED表示链接已经关闭
	return 0;
}

int tcp_check(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//检查接受到的TCP的checksun校验和是否正确（参数同上，如果正确返回0，错误返回-1）
{
	int i = 0;
	int len = 0;
	unsigned int sum = 0;
	unsigned short* p = (unsigned short*)pTcpSeg;
	unsigned short *pIp;
	unsigned int myip1 = pTcb->local_ip;
	unsigned int myip2 = pTcb->remote_ip;

	if( pTcb == NULL || pTcpSeg == NULL )
	{
		return -1;
	}

	for( i=0; i<10; i++)
	{
		sum = sum + p[i];
	}
	sum = sum - p[6] + ntohs(p[6]);

	if( (len = pTcpSeg->len) > 20 )
	{
		if( len % 2 == 1 )
		{
			pTcpSeg->data[len - 20] = 0;
			len++;
		}

		for( i=10; i<len/2; i++ )
		{
			sum += ntohs(p[i]);
		}
	}

	sum = sum + (unsigned short)(myip1>>16)
		+ (unsigned short)(myip1&0xffff)
		+ (unsigned short)(myip2>>16)
		+ (unsigned short)(myip2&0xffff);
	sum = sum + 6 + pTcpSeg->len;

	sum = ( sum & 0xFFFF ) + ( sum >> 16 );
	sum = ( sum & 0xFFFF ) + ( sum >> 16 );

	if( (unsigned short)(~sum) != 0 )
	{
		// TODO:
		printf("check sum error!\n");

		return -1;
		//return 0;
	}
	else
	{
		return 0;
	}
}

int tcp_switch(struct MyTCB* pTcb, struct MyTcpSeg* pTcpSeg)
//TCP的状态转换机，用该控制TCP的各个状态之间的转化和函数的调用（参数同上，返回值为调用函数是否成功）
{
	int ret = 0;

	switch(pTcb->current_state)
	{
	case CLOSED:
		ret = tcp_closed(pTcb, pTcpSeg);
		break;
	case SYN_SENT:
		ret = tcp_syn_sent(pTcb, pTcpSeg);
		break;
	case ESTABLISHED:
		ret = tcp_established(pTcb, pTcpSeg);
		break;
	case FIN_WAIT1:
		ret = tcp_finwait_1(pTcb, pTcpSeg);
		break;
	case FIN_WAIT2:
		ret = tcp_finwait_2(pTcb, pTcpSeg);
		break;
	case TIME_WAIT:
		ret = tcp_time_wait(pTcb, pTcpSeg);
		break;
	default:
		ret = -1;
		break;
	}

	return ret;
}

int tcp_input(char* pBuffer, unsigned short len, unsigned int srcAddr, unsigned int dstAddr)
//用来通过地址和数据建立一个完整的TCP报文
{
	struct MyTcpSeg tcp_seg;
	int sockfd = -1;

	if( len < 20 )
	{
		return -1;
	}

	memcpy(&tcp_seg, pBuffer, len);

	tcp_seg.len = len;

	convert_tcp_hdr_ntoh(&tcp_seg);

	sockfd = get_socket(tcp_seg.dst_port, tcp_seg.src_port);

	if( sockfd == -1 || gTCB[sockfd].local_ip != ntohl(dstAddr) || gTCB[sockfd].remote_ip != ntohl(srcAddr) )
	{
		printf("sock error in tcp_input()\n");
		return -1;
	}

	if( tcp_check(&gTCB[sockfd], &tcp_seg) != 0 )
	{
		return -1;
	}

	gTCB[sockfd].iotype = INPUT;
	memcpy(gTCB[sockfd].data,tcp_seg.data,len - 20);
	gTCB[sockfd].data_len = len - 20;

	tcp_switch(&gTCB[sockfd], &tcp_seg);

	return 0;
}

void tcp_output(char* pData, unsigned short len, unsigned char flag, unsigned short srcPort, unsigned short dstPort, unsigned int srcAddr, unsigned int dstAddr)
{
	struct MyTcpSeg my_seg;

	sockfd = get_socket(srcPort, dstPort);

	if( sockfd == -1 || gTCB[sockfd].local_ip != srcAddr || gTCB[sockfd].remote_ip != dstAddr )
	{
		return;
	}

	gTCB[sockfd].flags = flag;

	tcp_construct_segment(&my_seg, &gTCB[sockfd], len, (unsigned char *)pData);

	gTCB[sockfd].iotype = OUTPUT;

	tcp_switch(&gTCB[sockfd], &my_seg);
}

int tcp_socket(int domain, int type, int protocol)
//通过socket函数建立一个新的TCP套接字（domain是协议族（AF_INET表示ipv4网络协议），type是socket形式（SOCK_STREAM表示是流式套接字），protocol表示协议类型（IPROTO_TCP表示是TCP协议的套接字），成功创建套接字返回其值，不成功返回-1）
{
	int i = 1;
	int sockfd = -1;

	if( domain != AF_INET || type != SOCK_STREAM || protocol != IPPROTO_TCP )
	{
		return -1;
	}

	for( i=1; i<MAX_TCP_CONNECTIONS; i++ )
	{
		if( gTCB[i].is_used == NOT_USED )
		{
			sockfd = i;

			if( tcp_init(sockfd) == -1 )
			{
				return -1;
			}

			break;
		}
	}

	initialized = READY;

	return sockfd;
}

int tcp_connect(int sockfd, struct sockaddr_in* addr, int addrlen)
//通过套接字链接建立TCP链接（sockfd是新创建的套接字类型，addr是套接字的内部地址，addrlen是地址长度，成功建立连接返回1，失败返回0）
{
	char buffer[2048];
	int len;

	gTCB[sockfd].remote_ip = ntohl(addr->sin_addr.s_addr);
	gTCB[sockfd].remote_port = ntohs(addr->sin_port);

	tcp_output( NULL, 0, 0x02, gTCB[sockfd].local_port, gTCB[sockfd].remote_port, gTCB[sockfd].local_ip, gTCB[sockfd].remote_ip );

	len = waitIpPacket(buffer, 10);

	if( len < 20 )
	{
		return -1;
	}

	if (tcp_input(buffer, len, htonl(gTCB[sockfd].remote_ip), htonl(gTCB[sockfd].local_ip)) != 0){
		return 1;
	}
	else
	{
		return 0;
	}
}

int tcp_send(int sockfd, const unsigned char* pData, unsigned short datalen, int flags)
//简单的TCP报文发送函数，用来发送TCP报文（pData是要发送的数据，datalen是数据长度，flags是标志位，成功返回0，失败返回-1）
{
	char buffer[2048];
	int len;

	if( gTCB[sockfd].current_state != ESTABLISHED )
	{
		return -1;
	}

	tcp_output((char *)pData, datalen, flags, gTCB[sockfd].local_port, gTCB[sockfd].remote_port, gTCB[sockfd].local_ip, gTCB[sockfd].remote_ip);

	len = waitIpPacket(buffer, 10);

	if( len < 20 )
	{
		return -1;
	}

	tcp_input(buffer, len, htonl(gTCB[sockfd].remote_ip), htonl(gTCB[sockfd].local_ip));

	return 0;
}

int tcp_recv(int sockfd, unsigned char* pData, unsigned short datalen, int flags)
//简单的TCP报文接受函数，用来接收TCP报文（参数同TCP发送函数的参数，成功接受返回0，失败返回-1）
{
	char buffer[2048];
	int len;

	if( (len = waitIpPacket(buffer, 10)) < 20 )
	{
		return -1;
	}

	tcp_input(buffer, len,  htonl(gTCB[sockfd].remote_ip),htonl(gTCB[sockfd].local_ip));

	memcpy(pData, gTCB[sockfd].data, gTCB[sockfd].data_len);

	return gTCB[sockfd].data_len;
}

int tcp_close(int sockfd)
//关闭TCP连接的函数（更准确说是关闭套接字链接的函数，参数为套接字，成功返回0，失败返回-1）
{
	char buffer[2048];
	int len;

	tcp_output(NULL, 0, 0x11, gTCB[sockfd].local_port, gTCB[sockfd].remote_port, gTCB[sockfd].local_ip, gTCB[sockfd].remote_ip);

	if( (len = waitIpPacket(buffer, 10)) < 20 )
	{
		return -1;
	}

	tcp_input(buffer, len, htonl(gTCB[sockfd].remote_ip), htonl(gTCB[sockfd].local_ip));

	if( (len = waitIpPacket(buffer, 10)) < 20 )
	{
		return -1;
	}

	tcp_input(buffer, len, htonl(gTCB[sockfd].remote_ip), htonl(gTCB[sockfd].local_ip));

	gTCB[sockfd].is_used = NOT_USED;

	return 0;
}

