#define send_bytes 23
#define recv_bytes 77
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

enum {FIRST_MENU,SECOND_MENU,QUIT};

char send_buffer[send_bytes];
char recv_buffer[recv_bytes];
int init_socket(char *addr);
void print_main_menu();
void make_send_city_packet(char *city);
void clear_screen();
void print_day_menu();
void make_send_days_packet(char *city,int request_no,int days);

struct weather_inform{
	char weather;
	char temp;
};

struct recv_weather{
	char idefiner[2];
	char city[20];
	char date[4];
	char days;
	struct weather_inform inform[25];
};

int main(){
	clear_screen();
	int state = FIRST_MENU;
	while(state == FIRST_MENU){
		print_main_menu();
		char city[50];
		memset(city,0,50);
		scanf("%s",city);
		if(!strcmp(city,"#")){
			state = QUIT;
			continue;
		}
		if(!strcmp(city,"c")){
			clear_screen();
			continue;
		}
		int sockfd = init_socket("114.212.191.33");
        if(sockfd == -1){
        	printf("Can't create socket!\n");
        	return -1;
        }
		make_send_city_packet(city);
		send(sockfd,send_buffer,send_bytes,0);
		recv(sockfd,recv_buffer,recv_bytes,0);
		if((recv_buffer[0] != 01) && (recv_buffer[1] != 00) && (strcmp(recv_buffer+2,city))){
			printf("send city failed!\n");
			return -1;
		}
		clear_screen();
		print_day_menu();
		state = SECOND_MENU;
		while(state == SECOND_MENU){
			char day = getchar();
			if(day == 'r'){
				getchar();
				state = FIRST_MENU;
				continue;
			}
			if(day == '#'){
				getchar();
				state = QUIT;
				continue;
			}
			if(day == 'c'){
				getchar();
				clear_screen();
				print_day_menu();
				continue;
			}
			switch(day){
				case '1':{
						make_send_days_packet(city,1,1);
						send(sockfd,send_buffer,send_bytes,0);
						recv(sockfd,recv_buffer,recv_bytes,0);
						if((recv_buffer[0] != 03) && (recv_buffer[1] != 41) && (strcmp(recv_buffer+2,city))){
							printf("send today failed!\n");
							return -1;
						}
						struct recv_weather recv;
						memcpy((char *)&recv,recv_buffer,recv_bytes);
						printf("City: %s  Today is: 2017/03/10  Weather information is as follows:\n",recv.city);
						switch(recv.inform[0].weather){
							case 0:printf("Today's Weather is: shower;  Temp:%d\n",recv.inform[0].temp);break;
							case 1:printf("Today's Weather is: clear;  Temp:%d\n",recv.inform[0].temp);break;
							case 2:printf("Today's Weather is: cloudy;  Temp:%d\n",recv.inform[0].temp);break;
							case 3:printf("Today's Weather is: rain;  Temp:%d\n",recv.inform[0].temp);break;
							case 4:printf("Today's Weather is: fog;  Temp:%d\n",recv.inform[0].temp);break;
							default:printf("Don't have this weather!\n");
						}
				}break;
				case '2':{
						make_send_days_packet(city,2,3);
						send(sockfd,send_buffer,send_bytes,0);
						recv(sockfd,recv_buffer,recv_bytes,0);
						if((recv_buffer[0] != 03) && (recv_buffer[1] != 41) && (strcmp(recv_buffer+2,city))){
							printf("send 3 days failed!\n");
							return -1;
						}
						struct recv_weather recv;
						memcpy((char *)&recv,recv_buffer,recv_bytes);
						printf("City: %s  Today is: 2017/03/10  Weather information is as follows:\n",recv.city);
						for(int i = 0; i < 3; i++){
							switch(recv.inform[i].weather){
								case 0:printf("The %dth day's Weather is: shower;  Temp:%d\n",i+1,recv.inform[i].temp);break;
								case 1:printf("The %dth day's Weather is: clear;  Temp:%d\n",i+1,recv.inform[i].temp);break;
								case 2:printf("The %dth day's Weather is: cloudy;  Temp:%d\n",i+1,recv.inform[i].temp);break;
								case 3:printf("The %dth day's Weather is: rain;  Temp:%d\n",i+1,recv.inform[i].temp);break;
								case 4:printf("The %dth day's Weather is: fog;  Temp:%d\n",i+1,recv.inform[i].temp);break;
								default:printf("Don't have this weather!\n");
							}
						}
				}break;
				case '3':{
						printf("Please enter the day number(below 10,e.g. 1 means today):");
						int n_day = 0;
						scanf("%d",&n_day);
						if(n_day < 1 || n_day > 9){
							printf("error\n");
							break;
						}
						make_send_days_packet(city,1,n_day);
						send(sockfd,send_buffer,send_bytes,0);
						recv(sockfd,recv_buffer,recv_bytes,0);
						if((recv_buffer[0] != 03) && (recv_buffer[1] != 41) && (strcmp(recv_buffer+2,city))){
							printf("send 3 days failed!\n");
							return -1;
						}
						struct recv_weather recv;
						memcpy((char *)&recv,recv_buffer,recv_bytes);
						printf("City: %s  Today is: 2017/03/10  Weather information is as follows:\n",recv.city);
						switch(recv.inform[0].weather){
							case 0:printf("The %dth day's Weather is: shower;  Temp:%d\n",n_day,recv.inform[0].temp);break;
							case 1:printf("The %dth day's Weather is: clear;  Temp:%d\n",n_day,recv.inform[0].temp);break;
							case 2:printf("The %dth day's Weather is: cloudy;  Temp:%d\n",n_day,recv.inform[0].temp);break;
							case 3:printf("The %dth day's Weather is: rain;  Temp:%d\n",n_day,recv.inform[0].temp);break;
							case 4:printf("The %dth day's Weather is: fog;  Temp:%d\n",n_day,recv.inform[0].temp);break;
							default:printf("Don't have this weather!\n");
						}
				}break;
				default:break;
			}
		}
		clear_screen();
	}
	return 0;
}

int init_socket(char *ip_addr){
	int tcp_socket = -1;
	tcp_socket = socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
	if(tcp_socket == -1)
	{
		printf("socket create failure!");
		return -1;
	}
	struct sockaddr_in addr;
	memset((char *)&addr,0,sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(4321);
	addr.sin_addr.s_addr = inet_addr(ip_addr);
	int tcp_connect = connect(tcp_socket,(struct sockaddr *)&addr,sizeof(struct sockaddr));
	if(tcp_connect == -1){
		printf("connection failed!");
		return -1;
	}
	return tcp_socket;
}

void print_main_menu(){
	printf("Welcome to NJUCS Weather Forecast Demo Program!\nPlease input City Name in Chinese pinyin(e.g. nanjing or beijing)\n(c)cls,(#)exit\n");
}

void make_send_city_packet(char *city){
	memset(send_buffer,0,send_bytes);
	send_buffer[0] = 1;
	send_buffer[1] = 1;
	memcpy(send_buffer + 2,city,strlen(city));
	send_buffer[send_bytes - 1] = 5;
}

void clear_screen(){
	system("clear");
}

void print_day_menu(){
	printf("Please enter the given number to query\n1.today\n2.three days from today\n3.custom day by yourself\n(r)back,(c)cls,(#)exit\n===================================================\n");
}

void make_send_days_packet(char *city,int request_no,int days){
	memset(send_buffer,0,send_bytes);
	send_buffer[0] = 2;
	send_buffer[1] = request_no;
	memcpy(send_buffer + 2,city,strlen(city));
	send_buffer[send_bytes - 1] = days;
}
	
