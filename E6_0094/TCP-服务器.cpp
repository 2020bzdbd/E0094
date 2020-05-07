#include <stdio.h>
#include<stdlib.h>
#include <winsock2.h>
#include<string.h>
#pragma comment(lib,"ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS

int main() {
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	struct sockaddr_in ser_addr;
	struct sockaddr_in cli_addr;
	char msg[512];
	SOCKET ser_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ser_sockfd < 0) {
		printf("socket error !");
		return -1;
	}
	int addrlen = sizeof(struct sockaddr_in);
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_addr.S_un.S_addr = INADDR_ANY;
	ser_addr.sin_port = htons(50000);
	if (bind(ser_sockfd, (struct sockaddr*) & ser_addr, sizeof(ser_addr)) < 0) {
		printf("bind error !");
		return -1;
	}
	if (listen(ser_sockfd, 100) < 0) {
		printf("listen error !");
		return -1;
	}
	SOCKET cli_sockfd;
	int gets = 0;
	strcpy(msg, "finish send");
	FILE* newf(fopen("medium.txt", "wb"));
	fclose(newf);
	cli_sockfd = accept(ser_sockfd, (struct sockaddr*) & cli_addr, &addrlen);
	while (true)
	{
		FILE *fp(fopen("medium.txt", "a+"));
		
		if (cli_sockfd < 0) {
			printf("accept error !");
			return -1;
		}
		else {
			memset(msg, 0, 512);
			msg[0] = -1;
			int rec=recv(cli_sockfd, msg, 512, 0);
			if (rec < 0&&strcmp(msg, "finish send")!=0) {
				printf("客户端失去连接\n");
				return -1;
			}
			else if (rec < 0) {
				printf("rec error\n");
				return -1;
			}
			else if (strcmp(msg, "finish send") == 0) {
				printf("finish\n");
				return -1;
			}
			else if(rec>0&&strcmp(msg,"finish send")){
				int i;
				for (i = 0; i < 512; i++) {
					if ((int)msg[i]==0|| (int)msg[i]==-1) {
						break;
					}
				}
				//printf("%s\n", msg);
				gets += i;
				printf("正在写入\n");
				fwrite(msg, 1, i, fp);
				printf("recevce:%d\n", gets);
			}
			
		}
	}
	closesocket(cli_sockfd);
	closesocket(ser_sockfd);
	return 0;
}
