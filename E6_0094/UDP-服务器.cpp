#pragma comment(lib,"Ws2_32.lib")
#include<WinSock2.h>
#include<WS2tcpip.h>
#include<stdio.h>
#include<stdlib.h>
#include<Windows.h>

int main() 
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET ser_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	int len;
	socklen_t addrlen;
	struct sockaddr_in ser_addr;
	char seraddr[128];
	if (ser_sockfd < 0) {
		printf("socket error");
		return -1;
	}
	addrlen = sizeof(struct sockaddr_in);
	//memset(&ser_addr, 0, addrlen);
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	ser_addr.sin_port = htons(50000);
	if (bind(ser_sockfd, (struct sockaddr*) & ser_addr, addrlen) < 0) {
		DWORD dw = GetLastError();
		printf("bind error\n%d",dw);
		return -1;
	}
	int gets = 0;
	FILE* newf(fopen("medium.txt", "wb"));
	fclose(newf);
	while (true) {
		FILE* fp(fopen("medium.txt", "a+"));
		len = recvfrom(ser_sockfd, seraddr, sizeof(seraddr), 0, (struct sockaddr*) & ser_addr, &addrlen);
		if (len > 0) {
			int i;
			for (i = 0; i < 127; i++) {
				if (seraddr[i] == -1) { i--; break; }
			}
			if (strcmp(seraddr, "finish send") == 0) {
				printf("finish\n");
			}
			else {
				gets += (i + 1);
				fwrite(seraddr, 1, i + 1, fp);
				printf("recevce:%d\n", gets);
			}
		}
		else if (len < 0&&strcmp(seraddr,"finish send")) {
			printf("连接已断开");
			remove("medium.txt");
		}
	}

	return 0;
}