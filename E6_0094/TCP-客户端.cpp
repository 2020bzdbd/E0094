#include <stdio.h>
#include<stdlib.h>
#include <winsock2.h>
#include<string.h>
#pragma comment(lib,"ws2_32.lib")
#define _WINSOCK_DEPRECATED_NO_WARNINGS

int main() {
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	int addrlen;
	char seraddr[14];
	struct sockaddr_in ser_addr;
	struct sockaddr_in cli_addr;
	char msg[512];
	//GetServerAddr(seraddr);
	SOCKET cli_sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (cli_sockfd < 0) {
		printf("socket error !");
		return -1;
	}
	addrlen = sizeof(struct sockaddr_in);
	memset(&cli_addr, 0, addrlen);
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	cli_addr.sin_port = htons(50000);
	/*if (bind(cli_sockfd, (struct sockaddr*) & cli_addr, sizeof(struct sockaddr_in)) < 0) {
		DWORD dw = GetLastError();
		printf("bind error !%d\n",dw);
		return -1;
	}*/
	
	memset(&ser_addr, 0, addrlen);
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_addr.S_un.S_addr = inet_addr("192.168.100.3");
	ser_addr.sin_port = htons(50000);
	if (connect(cli_sockfd, (struct sockaddr*) & ser_addr, addrlen)!=0) {
		/*DWORD dw = GetLastError();
		printf("connect error %d\n",dw);*/
		printf("服务器失去连接\n");
		return -1;
	}

	FILE* fp(fopen("D:\\Desktop\\medium.txt", "rb"));
	fseek(fp, 0, SEEK_END);
	int flength = ftell(fp);
	int tlength = 0;
	rewind(fp);
	unsigned char ch;
	while (!feof(fp)) {
		memset(msg, 0, sizeof(msg));
		int i;
		for (i = 0; i < 512; i++) {
			if (!feof(fp)) {
				ch = fgetc(fp);
				msg[i] = ch;
			}
			else {
				msg[i] = -1;
				break;
			}
		}
		int sw = send(cli_sockfd, msg, i, 0);
		if (sw < 0) {
			DWORD dw = GetLastError();
			printf("send error.%d\n",dw);
		}
		else
		{
			tlength += sw;
			printf("send %d/%d\n", ftell(fp) ,flength);
		}
	}
	strcpy(msg, "finish send");
	send(cli_sockfd, msg, 11, 0);
	closesocket(cli_sockfd);
	
	return 0;
}