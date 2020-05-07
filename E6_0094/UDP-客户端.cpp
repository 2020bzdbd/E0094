#pragma comment(lib,"Ws2_32.lib")
#include<WinSock2.h>
#include<winsock.h>
#include<WS2tcpip.h>
#include<stdio.h>
#include <stdlib.h>
#include<Windows.h>

int main()
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);

	SOCKET cli_sockfd;
	int len;
	socklen_t addrlen;
	char seraddr[14]="192.168.100.3";
	struct sockaddr_in cli_addr;
	char buffer[128];
	cli_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (cli_sockfd < 0)
	{
		printf("socket error\n%d", WSAGetLastError);
		return -1;
	}
	addrlen = sizeof(struct sockaddr_in);
	memset(&cli_addr, 0, addrlen);
	cli_addr.sin_family = AF_INET;
	cli_addr.sin_addr.s_addr = inet_addr("192.168.100.3");
	cli_addr.sin_port = htons(50000);

	memset(buffer, 0, sizeof(buffer));
	FILE* fp(fopen("D:\\Desktop\\medium.txt","r"));
	fseek(fp, 0, SEEK_END);
	int flength = ftell(fp);
	rewind(fp);
	unsigned char ch;
	ch = fgetc(fp);
	while (!feof(fp)) {
		memset(buffer, 0, sizeof(buffer));
		for (int i = 0; i < 128; i++) {
			buffer[i] = ch;
			ch = fgetc(fp);
			if (ch == -1) {
				buffer[i] = -1;
				break;
			}
		}

		len = sizeof(buffer);
		int a = sendto(cli_sockfd, buffer, len, 0, (struct sockaddr*) & cli_addr, addrlen);
		if (a < 0) {
			DWORD dw = GetLastError();
			printf("send error\n%d\n", dw);
		}
		else {
			printf("send %d/%d\n",ftell(fp),flength);
		}
	}
	strcpy(buffer, "finish send");
	sendto(cli_sockfd, buffer, len, 0, (struct sockaddr*) & cli_addr, addrlen);
	
	closesocket(cli_sockfd);
}