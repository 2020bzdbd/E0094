#define WIN32
#define _CRT_SECURE_NO_WARNINGS
#define HAVE_REMOTE

#include <pcap.h>
#include <Packet32.h>
#include <ntddndis.h>
#include <stdio.h>
#include <time.h>

#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

u_char user[20];//�û���
u_char pass[20];//����

typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

typedef struct tcp_header
{
	u_short sport;//Դ�˿�
	u_short dsport;//Ŀ�Ķ˿�
	u_int seq;//���
	u_int ack_num;//ȷ�Ϻ�
	u_char ihl; //ͷ�����Ⱥ�һ���ֱ���
	u_char frame;//һ���ֱ�����URG ACK��
	u_short wsize;//����
	u_short crc; //У���
	u_short urg;//����ָ��
}tcp_header;

typedef struct ip_header {
	u_char ver_ihl; // Version (4 bits) +Internet header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragmentoffset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	u_char saddr[4]; // Source address
	u_char daddr[4]; // Destination address
	u_int op_pad; // Option + Padding
} ip_header;

void output(ip_header* ih, mac_header* mh, const struct pcap_pkthdr* header, char user[], char pass[], bool isSucceed)
{
	if (user[0] == '\0')
		return;

	char timestr[46];
	struct tm* ltime;
	time_t local_tv_sec;

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);//ʱ��ת��

	printf("%s,", timestr);//ʱ��

	printf("FTP: %d.%d.%d.%d  ",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//IP

	printf(" USER: %s PAS: %s	", user, pass);//�˺�����

	if (isSucceed) {
		printf("STA: OK\n");
	}
	else {
		printf("STA: FAILED\n");
	}

	FILE* fp = fopen("AnalyseFTPPacket-log.csv", "a+");
	fprintf(fp, "%s,", timestr);

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->dest_addr[0],
		mh->dest_addr[1],
		mh->dest_addr[2],
		mh->dest_addr[3],
		mh->dest_addr[4],
		mh->dest_addr[5]);//�ͻ��˵�ַ
	fprintf(fp, "%d.%d.%d.%d,",
		ih->daddr[0],
		ih->daddr[1],
		ih->daddr[2],
		ih->daddr[3]);//�ͻ���IP

	fprintf(fp, "%02X-%02X-%02X-%02X-%02X-%02X,",
		mh->src_addr[0],
		mh->src_addr[1],
		mh->src_addr[2],
		mh->src_addr[3],
		mh->src_addr[4],
		mh->src_addr[5]);//FTP MAC
	fprintf(fp, "%d.%d.%d.%d,",
		ih->saddr[0],
		ih->saddr[1],
		ih->saddr[2],
		ih->saddr[3]);//FTP IP

	fprintf(fp, "%s,%s,", user, pass);//�˺�����

	if (isSucceed) {
		fprintf(fp, "SUCCEED\n");
	}
	else {
		fprintf(fp, "FAILED\n");
	}
	fclose(fp);

	user[0] = '\0';
}

//�ص�����
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	ip_header* ih;
	mac_header* mh;
	u_int i = 0;

	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + 14);

	int name_point = 0;
	int pass_point = 0;
	int tmp;
	for (int i = 0; i < ih->tlen - 40; i++) {
		if (*(pkt_data + i) == 'U' && *(pkt_data + i + 1) == 'S' && *(pkt_data + i + 2) == 'E' && *(pkt_data + i + 3) == 'R') {
			name_point = i + 5;//����user 

			int j = 0;
			while (!(*(pkt_data + name_point) == 13 && *(pkt_data + name_point + 1) == 10)) {//������Ϊֹ
				user[j] = *(pkt_data + name_point);//�洢�˺�
				++j;
				++name_point;
			}
			user[j] = '\0';
			break;
		}

		if (*(pkt_data + i) == 'P' && *(pkt_data + i + 1) == 'A' && *(pkt_data + i + 2) == 'S' && *(pkt_data + i + 3) == 'S') {
			pass_point = i + 5;////����pass 
			tmp = pass_point;

			int k = 0;
			while (!(*(pkt_data + pass_point) == 13 && *(pkt_data + pass_point + 1) == 10)) {
				pass[k] = *(pkt_data + pass_point);//�洢����
				++k;
				++pass_point;
			}
			pass[k] = '\0';

			while(1){
				if (*(pkt_data + tmp) == '2' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, true);
					break;
				}
				else if (*(pkt_data + tmp) == '5' && *(pkt_data + tmp + 1) == '3' && *(pkt_data + tmp + 2) == '0') {
					output(ih, mh, header, (char*)user, (char*)pass, false);
					break;
				}
				++tmp;
			}
			break;
		}
	}
}

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	u_int netmask;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	char Device[] = PCAP_SRC_IF_STRING;
	char packet_filter[] = "port 21";//ftp�����Ӷ˿ڣ��˴�ʵ��û���õ�
	struct bpf_program fcode;

	if (pcap_findalldevs_ex(Device, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}


	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	
	if ((adhandle = pcap_open(d->name,  
		65536,      
		PCAP_OPENFLAG_NOCAPTURE_LOCAL,
		1000,
		NULL,
		errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n"); 
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	printf("------------end all\n");
	system("pause");
	return 0;
}