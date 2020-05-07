#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include <stdio.h>
#include <conio.h>
#include "packet32.h"
#include <ntddndis.h>
#include<stdint.h>
#include<iostream>
#pragma comment(lib, "Packet")
#pragma comment(lib, "wpcap")
#pragma comment(lib, "WS2_32")

using namespace std;

#define Max_Num_Adapter 10
char		AdapterList[Max_Num_Adapter][1024];

 /* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr[4];		// Source address
	ip_address	daddr[4];		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

typedef struct mac_header {
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

string s1, s2;


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;


	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
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

	/* Check if the user specified a valid adapter */
	if (inum < 1 || inum > i)
	{
		printf("\nAdapter number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((adhandle = pcap_open_live(d->name,	// name of the device
		65536,			// portion of the packet to capture. 
					   // 65536 grants that the whole packet will be captured on all the MACs.
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Check the link layer. We support only Ethernet for simplicity. */
	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\nThis program works only on Ethernet networks.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		/* Retrieve the mask of the first address of the interface */
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		/* If the interface is without addresses we suppose to be in a C class network */
		netmask = 0xffffff;


	//compile the filter
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	//set the filter
	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\nError setting the filter.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\nlistening on %s...\n", d->description);

	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);


	/* start the capture */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	
	return 0;
}



void packet_handler(u_char* param, const struct pcap_pkthdr
	* header, const u_char* pkt_data)
{
	mac_header* mh;
	ip_header* ih;
	time_t local_tv_sec;
	struct tm time;
	char timestr[16];
	static int length=0;
	static clock_t start=clock();
	static int saddr[10][5];
	static int daddr[10][5];
	static int out[10], in[10];

	local_tv_sec = header->ts.tv_sec;
	localtime_s(&time, &local_tv_sec);
	/*printf("%d/%d/%d ", time.tm_year + 1900, time.tm_mon + 1, time.tm_mday);
	printf("%d:%d:%d,", time.tm_hour, time.tm_min, time.tm_sec);*/

	mh = (mac_header*)pkt_data;

	ih = (ip_header*)(pkt_data + sizeof(mac_header)); 

	/*for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->dest_addr[i]);
	}
	printf("%02X,", mh->dest_addr[5]);

	printf("%d.", ih->daddr->byte1);
	printf("%d.", ih->daddr->byte2);
	printf("%d.", ih->daddr->byte3);
	printf("%d,", ih->daddr->byte4);

	for (int i = 0; i < 5; i++) {
		printf("%02X-", mh->src_addr[i]);
	}
	printf("%02X,", mh->src_addr[5]);


	printf("%d.", ih->saddr->byte1);
	printf("%d.", ih->saddr->byte2);
	printf("%d.", ih->saddr->byte3);
	printf("%d,", ih->saddr->byte4);
	printf("%d\n", header->len);
	printf("\n");*/

	int i = 0;
	bool flag = false;
	while (in[i])
	{
		if (mh->dest_addr[1] == daddr[i][1] && mh->dest_addr[2] == daddr[i][2] && mh->dest_addr[3] == daddr[i][3] && mh->dest_addr[4] == daddr[i][4])
		{
			in[i] += header->len; flag = true; break;
		}
		i++;
	}
	if (flag == false)
	{
		daddr[i][1] = mh->dest_addr[1];
		daddr[i][2] = mh->dest_addr[2];
		daddr[i][3] = mh->dest_addr[3];
		daddr[i][4] = mh->dest_addr[4];
		in[i] = header->len;
	}

	flag = false;
	while (out[i])
	{
		if (mh->src_addr[1] == saddr[i][1] && mh->src_addr[2] == saddr[i][2] && mh->src_addr[3] == saddr[i][3] && mh->src_addr[4] == saddr[i][4])
		{
			in[i] += header->len; flag = true; break;
		}
		i++;
	}
	if (flag == false)
	{
		saddr[i][1] = mh->src_addr[1];
		saddr[i][2] = mh->src_addr[2];
		saddr[i][3] = mh->src_addr[3];
		saddr[i][4] = mh->src_addr[4];
		out[i] = header->len;
	}

	length += header->len;
	if (length > 1024*1024) {
		printf("1M\n");
		length -= 1024*1024;
	}
	clock_t now = clock();
	i = 0;
	if (now - start >= 60) {
		start+=60;
		while (in[i]&&out[i])
		{
			for (int j = 1; j < 4; j++)
				printf("%02X,", saddr[i][j]);
			printf("%02X", saddr[i][5]);
			cout << " in:" << in[i] << " out" << out[i] << endl;
			i++;
		}
		
	}
}
