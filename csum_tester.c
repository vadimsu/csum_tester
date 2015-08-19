#include <errno.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <getopt.h>

static unsigned short compute_checksum(unsigned short *addr,
					int len)
{
	register unsigned long sum = 0;

	while(len > 1) {
		sum += *addr++;
		len -= 2;
	}
	if (len > 0) {
		sum += ((*addr)&htons(0xFF00));
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;
	return sum;
}

static void compute_udp_checksum(struct iphdr *iph,unsigned short *payload)
{
	register unsigned long sum = 0;
	struct udphdr *uh = (struct udphdr *)payload;
	unsigned short udplen = htons(uh->len);

	sum += (iph->saddr >> 16)&0xFFFF;
	sum += (iph->saddr)&0xFFFF;
	sum += (iph->daddr >> 16)&0xFFFF;
	sum += (iph->daddr)&0xFFFF;
	sum += htons(IPPROTO_UDP);
	sum += uh->len;
	uh->check = 0;
	while (udplen > 1) {
		sum += *payload++;
		udplen -= 2;
	}
	if (udplen > 0) {
		sum += ((*payload)&htons(0xFF00));
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;
	uh->check = ((unsigned short)sum == 0x00)?0xFFFF:(unsigned short)sum;
}

static void compute_tcp_checksum(struct iphdr *iph,unsigned short *payload)
{
	register unsigned long sum = 0;
	struct tcphdr *th = (struct tcphdr *)payload;
	unsigned short tcplen = ntohs(iph->tot_len) - (iph->ihl << 2);

	sum += (iph->saddr >> 16)&0xFFFF;
	sum += (iph->saddr)&0xFFFF;
	sum += (iph->daddr >> 16)&0xFFFF;
	sum += (iph->daddr)&0xFFFF;
	sum += htons(IPPROTO_TCP);
	sum += htons(tcplen);
	th->check = 0;
	while (tcplen > 1) {
		sum += *payload++;
		tcplen -= 2;
	}
	if (tcplen > 0) {
		sum += ((*payload)&htons(0xFF00));
	}
	while (sum >> 16) {
		sum = (sum & 0xFFFF) + (sum >> 16);
	}
	sum = ~sum;
	th->check = (unsigned short)sum;
}



int main(int argc, char **argv)
{
	int sock;
	struct ifreq ifr;
	int c;
	int corrupt_l3 = 0;
	int corrupt_l4 = 0;
	char *ifname = NULL;
	unsigned int mac[6];
	unsigned char dst_mac[6];
	unsigned char message[1514];
	char *dstip = NULL,*srcip = NULL;
	struct iphdr *iph;
	struct sockaddr_ll socket_address;
	struct ethhdr *eh = (struct ethhdr*)message;
	int option_index;
	unsigned char protocol = 17;
	unsigned outer_header_size = 0;
	struct option long_options[] = { 
	{ "dstip", required_argument, 0, 0 },
	{ "srcip", required_argument, 0, 0 },
	{ "dstmac", required_argument, 0, 0 },
	};

	memset(dst_mac,0,sizeof(dst_mac));
	while ((c = getopt_long (argc, argv, "intp",long_options,&option_index)) != -1) {
		switch (c) {
			case 0:
				if (!strcmp(long_options[option_index].name, "dstip")) {
					dstip = optarg;
				} else if (!strcmp(long_options[option_index].name, "srcip")) {
					srcip = optarg;
				} else if (!strcmp(long_options[option_index].name, "dstmac")) {
					sscanf(optarg,"%x:%x:%x:%x:%x:%x",
							&mac[0],
							&mac[1],
							&mac[2],
							&mac[3],
							&mac[4],
							&mac[5]);
					dst_mac[0] = mac[0];
					dst_mac[1] = mac[1];
					dst_mac[2] = mac[2];
					dst_mac[3] = mac[3];
					dst_mac[4] = mac[4];
					dst_mac[5] = mac[5];
				}
				break;
			case 'i':
				ifname = argv[optind];
				break;
			case 'n':
				corrupt_l3 = 1;
				break;
			case 't':
				corrupt_l4 = 1;
				break;
			case 'p':
				protocol = atoi(argv[optind]);
				break;
			default:
				abort();
		}
	}
	printf("parameters: ifname %s corrupt IP csum %d corrupt transport csum %d\n",
		ifname,corrupt_l3,corrupt_l4);
	printf("dst_mac %x:%x:%x:%x:%x:%x",dst_mac[0],dst_mac[1],dst_mac[2],
					dst_mac[3],dst_mac[4],dst_mac[5]);
	if (ifname == NULL) {
		printf("\n-i <interface name> is mandatory option\n");
		exit(1);
	}
	if ((dstip == NULL) ||
	    (srcip == NULL)) {
		printf("no ip address(es) provided. using default\n");
		if (dstip == NULL)
			dstip = strdup("2.2.2.2");
		if (srcip == NULL)
			srcip = strdup("1.1.1.1");
	}
	memset(message,0,sizeof(message));
	sock = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	if (sock == -1) {
		printf("cannot open socket\n");
		return -1;
	}
	strcpy(ifr.ifr_name,ifname);
	if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1) {
		printf("cannot bind to interface\n");
		abort();
	}	
	socket_address.sll_family = PF_PACKET;
	socket_address.sll_protocol = htons(ETH_P_IP);
	socket_address.sll_ifindex = ifr.ifr_ifindex;
	socket_address.sll_hatype = ARPHRD_ETHER;
	socket_address.sll_pkttype = PACKET_OTHERHOST;
	socket_address.sll_halen = ETH_ALEN;
	socket_address.sll_addr[0] = dst_mac[0];
	socket_address.sll_addr[1] = dst_mac[1];
	socket_address.sll_addr[2] = dst_mac[2];
	socket_address.sll_addr[3] = dst_mac[3];
	socket_address.sll_addr[4] = dst_mac[4];
	socket_address.sll_addr[5] = dst_mac[5];
	socket_address.sll_addr[6] = 0;
	socket_address.sll_addr[7] = 0;
	memcpy(message,dst_mac,ETH_ALEN);
	strcpy(ifr.ifr_name,ifname);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		printf("cannot get hw address\n");
		abort();
	}
	memcpy(&message[ETH_ALEN+outer_header_size],ifr.ifr_hwaddr.sa_data,ETH_ALEN);
	eh->h_proto = htons(ETH_P_IP);
	iph = (struct iphdr *)&message[14+outer_header_size];
	iph->version = 4;
	iph->ihl = 5;
	iph->tot_len = htons((sizeof(message) - outer_header_size) - (14));
	iph->id = 0;
	iph->frag_off = 0;
	iph->tos = 0;
	iph->ttl = 1;
	iph->protocol = protocol;
	iph->saddr = inet_addr(srcip);
	iph->daddr = inet_addr(dstip);
	iph->check = 0;
	iph->check = compute_checksum((unsigned short*)iph,20);
	if (corrupt_l3)
		iph->check = ~iph->check;
	if (protocol == 17) {
		struct udphdr *uh = (struct udphdr *)(iph+1);
		uh->len = htons((sizeof(message) - outer_header_size) - (20+14));
		compute_udp_checksum(iph,(unsigned short *)uh);
		if (corrupt_l4)
			uh->check = ~uh->check;
	} else if (protocol == 6) {
		struct tcphdr *th = (struct tcphdr *)(iph+1);
		th->doff = 5;
		compute_tcp_checksum(iph,(unsigned short *)th);
		if (corrupt_l4)
			th->check = ~th->check;
	}
	
	for (c = 0; c < 1024;c++) {
		if (sendto (sock, 
			message, 
			sizeof(message), 
			0, 
			(struct sockaddr *)&socket_address, 
			sizeof(socket_address)) == -1) {
			printf("cannot send message\n");
		}
	}
	return 0;
}
