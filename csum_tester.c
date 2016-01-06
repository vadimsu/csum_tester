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
#define SIMPLE_GRE_HEADER 1
#if SIMPLE_GRE_HEADER
struct gre_header
{
	union
	{
		uint32_t word0;
		struct
		{
			int checksum_flag : 1;
			int reserved0 : 12;
			int ver : 3;
			uint16_t protocol;
		};
	};
}__attribute__((packed));
#else
struct gre_header
{
	union
	{
		uint32_t word0;
		struct
		{
			int checksum_flag : 1;
			int reserved0 : 12;
			int ver : 3;
			uint16_t protocol;
		};
	};
	uint16_t checksum;
	uint16_t reserved1;
}__attribute__((packed));
#endif
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

static unsigned build_mac(uint16_t innertag,uint16_t outertag,uint8_t *ethhdr, uint8_t  *dstmac,uint8_t *srcmac, int outervlantype)
{
	uint16_t val,offset = 0;
	bcopy(dstmac,ethhdr,ETH_ALEN);
	offset += ETH_ALEN;
	bcopy(srcmac,&ethhdr[offset],ETH_ALEN);
	offset += ETH_ALEN;
	if (outertag) {		
		val = (!outervlantype) ? ETH_P_8021AD : ETH_P_8021Q;
		bcopy(&val,&ethhdr[offset], sizeof(val));
		offset += sizeof(val);
		val = htons(outertag);
		bcopy(&val, &ethhdr[offset], sizeof(val));
		offset += sizeof(val);
	}
	if (innertag) {	
		val = ETH_P_8021Q;
		bcopy(&val, &ethhdr[offset], sizeof(val));
		offset += sizeof(val);
		val = htons(innertag);
		bcopy(&val, &ethhdr[offset], sizeof(val));
		offset += sizeof(val);
	}
	val = htons(ETH_P_IP);
	bcopy(&val, &ethhdr[offset], sizeof(val));
	offset += sizeof(val);
	return offset;
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
	int pkt_size = 1024;
	int pkt_count = 1024;
	unsigned char *message = NULL;
	uint16_t innervlan = 0, outervlan = 0, current_offset = 0;
	char *dstip = NULL,*srcip = NULL;
	struct iphdr *iph,*outeriph;
	struct sockaddr_ll socket_address;
	struct ethhdr *eh;
	int option_index;
	unsigned char protocol = 17;
	unsigned char outp = 0;
	unsigned outer_header_size = 0;
	struct gre_header *p_gre;
	int outervlantype = 0;
	struct option long_options[] = { 
	{ "dstip", required_argument, 0, 0 },
	{ "srcip", required_argument, 0, 0 },
	{ "dstmac", required_argument, 0, 0 },
	{ "innervlan", required_argument, 0, 0 },
	{ "outervlan", required_argument, 0, 0 },
	{ "outervlantype", required_argument, 0, 0 },
	{ "pktsize", required_argument, 0, 0 },
	{ "pktcount", required_argument, 0, 0 },
	};

	if (argc < 2) {
		printf("usage: csum_tester -i <interface_name> [--dstip <destination ip>] [--srcip <source ip>] [--dstmac <destination MAC>] [-o <outer protocol> (47 - GRE, 94 - IPIP)] [-n (corrupt l3 csum)] [-t (corrupt l4 csum)] [-p <protocol number> (IP protocol, 6 - TCP 17 - UDP (default))]\n");
		return 0;
	}

	memset(dst_mac,0,sizeof(dst_mac));
	while ((c = getopt_long (argc, argv, "intop",long_options,&option_index)) != -1) {
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
				} else if (!strcmp(long_options[option_index].name, "innervlan")) {
					innervlan = atoi(optarg);
				} else if (!strcmp(long_options[option_index].name, "outervlan")) {
					outervlan = atoi(optarg);
				} else if (!strcmp(long_options[option_index].name, "outervlantype")) {
					outervlantype = atoi(optarg);
				} else if (!strcmp(long_options[option_index].name, "pktsize")) {
					pkt_size = atoi(optarg);
				} else if (!strcmp(long_options[option_index].name, "pktcount")) {
					pkt_count = atoi(optarg);
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
			case 'o':
				outp = atoi(argv[optind]);
				outer_header_size = sizeof(struct iphdr);
				switch(outp) {
				case 47:
					outer_header_size += sizeof(struct gre_header);
					break;
				case 4:
					break;
				default:
					printf("illegal outer protocol\n");
					exit(1);
				}
				break;
			default:
				abort();
		}
	}
	printf("parameters: ifname %s corrupt IP csum %d corrupt transport csum %d pkt_size %d pkt_count %d\n",
		ifname,corrupt_l3,corrupt_l4,pkt_size, pkt_count);
	printf("dst_mac %x:%x:%x:%x:%x:%x\n",dst_mac[0],dst_mac[1],dst_mac[2],
					dst_mac[3],dst_mac[4],dst_mac[5]);
	fflush(0);
	message = (unsigned char *)malloc(pkt_size);
	memset(message, 0, pkt_size);
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
	if ((outervlan) &&(!innervlan)) {
		printf("cannot define outer vlan w/o inner\n");
		exit(1);
	}
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
	strcpy(ifr.ifr_name,ifname);
	if (ioctl(sock, SIOCGIFHWADDR, &ifr) == -1) {
		printf("cannot get hw address\n");
		abort();
	}
	
	current_offset = build_mac(innervlan, outervlan, message, dst_mac, ifr.ifr_hwaddr.sa_data, outervlantype);
	printf("outer ethernet header is %d bytes\n",current_offset);
	if (outp) {
		printf("tunneling protocol %d size %d\n",outp, outer_header_size);
		outeriph = (struct iphdr *)&message[current_offset];
		outeriph->tot_len = htons((sizeof(message) - (current_offset+outer_header_size)));
		if (outp != 47) {
			current_offset += 
			build_mac(innervlan, 
				outervlan, 
				&message[current_offset+outer_header_size+sizeof(*outeriph)], 
				dst_mac, ifr.ifr_hwaddr.sa_data,outervlantype);
		} else {
			p_gre = (struct gre_header *)(outeriph+1);	
			p_gre->reserved0 = 0;
			p_gre->ver = 0;
			p_gre->protocol = htons(ETH_P_IP);
#if SIMPLE_GRE_HEADER
			p_gre->checksum_flag = 0;
#else
			p_gre->checksum_flag = 1;
			p_gre->checksum = 0;
			p_gre->reserved1 = 0;
#endif

		}
		outeriph->version = 4;
		outeriph->ihl = 5;	
		outeriph->id = 0;
		outeriph->frag_off = 0;
		outeriph->tos = 0;
		outeriph->ttl = 1;
		outeriph->protocol = outp;
		outeriph->saddr = inet_addr(srcip);
		outeriph->daddr = inet_addr(dstip);
		outeriph->check = 0;
		outeriph->check = compute_checksum((unsigned short*)outeriph,20);
		current_offset += outer_header_size;
	}
printf("%s %d %p %p %d\n",__FILE__,__LINE__,&message[0],&message[current_offset],current_offset);
	if ((current_offset + sizeof(struct iphdr)) >= pkt_size) {
		printf("at least % bytes required for pkt size\n",
			(current_offset + sizeof(struct iphdr)));
		exit(0);
	}
	iph = (struct iphdr*)&message[current_offset];
	iph->tot_len = htons(pkt_size - current_offset);
	iph->version = 4;
	iph->ihl = 5;	
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
	current_offset += sizeof(*iph);
	if (protocol == 17) {
		struct udphdr *uh = (struct udphdr *)(iph+1);
		if ((current_offset + sizeof(struct udphdr)) >= pkt_size) {
			printf("at least % bytes required for pkt size\n",
				(current_offset + sizeof(struct iphdr)));
			exit(0);
		}
		uh->len = htons(pkt_size - current_offset);
		compute_udp_checksum(iph,(unsigned short *)uh);
		if (corrupt_l4)
			uh->check = ~uh->check;
	} else if (protocol == 6) {
		struct tcphdr *th = (struct tcphdr *)(iph+1);
		if ((current_offset + sizeof(struct tcphdr)) >= pkt_size) {
			printf("at least % bytes required for pkt size\n",
				(current_offset + sizeof(struct iphdr)));
			exit(0);
		}
		th->doff = 5;
		compute_tcp_checksum(iph,(unsigned short *)th);
		if (corrupt_l4)
			th->check = ~th->check;
	}
	
	for (c = 0; c < 1024;c++) {
		if (sendto (sock, 
			message, 
			pkt_size, 
			0, 
			(struct sockaddr *)&socket_address, 
			sizeof(socket_address)) == -1) {
			printf("cannot send message\n");
		}
	}
	return 0;
}
