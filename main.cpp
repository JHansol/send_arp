#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <libnet.h>
#include <sys/ioctl.h> 

#define ether_len  14
#define BUF_SIZE 65536
#define padding_size 18;

char errbuf[PCAP_ERRBUF_SIZE];
pcap_t *handle;

typedef struct
{
#define ARPHRD_NETROM   0   /* from KA9Q: NET/ROM pseudo */
#define ARPHRD_ETHER    1   /* Ethernet 10Mbps */
#define ARPHRD_EETHER   2   /* Experimental Ethernet */
#define ARPHRD_AX25     3   /* AX.25 Level 2 */
#define ARPHRD_PRONET   4   /* PROnet token ring */
#define ARPHRD_CHAOS    5   /* Chaosnet */
#define ARPHRD_IEEE802  6   /* IEEE 802.2 Ethernet/TR/TB */
#define ARPHRD_ARCNET   7   /* ARCnet */
#define ARPHRD_APPLETLK 8   /* APPLEtalk */
#define ARPHRD_LANSTAR  9   /* Lanstar */
#define ARPHRD_DLCI     15  /* Frame Relay DLCI */
#define ARPHRD_ATM      19  /* ATM */
#define ARPHRD_METRICOM 23  /* Metricom STRIP (new IANA id) */
#define ARPHRD_IPSEC    31  /* IPsec tunnel */
#define ARPOP_REQUEST    1  /* req to resolve address */
#define ARPOP_REPLY      2  /* resp to previous request */
#define ARPOP_REVREQUEST 3  /* req protocol address given hardware */
#define ARPOP_REVREPLY   4  /* resp giving protocol address */
#define ARPOP_INVREQUEST 8  /* req to identify peer */
#define ARPOP_INVREPLY   9  /* resp identifying peer */
	u_int16_t ar_hrd;         /* format of hardware address */
	u_int16_t ar_pro;         /* format of protocol address */
	u_int8_t  ar_hln;         /* length of hardware address */
	u_int8_t  ar_pln;         /* length of protocol addres */
	u_int16_t ar_op;          /* operation type */
	u_int8_t sender_mac[6];
	u_int8_t sender_ip[4];
	u_int8_t target_mac[6];
	u_int8_t target_ip[4];
} arp_header;

unsigned char *get_macaddr(char *ether) {
	int fd;
	struct ifreq ifr;
	char *iface = ether;
	unsigned char *mac;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);
	ioctl(fd, SIOCGIFHWADDR, &ifr);
	close(fd);

	mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
	return mac;

}
void pcap_setting(char *argv[]) {
	handle = pcap_open_live(argv[1], BUF_SIZE, 1, 1000, errbuf); // MAX recv byte, promis(1-every,0-me), time out
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		exit(0);
	}
	struct bpf_program fp;
	char filter_exp[] = "arp";
	bpf_u_int32 net;
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) { // filtering
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
	if (pcap_setfilter(handle, &fp) == -1) { // filtering apply
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(0);
	}
}

int arp_packet_send(char *argv[]) {
	struct libnet_ethernet_hdr eth;
	arp_header arp;
	// dynamic alloc
	int header_size = sizeof(libnet_ethernet_hdr) + sizeof(arp_header) + padding_size; //42 + 18
	printf("%d", header_size); 
	u_int8_t *packet = (u_int8_t*)malloc(sizeof(u_int8_t)*header_size);
	memset(packet, 0, header_size);

	// ethernet packet struct //
	memset(eth.ether_dhost,0xff,6);
	memcpy(eth.ether_shost, get_macaddr(argv[1]), 6);
	eth.ether_type = htons(ETHERTYPE_ARP);
	memcpy(packet,&eth, sizeof(libnet_ethernet_hdr));

	// arp packet struct //
	arp.ar_hrd = htons(ARPHRD_ETHER);
	arp.ar_pro = htons(ETHERTYPE_IP);
	arp.ar_hln = 0x06;
	arp.ar_pln = 0x04;
	arp.ar_op = htons(ARPOP_REQUEST);
	// arp mac, ip struct //
	memset(arp.target_mac, 0x00, 6);
	memcpy(arp.sender_mac, get_macaddr(argv[1]), 6);
	inet_pton(AF_INET, argv[2], arp.sender_ip);
	inet_pton(AF_INET, argv[3], arp.target_ip);
	memcpy(packet+ sizeof(libnet_ethernet_hdr), &arp, sizeof(arp_header));

	for (int i = 0; i<header_size; i++) {
		printf("%02x ", packet[i]);
	} printf("\n");

	pcap_sendpacket(handle, packet, header_size);
}

int main(int argc, char *argv[]) {
	//char *dev = pcap_lookupdev(errbuf);
	if (argc != 4) {  // argv exception
		fprintf(stderr,"send_arp <interface> <sender ip> <target ip> \n");
		exit(0); 
	}

	pcap_setting(argv);
	arp_packet_send(argv);

	int res = 0;
	struct pcap_pkthdr *headers;
	const unsigned char *pkt_data;
	while (res = pcap_next_ex(handle, &headers, &pkt_data) >= 0) {
		if (res == 0)
			continue;
		if (pkt_data[21] == 2) {
			printf("\t ------------------------------------------ \n");
			printf("\t target MAC \t : %02X:%02X:%02X:%02X:%02X:%02X \n",
				pkt_data[6], pkt_data[7], pkt_data[8],
				pkt_data[9], pkt_data[10], pkt_data[11]);
			printf("\t my MAC \t : %02X:%02X:%02X:%02X:%02X:%02X \n",
				pkt_data[0], pkt_data[1], pkt_data[2],
				pkt_data[3], pkt_data[4], pkt_data[5]);
			printf("\t ------------------------------------------ \n");
			return 0;
		}
	}
	return 0;
}

