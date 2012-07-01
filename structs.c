typedef struct {
    int *keys;
    int *values;
    int size;
} hash_t;

struct ip_addr 
{
	unsigned char firstInterval;
	unsigned char secondInterval;
	unsigned char thirdInterval;
	unsigned char fourthInterval;
};

struct ethernet 
{
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* Destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* Source host address */
    u_short ether_type;                     /* Type: IP, ARP, RARP, etc.. */
};

struct icmp_packet
{
	const struct ethernet *ethernet;
	const struct ip *ip;
	const struct icmp *icmp;
	char *icmpMessage;
};

struct icmp6_packet
{
	const struct ethernet *ethernet;
	const struct ip6_hdr *ip6;
	const struct icmp6_hdr *icmp6;
	char *icmpMessage;
};

struct tcp_packet
{
	const struct ethernet *ethernet;
	const struct ip *ip;
	const struct tcphdr *tcphdr;
	char *app_prot;
};

struct tcp6_packet
{
	const struct ethernet *ethernet;
	const struct ip6_hdr *ip6;
	const struct tcphdr *tcphdr;
	char *app_prot;
};

struct udp_packet
{
	const struct ethernet *ethernet;
	const struct ip *ip;
	const struct udphdr *udphdr;
	char *type;
};

struct udp6_packet
{
	const struct ethernet *ethernet;
	const struct ip6_hdr *ip6;
	const struct udphdr *udphdr;
	char *type;
};

struct ethernet_packet
{
	const struct ethernet *ethernet;
	char *type;
};

struct ip_packet
{
	const struct ethernet *ethernet;
	const struct ip *ip;
	char *type;
};

struct ip6_packet
{
	const struct ethernet *ethernet;
	const struct ip6_hdr *ip6;
	char *type;
};

union generic_packet
{
	struct tcp_packet *tcp_pack;
	struct udp_packet *udp_pack;
	struct icmp_packet *icmp_pack;
	struct tcp6_packet *tcp6_pack;
	struct udp6_packet *udp6_pack;
	struct icmp6_packet *icmp6_pack;
	struct ethernet_packet *eth_pack;
	struct ip_packet *ip_pack;
	struct ip6_packet *ip6_pack;
};

/* Types:
 * 0 = Ethernet
 * 1 = IP
 * TCP = 2
 * UDP = 3
 * ICMP = 4
 * IP6 = 5
 * TCP6 = 6
 * UDP6 = 7
 * ICMP6 = 8
*/
struct sniffer_packet
{
	union generic_packet *gen_pack;
	int type;
};

typedef struct sniffer_packet sniffer_packet;