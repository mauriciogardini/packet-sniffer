/* Instructions
 * Compiling: g++ -Wall test.cpp -lpcap -o test
 * Executing: ./test <interface> <packageammount> <filter> (Example: ./test en1 10 "net 10.0")
 * On Macbook:
 * en0: Ethernet
 * en1: Airport
 * en2: Bluetooth
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <unistd.h>
#include "structs.c"
#include "constants.c"

void get_ICMPv6_message(int icmpType, int icmpCode, char **icmpMessage);
void get_IPv6_message(int ipPriority, char **icmpMessage);

u_short ipv6Counter = 0;
u_short ipv4Counter = 0;

int size_ip;
int packet_counter = 0;

sniffer_packet **packets = NULL;			/* Packet array */
int num_elements = 0;						/* Number of elements used */
int num_allocated = 0;						/* How large the array is */
int is_capture_disabled = 0;
pcap_t *handle;

char param_filter[50] = "";
char *param_device = "en1";
int param_packets = -1;

/* Initializes a hash
 * int size: Size of the hash
 */
hash_t *hash_init(int size)
{
	hash_t *hash = malloc(sizeof(hash_t));

	if(hash == NULL) { /* trata o erro do malloc se tu quiser */ }

	hash->keys = malloc(sizeof(int) * size);
	hash->values = malloc(sizeof(int) * size);
	hash->size = 0;

	return hash;
}

/* Increments a hash
 * hash_t *hash: hash to be incremented
 * int key: Value of the key to be incremented
 */
void hash_increment(hash_t *hash, int key)
{
	int i = 0;
	int found = 0;
	while ((i < hash->size)&&(found != 1))
	{
		if(hash->keys[i] == key)
		{
			(hash->values[i])++;
			found = 1;
		}
		i++;
	}
	if (found == 0)
	{
		hash->keys[i] = key;
		hash->values[i] = 1;
		hash->size++;
	}
}

/* Free the memory used by the hash
 * hash_t *hash: hash to be incremented
 */
void free_hash(hash_t *hash)
{
	free(hash->keys);
	free(hash->values);
	free(hash);
	hash = NULL;
}

/* Add a sniffer_packet to the packets array
 * sniffer_packet item: packet to be added to the packet array
 */
int add_to_sniffer_array (sniffer_packet *item)
{
	if (num_elements == num_allocated) // Are more refs required?
		{
			if (num_allocated == 0)
				num_allocated = 3; // Start off with 3 refs
			else
				num_allocated *= 2; // Double the number of refs allocated

			// Make the reallocation transactional
			// by using a temporary variable first
			void *_tmp = realloc(packets, (num_allocated * sizeof(sniffer_packet*)));

			// If the reallocation didn't go so well,
			// inform the user and bail out
			if (!_tmp)
			{
				fprintf(stderr, "ERROR: Couldn't realloc memory!\n");
				return(-1);
			}

			packets = (sniffer_packet**)_tmp;
		}
	packets[num_elements] = item;

	num_elements++;
	return num_elements;
}

/* Prints the ICMPv6 graph */
void print_icmp6_graph(sniffer_packet **packets)
{
	hash_t *icmpv6_hash = hash_init(34);
	int counter;
	int icmp6_counter = 0;

	/* Processing ICMPv6 packets for type retrievement */
	for (counter = 0; counter < packet_counter; counter++)
	{
		if ((packets[counter]->type) == ICMP6_ID)
		{
			hash_increment(icmpv6_hash, ((((packets[counter]->gen_pack)->icmp6_pack)->icmp6)->icmp6_type));
			icmp6_counter = icmp6_counter + 1;
		}
	}

	if (icmpv6_hash->size > 0)
	{
		/* Printing the graph */
		printf("%s|", MSG_IDENTATION_1);
		int i;
		for (i=0; i < 62; i++)
		{
			printf("%s", "_");
		}
		printf("%s", "ICMPv6");
		for (i=0; i < 62; i++)
		{
			printf("%s", "_");
		}
		printf("\n");
		printf("\n");

		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);

		for(counter = 0; counter < icmpv6_hash->size; counter++)
		{
			float value;
			char *text;
			int i;

			value = ((float)icmpv6_hash->values[counter] * 100.0)/((float)icmp6_counter);
			printf("%s|", MSG_IDENTATION_1);
			for (i=0; i < ((int)value); i++)
			{
				printf("%s", "#");
			}

			get_ICMPv6_message(icmpv6_hash->keys[counter], -1, &text);

			printf(" %s - %i - %f\n", text, icmpv6_hash->values[counter], value);
		}

		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|", MSG_IDENTATION_1);
		for (i=0; i < 129; i++)
		{
			printf("%s", "_");
		}
		printf("\n");
		printf("\n");
		printf("\n");
	}

	else
	{
		printf("\n");
		printf("No ICMPv6 packets were captured.\n");
		printf("\n");
	}

	free_hash(icmpv6_hash);
}

/* Prints the IPv4 & IPv6 graph */
void print_ipv4_ipv6_graph(sniffer_packet **packets)
{
	float ipv4 = ((float)ipv4Counter * 100.0)/(float)packet_counter;
	float ipv6 = ((float)ipv6Counter * 100.0)/packet_counter;
	float other = (((float)packet_counter - (float)ipv4Counter - (float)ipv6Counter) * 100.0)/(float)packet_counter;
	printf("\n%i packages were processed successfully, being %i IPv4, %i IPv6 and %i of other types.\n", packet_counter, ipv4Counter, ipv6Counter, packet_counter - ipv4Counter - ipv6Counter);
	printf("\n");

	printf("%s|", MSG_IDENTATION_1);
	int i;
	for (i=0; i < 58; i++)
	{
		printf("%s", "_");
	}
	printf("%s", "IPv4 vs. IPv6");
	for (i=0; i < 58; i++)
	{
		printf("%s", "_");
	}
	printf("\n");
	printf("\n");

	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|", MSG_IDENTATION_1);

	for (i=0; i < ((int)ipv4); i++)
	{
		printf("%s", "#");
	}
	printf(" %s - %f\n", "IPv4", ipv4);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|", MSG_IDENTATION_1);

	for (i=0; i < ((int)ipv6); i++)
	{
		printf("%s", "#");
	}
	printf(" %s - %f\n", "IPv6", ipv6);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|", MSG_IDENTATION_1);

	for (i=0; i < ((int)other); i++)
	{
		printf("%s", "#");
	}
	printf(" %s - %f\n", "Other", other);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|\n", MSG_IDENTATION_1);
	printf("%s|", MSG_IDENTATION_1);
	for (i=0; i < 129; i++)
	{
		printf("%s", "_");
	}
	printf("\n");
	printf("\n");
	printf("\n");
}

/* Prints the IPv6 graph */
void print_ipv6_graph(sniffer_packet **packets)
{
	hash_t *ipv6_hash = hash_init(34);
	int counter;
	int ip6_counter = 0;

	/* Processing ICMPv6 packets for type retrievement */
	for (counter = 0; counter < packet_counter; counter++)
	{
		if ( ((packets[counter]->type) == IP6_ID) || ((packets[counter]->type) == TCP6_ID) || ((packets[counter]->type) == UDP6_ID) || ((packets[counter]->type) == ICMP6_ID))
		{
			switch((packets[counter]->type))
			{
				case IP6_ID:
					hash_increment(ipv6_hash, (((packets[counter]->gen_pack)->ip6_pack)->ip6)->ip6_vfc&15);
					break;
				case TCP6_ID:
					hash_increment(ipv6_hash, (((packets[counter]->gen_pack)->tcp6_pack)->ip6)->ip6_vfc&15);
					break;
				case UDP6_ID:
					hash_increment(ipv6_hash, (((packets[counter]->gen_pack)->udp6_pack)->ip6)->ip6_vfc&15);
					break;
				case ICMP6_ID:
					hash_increment(ipv6_hash, (((packets[counter]->gen_pack)->icmp6_pack)->ip6)->ip6_vfc&15);
					break;
				default:
					hash_increment(ipv6_hash, (((packets[counter]->gen_pack)->ip6_pack)->ip6)->ip6_vfc&15);
					break;
			}
			ip6_counter = ip6_counter + 1;
		}
	}

	if (ipv6_hash->size > 0)
	{
		/* Printing the graph */
		printf("%s|", MSG_IDENTATION_1);
		int i;
		for (i=0; i < 62; i++)
		{
			printf("%s", "_");
		}
		printf("%s", "IPv6");
		for (i=0; i < 62; i++)
		{
			printf("%s", "_");
		}
		printf("\n");
		printf("\n");

		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);

		for(counter = 0; counter < ipv6_hash->size; counter++)
		{
			float value;
			char *text;
			int i;

			value = ((float)ipv6_hash->values[counter] * 100.0)/((float)ip6_counter);
			printf("%s|", MSG_IDENTATION_1);
			for (i=0; i < ((int)value); i++)
			{
				printf("%s", "#");
			}

			get_IPv6_message(ipv6_hash->keys[counter], &text);

			printf(" %s (%i) - %i - %f\n", text, ipv6_hash->keys[counter], ipv6_hash->values[counter], value);
		}

		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|\n", MSG_IDENTATION_1);
		printf("%s|", MSG_IDENTATION_1);
		for (i=0; i < 129; i++)
		{
			printf("%s", "_");
		}
		printf("\n");
		printf("\n");
		printf("\n");
	}

	else
	{
		printf("\n");
		printf("No IPv6 packets were captured.\n");
		printf("\n");
	}

	free_hash(ipv6_hash);
}

/* Prints the summary of the packet capture */
void print_summary()
{
	printf("\n");
	printf("\n%i packages were processed successfully, being %i IPv4, %i IPv6 and %i of other types.\n", packet_counter, ipv4Counter, ipv6Counter, packet_counter - ipv4Counter - ipv6Counter);
	printf("\n");
}

/* Prints the packets' header (bash) */
void print_header()
{
	printf("| P. ID  | Dest. MAC Address | Srce. MAC Address |			Dest. IP:Port			|		   Srce. IP:Port		   |	Protocol	|				Description				  |\n");
}

/* Prints the packet passed by parameter
 * sniffer_packet *sp: pointer to the sniffer packet
 * int number: number of the packet to be printed
 */
void print_packet_line(struct sniffer_packet *sp, int number)
{
	#define PACKET_NUMBER_SIZE 6
	#define MAC_ADDRESS_SIZE 18
	#define IP_ADDRESS_SIZE 26
	#define PORT_SIZE 5
	#define PROTOCOL_SIZE 14
	#define DESCRIPTION_SIZE 39

	printf("|");

	//Writing the packet number
	char packet_number[PACKET_NUMBER_SIZE];
	int number_lenght = 0;
	number_lenght = sprintf(packet_number, "%i", number);

	printf(" %*s ", PACKET_NUMBER_SIZE, packet_number);
	printf("|");

	//Writing MAC adresses
	//Verifying if it's a valid packet
	if ((sp->type == ETHERNET_ID) || (sp->type == IP_ID) || (sp->type == TCP_ID) || (sp->type == UDP_ID) || (sp->type == ICMP_ID) ||
		(sp->type == IP6_ID) || (sp->type == TCP6_ID) || (sp->type == UDP6_ID) || (sp->type == ICMP6_ID))
	{
		char packet_destination_mac[MAC_ADDRESS_SIZE] = "";
		char packet_source_mac[MAC_ADDRESS_SIZE] = "";
		char temp_mac[3];
		int destination_mac_lenght = 0;
		int source_mac_lenght = 0;
		int temp_lenght = 0;
		int x;

		x = 0;
		while (x < 6)
		{
			switch (sp->type)
			{
				case ETHERNET_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->eth_pack)->ethernet)->ether_dhost[x]);
				case IP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->ip_pack)->ethernet)->ether_dhost[x]);
				case TCP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->tcp_pack)->ethernet)->ether_dhost[x]);
				case UDP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->udp_pack)->ethernet)->ether_dhost[x]);
				case ICMP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->icmp_pack)->ethernet)->ether_dhost[x]);
				case IP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->ip6_pack)->ethernet)->ether_dhost[x]);
				case TCP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->tcp6_pack)->ethernet)->ether_dhost[x]);
				case UDP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->udp6_pack)->ethernet)->ether_dhost[x]);
				case ICMP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->icmp6_pack)->ethernet)->ether_dhost[x]);
				default: ;
			}
			destination_mac_lenght += temp_lenght;
			strcat(packet_destination_mac, temp_mac);
			if (x != 5)
			{
				strcat(packet_destination_mac, "-");
				destination_mac_lenght += 1;
			}
			x++;
		}

		printf(" %*s ", MAC_ADDRESS_SIZE - 1, packet_destination_mac);
		printf("|");

		x = 0;
		while (x < 6)
		{
			switch (sp->type)
			{
				case ETHERNET_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->eth_pack)->ethernet)->ether_shost[x]);
				case IP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->ip_pack)->ethernet)->ether_shost[x]);
				case TCP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->tcp_pack)->ethernet)->ether_shost[x]);
				case UDP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->udp_pack)->ethernet)->ether_shost[x]);
				case ICMP_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->icmp_pack)->ethernet)->ether_shost[x]);
				case IP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->ip6_pack)->ethernet)->ether_shost[x]);
				case TCP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->tcp6_pack)->ethernet)->ether_shost[x]);
				case UDP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->udp6_pack)->ethernet)->ether_shost[x]);
				case ICMP6_ID: temp_lenght = sprintf(temp_mac, "%X", (((sp->gen_pack)->icmp6_pack)->ethernet)->ether_shost[x]);
				default: ;
			}
			//printf(" %s -", temp_mac);
			source_mac_lenght += temp_lenght;
			strcat(packet_source_mac, temp_mac);
			if (x != 5)
			{
				strcat(packet_source_mac, "-");
				source_mac_lenght += 1;
			}
			x++;
		}

		printf(" %*s ", MAC_ADDRESS_SIZE - 1, packet_source_mac);
		printf("|");
	}


	//Writing IP adresses, protocol & description
	switch (sp->type)
	{
		case ETHERNET_ID:
		{
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, " ");
			printf("|");
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, " ");
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, ((sp->gen_pack)->eth_pack)->type);
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, " ");
			printf("|");
		} break;
		case IP_ID:
		{
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, inet_ntoa((((sp->gen_pack)->ip_pack)->ip)->ip_dst));
			printf("|");
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, inet_ntoa((((sp->gen_pack)->ip_pack)->ip)->ip_src));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, ((sp->gen_pack)->ip_pack)->type);
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, " ");
			printf("|");
		} break;
		case TCP_ID:
		{
			printf(" %*s", IP_ADDRESS_SIZE, inet_ntoa((((sp->gen_pack)->tcp_pack)->ip)->ip_dst));
			printf(":");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->tcp_pack)->tcphdr)->th_dport));
			printf("|");
			printf(" %*s", IP_ADDRESS_SIZE, inet_ntoa((((sp->gen_pack)->tcp_pack)->ip)->ip_src));
			printf(":");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->tcp_pack)->tcphdr)->th_sport));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, "TCP (IPv4)");
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, ((sp->gen_pack)->tcp_pack)->app_prot);
			printf("|");
		} break;
		case UDP_ID:
		{
			printf(" %*s", IP_ADDRESS_SIZE, inet_ntoa((((sp->gen_pack)->udp_pack)->ip)->ip_dst));
			printf(":");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->udp_pack)->udphdr)->uh_dport));
			printf("|");
			printf(" %*s", IP_ADDRESS_SIZE, inet_ntoa((((sp->gen_pack)->udp_pack)->ip)->ip_src));
			printf(":");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->udp_pack)->udphdr)->uh_sport));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, ((sp->gen_pack)->udp_pack)->type);
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, "");
			printf("|");
		} break;
		case ICMP_ID:
		{
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, inet_ntoa((((sp->gen_pack)->icmp_pack)->ip)->ip_dst));
			printf("|");
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, inet_ntoa((((sp->gen_pack)->icmp_pack)->ip)->ip_src));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, "ICMPv4");
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, ((sp->gen_pack)->icmp_pack)->icmpMessage);
			printf("|");
		} break;
		case IP6_ID:
		{
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &((((sp->gen_pack)->ip6_pack)->ip6)->ip6_dst), str, INET6_ADDRSTRLEN);
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, str);
			printf("|");
			inet_ntop(AF_INET6, &((((sp->gen_pack)->ip6_pack)->ip6)->ip6_src), str, INET6_ADDRSTRLEN);
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, str);
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, ((sp->gen_pack)->ip6_pack)->type);
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, " ");
			printf("|");
		} break;
		case TCP6_ID:
		{
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &((((sp->gen_pack)->tcp6_pack)->ip6)->ip6_dst), str, INET6_ADDRSTRLEN);
			printf(" %*s", IP_ADDRESS_SIZE, str);
			printf("]");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->tcp6_pack)->tcphdr)->th_sport));
			printf("|");
			inet_ntop(AF_INET6, &((((sp->gen_pack)->tcp6_pack)->ip6)->ip6_src), str, INET6_ADDRSTRLEN);
			printf(" %*s", IP_ADDRESS_SIZE, str);
			printf("]");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->tcp6_pack)->tcphdr)->th_dport));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, "TCP (IPv6)");
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, ((sp->gen_pack)->tcp6_pack)->app_prot);
			printf("|");
		} break;
		case UDP6_ID:
		{
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &((((sp->gen_pack)->udp6_pack)->ip6)->ip6_dst), str, INET6_ADDRSTRLEN);
			printf(" %*s", IP_ADDRESS_SIZE, str);
			printf("]");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->udp6_pack)->udphdr)->uh_dport));
			printf("|");
			inet_ntop(AF_INET6, &((((sp->gen_pack)->udp6_pack)->ip6)->ip6_src), str, INET6_ADDRSTRLEN);
			printf(" %*s", IP_ADDRESS_SIZE, str);
			printf("]");
			printf("%*d ", PORT_SIZE, ntohs((((sp->gen_pack)->udp6_pack)->udphdr)->uh_sport));
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, ((sp->gen_pack)->udp6_pack)->type);
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, "");
			printf("|");
		} break;
		case ICMP6_ID:
		{
			char str[INET6_ADDRSTRLEN];
			inet_ntop(AF_INET6, &((((sp->gen_pack)->icmp6_pack)->ip6)->ip6_dst), str, INET6_ADDRSTRLEN);
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, str);
			printf("|");
			inet_ntop(AF_INET6, &((((sp->gen_pack)->icmp6_pack)->ip6)->ip6_src), str, INET6_ADDRSTRLEN);
			printf(" %*s ", IP_ADDRESS_SIZE + PORT_SIZE + 1, str);
			printf("|");
			printf(" %*s ", PROTOCOL_SIZE, "ICMPv6");
			printf("|");
			printf(" %*s ", DESCRIPTION_SIZE, ((sp->gen_pack)->icmp6_pack)->icmpMessage);
			printf("|");
		} break;
		default: break;
	}
	printf("\n");
}

/* Prints all the packets in the packet array
 * sniffer_packet *packets: pointer to the sniffer packets' array
 */
void print_packets(sniffer_packet *packets)
{
	int counter;
	print_header();
	for (counter = 0; counter < packet_counter; counter++)
	{
		print_packet_line(&packets[counter], counter);
	}
}

/* Gets the IPv6 Priority message for the Priority code passed by parameter
 * int ipPriority: Priority code
 * char **icmpMessage: pointer to a char pointer which will store the message
 */
void get_IPv6_message(int ipPriority, char **icmpMessage)
{
	switch (ipPriority)
	{
		case IPV6_UNCHARACTERIZED_TRAFFIC: *icmpMessage = MSG_IPV6_UNCHARACTERIZED_TRAFFIC; break;
		case IPV6_FILLER_TRAFFIC: *icmpMessage = MSG_IPV6_FILLER_TRAFFIC; break;
		case IPV6_UNATTENDED_DATA_TRANSFER: *icmpMessage = MSG_IPV6_UNATTENDED_DATA_TRANSFER; break;
		case IPV6_RESERVED_1: *icmpMessage = MSG_IPV6_RESERVED_1; break;
		case IPV6_ATTENDED_BULK_TRANSFER: *icmpMessage = MSG_IPV6_ATTENDED_BULK_TRANSFER; break;
		case IPV6_RESERVED_2: *icmpMessage = MSG_IPV6_RESERVED_2; break;
		case IPV6_INTERACTIVE_TRAFFIC: *icmpMessage = MSG_IPV6_INTERACTIVE_TRAFFIC; break;
		case IPV6_CONTROL_TRAFFIC: *icmpMessage = MSG_IPV6_CONTROL_TRAFFIC; break;
		default: *icmpMessage = MSG_IPV6_UNKNOWN; break;
	}
}

/* Gets the ICMP message for the type and code passed by parameter
 * int icmpType: ICMP type
 * int icmpCode: ICMP code (if it exists)
 * char **icmpMessage: pointer to a char pointer which will store the message
 */
void get_ICMP_message(int icmpType, int icmpCode, char **icmpMessage)
{
	switch (icmpType)
	{
		case ICMP_ECHOREPLY: *icmpMessage = MSG_ICMP_ECHOREPLY; break;
		case ICMP_UNREACH:
		switch(icmpCode)
		{
			case ICMP_UNREACH_NET: *icmpMessage = MSG_ICMP_UNREACH_NET; break;
			case ICMP_UNREACH_HOST: *icmpMessage = MSG_ICMP_UNREACH_HOST; break;
			case ICMP_UNREACH_PROTOCOL: *icmpMessage = MSG_ICMP_UNREACH_PROTOCOL; break;
			case ICMP_UNREACH_PORT: *icmpMessage = MSG_ICMP_UNREACH_PORT; break;
			case ICMP_UNREACH_NEEDFRAG: *icmpMessage = MSG_ICMP_UNREACH_NEEDFRAG; break;
			case ICMP_UNREACH_SRCFAIL: *icmpMessage = MSG_ICMP_UNREACH_SRCFAIL; break;
			case ICMP_UNREACH_NET_UNKNOWN: *icmpMessage = MSG_ICMP_UNREACH_NET_UNKNOWN; break;
			case ICMP_UNREACH_HOST_UNKNOWN: *icmpMessage = MSG_ICMP_UNREACH_HOST_UNKNOWN; break;
			case ICMP_UNREACH_ISOLATED: *icmpMessage = MSG_ICMP_UNREACH_ISOLATED; break;
			case ICMP_UNREACH_NET_PROHIB: *icmpMessage = MSG_ICMP_UNREACH_NET_PROHIB; break;
			case ICMP_UNREACH_HOST_PROHIB: *icmpMessage = MSG_ICMP_UNREACH_HOST_PROHIB; break;
			case ICMP_UNREACH_TOSNET: *icmpMessage = MSG_ICMP_UNREACH_TOSNET; break;
			case ICMP_UNREACH_TOSHOST: *icmpMessage = MSG_ICMP_UNREACH_TOSHOST; break;
			case ICMP_UNREACH_FILTER_PROHIB: *icmpMessage = MSG_ICMP_UNREACH_FILTER_PROHIB; break;
			case ICMP_UNREACH_HOST_PRECEDENCE: *icmpMessage = MSG_ICMP_UNREACH_HOST_PRECEDENCE; break;
			case ICMP_UNREACH_PRECEDENCE_CUTOFF: *icmpMessage = MSG_ICMP_UNREACH_PRECEDENCE_CUTOFF; break;
			default: *icmpMessage = MSG_ICMP_UNREACH_SUBTYPE_UNKNOWN; break;
		}
		break;
		case ICMP_SOURCEQUENCH: *icmpMessage = MSG_ICMP_SOURCEQUENCH; break;
		case ICMP_REDIRECT:
		switch (icmpCode)
		{
			case ICMP_REDIRECT_NET: *icmpMessage = MSG_ICMP_REDIRECT_NET; break;
			case ICMP_REDIRECT_HOST: *icmpMessage = MSG_ICMP_REDIRECT_HOST; break;
			case ICMP_REDIRECT_TOSNET: *icmpMessage = MSG_ICMP_REDIRECT_TOSNET; break;
			case ICMP_REDIRECT_TOSHOST: *icmpMessage = MSG_ICMP_REDIRECT_TOSHOST; break;
			default: *icmpMessage = MSG_ICMP_REDIRECT_SUBTYPE_UNKNOWN; break;
		}
		break;
		case ICMP_ECHO: *icmpMessage = MSG_ICMP_ECHO; break;
		case ICMP_ROUTERADVERT: *icmpMessage = MSG_ICMP_ROUTERADVERT; break;
		case ICMP_ROUTERSOLICIT: *icmpMessage = MSG_ICMP_ROUTERSOLICIT; break;
		case ICMP_TIMXCEED:
		switch (icmpCode)
		{
			case ICMP_TIMXCEED_INTRANS: *icmpMessage = MSG_ICMP_TIMXCEED_INTRANS; break;
			case ICMP_TIMXCEED_REASS: *icmpMessage = MSG_ICMP_TIMXCEED_REASS; break;
			default: *icmpMessage = MSG_ICMP_TIMXCEED_SUBTYPE_UNKNOWN; break;
		}
		break;
		case ICMP_PARAMPROB:
		switch (icmpCode)
		{
			case ICMP_PARAMPROB_ERRATPTR: *icmpMessage = MSG_ICMP_PARAMPROB_ERRATPTR; break;
			case ICMP_PARAMPROB_OPTABSENT: *icmpMessage = MSG_ICMP_PARAMPROB_OPTABSENT; break;
			case ICMP_PARAMPROB_LENGTH: *icmpMessage = MSG_ICMP_PARAMPROB_LENGTH; break;
			default: *icmpMessage = MSG_ICMP_PARAMPROB_SUBTYPE_UNKNOWN; break;
		}
		break;
		case ICMP_TSTAMP: *icmpMessage = MSG_ICMP_TSTAMP; break;
		case ICMP_TSTAMPREPLY: *icmpMessage = MSG_ICMP_TSTAMPREPLY; break;
		case ICMP_IREQ: *icmpMessage = MSG_ICMP_IREQ; break;
		case ICMP_IREQREPLY: *icmpMessage = MSG_ICMP_IREQREPLY; break;
		case ICMP_MASKREQ: *icmpMessage = MSG_ICMP_MASKREQ; break;
		case ICMP_MASKREPLY: *icmpMessage = MSG_ICMP_MASKREPLY; break;
		case ICMP_TRACEROUTE: *icmpMessage = MSG_ICMP_TRACEROUTE; break;
		case ICMP_DATACONVERR: *icmpMessage = MSG_ICMP_DATACONVERR; break;
		case ICMP_MOBILE_REDIRECT: *icmpMessage = MSG_ICMP_MOBILE_REDIRECT; break;
		case ICMP_IPV6_WHEREAREYOU: *icmpMessage = MSG_ICMP_IPV6_WHEREAREYOU; break;
		case ICMP_IPV6_IAMHERE: *icmpMessage = MSG_ICMP_IPV6_IAMHERE; break;
		case ICMP_MOBILE_REGREQUEST: *icmpMessage = MSG_ICMP_MOBILE_REGREQUEST; break;
		case ICMP_MOBILE_REGREPLY: *icmpMessage = MSG_ICMP_MOBILE_REGREPLY; break;
		case ICMP_DNS: *icmpMessage = MSG_ICMP_DNS; break;
		case ICMP_DNSREPLY: *icmpMessage = MSG_ICMP_DNSREPLY; break;
		case ICMP_SKIP: *icmpMessage = MSG_ICMP_SKIP; break;
		case ICMP_PHOTURIS:
		switch (icmpCode)
		{
			case ICMP_PHOTURIS_UNKNOWN_INDEX: *icmpMessage = MSG_ICMP_PHOTURIS_UNKNOWN_INDEX; break;
			case ICMP_PHOTURIS_AUTH_FAILED: *icmpMessage = MSG_ICMP_PHOTURIS_AUTH_FAILED; break;
			case ICMP_PHOTURIS_DECRYPT_FAILED: *icmpMessage = MSG_ICMP_PHOTURIS_DECRYPT_FAILED; break;
			default: *icmpMessage = MSG_ICMP_PHOTURIS_SUBTYPE_UNKNOWN; break;
		}
		break;
		default: *icmpMessage = MSG_ICMP_TYPE_UNKNOWN; break;
	}
}

/* Gets the ICMPv6 message for the type and code passed by parameter
 * int icmpType: ICMP type
 * int icmpCode: ICMP code (if it exists)
 * char **icmpMessage: pointer to a char pointer which will store the message
 */
void get_ICMPv6_message(int icmpType, int icmpCode, char **icmpMessage)
{
	switch (icmpType)
	{
		case ICMP6_DST_UNREACH:
		switch (icmpCode)
		{
			case ICMP6_DST_UNREACH_NOROUTE: *icmpMessage = MSG_ICMP6_DST_UNREACH_NOROUTE; break;
			case ICMP6_DST_UNREACH_ADMIN: *icmpMessage = MSG_ICMP6_DST_UNREACH_ADMIN; break;
			case ICMP6_DST_UNREACH_BEYONDSCOPE: *icmpMessage = MSG_ICMP6_DST_UNREACH_BEYONDSCOPE; break;
			case ICMP6_DST_UNREACH_ADDR: *icmpMessage = MSG_ICMP6_DST_UNREACH_ADDR; break;
			case ICMP6_DST_UNREACH_NOPORT: *icmpMessage = MSG_ICMP6_DST_UNREACH_NOPORT; break;
			default: *icmpMessage = MSG_ICMP6_DST_UNREACH; break;
		}
		break;
		case ICMP6_PACKET_TOO_BIG: *icmpMessage = MSG_ICMP6_PACKET_TOO_BIG; break;
		case ICMP6_TIME_EXCEEDED: *icmpMessage = MSG_ICMP6_TIME_EXCEEDED; break;
		case ICMP6_PARAM_PROB: *icmpMessage = MSG_ICMP6_PARAM_PROB; break;
		case ICMP6_ECHO_REQUEST: *icmpMessage = MSG_ICMP6_ECHO_REQUEST; break;
		case ICMP6_ECHO_REPLY: *icmpMessage = MSG_ICMP6_ECHO_REPLY; break;
		case MLD6_LISTENER_QUERY: *icmpMessage = MSG_MLD6_LISTENER_QUERY; break;
		case MLD6_LISTENER_REPORT: *icmpMessage = MSG_MLD6_LISTENER_REPORT; break;
		case MLD6_LISTENER_DONE: *icmpMessage = MSG_MLD6_LISTENER_DONE; break;
		case ND_ROUTER_SOLICIT: *icmpMessage = MSG_ND_ROUTER_SOLICIT; break;
		case ND_ROUTER_ADVERT: *icmpMessage = MSG_ND_ROUTER_ADVERT; break;
		case ND_NEIGHBOR_SOLICIT: *icmpMessage = MSG_ND_NEIGHBOR_SOLICIT; break;
		case ND_NEIGHBOR_ADVERT: *icmpMessage = MSG_ND_NEIGHBOR_ADVERT; break;
		case ND_REDIRECT: *icmpMessage = MSG_ND_REDIRECT; break;
		case ICMP6_ROUTER_RENUMBERING: *icmpMessage = MSG_ICMP6_ROUTER_RENUMBERING; break;
		case IND_SOLICIT: *icmpMessage = MSG_IND_SOLICIT; break;
		case IND_ADVERT: *icmpMessage = MSG_IND_ADVERT; break;
		case MLDV2_LISTENER_REPORT: *icmpMessage = MSG_MLDV2_LISTENER_REPORT; break;
		case ICMP6_HADISCOV_REQUEST: *icmpMessage = MSG_ICMP6_HADISCOV_REQUEST; break;
		case ICMP6_HADISCOV_REPLY: *icmpMessage = MSG_ICMP6_HADISCOV_REPLY; break;
		case ICMP6_MOBILEPREFIX_SOLICIT: *icmpMessage = MSG_ICMP6_MOBILEPREFIX_SOLICIT; break;
		case ICMP6_MOBILEPREFIX_ADVERT: *icmpMessage = MSG_ICMP6_MOBILEPREFIX_ADVERT; break;
		case ICMP6_WRUREQUEST: *icmpMessage = MSG_ICMP6_WRUREQUEST; break;
		case ICMP6_WRUREPLY: *icmpMessage = MSG_ICMP6_WRUREPLY; break;
		case MLD6_MTRACE: *icmpMessage = MSG_MLD6_MTRACE; break;
		case MLD6_MTRACE_RESP: *icmpMessage = MSG_MLD6_MTRACE_RESP; break;
		case ND_RPL_MESSAGE: *icmpMessage = MSG_ND_RPL_MESSAGE; break;
	}
}

/* Processes an ICMP packet
 * const u_char *packet: packet to be processed
 */
void process_ICMP(const u_char *packet)
{
	const struct ip *ip;
	const struct ethernet *ethernet;
	const struct icmp *icmp;
	struct icmp_packet *i_packet;
	char* icmpMessage;
	struct sniffer_packet *s_packet;
	union generic_packet *g_packet;

	s_packet = (struct sniffer_packet*) malloc(sizeof(struct sniffer_packet));
	g_packet = (union generic_packet*) malloc(sizeof(union generic_packet));
	i_packet = (struct icmp_packet*) malloc(sizeof(struct icmp_packet));
	i_packet->ethernet = (struct ethernet*) malloc(sizeof(struct ethernet));
	i_packet->ip = (struct ip*) malloc(sizeof(struct ip));
	i_packet->icmp = (struct icmp*) malloc(sizeof(struct icmp));

	ethernet = (struct ethernet*)(packet);
	ip = (struct ip*)(packet + sizeof(struct ethernet));
	icmp = (struct icmp*)(packet + sizeof(struct ethernet) + sizeof(struct ip));

	memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
	memcpy(i_packet->ip, ip, sizeof(struct ip));
	memcpy(i_packet->icmp, icmp, sizeof(struct icmp));
	get_ICMP_message(icmp->icmp_type, icmp->icmp_code, &icmpMessage);
	i_packet->icmpMessage = icmpMessage;
	g_packet->icmp_pack = i_packet;
	s_packet->gen_pack = g_packet;
	s_packet->type = ICMP_ID;

	print_packet_line(s_packet, packet_counter);
	add_to_sniffer_array(s_packet);
}

/* Processes an ICMPv6 packet
* const u_char *packet: packet to be processed
*/
void process_ICMPv6(const u_char *packet)
{
	struct ip6_hdr *ip6;
	struct ethernet *ethernet;
	struct icmp6_hdr *icmp6;
	struct icmp6_packet *i6_packet;
	char* icmpMessage;
	struct sniffer_packet *s_packet;
	union generic_packet *g_packet;

	s_packet = (struct sniffer_packet*) malloc(sizeof(struct sniffer_packet));
	g_packet = (union generic_packet*) malloc(sizeof(union generic_packet));
	i6_packet = (struct icmp6_packet*) malloc(sizeof(struct icmp6_packet));
	i6_packet->ethernet = (struct ethernet*) malloc(sizeof(struct ethernet));
	i6_packet->ip6 = (struct ip6_hdr*) malloc(sizeof(struct ip6_hdr));
	i6_packet->icmp6 = (struct icmp6_hdr*) malloc(sizeof(struct icmp6_hdr));

	ethernet = (struct ethernet*)(packet);
	ip6 = (struct ip6_hdr*)(packet + sizeof(struct ethernet));
	icmp6 = (struct icmp6_hdr*)(packet + sizeof(struct ethernet) + sizeof(struct ip6_hdr));

	memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
	memcpy(i6_packet->ip6, ip6, sizeof(struct ip6_hdr));
	memcpy(i6_packet->icmp6, icmp6, sizeof(struct icmp6_hdr));
	get_ICMPv6_message(icmp6->icmp6_type, icmp6->icmp6_code, &icmpMessage);
	i6_packet->icmpMessage = icmpMessage;
	g_packet->icmp6_pack = i6_packet;
	s_packet->gen_pack = g_packet;
	s_packet->type = ICMP6_ID;

	print_packet_line(s_packet, packet_counter);
	add_to_sniffer_array(s_packet);
}

/* Processes an IP packet
* const u_char *packet: packet to be processed
*/
void process_IP(const u_char *packet)
{
	const struct ip *ip;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	struct sniffer_packet *s_packet;
	union generic_packet *g_packet;
	struct ip_packet *i_packet;
	struct tcp_packet *t_packet;
	struct udp_packet *u_packet;
	const struct ethernet *ethernet;
	int wasProcessed = 0;

	s_packet = (struct sniffer_packet*) malloc(sizeof(struct sniffer_packet));
	g_packet = (union generic_packet*) malloc(sizeof(union generic_packet));

	ethernet = (struct ethernet*)(packet);
	ip = (struct ip*)(packet + sizeof(struct ethernet));

	/* Determining the protocol */
	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			{
				t_packet = (struct tcp_packet*) malloc(sizeof(struct tcp_packet));
				t_packet->app_prot = (char*) malloc((sizeof(char) * 20));
				t_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				t_packet->ip = (struct ip*) malloc((sizeof(struct ip)));
				t_packet->tcphdr = (struct tcphdr*) malloc((sizeof(struct tcphdr)));

				tcp = (struct tcphdr*)(packet + sizeof(struct ethernet) + size_ip);

				/* Determinando o Application protocol (se houver) */
				switch (ntohs(tcp->th_dport))
				{
					case 20:
					case 21:
						memcpy(t_packet->app_prot, "FTP (IPv4)", sizeof(char) * (strlen("FTP (IPv4)") + 1));
						break;
					case 22:
						memcpy(t_packet->app_prot, "SSH (IPv4)", sizeof(char) * (strlen("SSH (IPv4)") + 1));
						break;
					case 23:
						memcpy(t_packet->app_prot, "Telnet (IPv4)", sizeof(char) * (strlen("Telnet (IPv4)") + 1));
						break;
					case 25:
						memcpy(t_packet->app_prot, "SMTP (IPv4)", sizeof(char) * (strlen("SMTP (IPv4)") + 1));
						break;
					case 80:
						memcpy(t_packet->app_prot, "HTTP (IPv4)", sizeof(char) * (strlen("HTTP (IPv4)") + 1));
						break;
					case 110:
						memcpy(t_packet->app_prot, "POP3 (IPv4)", sizeof(char) * (strlen("POP3 (IPv4)") + 1));
						break;
					case 123:
						memcpy(t_packet->app_prot, "NTP (IPv4)", sizeof(char) * (strlen("NTP (IPv4)") + 1));
						break;
					case 143:
						memcpy(t_packet->app_prot, "IMAP (IPv4)", sizeof(char) * (strlen("IMAP (IPv4)") + 1));
						break;
					case 161:
					case 162:
						memcpy(t_packet->app_prot, "SNMP (IPv4)", sizeof(char) * (strlen("SNMP (IPv4)") + 1));
						break;
					case 163:
					case 164:
						memcpy(t_packet->app_prot, "CMIP (IPv4)", sizeof(char) * (strlen("CMIP (IPv4)") + 1));
						break;
					case 179:
						memcpy(t_packet->app_prot, "BGP (IPv4)", sizeof(char) * (strlen("BGP (IPv4)") + 1));
						break;
					case 194:
						memcpy(t_packet->app_prot, "IRC (IPv4)", sizeof(char) * (strlen("IRC (IPv4)") + 1));
						break;
					case 443:
						memcpy(t_packet->app_prot, "HTTPS (IPv4)", sizeof(char) * (strlen("HTTPS (IPv4)") + 1));
						break;
					case 989:
					case 990:
						memcpy(t_packet->app_prot, "FTPS (IPv4)", sizeof(char) * (strlen("FTPS (IPv4)") + 1));
						break;
					case 1863:
						memcpy(t_packet->app_prot, "MSNP (IPv4)", sizeof(char) * (strlen("MSNP (IPv4)") + 1));
						break;
					default:
						memcpy(t_packet->app_prot, " ", sizeof(char) * (strlen(" ") + 1));
						break;
				}

				memcpy((t_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((t_packet->ip), ip, sizeof(struct ip));
				memcpy((t_packet->tcphdr), tcp, sizeof(struct tcphdr));
				g_packet->tcp_pack = t_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = TCP_ID;
			}
			break;

		case IPPROTO_UDP:
			{
				u_packet = (struct udp_packet*) malloc(sizeof(struct udp_packet));
				u_packet->type = (char*) malloc((sizeof(char) * 15));
				u_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				u_packet->ip = (struct ip*) malloc((sizeof(struct ip)));
				u_packet->udphdr = (struct udphdr*) malloc((sizeof(struct udphdr)));

				udp = (struct udphdr*)(packet + sizeof(struct ethernet) + size_ip);

				if ((ntohs(udp->uh_sport) == 520) || (ntohs(udp->uh_dport) == 520))
					memcpy(u_packet->type, "RIP (IPv4)", sizeof(char) * (strlen("RIP (IPv4)") + 1));
				else if (ntohs(udp->uh_sport) == 53)
					memcpy(u_packet->type, "DNS (IPv4)", sizeof(char) * (strlen("DNS (IPv4)") + 1));
				else
					memcpy(u_packet->type, "UDP (IPv4)", sizeof(char) * (strlen("UDP (IPv4)") + 1));

				memcpy((u_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((u_packet->ip), ip, sizeof(struct ip));
				memcpy((u_packet->udphdr), udp, sizeof(struct udphdr));
				g_packet->udp_pack = u_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = UDP_ID;
			}
			break;

		case IPPROTO_ICMP:
			{
				process_ICMP(packet);
				wasProcessed = 1;
			}
			break;

		case IPPROTO_OSPF:
			{
				i_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
				i_packet->type = (char*) malloc((sizeof(char) * 15));
				i_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i_packet->ip = (struct ip*) malloc((sizeof(struct ip)));

				memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i_packet->ip), ip, sizeof(struct ip));
				memcpy(i_packet->type, "OSPF (IPv4)", sizeof(char) * (strlen("OSPF (IPv4)") + 1));
				g_packet->ip_pack = i_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP_ID;
			}
			break;

		case IPPROTO_IP:
			{
				i_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
				i_packet->type = (char*) malloc((sizeof(char) * 15));
				i_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i_packet->ip = (struct ip*) malloc((sizeof(struct ip)));

				memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i_packet->ip), ip, sizeof(struct ip));
				memcpy(i_packet->type, "IP (IPv4)", sizeof(char) * (strlen("IP (IPv4)") + 1));
				g_packet->ip_pack = i_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP_ID;
			}
			break;

		case IPPROTO_IPV6:
			{
				i_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
				i_packet->type = (char*) malloc((sizeof(char) * 15));
				i_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i_packet->ip = (struct ip*) malloc((sizeof(struct ip)));

				memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i_packet->ip), ip, sizeof(struct ip));
				memcpy(i_packet->type, "IPv6 (IPv4)", sizeof(char) * (strlen("IPv6 (IPv4)") + 1));
				g_packet->ip_pack = i_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP_ID;
			}
			break;

		case IPPROTO_IGMP:
			{
				i_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
				i_packet->type = (char*) malloc((sizeof(char) * 15));
				i_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i_packet->ip = (struct ip*) malloc((sizeof(struct ip)));

				memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i_packet->ip), ip, sizeof(struct ip));
				memcpy(i_packet->type, "IGMP (IPv4)", sizeof(char) * (strlen("IGMP (IPv4)") + 1));
				g_packet->ip_pack = i_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP_ID;
			}
			break;

		default:
			{
				i_packet = (struct ip_packet*) malloc(sizeof(struct ip_packet));
				i_packet->type = (char*) malloc((sizeof(char) * 15));
				i_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i_packet->ip = (struct ip*) malloc((sizeof(struct ip)));

				memcpy((i_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i_packet->ip), ip, sizeof(struct ip));
				memcpy(i_packet->type, "Unknown (IPv4)", sizeof(char) * (strlen("Unknown (IPv4)") + 1));
				g_packet->ip_pack = i_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP_ID;
			}
			break;
	}
	ipv4Counter++;
	if (!wasProcessed)
	{
		print_packet_line(s_packet, packet_counter);
		add_to_sniffer_array(s_packet);
	}
}

/* Processes an IPv6 packet
* const u_char *packet: packet to be processed
*/
void process_IPv6(const u_char *packet)
{
	const struct ip6_hdr *ip6;
	const struct ethernet *ethernet;
	const struct tcphdr *tcp;
	const struct udphdr *udp;
	struct sniffer_packet *s_packet;
	union generic_packet *g_packet;
	struct ip6_packet *i6_packet;
	struct tcp6_packet *t6_packet;
	struct udp6_packet *u6_packet;
	int wasProcessed = 0;

	s_packet = (struct sniffer_packet*) malloc(sizeof(struct sniffer_packet));
	g_packet = (union generic_packet*) malloc(sizeof(union generic_packet));

	ethernet = (struct ethernet*)(packet);
	ip6 = (struct ip6_hdr*)(packet + sizeof(struct ethernet));

	/* Determining the protocol */
	switch(ip6->ip6_nxt)
	{
		case IPPROTO_TCP:
			{
				t6_packet = (struct tcp6_packet*) malloc(sizeof(struct tcp6_packet));

				tcp = (struct tcphdr*)(packet + sizeof(struct ethernet) + sizeof(struct ip6_hdr));
				t6_packet->app_prot = (char*) malloc((sizeof(char) * 20));
				t6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				t6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));
				t6_packet->tcphdr = (struct tcphdr*) malloc((sizeof(struct tcphdr)));

				memcpy((t6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((t6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy((t6_packet->tcphdr), tcp, sizeof(struct tcphdr));

				/* Determinando o Application protocol (se houver) */
				switch (ntohs(tcp->th_dport))
				{
					case 20:
					case 21:
						memcpy(t6_packet->app_prot, "FTP (IPv6)", sizeof(char) * (strlen("FTP (IPv6)") + 1));
						break;
					case 22:
						memcpy(t6_packet->app_prot, "SSH (IPv6)", sizeof(char) * (strlen("SSH (IPv6)") + 1));
						break;
					case 23:
						memcpy(t6_packet->app_prot, "Telnet (IPv6)", sizeof(char) * (strlen("Telnet (IPv6)") + 1));
						break;
					case 25:
						memcpy(t6_packet->app_prot, "SMTP (IPv6)", sizeof(char) * (strlen("SMTP (IPv6)") + 1));
						break;
					case 80:
						memcpy(t6_packet->app_prot, "HTTP (IPv6)", sizeof(char) * (strlen("HTTP (IPv6)") + 1));
						break;
					case 110:
						memcpy(t6_packet->app_prot, "POP3 (IPv6)", sizeof(char) * (strlen("POP3 (IPv6)") + 1));
						break;
					case 123:
						memcpy(t6_packet->app_prot, "NTP (IPv6)", sizeof(char) * (strlen("NTP (IPv6)") + 1));
						break;
					case 143:
						memcpy(t6_packet->app_prot, "IMAP (IPv6)", sizeof(char) * (strlen("IMAP (IPv6)") + 1));
						break;
					case 161:
					case 162:
						memcpy(t6_packet->app_prot, "SNMP (IPv6)", sizeof(char) * (strlen("SNMP (IPv6)") + 1));
						break;
					case 163:
					case 164:
						memcpy(t6_packet->app_prot, "CMIP (IPv6)", sizeof(char) * (strlen("CMIP (IPv6)") + 1));
						break;
					case 179:
						memcpy(t6_packet->app_prot, "BGP (IPv6)", sizeof(char) * (strlen("BGP (IPv6)") + 1));
						break;
					case 194:
						memcpy(t6_packet->app_prot, "IRC (IPv6)", sizeof(char) * (strlen("IRC (IPv6)") + 1));
						break;
					case 443:
						memcpy(t6_packet->app_prot, "HTTPS (IPv6)", sizeof(char) * (strlen("HTTPS (IPv6)") + 1));
						break;
					case 989:
					case 990:
						memcpy(t6_packet->app_prot, "FTPS (IPv6)", sizeof(char) * (strlen("FTPS (IPv6)") + 1));
						break;
					case 1863:
						memcpy(t6_packet->app_prot, "MSNP (IPv6)", sizeof(char) * (strlen("MSNP (IPv6)") + 1));
						break;
					default:
						memcpy(t6_packet->app_prot, " ", sizeof(char) * (strlen(" ") + 1));
						break;
				}

				memcpy((t6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((t6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy((t6_packet->tcphdr), tcp, sizeof(struct tcphdr));
				g_packet->tcp6_pack = t6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = TCP6_ID;

			}
			break;

		case IPPROTO_UDP:
			{
				u6_packet = (struct udp6_packet*) malloc(sizeof(struct udp6_packet));
				u6_packet->type = (char*) malloc((sizeof(char) * 15));
				u6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				u6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));
				u6_packet->udphdr = (struct udphdr*) malloc((sizeof(struct udphdr)));

				udp = (struct udphdr*)(packet + sizeof(struct ethernet) + sizeof(struct ip6_hdr));

				if ((ntohs(udp->uh_sport) == 520) || (ntohs(udp->uh_dport) == 520))
					memcpy(u6_packet->type, "RIP (IPv6)", sizeof(char) * (strlen("RIP (IPv6)") + 1));
				else if (ntohs(udp->uh_sport) == 53)
					memcpy(u6_packet->type, "DNS (IPv6)", sizeof(char) * (strlen("DNS (IPv6)") + 1));
				else
					memcpy(u6_packet->type, "UDP (IPv6)", sizeof(char) * (strlen("UDP (IPv6)") + 1));

				memcpy((u6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((u6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy((u6_packet->udphdr), udp, sizeof(struct udphdr));
				g_packet->udp6_pack = u6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = UDP6_ID;
			}
			break;

		case IPPROTO_ICMPV6:
			{
				process_ICMPv6(packet);
				wasProcessed = 1;
			}
			break;

		case IPPROTO_OSPF:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "OSPF (IPv6)", sizeof(char) * (strlen("OSPF (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_IPV6:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "IPv6 (IPv6)", sizeof(char) * (strlen("IPv6 (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_IPV4:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "IPv4 (IPv6)", sizeof(char) * (strlen("IPv4 (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_PGM:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "PGM (IPv6)", sizeof(char) * (strlen("PGM (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_GRE:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "GRE (IPv6)", sizeof(char) * (strlen("GRE (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_RSVP:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "RSVP (IPv6)", sizeof(char) * (strlen("RSVP (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		case IPPROTO_NONE:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "None (IPv6)", sizeof(char) * (strlen("None (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;

		default:
			{
				i6_packet = (struct ip6_packet*) malloc(sizeof(struct ip6_packet));
				i6_packet->type = (char*) malloc((sizeof(char) * 15));
				i6_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));
				i6_packet->ip6 = (struct ip6_hdr*) malloc((sizeof(struct ip6_hdr)));

				memcpy((i6_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy((i6_packet->ip6), ip6, sizeof(struct ip6_hdr));
				memcpy(i6_packet->type, "Unknown (IPv6)", sizeof(char) * (strlen("Unknown (IPv6)") + 1));
				g_packet->ip6_pack = i6_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = IP6_ID;
			}
			break;
	}
	ipv6Counter++;
	if (!wasProcessed)
	{
		print_packet_line(s_packet, packet_counter);
		add_to_sniffer_array(s_packet);
	}
}

/* Processes an Ethernet packet
* const u_char *packet: packet to be processed
*/
void process_ethernet(const u_char *packet)
{
	struct sniffer_packet *s_packet;
	union generic_packet *g_packet;
	struct ethernet_packet *e_packet;
	const struct ethernet *ethernet;
	int wasProcessed = 0;
	/* Checking ethernet type
	 * Caso precisar de mais casos, consultar:
	 * ethertype.h
	 * http://en.wikipedia.org/wiki/EtherType
	 */

	s_packet = (struct sniffer_packet*) malloc(sizeof(struct sniffer_packet));
	g_packet = (union generic_packet*) malloc(sizeof(union generic_packet));

	ethernet = (struct ethernet*)(packet);

	switch(ntohs (ethernet->ether_type))
	{
		case ETHERTYPE_IP:
			{
				process_IP(packet);
				wasProcessed = 1;
			}
			break;
		case ETHERTYPE_ARP:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "ARP", sizeof(char) * (strlen("ARP") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
		case ETHERTYPE_REVARP:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "Reverse ARP", sizeof(char) * (strlen("Reverse ARP") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
		case ETHERTYPE_IPV6:
			{
				process_IPv6(packet);
				wasProcessed = 1;
			}
			break;
		case ETHERTYPE_VLAN:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "802.1q", sizeof(char) * (strlen("802.1q") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
		case 34915:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "PPoE Discovery", sizeof(char) * (strlen("PPoE Discovery") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
		case 34916:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "PPoE Session", sizeof(char) * (strlen("PPoE Session") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
		default:
			{
				e_packet = (struct ethernet_packet*) malloc(sizeof(struct ethernet_packet));
				e_packet->type = (char*) malloc((sizeof(char) * 15));
				e_packet->ethernet = (struct ethernet*) malloc((sizeof(struct ethernet)));

				memcpy((e_packet->ethernet), ethernet, sizeof(struct ethernet));
				memcpy(e_packet->type, "Unknown", sizeof(char) * (strlen("Unknown") + 1));
				g_packet->eth_pack = e_packet;
				s_packet->gen_pack = g_packet;
				s_packet->type = ETHERNET_ID;
			}
			break;
	}
	if (!wasProcessed)
	{
		print_packet_line(s_packet, packet_counter);
		add_to_sniffer_array(s_packet);
	}
}

/* Processes the receivement of a packet */
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	if (is_capture_disabled == 0)
	{
		process_ethernet(packet);
		packet_counter++;
	}
}

/* Watches the keyboard for the input of the 'q' character
 * void *data: parameter sent from pthread_init
*/
void* watching_keyboard(void *data)
{
	char c;
	do
	{
		scanf("%c", &c);
	} while ((c != 'q') && (c != 'Q'));

	is_capture_disabled = 1;
	sleep(1);
	pcap_breakloop(handle);

	return 0;
}

int main(int argc, char *argv[])
{
	pthread_t keyboard_thread;
	struct bpf_program fp;				/* O filtro compilado. */
	char filter_exp[1024];				/* A expressão do filtro. */
	char errbuf[PCAP_ERRBUF_SIZE];		/* Armazenará uma mensagem de erro em caso de falha do pcap_lookupdev(). */
	bpf_u_int32 maskAddress;			/* A máscara de rede do dispositivo. */
	bpf_u_int32 netAddress;				/* O IP do dispositivo. */
	int menu_option = -1;
	pcap_if_t *devices;
	pcap_if_t *d;

	do
	{
		printf("\n");
		printf("Welcome to the Packet Sniffer 1.0!\n");
		printf("What do you want to do?\n");
		printf("1 - Set the device (Current: %s)\n", param_device);
		printf("2 - Set the filter (Current: %s)\n", param_filter);
		printf("3 - Set the number of packets to be captured (Current: %i)\n", param_packets);
		printf("4 - Start capture\n");
		printf("0 - Quit\n");

		char c = -1;
		do
		{
			c = getchar();
		} while ((c != '1') && (c != '2') && (c != '3') && (c != '4') && (c != '0'));

		printf("\n");

		menu_option = atoi(&c);

		switch (menu_option)
		{
			case 1:
			{
				if (pcap_findalldevs(&devices, errbuf) == -1)
				{
					printf("Couldn't get the device list. The program will be finished.");
					exit(1);
				}
				else
				{
					char c = -1;
					int i = 0;
					char **devicenames;

					devicenames = (char**) malloc(100);

					printf("Type the new device.\n");
					for(d = devices; d; (d=d->next))
					{
						devicenames[i] = (d->name);
						printf("%d) %s\n", ++i, d->name);
					}

					do
					{
						c = getchar();
					} while ((c != '1') && (c != '2') && (c != '3') && (c != '4') && (c != '5'));

					param_device = (char *) devicenames[atoi(&c) - 1];
					free (devicenames);
				}
			}
			break;

			case 2:
			{
				printf("Type the new filter (Or type '0' for a blank filter).\n");
				rewind(stdin);
				fgets(param_filter, 25, stdin);
			}
			break;

			case 3:
			{
				int i = 0;
				printf("Type the number of packets to be captured (-1 for infinite)");
				scanf ("%d",&i);
				if (i < -1)
					param_packets = -1;
				else
					param_packets = i;
			}
			default:
			{}
			break;
		}
	} while ((menu_option != 4) && (menu_option != 0));

	if (menu_option == 4)
	{
		/* Verifying for the device */
		if (pcap_lookupnet(param_device, &netAddress, &maskAddress, errbuf) == -1)
		{
			fprintf(stderr, "Can't get netmask for device %s\n", param_device);
			netAddress = 0;
			maskAddress = 0;
		}

		struct ip_addr *net = (struct ip_addr*)&netAddress;
		struct ip_addr *mask = (struct ip_addr*)&maskAddress;
		printf(" ");
		printf("\n-------\n");
		printf("Device: %s\n", param_device);
		printf("Network address: %d.%d.%d.%d\n", net->firstInterval, net->secondInterval, net->thirdInterval, net->fourthInterval);
		printf("Netmask: %d.%d.%d.%d\n", mask->firstInterval, mask->secondInterval, mask->thirdInterval, mask->fourthInterval);
		printf("-------\n");

		/* Opening the device */

		/* dev = O dispositivo a ser escaneado.
		 * BUSFIZ = Número máximo de bytes a ser capturado pelo pcap.
		 * 1 = 1 para "promiscuous mode", 0 para "non-promiscuous mode".
		 * 1000 = Tempo de timeout em milissegundos.
		 * errbuf = Armazenará uma mensagem de erro em caso de falha do pcap_open_live().
		 */
		handle = pcap_open_live(param_device, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL)
		{
			fprintf(stderr, "Couldn't open device %s: %s\n", param_device, errbuf);
			return(2);
		}

		/* Building the filter */
		if (param_filter != NULL)
			strcat(filter_exp, param_filter);

		if (pcap_compile(handle, &fp, filter_exp, 0, netAddress) == -1)
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		/* Setting the filter */
		if (pcap_setfilter(handle, &fp) == -1)
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
			return(2);
		}

		pthread_create(&keyboard_thread, NULL, watching_keyboard, NULL);

		print_header();

		/* Capturing the packets */
		pcap_loop(handle, param_packets, got_packet, NULL);

		print_summary();

		menu_option = -1;

		do
		{
			printf("\n");
			printf("What do you want to do now?\n");
			printf("1 - Print the IPv4 / IPv6 packets' status.\n");
			printf("2 - Print the IPv6 packets' status.\n");
			printf("3 - Print the ICMPv6 packets' status.\n");
			printf("0 - Quit\n");

			char c = -1;
			do
			{
				c = getchar();
			} while ((c != '1') && (c != '2') && (c != '3') && (c != '0'));

			menu_option = atoi(&c);

			switch (menu_option)
			{
				case 1:
				{
					print_ipv4_ipv6_graph(packets);
				}
				break;
				case 2:
				{
					print_ipv6_graph(packets);
				}
				break;
				case 3:
				{
					print_icmp6_graph(packets);
				}
				break;
				default:
				{}
				break;
			}

		} while (menu_option != 0);
	}
	return(0);
}
