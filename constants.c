#define SIZE_ETHERNET 	14 					/* Ethernet headers are 14 bytes */
#define ETHER_ADDR_LEN 	6					/* Ethernet addresses are 6 bytes */

#define ETHERNET_ID 0
#define IP_ID 1
#define TCP_ID 2
#define UDP_ID 3
#define ICMP_ID 4
#define IP6_ID 5
#define TCP6_ID 6
#define UDP6_ID 7
#define ICMP6_ID 8

/* Missing constants */
#define IPPROTO_OSPF					89
#define ICMP_DNS						37		/* Domain name request */
#define ICMP_DNSREPLY 					38		/* Domain name reply */
#define IND_SOLICIT						141		/* inverse neighbor solicitation */
#define IND_ADVERT						142		/* inverse neighbor advertisement */
#define MLDV2_LISTENER_REPORT			143		/* v2 multicast listener report */
#define ICMP6_MOBILEPREFIX_SOLICIT		146
#define ICMP6_MOBILEPREFIX_ADVERT		147
#define ND_RPL_MESSAGE				 	0x9B

/* Message-related constants */
/* ICMPv4 */
#define MSG_IDENTATION_1 "   "
#define MSG_ICMP_ECHOREPLY 						"Echo reply"
#define MSG_ICMP_UNREACH_NET 					"Destination network unreachable"
#define MSG_ICMP_UNREACH_HOST 					"Destination host unreachable"
#define MSG_ICMP_UNREACH_PROTOCOL 				"Destination protocol unreachable"
#define MSG_ICMP_UNREACH_PORT 					"Destination port unreachable"
#define MSG_ICMP_UNREACH_NEEDFRAG 				"Fragmentation required - DF flag set"
#define MSG_ICMP_UNREACH_SRCFAIL 				"Source route failed"
#define MSG_ICMP_UNREACH_NET_UNKNOWN 			"Destination network unknown"
#define MSG_ICMP_UNREACH_HOST_UNKNOWN 			"Destination host unknown"
#define MSG_ICMP_UNREACH_ISOLATED 				"Source host isolated"
#define MSG_ICMP_UNREACH_NET_PROHIB 			"Network administratively prohibited"
#define MSG_ICMP_UNREACH_HOST_PROHIB 			"Host administratively prohibited"
#define MSG_ICMP_UNREACH_TOSNET 				"Network unreachable for TOS"
#define MSG_ICMP_UNREACH_TOSHOST 				"Host unreachable for TOS"
#define MSG_ICMP_UNREACH_FILTER_PROHIB 			"Communic. administratively prohibited"
#define MSG_ICMP_UNREACH_HOST_PRECEDENCE 		"Host precedence violated."
#define MSG_ICMP_UNREACH_PRECEDENCE_CUTOFF 		"Precedence cuttoff"
#define MSG_ICMP_UNREACH_SUBTYPE_UNKNOWN 		"Subtype unknown"
#define MSG_ICMP_SOURCEQUENCH 					"Source Quench"
#define MSG_ICMP_REDIRECT_NET 					"Redirect Datagram for Network"
#define MSG_ICMP_REDIRECT_HOST 					"Redirect Datagram for Host"
#define MSG_ICMP_REDIRECT_TOSNET 				"Redirect Datagram for TOS & network"
#define MSG_ICMP_REDIRECT_TOSHOST 				"Redirect Datagram for TOS & host"
#define MSG_ICMP_REDIRECT_SUBTYPE_UNKNOWN 		"Redirect - Subtype unknown"
#define MSG_ICMP_ECHO 							"Echo request"
#define MSG_ICMP_ROUTERADVERT 					"Router Advertisement"
#define MSG_ICMP_ROUTERSOLICIT 					"Router discovery/solicitation"
#define MSG_ICMP_TIMXCEED_INTRANS 				"TTL expired in transit"
#define MSG_ICMP_TIMXCEED_REASS 				"Fragment reassembly time exceeded"
#define MSG_ICMP_TIMXCEED_SUBTYPE_UNKNOWN 		"Time Exceeded - Subtype unknown"
#define MSG_ICMP_PARAMPROB_ERRATPTR 			"Pointer indicates the error"
#define MSG_ICMP_PARAMPROB_OPTABSENT 			"Missing a required option"
#define MSG_ICMP_PARAMPROB_LENGTH 				"Bad length"
#define MSG_ICMP_PARAMPROB_SUBTYPE_UNKNOWN 		"Subtype unknown"
#define MSG_ICMP_TSTAMP 						"Timestamp"
#define MSG_ICMP_TSTAMPREPLY 					"Timestamp Reply"
#define MSG_ICMP_IREQ 							"Information Request"
#define MSG_ICMP_IREQREPLY 						"Information Reply"
#define MSG_ICMP_MASKREQ 						"Address Mask Request"
#define MSG_ICMP_MASKREPLY 						"Address Mask Reply"
#define MSG_ICMP_TRACEROUTE 					"Traceroute"
#define MSG_ICMP_DATACONVERR 					"Datagram Conversion Error"
#define MSG_ICMP_MOBILE_REDIRECT 				"Mobile Host Redirect"
#define MSG_ICMP_IPV6_WHEREAREYOU 				"Where-Are-You"
#define MSG_ICMP_IPV6_IAMHERE 					"I-Am-Here"
#define MSG_ICMP_MOBILE_REGREQUEST 				"Mobile Registration Request"
#define MSG_ICMP_MOBILE_REGREPLY 				"Mobile Registration Reply"
#define MSG_ICMP_DNS 							"Domain Name Request"
#define MSG_ICMP_DNSREPLY 						"Domain Name Reply"
#define MSG_ICMP_SKIP 							"SKIP Algorithm Discovery Protocol"
#define MSG_ICMP_PHOTURIS_UNKNOWN_INDEX 		"Photuris - Unknown sec. param. index"
#define MSG_ICMP_PHOTURIS_AUTH_FAILED 			"Photuris - Authentication failed"
#define MSG_ICMP_PHOTURIS_DECRYPT_FAILED 		"Photuris - Decryptation failed"
#define MSG_ICMP_PHOTURIS_SUBTYPE_UNKNOWN		"Photuris - Subtype unknown"
#define MSG_ICMP_TYPE_UNKNOWN 					"Unknown type"

/* ICMPv6 */
#define MSG_ICMP6_DST_UNREACH 					"Destination Unreachable"
#define MSG_ICMP6_DST_UNREACH_NOROUTE 			"Unreachable Route" 
#define MSG_ICMP6_DST_UNREACH_ADMIN 			"Unreachable Prohibited"
#define MSG_ICMP6_DST_UNREACH_BEYONDSCOPE 		"Beyond Scope"
#define MSG_ICMP6_DST_UNREACH_ADDR 				"Unreachable Address"
#define MSG_ICMP6_DST_UNREACH_NOPORT 			"Unreachable Port"
#define MSG_ICMP6_PACKET_TOO_BIG 				"Packet Too Big"
#define MSG_ICMP6_TIME_EXCEEDED 				"Time Exceeded In-Transit"
#define MSG_ICMP6_PARAM_PROB 					"Parameter Problem"
#define MSG_ICMP6_ECHO_REQUEST  				"Echo Request"
#define MSG_ICMP6_ECHO_REPLY 					"Echo Reply"
#define MSG_MLD6_LISTENER_QUERY 				"Multicast Listener Query"
#define MSG_MLD6_LISTENER_REPORT 				"Multicast Listener Report"
#define MSG_MLD6_LISTENER_DONE 					"Multicast lListener Done"
#define MSG_ND_ROUTER_SOLICIT 					"Router Solicitation"
#define MSG_ND_ROUTER_ADVERT 					"Router Advertisement"
#define MSG_ND_NEIGHBOR_SOLICIT 				"Neighbor Solicitation"
#define MSG_ND_NEIGHBOR_ADVERT 					"Neighbor Advertisement"
#define MSG_ND_REDIRECT 						"Redirect"
#define MSG_ICMP6_ROUTER_RENUMBERING 			"Router Renumbering"
#define MSG_IND_SOLICIT 						"Inverse Neighbor Solicitation"
#define MSG_IND_ADVERT 							"Inverse Neighbor Advertisement"
#define MSG_MLDV2_LISTENER_REPORT 				"Multicast Listener Report V2"
#define MSG_ICMP6_HADISCOV_REQUEST 				"Ha Discovery Request"
#define MSG_ICMP6_HADISCOV_REPLY 				"Ha Discovery Reply"
#define MSG_ICMP6_MOBILEPREFIX_SOLICIT 			"Mobile Router Solicitation"
#define MSG_ICMP6_MOBILEPREFIX_ADVERT 			"Mobile Router Advertisement"
#define MSG_ICMP6_WRUREQUEST 					"Who-Are-You request"
#define MSG_ICMP6_WRUREPLY 						"Who-Are-You Reply"
#define MSG_ICMP6_NI_QUERY 						"Node Information Query"
#define MSG_ICMP6_NI_REPLY 						"Node Information Reply"
#define MSG_MLD6_MTRACE 						"Mtrace Message"
#define MSG_MLD6_MTRACE_RESP 					"Mtrace Response"
#define MSG_ND_RPL_MESSAGE 						"RPL"

#define IPV6_UNCHARACTERIZED_TRAFFIC 	0
#define IPV6_FILLER_TRAFFIC				1
#define IPV6_UNATTENDED_DATA_TRANSFER	2
#define IPV6_RESERVED_1 				3
#define IPV6_ATTENDED_BULK_TRANSFER 	4
#define IPV6_RESERVED_2 				5
#define IPV6_INTERACTIVE_TRAFFIC		6
#define IPV6_CONTROL_TRAFFIC			7

#define MSG_IPV6_UNCHARACTERIZED_TRAFFIC 	"Uncharacterized Traffic"
#define MSG_IPV6_FILLER_TRAFFIC				"Filler Traffic"
#define MSG_IPV6_UNATTENDED_DATA_TRANSFER	"Unattended Data Transfer"
#define MSG_IPV6_RESERVED_1 				"Reserved"
#define MSG_IPV6_ATTENDED_BULK_TRANSFER 	"Attended Bulk Transfer"
#define MSG_IPV6_RESERVED_2 				"Reserved"
#define MSG_IPV6_INTERACTIVE_TRAFFIC		"Interactive Traffic"
#define MSG_IPV6_CONTROL_TRAFFIC			"Internet Control Traffic"
#define MSG_IPV6_UNKNOWN					"Unknown"