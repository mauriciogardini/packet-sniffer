all:
	gcc -Wall packet_sniffer.c -o packet_sniffer -lpcap -lpthread