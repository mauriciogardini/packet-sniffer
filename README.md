# Packet Sniffer

Simple packet sniffer implemented in C.

## Compilation

To compile it, run the following command:

`gcc -Wall packet_sniffer.c -o packet_sniffer -lpcap -lpthread`

## Usage

You can run this program (as superuser) with:
`./packet_sniffer`

A menu will be shown.

Option 1 - Select the device to be sniffed (Default: en1);
Option 2 - Configure the capture filter (Default: empty);
Option 3 - Configure the amount of packages to be captured, or -1 to capture infinitely (Default: -1)
Option 4 - Start the package capture

Once in capture mode, press "q" or "Q" to finish the capture. The post capture menu will be shown.

Option 1 - Show a graphical comparison between IPv4 / IPv6 packages
Option 2 - Show a graphical comparison between the IPv6 packages priorities
Option 3 - Show a graphical comparison between the messages of the ICMPv6 packages
Option 4 - Close the program
