#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <libnet.h>
#include <arpa/inet.h>

#define ETHERNET_ADDR_LEN 6

void usage()
{
	printf("syntax : pcap_test <interface>\n");
	printf("sample : pcap_test wlan0\n");
}

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	int i, datalen;
	struct libnet_ethernet_hdr* ethernet;
	struct libnet_ipv4_hdr* ip;
	struct libnet_tcp_hdr* tcp;
	uint8_t* payload;

	while(1)
	{
		struct pcap_pkthdr* header;
		const u_char* packet;
		
		int res = pcap_next_ex(handle, &header, &packet);
		if(res == 0)
			continue;
		if(res == -1 || res == -2)
			break;
		
		// ethernet information
		ethernet = (struct libnet_ethernet_hdr*)packet;
		
		printf("----------------------------------------------\n");
		printf("%u bytes captured\n",header->caplen);
		
		printf("Source MAC addr : %02X", ethernet->ether_shost[0]);
		for(i=1;i<ETHERNET_ADDR_LEN;i++)
			printf(":%02X", ethernet->ether_shost[i]);
		printf("\n");

		printf("Destination MAC addr : %02X", ethernet->ether_dhost[0]);
		for(i=1;i<ETHERNET_ADDR_LEN;i++)
			printf(":%02X", ethernet->ether_dhost[i]);
		printf("\n\n");

		
		if(ntohs(ethernet->ether_type) == ETHERTYPE_IP) // if ip
		{
			// ip information
			ip = (struct libnet_ipv4_hdr*)(sizeof(struct libnet_ethernet_hdr) + packet);
			printf("Source addr : %s\n", inet_ntoa(ip->ip_src));
			printf("Destination addr : %s\n\n", inet_ntoa(ip->ip_dst));

			if(ip->ip_p == 0x06) // if tcp
			{
				// tcp information
				tcp = (struct libnet_tcp_hdr*)(sizeof(struct libnet_ethernet_hdr) + 4 * ip->ip_hl + packet);
				printf("Source port : %d\n", ntohs(tcp->th_sport));
				printf("Destination port : %d\n\n", ntohs(tcp->th_dport));
			}

			datalen = ip->ip_len - 4 * ip->ip_hl - 4 * tcp->th_off;
			if(datalen > 0) // if data exist
			{
				// data information
				payload = (uint8_t*)(sizeof(struct libnet_ethernet_hdr) + 4 * ip->ip_hl + 4 * tcp->th_off + packet);
				printf("Data(first 16 bytes) : \n");
				for(i=0;i<datalen;i++)
				{
					printf("%02X ",payload[i]);
					if(i == 15) // for print only 16 bytes of data
						break; 
				}
				printf("\n----------------------------------------------\n\n");
			}
		}
	}

	pcap_close(handle);
	return 0;
}
