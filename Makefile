all : pcap_test

pcap_test : main.c
	g++ -o pcap_test main.c -lpcap

clean : 
	rm pcap_test
