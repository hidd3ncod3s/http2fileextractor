#include <pcapparser.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

// #define PKTPARSERDEBUG

#if defined(PKTPARSERDEBUG) || defined(DEBUG)
uint64_t pktcount= 1;
#endif

/* Finds the payload of a TCP/IP packet */
void my_packet_handlerv1(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	#if defined(PKTPARSERDEBUG) || defined(DEBUG)
	printf("[PKT] pktcount= %ld\n", pktcount);
	pktcount+= 1;
	#endif
	
	/* First, lets make sure we have an IP packet */
	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		#ifdef PKTPARSERDEBUG
		printf("Not an IP packet. Skipping...\n\n");
		#endif
		return;
	}

	/* The total packet length, including all headers
	and the data payload is stored in
	header->len and header->caplen. Caplen is
	the amount actually available, and len is the
	total packet length even if it is larger
	than what we currently have captured. If the snapshot
	length set with pcap_open_live() is too small, you may
	not have the whole packet. */
	#ifdef PKTPARSERDEBUG
	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);
	#endif

	/* Pointers to start point of various headers */
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	/* Header lengths in bytes */
	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length;
	int tcp_header_length;
	int payload_length;

	/* Find start of IP header */
	ip_header = packet + ethernet_header_length;
	/* The second-half of the first byte in ip_header
	contains the IP header length (IHL). */
	ip_header_length = ((*ip_header) & 0x0F);
	/* The IHL is number of 32-bit segments. Multiply
	by four to get a byte count for pointer arithmetic */
	ip_header_length = ip_header_length * 4;
	#ifdef PKTPARSERDEBUG
	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
	#endif

	/* Now that we know where the IP header is, we can 
	inspect the IP header for a protocol number to 
	make sure it is TCP before going any further. 
	Protocol is always the 10th byte of the IP header */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) {
		#ifdef PKTPARSERDEBUG
		printf("Not a TCP packet. Skipping...\n\n");
		#endif
		return;
	}

	/* Add the ethernet and ip header length to the start of the packet
	to find the beginning of the TCP header */
	tcp_header = packet + ethernet_header_length + ip_header_length;
	/* TCP header length is stored in the first half 
	of the 12th byte in the TCP header. Because we only want
	the value of the top half of the byte, we have to shift it
	down to the bottom half otherwise it is using the most 
	significant bits instead of the least significant bits */
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	/* The TCP header length stored in those 4 bits represents
	how many 32-bit words there are in the header, just like
	the IP header length. We multiply by four again to get a
	byte count. */
	tcp_header_length = tcp_header_length * 4;
	#ifdef PKTPARSERDEBUG
	printf("TCP header length in bytes: %d\n", tcp_header_length);
	#endif

	/* Add up all the header sizes to find the payload offset */
	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	#ifdef PKTPARSERDEBUG
	printf("Size of all headers combined: %d bytes\n", total_headers_size);
	#endif
	payload_length = header->caplen -
	(ethernet_header_length + ip_header_length + tcp_header_length);
	#ifdef PKTPARSERDEBUG
	printf("Payload size: %d bytes\n", payload_length);
	#endif
	payload = packet + total_headers_size;
	#ifdef PKTPARSERDEBUG
	printf("Memory address where payload begins: %p\n\n", payload);
	#endif

	/* Print payload in ASCII */
	 
	#ifdef PKTPARSERDEBUG
	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		while (byte_count++ < payload_length) {
			printf("%x", *temp_pointer);
			temp_pointer++;
		}
		printf("\n");
	}
	#endif
	
	// if (payload_length >0 && NULL != args){
	if (NULL != args){
		data_handlers *datahan= (data_handlers*)args;
		#ifdef PKTPARSERDEBUG
		printf("Calling handler with : %p(%d)\n\n", payload, payload_length);
		#endif
		(datahan->tcphandler)( (const uint8_t *)ip_header , (const uint64_t)ip_header_length,
							   (const uint8_t *)tcp_header, (const uint64_t)tcp_header_length,
							   (const uint8_t *)payload   , (const uint64_t)payload_length);
	}
	
	return;
}

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	#if defined(PKTPARSERDEBUG) || defined(DEBUG)
	printf("[PKT] pktcount= %ld\n", pktcount);
	pktcount+= 1;
	#endif
	
	/* First, lets make sure we have an IP packet */
	struct ether_header *eth_header;
	eth_header = (struct ether_header *) packet;
	if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
		#ifdef PKTPARSERDEBUG
		printf("Not an IP packet. Skipping...\n\n");
		#endif
		return;
	}

	/* The total packet length, including all headers
	and the data payload is stored in
	header->len and header->caplen. Caplen is
	the amount actually available, and len is the
	total packet length even if it is larger
	than what we currently have captured. If the snapshot
	length set with pcap_open_live() is too small, you may
	not have the whole packet. */
	#ifdef PKTPARSERDEBUG
	printf("Total packet available: %d bytes\n", header->caplen);
	printf("Expected packet size: %d bytes\n", header->len);
	#endif

	/* Pointers to start point of various headers */
	const u_char *ip_header;
	const u_char *tcp_header;
	const u_char *payload;

	/* Header lengths in bytes */
	int ethernet_header_length = 14; /* Doesn't change */
	int ip_header_length= 0;
	uint32_t ip_total_length= 0;
	int tcp_header_length= 0;
	int payload_length= 0;

	/* Find start of IP header */
	ip_header = packet + ethernet_header_length;
	/* The second-half of the first byte in ip_header
	contains the IP header length (IHL). */
	ip_header_length = ((*ip_header) & 0x0F);
	ip_total_length = ntohs(*(uint16_t*)(ip_header+2));
	/* The IHL is number of 32-bit segments. Multiply
	by four to get a byte count for pointer arithmetic */
	ip_header_length = ip_header_length * 4;
	#ifdef PKTPARSERDEBUG
	printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
	#endif

	/* Now that we know where the IP header is, we can 
	inspect the IP header for a protocol number to 
	make sure it is TCP before going any further. 
	Protocol is always the 10th byte of the IP header */
	u_char protocol = *(ip_header + 9);
	if (protocol != IPPROTO_TCP) {
		#ifdef PKTPARSERDEBUG
		printf("Not a TCP packet. Skipping...\n\n");
		#endif
		return;
	}

	/* Add the ethernet and ip header length to the start of the packet
	to find the beginning of the TCP header */
	tcp_header = packet + ethernet_header_length + ip_header_length;
	/* TCP header length is stored in the first half 
	of the 12th byte in the TCP header. Because we only want
	the value of the top half of the byte, we have to shift it
	down to the bottom half otherwise it is using the most 
	significant bits instead of the least significant bits */
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	/* The TCP header length stored in those 4 bits represents
	how many 32-bit words there are in the header, just like
	the IP header length. We multiply by four again to get a
	byte count. */
	tcp_header_length = tcp_header_length * 4;
	#ifdef PKTPARSERDEBUG
	printf("TCP header length in bytes: %d\n", tcp_header_length);
	#endif

	/* Add up all the header sizes to find the payload offset */
	int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	#ifdef PKTPARSERDEBUG
	printf("Size of all headers combined: %d bytes\n", total_headers_size);
	printf("ip_total_length: %d bytes\n", (ip_total_length));
	printf("Total size as per IP: %d bytes\n", (ip_total_length + ethernet_header_length));
	#endif
	
	if (header->caplen < (ip_total_length + ethernet_header_length)){
		printf("[PKT - ERR] Seen truncated packet.\n");
		payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
	} else {
		payload_length = ip_total_length - (ip_header_length + tcp_header_length);
	}
	
	
	#ifdef PKTPARSERDEBUG
	printf("Payload size: %d bytes\n", payload_length);
	#endif
	payload = packet + total_headers_size;
	#ifdef PKTPARSERDEBUG
	printf("Memory address where payload begins: %p\n\n", payload);
	#endif

	/* Print payload in ASCII */
	 
	#ifdef PKTPARSERDEBUG
	if (payload_length > 0) {
		const u_char *temp_pointer = payload;
		int byte_count = 0;
		while (byte_count++ < payload_length) {
			printf("%x", *temp_pointer);
			temp_pointer++;
		}
		printf("\n");
	}
	#endif
	
	// if (payload_length >0 && NULL != args){
	if (NULL != args){
		data_handlers *datahan= (data_handlers*)args;
		#ifdef PKTPARSERDEBUG
		printf("Calling handler with : %p(%d)\n\n", payload, payload_length);
		#endif
		(datahan->tcphandler)( (const uint8_t *)ip_header , (const uint64_t)ip_header_length,
							   (const uint8_t *)tcp_header, (const uint64_t)tcp_header_length,
							   (const uint8_t *)payload   , (const uint64_t)payload_length);
	}
	
	return;
}
