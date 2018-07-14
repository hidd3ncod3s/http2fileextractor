#pragma once

#include <http2fileextractor.h>
#include <pcap.h>

/* Finds the payload of a TCP/IP packet */
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);
