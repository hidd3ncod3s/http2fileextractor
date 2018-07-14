#pragma once

#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>

typedef int (*handler)(const uint8_t *l3hdr, const uint64_t l3hdrlen, const uint8_t *l4hdr, const uint64_t l4hdrlen, const uint8_t *data, const uint64_t datalen);

typedef struct pcap_data_handlers_s
{
	handler tcphandler;
	handler udphandler;
}data_handlers;

