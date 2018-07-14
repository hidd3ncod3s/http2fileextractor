#include <http2fileextractor.h>
#include <pcapparser.h>
#include <http2parser.h>

char *filename= "capture_file.pcap";

void usage(char *exe)
{
	printf("Usage: \n\t%s <pcap filepath> <pcap filter>\n \
	pcap filepath - %s\n\n", exe, filename);
}

int main(int argc, char **argv)
{
	char error_buffer[PCAP_ERRBUF_SIZE];
	
	pcap_t *handle= NULL;
	/* Snapshot length is how many bytes to capture from each packet. This includes*/
	/* End the loop after this many packets are captured */
	int total_packet_count = 200;
	// u_char *my_arguments = (u_char *);
	data_handlers funch= {.tcphandler= &tcpdatahandler};
	struct bpf_program fp;      /* hold compiled program     */
	bpf_u_int32 netp;           /* ip                        */
	
	if (argc == 1){
		usage(argv[0]);
	}
	
	if (argc > 1){
		printf("Using this pcap file %s\n", argv[1]);
		filename= argv[1];
	} else {
		printf("Using this pcap file %s\n", filename);
	}

	handle = pcap_open_offline(filename, error_buffer);
	if (NULL == handle){
		printf("Error in opening the file. %s\n", error_buffer);
		exit(-1);
	}
	
	if (argc > 2){
		if(pcap_compile(handle,&fp,argv[2],0,netp) == -1){
			fprintf(stderr,"Error calling pcap_compile\n");
			exit(-1);
		}
		
		if(pcap_setfilter(handle,&fp) == -1){
			fprintf(stderr,"Error setting filter\n");
			exit(1);
		}
	}

	pcap_loop(handle, 0, my_packet_handler, (u_char*)&funch);

	return 0;
}