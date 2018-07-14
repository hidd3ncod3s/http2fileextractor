#pragma once

#ifdef __cplusplus
extern "C" {
#endif
#include <http2fileextractor.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <http2ng.h>
#include <sys/stat.h>
#include <unistd.h>
#include <wordexp.h>
#include <zlib.h>
#ifdef __cplusplus
}
#endif


#ifdef __cplusplus
#include <iostream>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <list>
#include <fstream>

using namespace std;
#endif

typedef struct{
	union{
		struct{
			uint8_t len[3];
			uint8_t type;
		}__attribute__((packed));
		uint32_t len_type;
	};
	uint8_t flags;
	union{
		struct{
			#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
				uint32_t stream_id:31;
				uint32_t res:1;
			#else
				uint32_t res:1;
				uint32_t stream_id:31;
			#endif
			
		}__attribute__((packed));
		uint32_t res_stream_id;
	};
}__attribute__((packed)) http2_frame_header;


#ifdef __cplusplus
extern "C" {
#endif

typedef enum _pktdir
{
	HTTP2PKT_DIR_UNKNOWN,
	HTTP2PKT_DIR_REQ,
	HTTP2PKT_DIR_RSP
}pktdir;

typedef enum _HTTP2_FRAME_PROC_STATUS
{
	HTTP2_FRAME_PROC_STATUS_START= 0,
	HTTP2_FRAME_PROC_STATUS_FRAG,
	HTTP2_FRAME_PROC_STATUS_SKIP_WO_WRITE,
	HTTP2_FRAME_PROC_STATUS_SKIP_W_WRITE,
}HTTP2_FRAME_PROC_STATUS;

typedef enum _HTTP2_FLOW_STATUS
{
	HTTP2_FLOW_STATUS_UNKNOWN,
	HTTP2_FLOW_STATUS_SEEN_HTTP2_MAGIC,
	HTTP2_FLOW_STATUS_SEEN_HTTP2_REQ_SETTING,
	HTTP2_FLOW_STATUS_HTTP2_FULLFLOW_SETUP,
}HTTP2_FLOW_STATUS;

typedef enum _streamstatus
{
	HTTP2_STREAM_STATUS_UNKNOWN,
	HTTP2_STREAM_STATUS_SEEN_REQ,
	HTTP2_STREAM_STATUS_REQ_FAIL,
	HTTP2_STREAM_STATUS_REQ_SUCCESS,
	HTTP2_STREAM_STATUS_REQ_MIDDLE_OF_STREAM,
	HTTP2_STREAM_STATUS_REQ_ENDOFSTREAM,
}streamstatus;

int tcpdatahandler(const uint8_t *iphdr, const uint64_t iphdrlen, const uint8_t *tcphdr, const uint64_t tcphdrlen, const uint8_t *data, const uint64_t datalen);
void dumpframehdr(http2_frame_header *frhdr);
const char * getpktdirstr(pktdir curpktdir);
const char * getframeprocstatusstr(HTTP2_FRAME_PROC_STATUS procStatus);
uint32_t getlength(http2_frame_header *frhdr);
const char * getframetypestr(uint8_t ftype);
const char * getflowstatusstr(HTTP2_FLOW_STATUS flowstatus);
const char * getstreamstatusstr(streamstatus streamStatus);

#ifdef __cplusplus
}
#endif

#ifdef __cplusplus


typedef class strminfo
{
	std::string method;
	std::string url;
	std::string host;
	std::string scheme;
	pktdir    filemovementdir;
	streamstatus    streamStatus;
	std::ofstream ofs;
	bool needCompression;
public:
	strminfo():filemovementdir(HTTP2PKT_DIR_UNKNOWN), streamStatus(HTTP2_STREAM_STATUS_UNKNOWN), needCompression(false){}
	
	void reset()
	{
		method= "";
		url= "";
		host= "";
		scheme= "";
		filemovementdir= HTTP2PKT_DIR_UNKNOWN;
		streamStatus= HTTP2_STREAM_STATUS_UNKNOWN;
		needCompression= false;
	}
	
	void handlethisdata(std::string fulldp, const uint8_t *data, uint32_t data_len, bool endofstream);
	void openthedatafile(std::string fulldp);
	void appendthisdata(const uint8_t *data, uint32_t data_len);
	void closethedatafile();
	
	void seturl(uint8_t *burl, uint32_t url_len);
	void setmethod(uint8_t *bmethod, uint32_t method_len);
	void sethost(uint8_t *bhost, uint32_t host_len);
	void setscheme(uint8_t *bscheme, uint32_t scheme_len);
	
	std::string &getmethod() {return method;}
	std::string &geturl() {return url;}
	std::string &gethost() {return host;}
	std::string &getscheme() {return scheme;}
	
	void setReqSucess(){streamStatus= HTTP2_STREAM_STATUS_REQ_SUCCESS;}
	void setReqFail(){streamStatus= HTTP2_STREAM_STATUS_REQ_FAIL;}
	void setNeedMoreDataFrames(){streamStatus= HTTP2_STREAM_STATUS_REQ_MIDDLE_OF_STREAM;}
	void setEndofDataFrames(){streamStatus= HTTP2_STREAM_STATUS_REQ_ENDOFSTREAM;}
	
	void needDecompression() {needCompression= true; }
	bool doDecompress() {return needCompression; }
	
	bool isReqSuccess() { return (streamStatus >= HTTP2_STREAM_STATUS_REQ_SUCCESS);}
	
	#define CHUNK 16384
	bool Uncompress(const uint8_t *data, uint32_t data_len, std::string&);
}strminfo;



typedef class h2FrameProcStatus
{
public:
	HTTP2_FRAME_PROC_STATUS curFrameStatus;
	// uint8_t  frame_type;
	// uint32_t stream_id;
	uint32_t byteCount;
	std::vector<uint8_t> framebuf;
	
	h2FrameProcStatus(): curFrameStatus(HTTP2_FRAME_PROC_STATUS_START), 
						 // frame_type(NGHTTP2_UNKNOWN),
						 byteCount(0)
						 // stream_id(0xdeadbaba)
	{}
	
	void reset()
	{
		curFrameStatus= HTTP2_FRAME_PROC_STATUS_START; 
		// frame_type= NGHTTP2_UNKNOWN;
		byteCount= 0;
		// stream_id= 0xdeadbaba;
		
		framebuf.clear();
	}
	
	bool startcopy(const uint8_t *data, uint32_t datalen);
	bool appenddata(const uint8_t *data, uint32_t datalen);
	
	uint32_t getbytecountneeded();
	
}h2FrameProcStatus;


typedef class flow
{
private:
	flow() = delete;
	nghttp2_hd_inflater hd_inflater;
	HTTP2_FLOW_STATUS h2flowprocstatus;
	nghttp2_hd_inflater *inflater;
	map <uint32_t, strminfo*> streamtable;
	std::string authority;
public:
	vector <h2FrameProcStatus> curh2procStatus;
	uint32_t ip_src;
	uint32_t ip_dst;
	u_short th_sport;
	u_short th_dport;
	uint8_t protocol;
	pktdir dir;
	bool   skip;
	
	flow(uint32_t ip_src, u_short th_sport, uint32_t ip_dst, u_short th_dport, uint8_t protocol, pktdir dir): 
		ip_src(ip_src),
		th_sport(th_sport),
		ip_dst(ip_dst),
		th_dport(th_dport),
		protocol(protocol),
		dir(dir), skip(false), h2flowprocstatus(HTTP2_FLOW_STATUS_UNKNOWN)
	{
		curh2procStatus.reserve(HTTP2PKT_DIR_RSP + 1);
		
		for (uint8_t i = 0; i <= HTTP2PKT_DIR_RSP; ++i) {
			curh2procStatus.push_back(h2FrameProcStatus());
		}
		
		inflater= NULL;
		
		int rv = nghttp2_hd_inflate_new(&inflater);
		 if (rv != 0) {
			fprintf(stderr, "nghttp2_hd_inflate_init failed with error: %s\n", nghttp2_strerror(rv));
			exit(-1);
		}
	}
	
	bool skipme() {return skip;}
	void startskippingme()
	{
		cout << "[FLOW] Skip flow from here." << endl;
		skip= true;
	}
	
	void packetdataprocess(const uint8_t *data, const uint32_t datalen, pktdir curpktdir);
	void processh2data(const uint8_t *data, uint32_t datalen, pktdir curpktdir);
	void processthisfullframe(const uint8_t *data, uint32_t datalen, pktdir curpktdir);
	
	int inflate_header_block(uint8_t type, uint32_t stream_id, uint8_t *in, size_t inlen, int final, pktdir curpktdir);
	
	bool streaminfoexists(uint32_t stream_id, pktdir curpktdir);
	bool initializestreaminfo(uint32_t stream_id, pktdir curpktdir);
	
	void setauthority(uint8_t *bauthority, uint32_t authority_len);
	
	std::string getfullurl(uint32_t stream_id);
	std::string getdirpath(uint32_t stream_id);
	
	void dumpprocStatus(pktdir curpktdir);
}flow;

typedef class flowtable
{
	vector<flow> flowtablevec;
public:
	int32_t CreateFlowRecord(uint32_t ip_src, u_short th_sport, uint32_t ip_dst, u_short th_dport, uint8_t protocol, pktdir dir);
	int32_t getFlowRecord(uint32_t ip_src, u_short th_sport, uint32_t ip_dst, u_short th_dport, uint8_t protocol, pktdir &dir);
	bool skipprocessing(int32_t flowidx);
	void packetdataprocess(int32_t flowidx, const uint8_t *data, const uint32_t datalen, pktdir curpktdir);
}flowtable;
#endif