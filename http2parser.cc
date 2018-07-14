#include <http2parser.h>
#include <iostream>
#include "http2ng.h"

flowtable tcpft;
std::string rootoutputdir= "/mnt/hgfs/http2fileextractor/output/";

int32_t flowtable::CreateFlowRecord(uint32_t ip_src, u_short th_sport, uint32_t ip_dst, u_short th_dport, uint8_t protocol, pktdir _dir)
{
	pktdir dir;
	
	int32_t flowidx= flowtable::getFlowRecord(ip_src, th_sport, ip_dst, th_dport, protocol, dir);
	if (flowidx != -1){
		return flowidx;
	}
	// new flow.
	flowtablevec.insert(flowtablevec.end(), flow(ip_src, th_sport, ip_dst, th_dport, IPPROTO_TCP, _dir));
	#ifdef DEBUG
	cout << "Adding new flow.\n";
	#endif
	
	return flowtablevec.size() - 1;
}

int32_t flowtable::getFlowRecord(uint32_t ip_src, u_short th_sport, uint32_t ip_dst, u_short th_dport, uint8_t protocol, pktdir &dir)
{
	for(auto it = flowtablevec.begin(); it != flowtablevec.end(); it++ ){
		if (th_sport == it->th_sport && 
			th_dport == it->th_dport &&
			ip_src == it->ip_src &&
			ip_dst == it->ip_dst){
			dir= HTTP2PKT_DIR_REQ;
			return (it - flowtablevec.begin());
		}
		
		if (th_dport == it->th_sport && 
			th_sport == it->th_dport &&
			ip_dst == it->ip_src &&
			ip_src == it->ip_dst){
			dir= HTTP2PKT_DIR_RSP;
			return (it - flowtablevec.begin());
		}
	}
	
	return -1;
}

bool flowtable::skipprocessing(int32_t flowidx)
{
	if (flowidx >= flowtablevec.size())
		return true;
	
	if(flowtablevec[flowidx].skipme())
		return true;
	
	return false;
}

void flowtable::packetdataprocess(int32_t flowidx, const uint8_t *data, const uint32_t datalen, pktdir curpktdir)
{
	if (flowidx >= flowtablevec.size())
		return;
	
	if(flowtablevec[flowidx].skipme()){
		return;
	}
	
	return flowtablevec[flowidx].packetdataprocess(data, datalen, curpktdir);
}

bool h2FrameProcStatus::startcopy(const uint8_t *data, uint32_t datalen)
{
	framebuf.clear();
	copy(data, data + datalen, back_inserter(framebuf));
	return true;
}

uint32_t h2FrameProcStatus::getbytecountneeded()
{
	return (byteCount - framebuf.size());
}

bool h2FrameProcStatus::appenddata(const uint8_t *data, uint32_t datalen)
{
	copy(data, data + datalen, back_inserter(framebuf));
	return true;
}

void flow::packetdataprocess(const uint8_t *data, uint32_t datalen, pktdir curpktdir)
{
	#ifdef DEBUG
	cout << "Processing data packet :" << (void*)data << " of len " << datalen << " "<< getpktdirstr(curpktdir) <<endl;
	#endif
	
	while(datalen > 0){
		#ifdef DEBUG
		cout << "Current HTTP/2 flow status " << h2flowprocstatus << "("<< getflowstatusstr(h2flowprocstatus) << ")" << std::endl;
		#endif
		
		switch(h2flowprocstatus){
			case HTTP2_FLOW_STATUS_UNKNOWN:
				{
					if (HTTP2PKT_DIR_REQ != curpktdir)
						return;
					
					if (datalen < NGHTTP2_CLIENT_MAGIC_LEN){
						cout << "[ERROR] " << __func__ << " Length of the data("<< datalen<< ") is less than length of the magic - " << NGHTTP2_CLIENT_MAGIC_LEN << endl;
						startskippingme();
						return;
					}
					
					if(0 == memcmp(data, NGHTTP2_CLIENT_MAGIC, NGHTTP2_CLIENT_MAGIC_LEN)){
						h2flowprocstatus= HTTP2_FLOW_STATUS_SEEN_HTTP2_MAGIC;
						
						data    += NGHTTP2_CLIENT_MAGIC_LEN;
						datalen -= NGHTTP2_CLIENT_MAGIC_LEN;
					} else {
						cout << "[ERROR] " << __func__ << " We didn't see the magic." << endl;
						startskippingme();
						return;
					}
				}
				break;
			case HTTP2_FLOW_STATUS_SEEN_HTTP2_MAGIC:
				{
					if (HTTP2PKT_DIR_REQ != curpktdir){
						cout << "[ERROR] " << __func__ << " Unexpected transition in the flow." << endl;
						startskippingme();
						return;
					}
					
					if (datalen < sizeof(http2_frame_header)){
						cout << "[ERROR] " << __func__ << " Unexpected transition in the flow(2)." << endl;
						startskippingme();
						return;
					}
					
					// Peak at the frame type
					http2_frame_header *frhdr= (http2_frame_header*)data;
					#ifdef DEBUG
					dumpframehdr(frhdr);
					#endif
					
					if (NGHTTP2_SETTINGS != frhdr->type){
						cout << "[ERROR] " << __func__ << " SETTINGS frame(req) is expected." << endl;
						startskippingme();
						return;
					}
					
					h2flowprocstatus= HTTP2_FLOW_STATUS_SEEN_HTTP2_REQ_SETTING;
				}
				break;
			case HTTP2_FLOW_STATUS_SEEN_HTTP2_REQ_SETTING:
				{
					if (HTTP2PKT_DIR_REQ == curpktdir){
						// todo: process this data.
						return processh2data(data, datalen, curpktdir);
					} else {
						if (datalen < sizeof(http2_frame_header)){
							cout << "[ERROR] " << __func__ << " Length of the data("<< datalen<< ") is less than frame header len" << sizeof(http2_frame_header) << endl;
							startskippingme();
							return;
						}
						
						// Peak at the frame type
						http2_frame_header *frhdr= (http2_frame_header*)data;
						#ifdef DEBUG
						dumpframehdr(frhdr);
						#endif
						
						if (NGHTTP2_SETTINGS != frhdr->type){
							cout << "[ERROR] " << __func__ << " SETTINGS frame(rsp) is expected." << endl;
							startskippingme();
							dumpframehdr(frhdr);
							return;
						}
						
						h2flowprocstatus= HTTP2_FLOW_STATUS_HTTP2_FULLFLOW_SETUP;
					}
				}
				break;
			case HTTP2_FLOW_STATUS_HTTP2_FULLFLOW_SETUP:
				{
					return processh2data(data, datalen, curpktdir);
				}
				break;
			default:
				cout << "unknown status " << h2flowprocstatus << std::endl;
				break;
		}
	}
}

void flow::processh2data(const uint8_t *data, uint32_t datalen, pktdir curpktdir)
{
	#ifdef DEBUG
	printf("[PKT] data=%p of length %d(%s)\n", data, datalen, getpktdirstr(curpktdir));
	printf("[FRAME] START (%s)\n", __func__);
	#endif
	
	
	while (datalen > 0){
		#ifdef DEBUG
		dumpprocStatus(curpktdir);
		printf("[FRAME] (%s) data=%p of length %d\n", __func__ ,data, datalen);
		#endif
		
		switch(curh2procStatus[curpktdir].curFrameStatus){
			case HTTP2_FRAME_PROC_STATUS_START:
				{
					uint32_t framelen=0xdead;
					http2_frame_header *framehdr= (http2_frame_header *) data;
					
					if (datalen < sizeof(http2_frame_header)){
						cout << "[ERROR] " << __func__ << " Length of the data("<< datalen<< ") is less than frame header len" << sizeof(http2_frame_header) << endl;
						startskippingme();
						return;
					}
					
					#ifdef DEBUG
					dumpframehdr(framehdr);
					#endif
					
					framelen= getlength(framehdr);
					
					if ( framelen <= (datalen - sizeof(http2_frame_header)) ){
						#ifdef DEBUG
						printf("[FRAME] framelen(%d) is less than or equal to datalen(%d)\n", framelen, datalen);
						#endif
						
						processthisfullframe(data, framelen + sizeof(http2_frame_header), curpktdir);
						
						data    += sizeof(http2_frame_header);
						datalen -= sizeof(http2_frame_header);

						data    += framelen;
						datalen -= framelen;
					} else {
						// todo: handle fragmentation.
						curh2procStatus[curpktdir].curFrameStatus= HTTP2_FRAME_PROC_STATUS_FRAG;
						// curh2procStatus[curpktdir].frame_type    = framehdr->type;
						curh2procStatus[curpktdir].byteCount     = framelen + sizeof(http2_frame_header);
						// curh2procStatus[curpktdir].stream_id     = framehdr->stream_id;
						
						// Copy everything from frame header
						curh2procStatus[curpktdir].startcopy(data, datalen);
						
						data    += datalen;
						datalen -= datalen;
					}
					
					break;
				}
			case HTTP2_FRAME_PROC_STATUS_FRAG:
				{
					uint32_t neededcount= curh2procStatus[curpktdir].getbytecountneeded();
					
					if (datalen < neededcount){
						// Intermediate fragmented data.
						curh2procStatus[curpktdir].appenddata(data, datalen);
						data    += datalen;
						datalen -= datalen;
					} else {
						// Final fragmented piece.
						curh2procStatus[curpktdir].appenddata(data, neededcount);
						
						processthisfullframe(&curh2procStatus[curpktdir].framebuf[0], curh2procStatus[curpktdir].byteCount, curpktdir);
						
						curh2procStatus[curpktdir].reset();
						data    += neededcount;
						datalen -= neededcount;
					}
				}
				break;
			default:
				cout << "[ERROR] " << __func__ << " Unknown frame processing status.(skip me)" << endl;
				startskippingme();
				return;
		}
	}
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	printf("[FRAME] END (%s)\n", __func__);
	#endif
	
	#ifdef DEBUG
	dumpprocStatus(curpktdir);
	#endif
}

void flow::processthisfullframe(const uint8_t *data, uint32_t fullframelen, pktdir curpktdir)
{
	#ifdef DEBUG
	printf("[FULLFRAME] data=%p of length %d(%s)\n", data, fullframelen, getpktdirstr(curpktdir));
	#endif
	
	http2_frame_header *framehdr= (http2_frame_header *) data;
	#ifdef DEBUG
	dumpframehdr(framehdr);
	#endif
	
	data         += sizeof(http2_frame_header);
	fullframelen -= sizeof(http2_frame_header);
	
	uint32_t stream_id= ntohl(framehdr->stream_id);
	
	switch(framehdr->type){
		case NGHTTP2_HEADERS:
			{
				uint8_t padlength= 0;
				#ifdef DEBUG
				cout << "[FULLFRAME]: NGHTTP2_HEADERS" << endl;
				#endif
				
				// padding.
				if ((framehdr->flags & NGHTTP2_FLAG_PADDED)){
					if (fullframelen == 0)
						return;
					
					padlength= *data;
					#if defined(DEBUG) || defined(HTTP2_DEBUG)
					cout << "[FULLFRAME]: Pad length: " << padlength << endl;
					#endif
					
					data         += sizeof(uint8_t);
					fullframelen -= sizeof(uint8_t);
				}
				
				if ((framehdr->flags & NGHTTP2_FLAG_PRIORITY)){
					// stream dependency.
					if (fullframelen < sizeof(uint32_t))
						return;
					#if defined(DEBUG) || defined(HTTP2_DEBUG)
					cout << "[FULLFRAME]: Stream Exclusive:  " << (ntohl(((*(uint32_t*)data)) & 0x80000000) >> 7) << endl;
					cout << "[FULLFRAME]: Stream dependency: " << (ntohl((*(uint32_t*)data)) & 0x7fffffff) << endl;
					#endif
					
					data         += sizeof(uint32_t);
					fullframelen -= sizeof(uint32_t);
					
					// weight.
					if (fullframelen == 0)
						return;
					#if defined(DEBUG) || defined(HTTP2_DEBUG)
					cout << "[FULLFRAME]: Weight: " << (uint32_t)*data << endl;
					#endif
					
					data         += sizeof(uint8_t);
					fullframelen -= sizeof(uint8_t);
				}
				
				// padding.
				if (fullframelen < padlength){
					cout << "[ERROR - HEADERS] " << __func__ << " Length of the data("<< fullframelen<< ") is less than (padding)size needed " << padlength << endl;
					exit(-1);
				}
				
				// call fragments.
				if(0 != inflate_header_block(NGHTTP2_HEADERS, stream_id, (uint8_t *)data, fullframelen - padlength, framehdr->flags & NGHTTP2_FLAG_END_HEADERS? true: false, curpktdir)){
					cout << "[HPACK] Decoding failed.\n";
					exit(-1);
				}
			}
			break;
		case NGHTTP2_DATA:
			{
				if(streamtable[stream_id]->isReqSuccess()){
					cout << "Writing this stream " << stream_id << " data for http req ";
					cout << getfullurl(stream_id) << " to file " << getdirpath(stream_id)<< endl;
					streamtable[stream_id]->handlethisdata(getdirpath(stream_id), data, fullframelen, framehdr->flags & NGHTTP2_FLAG_END_STREAM? true: false);
				}
			}
			break;
		case NGHTTP2_CONTINUATION:
			{
				// todo: check whether we follow the right http2 flow !!
				if(0 != inflate_header_block(NGHTTP2_CONTINUATION, stream_id, (uint8_t *)data, fullframelen, framehdr->flags & NGHTTP2_FLAG_END_HEADERS? true: false, curpktdir)){
					cout << "[HPACK] Decoding failed.\n";
					exit(-1);
				}
			}
			break;
		case NGHTTP2_PUSH_PROMISE:
			{
				uint8_t padlength= 0;
				#if defined(DEBUG) || defined(HTTP2_DEBUG)
				cout << "[FULLFRAME]: NGHTTP2_PUSH_PROMISE" << endl;
				#endif
				
				// padding.
				if ((framehdr->flags & NGHTTP2_FLAG_PADDED)){
					if (fullframelen == 0)
						return;
					
					padlength= *data;
					#if defined(DEBUG) || defined(HTTP2_DEBUG)
					cout << "[FULLFRAME]: Pad length: " << padlength << endl;
					#endif
					
					data         += sizeof(uint8_t);
					fullframelen -= sizeof(uint8_t);
				}
				
				if (fullframelen < sizeof(uint32_t)){
					cout << "[ERROR - PUSH_PROMISE] " << __func__ << " Length of the data("<< fullframelen<< ") is less than size needed " << sizeof(uint32_t) << endl;
					exit(-1);
				}
				
				stream_id= ntohl(*(uint32_t*)data);
				#if defined(DEBUG) || defined(HTTP2_DEBUG)
				cout << "[PUSH_PROMISE]: Promised StreamID: " << stream_id << endl;
				#endif
				
				data         += sizeof(uint32_t);
				fullframelen -= sizeof(uint32_t);
				
				// padding.
				if (fullframelen < padlength){
					cout << "[ERROR - PUSH_PROMISE] " << __func__ << " Length of the data("<< fullframelen<< ") is less than (padding)size needed " << padlength << endl;
					exit(-1);
				}
				
				if(0 != inflate_header_block(NGHTTP2_PUSH_PROMISE, stream_id, (uint8_t *)data, fullframelen - padlength, framehdr->flags & NGHTTP2_FLAG_END_HEADERS? true: false, curpktdir)){
					cout << "[HPACK] Decoding failed.\n";
					exit(-1);
				}
			}
			break;
		case NGHTTP2_RST_STREAM:
			// todo
			break;
		case NGHTTP2_GOAWAY:
			// todo
			break;
		case NGHTTP2_ALTSVC:
			// todo
			break;
		default:
			break;
	}
}

bool flow::streaminfoexists(uint32_t stream_id, pktdir curpktdir)
{
	auto it= streamtable.find(stream_id);
	if(it != streamtable.end()){
		return true;
	}
	return false;
}

bool flow::initializestreaminfo(uint32_t stream_id, pktdir curpktdir)
{
	streamtable.insert(pair <uint32_t, strminfo*> (stream_id, new strminfo()));
	return false;
}

std::wstring StringToWString(const std::string& s)
{
    std::wstring temp(s.length(),L' ');
    std::copy(s.begin(), s.end(), temp.begin());
    return temp; 
}

bool folderExists(const char* folderName)
{
	struct stat info;

	if(stat( folderName, &info ) != 0)
		return 0;
	else if(info.st_mode & S_IFDIR)
		return 1;
	else
		return false;
}

bool createFolder(std::string folderName)
{
    list<std::string> folderLevels;
    char* c_str = (char*)folderName.c_str();

    // Point to end of the string
    char* strPtr = &c_str[strlen(c_str) - 1];

	if(chdir(rootoutputdir.c_str())){
		if (mkdir(rootoutputdir.c_str(), S_IRWXU | S_IRWXG)) {
            return false;
        }
		chdir(rootoutputdir.c_str());
	}
	
    // Create a list of the folders which do not currently exist
    do {
        if (folderExists(c_str)) {
            break;
        }
        // Break off the last folder name, store in folderLevels list
        do {
            strPtr--;
        } while ((*strPtr != '\\') && (*strPtr != '/') && (strPtr >= c_str));
		#ifdef DEBUG
		cout << "Create me " << string(strPtr + 1) << endl;
		#endif
        folderLevels.push_front(string(strPtr + 1));
        strPtr[1] = 0;
    } while (strPtr >= c_str);
	
	#ifdef DEBUG
	cout << "change dir " << c_str << endl;
	#endif
    if (*c_str != '\0' && chdir(c_str)) {
        return false;
    }
	#ifdef DEBUG
	cout << "change dir " << c_str << endl;
	#endif
	
    // Create the folders iteratively
    for (list<std::string>::iterator it = folderLevels.begin(); it != folderLevels.end(); it++) {
		#ifdef DEBUG
		cout << "Creating directory: " << it->c_str() << endl;
		#endif
        if (mkdir(it->c_str(), S_IRWXU | S_IRWXG)) {
            return false;
        }
        chdir(it->c_str());
    }
	
	chdir(rootoutputdir.c_str());

    return false;
}

//https://raw.githubusercontent.com/chafey/GZipCodec/master/GZipCodec/GZipCodec/GZipCodec.cpp
bool strminfo::Uncompress(const uint8_t *indata, uint32_t indata_len, std::string& data)
{
  int ret;
  unsigned have;
  z_stream strm;
  unsigned char out[CHUNK];

  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  strm.avail_in = 0;
  strm.next_in = Z_NULL;
  if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK)
  {
    return false;
  }

  strm.avail_in = indata_len;
  strm.next_in = (unsigned char*)indata;
  do {
    strm.avail_out = CHUNK;
    strm.next_out = out;
    ret = inflate(&strm, Z_NO_FLUSH);
    switch (ret) {
    case Z_NEED_DICT:
    case Z_DATA_ERROR:
    case Z_MEM_ERROR:
      inflateEnd(&strm);
      return false;
    }
    have = CHUNK - strm.avail_out;
    data.append((char*)out, have);
  } while (strm.avail_out == 0);

  if (inflateEnd(&strm) != Z_OK) {
    return false;
  }
  
  return true;
}

//void strminfo::openthefile(std::string fulldp, )
void strminfo::openthedatafile(std::string fulldp)
{
	std::string uri;
	std::string dirname;
	std::string filename;
	std::string::size_type n;
	
	n= fulldp.find("?");
	if (n == std::string::npos)
		uri= fulldp;
	else
		uri= fulldp.substr(0, n);
	
	n= uri.rfind("/");
	if (n == std::string::npos){
		cout << "Unknown format for URI= " << uri;
		exit(-1);
	}
	
	dirname= uri.substr(0, n);
	filename= uri.substr(n);
	
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Directory name= " << dirname << endl;
	cout << "File name(old)= " << filename << endl;
	#endif
	
	if (filename == "/" || filename == "")
		filename= "/index.html";
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "File name(new)= " << filename << endl;
	#endif
	
	createFolder(dirname.c_str());
	chdir(rootoutputdir.c_str());
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Creating file " << (dirname + filename) << endl;
	#endif
	char cCurrentPath[FILENAME_MAX];
	getcwd(cCurrentPath, sizeof(cCurrentPath));
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Current working directory " << cCurrentPath << endl;
	#endif
	
	ofs.open((dirname + filename), ios::out | ios::binary | ios::trunc);
}

void strminfo::appendthisdata(const uint8_t *data, uint32_t data_len)
{
	std::string uncompressed;
	
	if (doDecompress()){
		#if defined(DEBUG) || defined(HTTP2_DEBUG)
		cout << "[STREAM] Do decompression\n";
		#endif
		if(Uncompress(data, data_len, uncompressed)){
			ofs.write (uncompressed.c_str(), uncompressed.size());
		} else {
			cerr << "Failed to decompress." << endl;
			exit(-1);
		}
	}
	else {
		ofs.write ((const char*)data,data_len);
	}
}

void strminfo::closethedatafile()
{
	ofs.close();
}

void strminfo::handlethisdata(std::string fulldp, const uint8_t *data, uint32_t data_len, bool endofstream)
{
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "[STREAM] status= " << getstreamstatusstr(streamStatus) << endl;
	#endif
	switch(streamStatus){
		case HTTP2_STREAM_STATUS_REQ_SUCCESS:
			// start of response
			openthedatafile(fulldp);
			appendthisdata(data, data_len);
			if (!endofstream)
				setNeedMoreDataFrames();
			else{
				setEndofDataFrames();
				closethedatafile();
			}
			break;
		case HTTP2_STREAM_STATUS_REQ_MIDDLE_OF_STREAM:
			appendthisdata(data, data_len);
			if (endofstream){
				setEndofDataFrames();
				closethedatafile();
			}
			break;
		case HTTP2_STREAM_STATUS_REQ_ENDOFSTREAM:
			break;
		default:
			break;
	}
}

void strminfo::seturl(uint8_t *burl, uint32_t url_len)
{
	std::string asstring((const char*)burl, (long unsigned int)url_len);
	// if (asstring == std::string("/"))
		// asstring= "/index.html";
	
	url= asstring;
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "URL: " << url << endl;
	#endif
}

void strminfo::setscheme(uint8_t *bscheme, uint32_t scheme_len)
{
	scheme= std::string((const char*)bscheme, (long unsigned int)scheme_len);
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Scheme: " << scheme << endl;
	#endif
}

void strminfo::setmethod(uint8_t *bmethod, uint32_t method_len)
{
	method= std::string((const char*)bmethod, (long unsigned int)method_len);
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Method: " << method << endl;
	#endif
}

void flow::setauthority(uint8_t *bauthority, uint32_t authority_len)
{
	authority= std::string((const char*)bauthority, (long unsigned int)authority_len);
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "Authority: " << authority << endl;
	#endif
}

void strminfo::sethost(uint8_t *bhost, uint32_t host_len)
{
	host= std::string((const char*)bhost, (long unsigned int)host_len);
	#if defined(DEBUG) || defined(HTTP2_DEBUG)
	cout << "HOST: " << host << endl;
	#endif
}

std::string flow::getfullurl(uint32_t stream_id)
{
	if (streamtable[stream_id]->gethost().size() > 0)
		return (streamtable[stream_id]->getscheme() + "://" + streamtable[stream_id]->gethost() + streamtable[stream_id]->geturl());
	else
		return (streamtable[stream_id]->getscheme() + "://" + authority + streamtable[stream_id]->geturl());
}

std::string flow::getdirpath(uint32_t stream_id)
{
	if (streamtable[stream_id]->gethost().size() > 0)
		return (streamtable[stream_id]->gethost() + streamtable[stream_id]->geturl());
	else
		return (authority + streamtable[stream_id]->geturl());
}

//https://raw.githubusercontent.com/jdkoftinoff/mb-linux-msli/master/uClinux-dist/user/hping/memstr.c
char *memstr(char *haystack, char *needle, int size)
{
	char *p;
	char needlesize = strlen(needle);

	for (p = haystack; p <= (haystack-needlesize+size); p++)
	{
		if (memcmp(p, needle, needlesize) == 0)
			return p; /* found */
	}
	return NULL;
}

int flow::inflate_header_block(uint8_t type, uint32_t stream_id, uint8_t *in, size_t inlen, int final, pktdir curpktdir)
{
  ssize_t rv;
  
  if (HTTP2PKT_DIR_UNKNOWN == curpktdir)
	  return -1;
  
  if (!streaminfoexists(stream_id, curpktdir))
	  initializestreaminfo(stream_id, curpktdir); // TODO: check for return value.
  

  for (;;) {
    nghttp2_nv nv;
    int inflate_flags = 0;
    size_t proclen;

    rv = nghttp2_hd_inflate_hd(inflater, &nv, &inflate_flags, in, inlen, final);

    if (rv < 0) {
      printf("[ERR]inflate failed with error code %zd", rv);
      return -1;
    }

    proclen = (size_t)rv;

    in += proclen;
    inlen -= proclen;

    if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
	  int32_t curtoken= lookup_token(nv.name, nv.namelen);
	  #if defined(DEBUG) || defined(HTTP2_DEBUG)
      fwrite(nv.name, 1, nv.namelen, stderr);
      fprintf(stderr, ": ");
      fwrite(nv.value, 1, nv.valuelen, stderr);
      fprintf(stderr, "\n");
	  #endif
	  
	  
	  if ((HTTP2PKT_DIR_REQ == curpktdir && (type == NGHTTP2_HEADERS || type == NGHTTP2_CONTINUATION)) || 
		 (HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
	  {
		  switch(curtoken)
		  {
			  case NGHTTP2_TOKEN__METHOD:
					streamtable[stream_id]->setmethod(nv.value, nv.valuelen);
					if ((HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
						streamtable[stream_id]->setReqSucess();
					break;
			  case NGHTTP2_TOKEN__PATH:
					streamtable[stream_id]->seturl(nv.value, nv.valuelen);
					if ((HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
						streamtable[stream_id]->setReqSucess();
					break;
			  case NGHTTP2_TOKEN__AUTHORITY:
					setauthority(nv.value, nv.valuelen);
					if ((HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
						streamtable[stream_id]->setReqSucess();
					break;
			  case NGHTTP2_TOKEN_HOST:
					streamtable[stream_id]->sethost(nv.value, nv.valuelen);
					if ((HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
						streamtable[stream_id]->setReqSucess();
					break;
			  case NGHTTP2_TOKEN__SCHEME:
					streamtable[stream_id]->setscheme(nv.value, nv.valuelen);
					if ((HTTP2PKT_DIR_RSP == curpktdir && (type == NGHTTP2_PUSH_PROMISE || type == NGHTTP2_CONTINUATION)))
						streamtable[stream_id]->setReqSucess();
					break;
			  default:
				break;
		  }
	  } else {
			switch(curtoken)
			{
				case NGHTTP2_TOKEN__STATUS:
					{
						if(nv.valuelen >=3 && 0 == memcmp(nv.value, "200", 3))
							streamtable[stream_id]->setReqSucess();
						else
							streamtable[stream_id]->setReqFail();
					}
					break;
				case NGHTTP2_TOKEN_CONTENT_ENCODING:
					{
						if(memstr((char*)nv.value, (char*)"gzip", nv.valuelen))
							streamtable[stream_id]->needDecompression();
					}
					break;
				default:
					break;
		  }
	  }
	 
    }

    if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
      nghttp2_hd_inflate_end_headers(inflater);
      break;
    }

    if ((inflate_flags & NGHTTP2_HD_INFLATE_EMIT) == 0 && inlen == 0) {
      break;
    }
  }

  return 0;
}

void flow::dumpprocStatus(pktdir curpktdir)
{
	cout << "\nCurrent Frame Process Status: " << endl;
	if (curpktdir >= curh2procStatus.size()){
		cout << "curpktdir(" << curpktdir << ") is greater than or equal to " << curh2procStatus.size() << endl;
		return;
	}
	
	cout << "\t Frame Process Status: " << getframeprocstatusstr(curh2procStatus[curpktdir].curFrameStatus) << endl;
	// cout << "\t Frame type          : " << int(curh2procStatus[curpktdir].frame_type) << "(" << getframetypestr(curh2procStatus[curpktdir].frame_type) << ")" << endl;
	// cout << "\t Frame Stream ID     : " << curh2procStatus[curpktdir].stream_id << endl;
	cout << "\t ByteCount           : " << curh2procStatus[curpktdir].byteCount << endl;
	cout << "\t BytesinFragbuf      : " << curh2procStatus[curpktdir].framebuf.size() << endl << endl;
}

#ifdef __cplusplus
extern "C" {
#endif

uint32_t getlength(http2_frame_header *frhdr)
{
	return (frhdr->len[0] << 16 | frhdr->len[1] << 8 | frhdr->len[2]);
}

void dumpframehdr(http2_frame_header *frhdr)
{
	printf("HTTP/2 Frame header:\n");
	printf("\t Length  : %d\n", getlength(frhdr));
	printf("\t StreamID: %d\n", ntohl(frhdr->stream_id));
	printf("\t Type    : %d(%s)\n", frhdr->type, getframetypestr(frhdr->type));
	printf("\t Flags   : %d\n", frhdr->flags);
	printf("\t Reserved: %d\n", frhdr->res);
}

const char * getstreamstatusstr(streamstatus streamStatus)
{
	switch(streamStatus)
	{
		case HTTP2_STREAM_STATUS_UNKNOWN:
			return "HTTP2_STREAM_STATUS_UNKNOWN";
		case HTTP2_STREAM_STATUS_SEEN_REQ:
			return "HTTP2_STREAM_STATUS_SEEN_REQ";
		case HTTP2_STREAM_STATUS_REQ_FAIL:
			return "HTTP2_STREAM_STATUS_REQ_FAIL";
		case HTTP2_STREAM_STATUS_REQ_SUCCESS:
			return "HTTP2_STREAM_STATUS_REQ_SUCCESS";
		case HTTP2_STREAM_STATUS_REQ_MIDDLE_OF_STREAM:
			return "HTTP2_STREAM_STATUS_REQ_MIDDLE_OF_STREAM";
		case HTTP2_STREAM_STATUS_REQ_ENDOFSTREAM:
			return "HTTP2_STREAM_STATUS_REQ_ENDOFSTREAM";
		default:
			return "UNKNOWN_STREAM_STATUS";
	}
}

const char * getflowstatusstr(HTTP2_FLOW_STATUS flowstatus)
{
	switch(flowstatus)
	{
		case HTTP2_FLOW_STATUS_UNKNOWN:
			return "HTTP2_FLOW_STATUS_UNKNOWN";
		case HTTP2_FLOW_STATUS_SEEN_HTTP2_MAGIC:
			return "HTTP2_FLOW_STATUS_SEEN_HTTP2_MAGIC";
		case HTTP2_FLOW_STATUS_SEEN_HTTP2_REQ_SETTING:
			return "HTTP2_FLOW_STATUS_SEEN_HTTP2_REQ_SETTING";
		case HTTP2_FLOW_STATUS_HTTP2_FULLFLOW_SETUP:
			return "HTTP2_FLOW_STATUS_HTTP2_FULLFLOW_SETUP";
		default:
			return "UNKNOWN_FLOW_STATUS";
	}
}

const char * getframetypestr(uint8_t ftype)
{
	switch(ftype)
	{
		case NGHTTP2_DATA:
			return "NGHTTP2_DATA";
		case NGHTTP2_HEADERS:
			return "NGHTTP2_HEADERS";
		case NGHTTP2_PRIORITY:
			return "NGHTTP2_PRIORITY";
		case NGHTTP2_RST_STREAM:
			return "NGHTTP2_RST_STREAM";
		case NGHTTP2_SETTINGS:
			return "NGHTTP2_SETTINGS";
		case NGHTTP2_PUSH_PROMISE:
			return "NGHTTP2_PUSH_PROMISE";
		case NGHTTP2_PING:
			return "NGHTTP2_PING";
		case NGHTTP2_GOAWAY:
			return "NGHTTP2_GOAWAY";
		case NGHTTP2_WINDOW_UPDATE:
			return "NGHTTP2_WINDOW_UPDATE";
		case NGHTTP2_CONTINUATION:
			return "NGHTTP2_CONTINUATION";
		case NGHTTP2_ALTSVC:
			return "NGHTTP2_ALTSVC";
		case NGHTTP2_ORIGIN:
			return "NGHTTP2_ORIGIN";
		case NGHTTP2_UNKNOWN:
			return "NGHTTP2_UNKNOWN";
		default:
			return "UNKNOWN FRAME TYPE";
	}
}

const char * getframeprocstatusstr(HTTP2_FRAME_PROC_STATUS procStatus)
{
	switch(procStatus)
	{
		case HTTP2_FRAME_PROC_STATUS_START:
			return "HTTP2_FRAME_PROC_STATUS_START";
		case HTTP2_FRAME_PROC_STATUS_FRAG:
			return "HTTP2_FRAME_PROC_STATUS_FRAG";
		case HTTP2_FRAME_PROC_STATUS_SKIP_WO_WRITE:
			return "HTTP2_FRAME_PROC_STATUS_SKIP_WO_WRITE";
		case HTTP2_FRAME_PROC_STATUS_SKIP_W_WRITE:
			return "HTTP2_FRAME_PROC_STATUS_SKIP_W_WRITE";
		default:
			return "UNKNOWN FRAME PROCESSING STATUS";
	}
}

const char * getpktdirstr(pktdir curpktdir)
{
	switch(curpktdir)
	{
		case HTTP2PKT_DIR_UNKNOWN:
			return "UNKNOWN DIRECTION";
		case HTTP2PKT_DIR_REQ:
			return "REQUEST";
		case HTTP2PKT_DIR_RSP:
			return "RESPONSE";
		default:
			return "UNKNOWN DIR FLAG";
	}
}

int tcpdatahandler(const uint8_t *_iphdr, const uint64_t _iphdrlen, const uint8_t *_tcphdr, const uint64_t _tcphdrlen, const uint8_t *_data, const uint64_t _datalen)
{
	struct ip     *iphdr= (struct ip*)_iphdr;
	struct tcphdr *tcphdr= (struct tcphdr*)_tcphdr;
	
	#ifdef FLOW_DEBUG
	printf("         From: %s\n", inet_ntoa(iphdr->ip_src));
	printf("           To: %s\n", inet_ntoa(iphdr->ip_dst));
	printf("(tcp)Src port: %d\n", ntohs(tcphdr->th_sport));
	printf("(tcp)Dst port: %d\n", ntohs(tcphdr->th_dport));
	printf("    tcp flags: %x\n", tcphdr->th_flags);
	#endif
	
	if ((tcphdr->th_flags & (TH_SYN)) != 0){
		// May be State change flags.
		
		if ((tcphdr->th_flags & (TH_SYN | TH_ACK)) == (TH_SYN | TH_ACK)){
			// syn + ack
			#ifdef FLOW_DEBUG
			printf("syn + ack packet\n");
			#endif
			int32_t flowidx= tcpft.CreateFlowRecord(*(uint32_t*)(&iphdr->ip_src), tcphdr->th_sport, *(uint32_t*)(&iphdr->ip_dst), tcphdr->th_dport, IPPROTO_TCP, HTTP2PKT_DIR_RSP);
		} else {
			#ifdef FLOW_DEBUG
			printf("syn packet\n");
			#endif
			int32_t flowidx= tcpft.CreateFlowRecord(*(uint32_t*)(&iphdr->ip_src), tcphdr->th_sport, *(uint32_t*)(&iphdr->ip_dst), tcphdr->th_dport, IPPROTO_TCP, HTTP2PKT_DIR_REQ);
		}
	}
	
	if (_datalen > 0){
		pktdir curpktdir= HTTP2PKT_DIR_UNKNOWN;
		
		int32_t flowidx= tcpft.getFlowRecord(*(uint32_t*)(&iphdr->ip_src), tcphdr->th_sport, *(uint32_t*)(&iphdr->ip_dst), tcphdr->th_dport, IPPROTO_TCP, curpktdir);
		#ifdef FLOW_DEBUG
		cout << "FlowID= " << flowidx;
		#endif
		if (flowidx < 0 || tcpft.skipprocessing(flowidx)){
			#ifdef FLOW_DEBUG
			cout << "Skip processing.\n";
			#endif
			return 0;
		}
		
		tcpft.packetdataprocess(flowidx, _data, _datalen, curpktdir);
	}
	
	return 0;
}


#ifdef __cplusplus
}
#endif