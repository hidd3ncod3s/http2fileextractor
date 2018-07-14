# http2fileextractor
Extract files from HTTP2 (HTTP 2.0) pcaps

This code uses the inflator code from the nghttp2. Currently it can save the files that are downloaded from the server.

## Compile:
```
  make clean; make
```
  If you want a debug version then you can pass a DEBUG flag to it.
```
  make clean; make DEBUG=1
```

## Usage:
Once compiled, you can pass the pcap file path to extract the files. Currently, it will create a "output/" folder under current working directory and create the files under that. Use it with care. Currently i haven't implemented few restriction that is needed. 
```
~/http2fileextractor$ ./http2fileextractor pcaps/capture.pcap
Using this pcap file pcaps/capture.pcap
Writing this stream 13 data for http req http://192.168.100.10/ to file 192.168.100.10/index.html

```

## Known issues:
  1. Cannot handle missing packets.
  2. Cannot handle packet resend
  3. Doesn't do packet reordering.
