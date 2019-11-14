
#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <sys/types.h>

typedef struct ether_header{
	unsigned char dst_host[6];
	unsigned char src_host[6];
	unsigned short frame_type;
}ether_header;

typedef struct ip_address {
	unsigned char byte1;
	unsigned char byte2;
	unsigned char byte3;
	unsigned char byte4;
}ip_address;

typedef struct ip_header{
	unsigned char ver_ihl;
	unsigned char tos;
	unsigned short tlen;
	unsigned short identification;
	unsigned short flags_fo;
	unsigned char ttl;
    unsigned char proto;
	unsigned short crc;
	ip_address saddr;
	ip_address daddr; 
}ip_header;

typedef struct udp_header {
	unsigned short sport;   
	unsigned short dport;
	unsigned short len;
	unsigned short crc;
}udp_header;

typedef struct DnsMessageHeader{
    short ID;

    unsigned char RD : 1;
    unsigned char TC : 1;
    unsigned char AA : 1;
    unsigned char OPCODE : 4;
    unsigned char QR : 1;

    unsigned char RCODE : 4;
    unsigned char CD : 1;
    unsigned char AD : 1;
    unsigned char Z : 1;
    unsigned char RA : 1;

    short QDCNT;
    short ANCNT;
    short NSCNT;
    short ARCNT;
}dns_header;

#endif