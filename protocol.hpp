
#ifndef PROTOCOL_HPP
#define PROTOCOL_HPP

#include <sys/types.h>

typedef struct ether_header{
	u_char dst_host[6];
	u_char src_host[6];
	u_short frame_type;
}ether_header;

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl;
	u_char tos;
	u_short tlen;
	u_short identification;
	u_short flags_fo;
	u_char ttl;
    u_char proto;
	u_short crc;
	ip_address saddr;
	ip_address daddr; 
	u_int op_pad;
}ip_header;

typedef struct udp_header {
	u_short sport;   
	u_short dport;
	u_short len;
	u_short crc;
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