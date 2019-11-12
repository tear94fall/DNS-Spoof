
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
	u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)  
	u_char tos; // Type of service   
	u_short tlen; // Total length   
	u_short identification; // Identification  
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)  
	u_char ttl; // Time to live  
	u_char proto; // Protocol  
	u_short crc; // Header checksum  
	ip_address saddr; // Source address  
	ip_address daddr; // Destination address  
	u_int op_pad; // Option + Padding  
}ip_header;

typedef struct udp_header {
	u_short sport;   // Source port  
	u_short dport;   // Destination port  
	u_short len;   // Datagram length  
	u_short crc;   // Checksum  
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
} dns_header;

struct dns_request {
    ether_header *ether_hdr;
    ip_header *ip_hdr;
    udp_header *udp_hdr;
    dns_header *dnshdr;
    char *dnsdata;
    char *request_domain;
    int port;
};


#endif