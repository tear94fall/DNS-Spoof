#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <pcap.h>
#include "protocol.hpp"

class packets{
    public:
    ether_header *eth_hdr;
    ip_header *ip_hdr;
    udp_header *udp_hdr;
    dns_header *dns_hdr;
};

class packet_handle : public packets{
    public:
    void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
};

#endif