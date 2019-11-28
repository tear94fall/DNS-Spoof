#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <pcap.h>
#include "protocol.hpp"

namespace packet{
    namespace packet_header{
        class packets{
            public:
            ether_header *eth_hdr;
            ip_header *ip_hdr;
            udp_header *udp_hdr;
            dns_header *dns_hdr;
        };
    }

    namespace packet_hndlr{
        class packet_hndlr:public packet_header::packets{
        public:
            struct pcap_pkthdr header;
            const unsigned char* pkt_data = NULL;
            int select_interface_number;
            char *select_interface_name;

            char domain[1024];
            char fake_webserver_ip[16];
            char *my_ip;

        private:
            void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
        };
    }
}

#endif