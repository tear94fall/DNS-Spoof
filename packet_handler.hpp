#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <pcap.h>
#include "protocol.hpp"

namespace packet{
    namespace packet_header{
        class dns_packet{
            public:
            ether_header *eth_hdr;
            ip_header *ip_hdr;
            udp_header *udp_hdr;
            dns_header *dns_hdr;
        };
    }

    namespace packet_hndlr{
        class packet_hndlr:public packet_header::dns_packet{
        public:
            void start_packet_capture(const char *filter, char *device_name, unsigned int packet_count);
            void stop_packet_capture();

        private:
            int select_interface_number;
            char *select_interface_name;

            char domain[1024];
            char fake_webserver_ip[16];
            char *my_ip;

            pcap_t *descriptor{};
            pcap_t *init_packet_capture(const char *filter, char *device_name);
            void start_packet_capture_loop(unsigned int packet_count);
            static void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
        };
    }
}

#endif