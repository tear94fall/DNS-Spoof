#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <pcap.h>

namespace packet{
    namespace packet_header{

    }

    namespace packet_hndlr{
        class packet_hndlr{
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