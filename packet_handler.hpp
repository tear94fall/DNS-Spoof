#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include "protocol.hpp"
#include "set_attack_info.hpp"

class packet_handle : public packets, public set_attack_info{
    private:
        struct bpf_program fcode;
        bpf_u_int32 mask;
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs, *d;

        std::vector<char*> interface_list;

        pcap_t *adhandle;
        struct pcap_pkthdr header;
        const unsigned char *pkt_data = NULL;

        char source_ip[16];
        char dest_ip[16];
        char display_domain[1024];
        int full_size;

        int sport;
        int dport;
        int dns_id;

        char extract_domain[1024];
        char fake_webserver_ip[16];
        
        int interface_number;
        char interface_name[256];
        char *my_ip;
    
    public:
        void set_my_ip();
        int set_network_interface();
        void print_network_interface();
        int select_network_interface();

        int packet_capture_start();
        void print_attack_info();
        void start_capture_loop();
        void set_protocol_header();
        void set_attack_data();
        void print_attack_success();

        void set_attack_ip_header();
        void set_attack_udp_header();

        void packet_handler();
        void make_domain();
        void sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size);
        bool compare_domain(const char *target_domain);
};

#endif
