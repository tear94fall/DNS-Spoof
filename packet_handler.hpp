#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include "protocol.hpp"
#include "set_attack_info.hpp"

class packet_handle : public packets, public set_attack_info{
    public:
        std::vector<char*> set_network_interface(pcap_t *adhandle, pcap_if_t *alldevs, pcap_if_t *d, char *errbuf);
        int select_network_interface(std::vector<char*> interface_list);
        char *get_interface_name(int interface_number, std::vector<char*> interface_list);
        bool valid_interface_number(int interface_number, std::vector<char*> interface_list);
        char* set_my_ip(char *interface_name);
        int start_capture_loop(char* interface_name, struct pcap_pkthdr header, const unsigned char *pkt_data, std::vector<std::string> domain_array, std::vector<std::string> ip_address,  char* my_ip);

        void print_attack_success(struct pcap_pkthdr header, const unsigned char *pkt_data, char *extract_domain, char *fake_webserver_ip, char* my_ip, int full_size);
        int packet_handler(struct pcap_pkthdr header, const unsigned char *pkt_data, char *extract_domain, std::vector<std::string> domain_array, std::vector<std::string> ip_addr_array, char* my_ip);
        char* make_domain(struct pcap_pkthdr header, const unsigned char *pkt_data);
        int sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size);
        bool compare_domain(const char *target_domain, std::vector<std::string> domain_list);
};

#endif
