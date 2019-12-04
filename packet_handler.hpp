#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "protocol.hpp"

class packet_handle{
    private:
        char *attack_info_file;
        char *my_ip;
        std::vector<std::pair<std::string, std::string> > attack_list;
        std::vector<std::string> domain_array;
        std::vector<std::string> fake_web_server_array;
    
    public:
        void set_attack_info_file(char* file_name);
        int packet_capture_start(void);
        void packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data);
        void sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size);
        void make_domain(const struct pcap_pkthdr *header, const u_char *pkt_data, char *result);
        void set_dom_and_ip(std::vector<std::pair<std::string, std::string> > attack_list, std::vector<std::string> &web_arr, std::vector<std::string> &dom_arr);
        char *set_my_ip(char *interface_name);
        bool compare_domain(const char *target_domain, std::vector<std::string> domain_array);
        std::vector<std::pair<std::string, std::string> > read_info_from_file(const char* file_name);
};

#endif
