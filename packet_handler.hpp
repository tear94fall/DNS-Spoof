#ifndef _PACKET_HANDLER_HPP
#define _PACKET_HANDLER_HPP

#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <vector>
#include <utility>
#include <unistd.h>
#include <algorithm>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "protocol.hpp"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

class packet_handle{
    private:
        pcap_t *adhandle;
        struct pcap_pkthdr header;
        const unsigned char *pkt_data = NULL;
        char extract_domain[1024];
        char fake_webserver_ip[16];
        int interface_number;
        char interface_name[256];
        char *attack_info_file;
        char *my_ip;
        std::vector<std::pair<std::string, std::string> > attack_list;
        std::vector<std::string> domain_array;
        std::vector<std::string> fake_web_server_array;
    
    public:
        void set_attack_info_file(char* file_name);
        void set_my_ip();
        int packet_capture_start();
        void start_capture_loop();
        void packet_handler();
        void make_domain();
        void sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size);
        void set_dom_and_ip();
        bool compare_domain(const char *target_domain, std::vector<std::string> domain_array);
        void read_info_from_file();
        bool validation_check_ip_addr(std::string ip_addr);
        void trim(std::string& str);
};

#endif
