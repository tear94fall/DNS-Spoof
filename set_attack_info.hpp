#ifndef _SET_ATTACK_INFO_HPP
#define _SET_ATTACK_INFO_HPP

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"


#include "common.hpp"

class set_attack_info{
    public:
        std::vector<std::pair<std::string, std::string> > read_info_from_file(char *attack_file_name);
        std::vector<std::string> get_ip_address_from_list(std::vector<std::pair<std::string, std::string> > attack_list);
        std::vector<std::string> get_domain_from_list(std::vector<std::pair<std::string, std::string> > attack_list);
        bool validation_check_ip_addr(std::string ip_addr);
        void trim(std::string& str);
};

#endif