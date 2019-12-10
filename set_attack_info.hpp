#ifndef _SET_ATTACK_INFO_HPP
#define _SET_ATTACK_INFO_HPP

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_RESET   "\x1b[0m"


#include "common.hpp"

class set_attack_info{
    private:
        std::vector<std::pair<std::string, std::string> > attack_list;
        std::vector<std::string> domain_array;
        std::vector<std::string> fake_web_server_array;
        char *attack_info_file;

    public:
        void set_attack_info_file(char* file_name);
        void read_info_from_file();
        void set_dom_and_ip();
        bool validation_check_ip_addr(std::string ip_addr);
        void trim(std::string& str);
        std::vector<std::pair<std::string, std::string> > get_attack_list();
        std::vector<std::string> get_domain_array();
};

#endif