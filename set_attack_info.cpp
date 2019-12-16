#include "set_attack_info.hpp"


std::vector<std::pair<std::string, std::string> > set_attack_info::read_info_from_file(char *attack_info_file){
    std::vector<std::pair<std::string, std::string> > vec;
    char line[256];
    int valid_cnt=0, invalid_cnt=0;

    FILE *fp = fopen(attack_info_file, "r"); 
    if(fp==NULL){return vec;}

    printf("[Read form \'%s\'.... ", attack_info_file);
    // const long delay = 1000 * 70;

    // for(int i=0;i<10;i++){
    //     printf("|");usleep(delay);fflush(stdout);printf("\b \b");
    //     printf("/");usleep(delay);fflush(stdout);printf("\b \b");
    //     printf("─");usleep(delay);fflush(stdout);printf("\b \b");
    //     printf("\\");usleep(delay);fflush(stdout);printf("\b \b");
    // }
    printf("END!]\n");

    while(!feof(fp)){
        char *ch = fgets(line, 80, fp);

        if(ch!=NULL){
            std::string str_ip(strtok(line, " ")), str_domain(strtok(NULL, "\n"));
            this->trim(str_domain);
            if(!validation_check_ip_addr(str_ip)){
                printf(ANSI_COLOR_RED   "[%-15s][%s] ==> X" ANSI_COLOR_RESET "\n", str_ip.c_str(), str_domain.c_str());
                invalid_cnt++;
            }else{
                printf(ANSI_COLOR_GREEN "[%-15s][%s] ==> O" ANSI_COLOR_RESET "\n", str_ip.c_str(), str_domain.c_str());
                vec.push_back(std::make_pair(str_ip, str_domain));
                valid_cnt++;
            }
        }
    }

    printf("Invalid [" ANSI_COLOR_RED "%d" ANSI_COLOR_RESET "], Valid [" ANSI_COLOR_GREEN "%d" ANSI_COLOR_RESET "]\n", invalid_cnt, valid_cnt);
    
    fclose(fp);

    return vec;
}


std::vector<std::string> set_attack_info::get_ip_address_from_list(std::vector<std::pair<std::string, std::string> > attack_list){
    std::vector<std::string> temp_web_arr;

    for(int i=0;i<attack_list.size();i++){
        temp_web_arr.push_back(attack_list[i].first);
    }

    return temp_web_arr;
}


std::vector<std::string> set_attack_info::get_domain_from_list(std::vector<std::pair<std::string, std::string> > attack_list){
    std::vector<std::string> temp_domain;
    
    for(int i=0;i<attack_list.size();i++){
        temp_domain.push_back(attack_list[i].second);
    }

    return temp_domain;
}


bool set_attack_info::validation_check_ip_addr(std::string ip_addr){
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_addr.c_str(), &(sa.sin_addr))==1 ? true : false;
}


void set_attack_info::trim(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
}
