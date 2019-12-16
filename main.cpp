#define ATTACK_INFO_FILE_EMPTY_ERROR -1
#define NETWORK_INTERFACE_NOT_FOUND_ERROR -2
#define NETWORK_INTERFACE_OUT_OF_RANGE_ERROR -3
#define NETWORK_INTERFACE_OPEN_ERROR -4
#define FILTER_INVALID_SYNTAX_ERROR -5
#define FILTER_ADAPTION_ERROR -6
#define LOPP_END 0

#include "packet_handler.hpp"

int check_permission(void);
int check_args(int argc, char **argv);
int print_error_msg(int error_code);

int main(int argc, char **argv) {
    if(check_permission()<0){return 0;}
    if(check_args(argc, argv)<0){return 0;}

    packet_handle pkt_hnd = packet_handle();
    
    struct bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;

    std::vector<std::pair<std::string, std::string> > attack_list = pkt_hnd.read_info_from_file(argv[2]);
    if(attack_list.size()<1){
        print_error_msg(-1);
        return 0;
    }

    std::vector<std::string> ip_array = pkt_hnd.get_ip_address_from_list(attack_list);
    std::vector<std::string> domain_array = pkt_hnd.get_domain_from_list(attack_list);

    std::vector<char *> interface_list = pkt_hnd.set_network_interface(adhandle, alldevs, d, errbuf);
    if(interface_list.size()<1){
        print_error_msg(-2);
        return 0;
    }

    printf(ANSI_COLOR_YELLOW "                                                                              ,...,,                      \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "`7MM\"\"\"Yb. `7MN.   `7MF'.M\"\"\"bgd      .M\"\"\"bgd                              .d' \"\"db                      \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "  MM    `Yb. MMN.    M ,MI    \"Y     ,MI    \"Y                              dM`                           \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "  MM     `Mb M YMb   M `MMb.         `MMb.   `7MMpdMAo.  ,pW\"Wq.   ,pW\"Wq. mMMmm`7MM  `7MMpMMMb.  .P\"Ybmmm\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "  MM      MM M  `MN. M   `YMMNq.       `YMMNq. MM   `Wb 6W'   `Wb 6W'   `Wb MM    MM    MM    MM :MI  I8  \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "  MM     ,MP M   `MM.M .     `MM     .     `MM MM    M8 8M     M8 8M     M8 MM    MM    MM    MM  WmmmP\"  \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "  MM    ,dP' M     YMM Mb     dM     Mb     dM MM   ,AP YA.   ,A9 YA.   ,A9 MM    MM    MM    MM 8M       \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW ".JMMmmmdP' .JML.    YM P\"Ybmmd\"      P\"Ybmmd\"  MMbmmd'   `Ybmd9'   `Ybmd9'.JMML..JMML..JMML  JMML.YMMMMMb \n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "                                               MM                                                6'     dP\n" ANSI_COLOR_RESET);
    printf(ANSI_COLOR_YELLOW "                                             .JMML.                                              Ybmmmd'  \n" ANSI_COLOR_RESET);

    int interface_number = pkt_hnd.select_network_interface(interface_list);
    if(!pkt_hnd.valid_interface_number(interface_number, interface_list)){
        print_error_msg(-3);
        return 0;
    }

    char* interface_name = pkt_hnd.get_interface_name(interface_number, interface_list);
    char* my_ip = pkt_hnd.set_my_ip(interface_name);
    
    struct pcap_pkthdr header;
    const unsigned char *pkt_data;
    
    int loop_end = pkt_hnd.start_capture_loop(interface_name, header, pkt_data, domain_array, ip_array, my_ip);
    print_error_msg(loop_end);

    return 0;
}


int check_permission(void){
    uid_t          user_id;
    struct passwd *user_pw;

    user_id = getuid();
    user_pw = getpwuid(user_id);

    if(user_pw->pw_uid!=0){
        printf("ERROR: User[%s], Permission denied\n", user_pw->pw_name);
        return -1;
    }
    return 0;
}


int check_args(int argc, char **argv){
    if (argc != 3 || strcmp(argv[1], "-f")!=0) {
        printf("ERROR: Invalid arguments\nUsage: ./main -f <attack info file>\n");
        return -1;
    }
    return 0;
}


int print_error_msg(int error_code){
    char error_message[1024];
    switch(error_code){
        case ATTACK_INFO_FILE_EMPTY_ERROR:
            strcpy(error_message, "Attack info is not valid. please check again attack info file...");
            break;
        case NETWORK_INTERFACE_NOT_FOUND_ERROR:
            strcpy(error_message, "Network interface not found. please retry...");
            break;
        case NETWORK_INTERFACE_OUT_OF_RANGE_ERROR:
            strcpy(error_message, "Network interface out of range. select valid value...");
            break;
        case NETWORK_INTERFACE_OPEN_ERROR:
            strcpy(error_message, "Network interface open error. please retry...");
            break;
        case FILTER_INVALID_SYNTAX_ERROR:
            strcpy(error_message, "Invalid Filter Syntax. please enter correct filter...");
            break;
        case FILTER_ADAPTION_ERROR:
            strcpy(error_message, "Can't setting the filer. please retry...");
            break;
        case LOPP_END:
            return 0;
    }

    if(error_code<0){
        printf("ERROR: %s\nExit program...\n", error_message);
    }else{
        printf("Goob Bye~!\n");
    }

    return error_code;
}
