#define ATTACK_INFO_FILE_EMPTY_ERROR -1
#define NETWORK_INTERFACE_NOT_FOUND_ERROR -2
#define NETWORK_INTERFACE_OUT_OF_RANGE_ERROR -3
#define NETWORK_INTERFACE_OPEN_ERROR -4
#define FILTER_INVALID_SYNTAX_ERROR -5
#define FILTER_ADAPTION_ERROR -6
#define CONFIG_SETTING_END 0

#include "packet_handler.hpp"

int check_permission(void);
int check_args(int argc, char **argv);
int print_error_msg(int error_code);

int main(int argc, char **argv) {
    if(check_permission()<0){return 0;}
    if(check_args(argc, argv)<0){return 0;}
    
    packet_handle pkt_hnd = packet_handle();
    pkt_hnd.set_attack_info_file(argv[2]);
    pkt_hnd.read_info_from_file();
    pkt_hnd.set_dom_and_ip();
    if(print_error_msg(pkt_hnd.packet_capture_start())!=0){return 0;}
    pkt_hnd.set_my_ip();
    pkt_hnd.print_capture_info();
    pkt_hnd.start_capture_loop();

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
        case CONFIG_SETTING_END:
            return 0;
    }

    printf("ERROR: %s\nExit program...\n", error_message);

    return error_code;
}
