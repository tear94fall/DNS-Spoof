#include "dns_spoof.hpp"
#include "packet_handler.hpp"

#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>

int main(int argc, char **argv) {
    uid_t          user_id;
    struct passwd *user_pw;

    user_id = getuid();
    user_pw = getpwuid(user_id);

    if(user_pw->pw_uid!=0){
        printf("Error: Permission denied\n", argv[0]);
        return 0;
    }
    
    if (argc != 3) {
        printf("Error: Invalid arguments\nUsage: ./main <domain_to_spoof> <fake_web_server>\n");
        return 0;
    }

    strncpy(domain, argv[1], 60);
    strncpy(fake_webserver_ip, argv[2], 16);

    int err_code = packet_capture_start();
    if(err_code < 0){
        printf("error!! exit program...");
        return 0;
    }

    return 0;
}