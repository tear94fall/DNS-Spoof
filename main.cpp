#include "dns_spoof.hpp"

int main(int argc, char **argv) {
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