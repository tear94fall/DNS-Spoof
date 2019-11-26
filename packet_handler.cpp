#include "packet_handler.hpp"

void packet::packet_hndlr::packet_hndlr::start_packet_capture(const char *filter, char *device_name, unsigned int packet_count) {
    descriptor = init_packet_capture(filter, device_name);
    start_packet_capture_loop(packet_count);
}

void packet::packet_hndlr::packet_hndlr::stop_packet_capture() {
    pcap_close(descriptor);
}

pcap_t *packet::packet_hndlr::packet_hndlr::init_packet_capture(const char *filter, char *device_name) {
    bpf_u_int32 mask, net; 
    char errorBuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp{};
    pcap_t* handle;

    char* dev = device_name;
    
    if(dev == nullptr){ perror("Couldn't find this device"); }
    if (pcap_lookupnet(dev, &net, &mask, errorBuf) == -1){ perror("Looking netmask for device"); }
    if ((handle = pcap_open_live(dev, BUFSIZ, 1, 100, errorBuf)) == nullptr){ perror("Opening device"); }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1){ perror("Couldn't compile filter"); }
    if (pcap_setfilter(handle, &fp) == -1){ perror("Couldn't set filter"); }

    return handle;
}

void packet::packet_hndlr::packet_hndlr::start_packet_capture_loop(unsigned int packet_count) {
    pcap_loop(descriptor, packet_count, &packet_handler, nullptr);
}

void packet::packet_hndlr::packet_hndlr::packet_handler(unsigned char *param, const struct pcap_pkthdr *header, const unsigned char *pkt_data) {
    for(int i=0;i<header->caplen;i++){
        if(i!=0&&i%8==0){
            printf("   ");
        }
        if(i!=0&&i%16==0){
            printf("\n");
        }
        printf("%.2x ", pkt_data[i]);
    }
    printf("\n\n\n");
}
