
/*
./main ens33 www.google.com 192.168.218.147 192.168.218.148 192.168.218.2
           intf      도메인     attacker's ip    victim's ip   gateway's ip
*/

#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

#include "protocol.hpp"

char domain[1024];

int packet_capture_start(void);
void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_packet_data(const struct pcap_pkthdr *header, const u_char *pkt_data);
void make_domain(const struct pcap_pkthdr *header, const u_char *pkt_data, char* result);

int main(int argc, char **argv) {
    if (argc != 5) {
        // printf("./main <interface> <domain_to_spoof> <ip_to_spoof> <target_ip> <gateway_ip>\n");
        printf("./main <domain_to_spoof> <ip_to_spoof> <target_ip> <gateway_ip>\n");
        return 0;
    }

    strncpy(domain, argv[1], 60);


    int err_code = packet_capture_start();
    if(err_code < 0){
        printf("error!! exit program...");
        return 0;
    }

    return 0;
}

int packet_capture_start(){
    struct bpf_program fcode;
    bpf_u_int32 mask;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;


    // 첫번째 필터는 DNS서버로 보낸거 두번째 필터는 DNS 서버에서 온것
    const char * filter = "port 53 and ((udp and (udp[10] & 128 = 0)) or (tcp and (tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0)))";
    // const char * filter = "port 53 and ((udp and (not udp[10] & 128 = 0)) or (tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0)))";

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return -1;
    }

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return -2;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i){
            break;
        }
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
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

    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);
}

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data) {
    char extract_domain[1024];
    memset(extract_domain, 0x00, 1024);
    make_domain(header, pkt_data, extract_domain);

    if(strstr(domain, extract_domain)!=NULL){
        printf("target domain captured!\n");
    }else{
        printf("%s %s\n", domain, extract_domain);
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