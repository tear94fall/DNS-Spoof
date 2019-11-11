
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



#include <linux/if_ether.h>

typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header{
	u_char ver_ihl; // Version (4 bits) + Internet header length (4 bits)  
	u_char tos; // Type of service   
	u_short tlen; // Total length   
	u_short identification; // Identification  
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)  
	u_char ttl; // Time to live  
	u_char proto; // Protocol  
	u_short crc; // Header checksum  
	ip_address saddr; // Source address  
	ip_address daddr; // Destination address  
	u_int op_pad; // Option + Padding  
}ip_header;

typedef struct udp_header {
	u_short sport;   // Source port  
	u_short dport;   // Destination port  
	u_short len;   // Datagram length  
	u_short crc;   // Checksum  
}udp_header;

typedef struct DnsMessageHeader{
    short ID;

    unsigned char RD : 1;
    unsigned char TC : 1;
    unsigned char AA : 1;
    unsigned char OPCODE : 4;
    unsigned char QR : 1;

    unsigned char RCODE : 4;
    unsigned char CD : 1;
    unsigned char AD : 1;
    unsigned char Z : 1;
    unsigned char RA : 1;

    short QDCNT;
    short ANCNT;
    short NSCNT;
    short ARCNT;
} dns_header;

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data);
void print_packet_data(const struct pcap_pkthdr *header, const u_char *pkt_data);


int main(int argc, char **argv) {
    struct bpf_program fcode;
    bpf_u_int32 mask;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *a;
    int i = 0;
    int no;

    const char * filter = "port 53 and ((udp and (not udp[10] & 128 = 0)) or (tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0)))";

    if (pcap_findalldevs(&alldevs, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }

    for (d=alldevs; d; d=d->next) {
        printf("%d :  %s\n", ++i, (d->description)?(d->description):(d->name));
    }

	printf("Enter the interface number you would like to sniff : ");
	scanf("%d", &no);

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return 2;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i){
            break;
        }
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return 3;
    }

	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        return 4;
	}

	if (pcap_setfilter(adhandle, &fcode) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
		return 5;
	}

    pcap_freealldevs(alldevs);
    pcap_loop(adhandle, 0, packet_handler, NULL);
    pcap_close(adhandle);

    return 0;
}

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data) {
    print_packet_data(header, pkt_data); 
}

void print_packet_data(const struct pcap_pkthdr *header, const u_char *pkt_data){
    dns_header *dns_hdr;
    dns_hdr = (dns_header*)(pkt_data + 42);
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