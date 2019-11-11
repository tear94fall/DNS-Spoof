#include <stdio.h>
#include <string.h>
#include <string>
#include <sstream>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>

typedef struct DnsMessageHeader{
    short ID;

     //Start of second row which is broken into 2 bytes
    unsigned char RD : 1;
    unsigned char TC : 1;
    unsigned char AA : 1;
    unsigned char OPCODE : 4;
    unsigned char QR : 1;

    // Start of Second byte needed for row 2

    unsigned char RCODE : 4;
    unsigned char CD : 1;
    unsigned char AD : 1;
    unsigned char Z : 1;
    unsigned char RA : 1;

    // End Second row
    short QDCNT;
    short ANCNT;
    short NSCNT;
    short ARCNT;
} dns_header;

void packet_handler(u_char *param,const struct pcap_pkthdr *header, const u_char *pkt_data) {
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


	unsigned char a, line[17], c;
    int Size = header->caplen;
    int i;
	int j;

	for (i = 0; i < Size; i++)	{
		c = pkt_data[i];
        if(i!=0&&i%8==0){
            printf("    ");
        }

        if(i!=0&&i%16==0){
            printf("\n");
        }
        printf("%.2x ", (unsigned int)c);
	}printf("\n\n");
}

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
 
    printf("=====================================================\n");

    if (!(no > 0 && no <= i)) {
        printf("number error\n");
        return 1;
    }

    for (d=alldevs, i=0; d; d=d->next) {
        if (no == ++i){
            break;
        }
    }

    if (!(adhandle= pcap_open_live(d->name, 65536, 1, 1000, errbuf))) {
        printf("pcap_open_live error %s\n", d->name);
        pcap_freealldevs(alldevs);
        return -1;
    }

	if (pcap_compile(adhandle, &fcode, filter, 1, mask) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
        return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) == -1) {
		fprintf(stderr, "ERROR: %s\n", pcap_geterr(adhandle));
		return -2;
	}

    pcap_freealldevs(alldevs);

    pcap_loop(adhandle, 0, packet_handler, NULL);

    pcap_close(adhandle);

    return 0;
}