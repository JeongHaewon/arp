#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>

typedef struct arphdr
{

    uint16_t htype;
    uint16_t ptype;
    u_char hlen;
    u_char plen;
    uint16_t oper;
    u_char sha[6];
    u_char spa[4];
    u_char tha[6];
    u_char tpa[4];

}arphdr_t;


typedef struct ether_header
{
    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t *type;
}ethhdr_t;

typedef struct ip_header
{
    uint8_t versionheaderl;
    uint8_t difsrv;
    uint16_t tlen;
    uint16_t identification;
    uint16_t frgoffset;
    uint8_t ttlive;
    uint8_t protocol;
    uint16_t hdrcsum;
    uint32_t sip;
    uint32_t dip;
}iphdr_t;

typedef struct tcp_header
{
    uint16_t sport;
    uint16_t dport;
    uint32_t sqnum;
    uint32_t acknum;
    uint8_t hdrl;
}tcphdr_t;


int main(int arvc,char* argv[])
{
    int snaplen=2048;
    int promisc=1;
    int to_ms=512;
    char errbuf[256];
    ethhdr_t *ethheader = NULL;
    iphdr_t *ipheader;
    tcphdr_t *tcpheader = NULL;

    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;
    const u_char *payload;

    pcap_t *handle;
    handle = pcap_open_live("ens33", snaplen, promisc, to_ms, errbuf);

    int number, i;
    char sbuf[100], dbuf[100];

    u_char packet[100];







    while(1)
    {
        number = pcap_next_ex(handle, &pkthdr, &pkt_data);

        if(number != 1 || pkt_data == NULL)
        {
            continue;
        }


        ethheader = (struct ethhdr_t *)(pkt_data);
        ipheader = (struct iphdr_t *)(pkt_data+14);
        int ipheaderlength = (ipheader->versionheaderl)&0X0f;
        tcpheader = (struct tcphdr_t *)(pkt_data+14+ipheaderlength*4);
        int tcpheaderlength = (tcpheader->hdrl) >> 4;

        if(ntohs(ethheader->type) == 0x0806);
        {

            if(ntohs(tcpheader->sport) == 80)
            {


                inet_ntop(AF_INET, &ipheader->sip, &sbuf, 16);
                inet_ntop(AF_INET, &ipheader->dip, &dbuf, 16);

                printf("Packet Lengh is: %d\n", pkthdr->len);
                printf("Destination MAC: ");
                for(i=0; i<6;i++)printf("%02x:", ethheader->dmac[i]);
                printf("\nSource MAC: ");
                for(i=0; i<6;i++)printf("%02x:", ethheader->smac[i]);
                printf("\n");
                printf("Source IP: %s\n", sbuf);
                printf("Destination IP: %s\n", dbuf);
                printf("\n");
                printf("Source port: %d\n", ntohs(tcpheader->sport));
                printf("Destination port: %d\n", ntohs(tcpheader->dport));

                payload = (u_char *)(pkt_data+14+ipheaderlength*4+tcpheaderlength*4);
                printf(payload);

                printf("\n-------------------------------------------------\n");
            }
        }

    }
    return 0;
}




