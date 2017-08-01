#include <pcap.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include "net/if.h"
#include "sys/ioctl.h"
#include <netdb.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

typedef struct ether_header
{

    uint8_t dmac[6];
    uint8_t smac[6];
    uint16_t *type;

}ether_t;

typedef struct arp_header
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



// ###For Reading MAC address: START###

unsigned char cMacAddr[8]; // Server's MAC address
static int GetSvrMacAddress( char *pIface )

{
    int nSD; // Socket descriptor
    struct ifreq sIfReq; // Interface request
    struct if_nameindex *pIfList; // Ptr to interface name index
    struct if_nameindex *pListSave; // Ptr to interface name index

    //
    // Initialize this function
    //
    pIfList = (struct if_nameindex *)NULL;
    pListSave = (struct if_nameindex *)NULL;
#ifndef SIOCGIFADDR
    // The kernel does not support the required ioctls
    return( 0 );
#endif

    //
    // Create a socket that we can use for all of our ioctls
    //
    nSD = socket( PF_INET, SOCK_STREAM, 0 );
    if ( nSD < 0 )
    {
        // Socket creation failed, this is a fatal error
        printf( "File %s: line %d: Socket failed\n", __FILE__, __LINE__ );
        return( 0 );
    }

    //
    // Obtain a list of dynamically allocated structures
    //
    pIfList = pListSave = if_nameindex();

    //
    // Walk thru the array returned and query for each interface's
    // address
    //
    for ( pIfList; *(char *)pIfList != 0; pIfList++ )
    {
        //
        // Determine if we are processing the interface that we
        // are interested in
        //
        if ( strcmp(pIfList->if_name, pIface) )
            // Nope, check the next one in the list
            continue;
        strncpy( sIfReq.ifr_name, pIfList->if_name, IF_NAMESIZE );

        //
        // Get the MAC address for this interface
        //
        if ( ioctl(nSD, SIOCGIFHWADDR, &sIfReq) != 0 )
        {
            // We failed to get the MAC address for the interface
            printf( "File %s: line %d: Ioctl failed\n", __FILE__, __LINE__ );
            return( 0 );
        }
        memmove( (void *)&cMacAddr[0], (void *)&sIfReq.ifr_ifru.ifru_hwaddr.sa_data[0], 6 );
        break;
    }

    //
    // Clean up things and return
    //

    // if_freenameindex( pListSave );    ??
    // close( nSD ); ??
    return( 1 );
}




int main(int argc, char * argv[])
{

    char *dev;
    int snaplen=2048;
    int promisc=1;
    int to_ms=1000;
    char errbuf[PCAP_ERRBUF_SIZE];
    dev="ens33";

    int number, i;
    uint8_t hostip[6];


    int domains[] = { AF_INET, AF_INET6 };


    bzero( (void *)&cMacAddr[0], sizeof(cMacAddr) );
    if ( !GetSvrMacAddress(dev) )
    {
        // We failed to get the local host's MAC address
        printf( "Fatal error: Failed to get local host's MAC address\n" );
    }
    printf( "HOST MAC ADDRESS: %02X:%02X:%02X:%02X:%02X:%02X\n",
            cMacAddr[0], cMacAddr[1], cMacAddr[2],
            cMacAddr[3], cMacAddr[4], cMacAddr[5] );

    // ###For Reading MAC address: FINISH###


    uint8_t gatemac[6];
    uint8_t targetmac[6];

    arphdr_t* arpheader;
    ether_t *etherheader;


    struct pcap_pkthdr *pkthdr;
    const u_char *pkt_data;

    pcap_t *handle;
    handle = pcap_open_live(dev, snaplen, promisc, to_ms, errbuf);


    if (handle == NULL) {

        printf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }


    u_char packet[42];

    for(i=0; i<6; i++)packet[i]=255; // 0xFF (BROADCAST)

    packet[6]= cMacAddr[0]; //HOST MAC ADDRESS
    packet[7]= cMacAddr[1];
    packet[8]= cMacAddr[2];
    packet[9]= cMacAddr[3];
    packet[10]= cMacAddr[4];
    packet[11]= cMacAddr[5];

    packet[12]= 8;
    packet[13]= 6;

    packet[14]= 0;
    packet[15]= 1;
    packet[16]= 8; //IPv4 0x0800
    packet[17]= 0;
    packet[18]= 6; //Hardware size 0x06
    packet[19]= 4; //Protocol size 0x04
    packet[20]= 0;
    packet[21]= 1; //Resquest

    for(int i=22;i<28;i++)packet[i]=packet[i-16]; //HOST MAC ADDRESS

    packet[28]=argv[1]; //HOST IP ADDRESS
    packet[29]=argv[2];
    packet[30]=argv[3];
    packet[31]=argv[4];

    for(int i=32;i<6;i++)packet[i]=0;

    for(int i=32;i<6;i++)packet[i]=0; //DO NOT KNOW TARGET'S MAC

    packet[38]=argv[5];
    packet[39]=argv[6];
    packet[40]=argv[7];
    packet[41]=argv[8];


    if (pcap_sendpacket(handle ,packet ,sizeof(packet)) != 0)
    {
        printf("Packet sending Failure\n");
    }

    else
    {
        while((number = pcap_next_ex(handle, &pkthdr, &pkt_data)) >= 0)
        {

            if(number == 0)
            {
                printf("Packet buffer time Expired\n");
                continue;
            }

            if(packet != NULL)
            {
                etherheader=(ether_t*)packet;

                if(ntohs(etherheader->type)==1544)
                {
                    arpheader=(arphdr_t*)(packet+14);
                    for(int i=0;i<6;i++)targetmac[i]=arpheader->sha[i];
                    for(i=0; i<6; i++)printf("TARGET MAC: %02x", targetmac[i]);
                }
            }
        }
    }

    packet[0]= targetmac[0];
    packet[1]= targetmac[1];
    packet[2]= targetmac[2];
    packet[3]= targetmac[3];
    packet[4]= targetmac[4];
    packet[5]= targetmac[5];

    packet[6]= cMacAddr[0]; //HOST MAC
    packet[7]= cMacAddr[1];
    packet[8]= cMacAddr[2];
    packet[9]= cMacAddr[3];
    packet[10]= cMacAddr[4];
    packet[11]= cMacAddr[5];

    packet[12]= 8;
    packet[13]= 6;

    packet[14]= 0;
    packet[15]= 1;
    packet[16]= 8; //IPv4 0x0800
    packet[17]= 0;
    packet[18]= 6; //Hardware size 0x06
    packet[19]= 4; //Protocol size 0x04
    packet[20]= 0;
    packet[21]= 1; //Resquest

    for(int i=0;i<5;i++)packet[i+22]=targetmac[i]; //GATEWAY MAC
    packet[27]= 0x01;

    packet[28]=argv[1]; //HOST IP ADDRESS
    packet[29]=argv[2];
    packet[30]=argv[3];
    packet[31]=argv[4];

    for(int i=0;i<6;i++)packet[i+32]=targetmac[i];

    packet[38]=argv[5];
    packet[39]=argv[6];
    packet[40]=argv[7];
    packet[41]=argv[8];


    while(1)
    {
        if (pcap_sendpacket(handle ,packet ,sizeof(packet)) != 0)
            printf("Packet sending Failure\n");
    }

    return 0;
}



