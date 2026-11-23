/* arp_reply.c  - Server B
 * Build:  gcc arp_reply.c -o arp_reply
 * Run:    sudo ./arp_reply eth0 192.168.1.200 [more_virtual_ips...]
 *         Answers ARP requests for the given (unused) IPs.
 */
#include "arp_common.h"

/* ---------- DSA: table of IPs this server will answer for ---------- */
#define MAX_IPS 8

struct ip_entry { unsigned char ip[4]; };

static struct ip_entry served[MAX_IPS];
static int served_count = 0;

static int is_served(const unsigned char ip[4])
{
    for (int i = 0; i < served_count; i++)          /* linear search */
        if (memcmp(served[i].ip, ip, 4) == 0) return 1;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <iface> <ip1> [ip2 ...]\n", argv[0]);
        return 1;
    }

    for (int i = 2; i < argc && served_count < MAX_IPS; i++) {
        if (inet_pton(AF_INET, argv[i], served[served_count].ip) != 1) {
            fprintf(stderr, "Invalid IP: %s\n", argv[i]);
            return 1;
        }
        served_count++;
    }

    unsigned char my_mac[6];
    int ifindex;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket (use sudo)"); return 1; }
    if (get_if_info(sock, argv[1], my_mac, &ifindex) < 0) return 1;

    printf("Listening for ARP requests on %s (my MAC ", argv[1]);
    print_mac(my_mac);
    printf(")\n");

    while (1) {
        unsigned char buf[2048];
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < (ssize_t)sizeof(struct eth_arp_frame)) continue;

        struct eth_arp_frame *rq = (struct eth_arp_frame *)buf;
        if (ntohs(rq->type) != ETH_P_ARP) continue;
        if (ntohs(rq->arp.oper) != ARP_REQUEST) continue;
        if (!is_served(rq->arp.tpa)) continue;      /* not our IP */

        printf("Request from %u.%u.%u.%u for %u.%u.%u.%u\n",
               rq->arp.spa[0], rq->arp.spa[1], rq->arp.spa[2], rq->arp.spa[3],
               rq->arp.tpa[0], rq->arp.tpa[1], rq->arp.tpa[2], rq->arp.tpa[3]);

        /* Build the ARP reply */
        struct eth_arp_frame rp;
        memset(&rp, 0, sizeof(rp));
        memcpy(rp.dst, rq->arp.sha, 6);             /* unicast to requester */
        memcpy(rp.src, my_mac, 6);
        rp.type = htons(ETH_P_ARP);

        rp.arp.htype = htons(1);
        rp.arp.ptype = htons(ETH_P_IP);
        rp.arp.hlen  = 6;
        rp.arp.plen  = 4;
        rp.arp.oper  = htons(ARP_REPLY);
        memcpy(rp.arp.sha, my_mac, 6);              /* "that IP is at my MAC" */
        memcpy(rp.arp.spa, rq->arp.tpa, 4);
        memcpy(rp.arp.tha, rq->arp.sha, 6);
        memcpy(rp.arp.tpa, rq->arp.spa, 4);

        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(addr));
        addr.sll_family  = AF_PACKET;
        addr.sll_ifindex = ifindex;
        addr.sll_halen   = 6;
        memcpy(addr.sll_addr, rq->arp.sha, 6);

        if (sendto(sock, &rp, sizeof(rp), 0,
                   (struct sockaddr *)&addr, sizeof(addr)) < 0)
            perror("sendto");
        else
            printf("ARP reply sent\n");
    }

    close(sock);
    return 0;
}
