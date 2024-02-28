/*
pktsnif - basic sniffer
Matt Vianueva | gmail diatribes
*/

#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#define _BSD_SOURCE

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>

#define IP_FMT "%u.%u.%u.%u"
#define PRINT_WIDTH 16

#define ntoh2(x,offs) ((x)[offs+1]<<0|(x)[offs+0]<<8)
#define iphdr_len(x) (((x)[0] & 0x0f) * 4)
#define print_tcp_flag(x, s) if(packet[iphl + 13] & (x)) fputs((s), stdout)
#define exit_if(x)\
        if((x)) {\
            fprintf(stderr,"error@%s:%d: %s\n", __FILE__, __LINE__,\
                    errno ? strerror(errno) : "Unknown");\
            exit(errno);\
        }

struct config {
    char *interface;
    int promisc;
    struct print {
        int tcp, udp, icmp, data;
    } print;
} config = { NULL, 1, { 1, 1, 1, 1 } };

uint64_t packet_count = 0;

static void print_usage(void)
{
    fprintf(stderr,
            "Usage: pktsnif [OPTIONS] [-i interface]\n"
            "   -p     disable promiscuous mode\n"
            "   -t     do not print tcp packets\n"
            "   -u     do not print udp packets\n"
            "   -m     do not print icmp packets\n"
            "   -d     do not print payload\n");
    fprintf(stderr, "e.g., pktsnif -um -i eth0\n");
}

static void handle_signal(int signum)
{
    switch(signum) {
    case SIGINT:
    case SIGTERM:
        fflush(stdout);
        printf("\n\n%lu packets captured\n", packet_count);
        exit(0);
    }
}

static char *timestamp(void)
{
    static char result[8 + 2 + 1];
    struct tm *local_time;
    time_t unix_time;
    unix_time = time(NULL);
    local_time = localtime(&unix_time);
    strftime(result, sizeof(result), "[%H:%M:%S]", local_time);
    return result;
}

static void print_data(const uint8_t *data, const int datalen)
{
    static char asc[PRINT_WIDTH + 1];
    int i, j;
    putchar('\n');
    for(i = 0; i < datalen; i += PRINT_WIDTH) {
        printf("  %08x: ", i);
        memset(asc, 0, sizeof(asc));
        for(j = 0; j < PRINT_WIDTH; ++j) {
            if (i + j < datalen) {
                asc[j] = isgraph(data[i + j]) ? data[i + j] : '.';
                printf("%02X", data[i + j]);
            } else {
                putchar(' ');
                putchar(' ');
            }
            if (j % 2 && j != PRINT_WIDTH - 1) putchar(' ');
        }
        putchar(' ');
        puts(asc);
    }
}

static void print_udp(uint8_t *packet, uint16_t len)
{
    uint16_t iphl = iphdr_len(packet);
    printf("\n%s "IP_FMT":%u > "IP_FMT":%u udp len %u ttl %u",
        timestamp(),
        packet[12], packet[13], packet[14], packet[15], ntoh2(packet, iphl + 0),
        packet[16], packet[17], packet[18], packet[19], ntoh2(packet, iphl + 2),
        len, packet[8]);
    if(config.print.data) {
        print_data(packet, len);
    }
}

static void print_icmp(uint8_t *packet, uint16_t len)
{
    uint16_t iphl = iphdr_len(packet);
    printf("\n%s "IP_FMT" > "IP_FMT" icmp type %u code %u len %u ttl %u",
        timestamp(),
        packet[12], packet[13], packet[14], packet[15],
        packet[16], packet[17], packet[18], packet[19],
        packet[iphl + 0], packet[iphl + 1],
        len, packet[8]);
    if(config.print.data) {
        print_data(packet, len);
    }
}

static void print_tcp(uint8_t *packet, uint16_t len)
{
    uint16_t iphl = iphdr_len(packet);
    printf("\n%s "IP_FMT":%u > "IP_FMT":%u tcp len %u ttl %u",
        timestamp(),
        packet[12], packet[13], packet[14], packet[15], ntoh2(packet, iphl + 0),
        packet[16], packet[17], packet[18], packet[19], ntoh2(packet, iphl + 2),
        len, packet[8]);

    print_tcp_flag(0x01, " FIN"); print_tcp_flag(0x02, " SYN");
    print_tcp_flag(0x04, " RST"); print_tcp_flag(0x08, " PSH");
    print_tcp_flag(0x10, " ACK"); print_tcp_flag(0x20, " URG");

    if(config.print.data) {
        print_data(packet, len);
    }
}

static int handle_packet(uint8_t *packet, ssize_t len)
{
    int valid = len >= 20
        && len == ntoh2(packet, 2)
        && iphdr_len(packet) >= 20
        && (packet[0] & 0xf0) == 0x40;

    if (valid) {
        switch(packet[9]) {
        case IPPROTO_ICMP:
            if(config.print.icmp) {
                print_icmp(packet, len);
            }
            break;
        case IPPROTO_TCP:
            if(config.print.tcp) {
                print_tcp(packet, len);
            }
            break;
        case IPPROTO_UDP:
            if(config.print.udp) {
                print_udp(packet, len);
            }
            break;
        default:
            valid = 0;
            break;
        }
    }

    return valid ? 0 : -1;
}

static int get_ifindex(int sockfd, const char *ifname)
{
    int rc;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
    rc = ioctl(sockfd, SIOCGIFINDEX, &ifr);
    exit_if(rc == -1);
    return ifr.ifr_ifindex;
}

static void set_promisc(int sockfd, int ifindex)
{
    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = ifindex;
    mr.mr_type = PACKET_MR_PROMISC;
    (void)setsockopt(sockfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));
}

static void set_all_promisc(int sockfd)
{
    struct ifconf ifc;
    struct ifreq ifr[0xff];
    int i, n, rc, ifindex;

    ifc.ifc_req = ifr;
    ifc.ifc_len = sizeof(ifr);
    rc = ioctl(sockfd, SIOCGIFCONF, &ifc);
    exit_if(rc == -1);

    n = ifc.ifc_len / sizeof(ifr[0]);
    for(i = 0; i < n; i++) {
        ifindex = ifr[i].ifr_ifindex;
        set_promisc(sockfd, ifindex);
    }

    return;
}

static int configure_interface(const char *ifname, int promisc)
{
    int rc;
    int sockfd;
    int ifindex;
    struct sockaddr_ll sll;

    sockfd = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_ALL));
    exit_if(sockfd == -1);

    if(ifname) {
        ifindex = get_ifindex(sockfd, ifname);
        if(promisc) {
            set_promisc(sockfd, ifindex);
        }
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = PF_PACKET;
        sll.sll_ifindex = ifindex;
        sll.sll_protocol = htons(ETH_P_IP);
        rc = bind(sockfd, (struct sockaddr *)&sll, sizeof(sll));
        exit_if(rc == -1);
    } else if(promisc) {
        set_all_promisc(sockfd);
    }
    return sockfd;
}

static void set_options(int argc, char **argv)
{
    char c;
    
    while ((c = getopt (argc, argv, "pdtumhi:-")) != -1) {
        switch (c) {
        case 'p': config.promisc = 0; break;
        case 't': config.print.tcp = 0; break;
        case 'u': config.print.udp = 0; break;
        case 'm': config.print.icmp = 0; break;
        case 'd': config.print.data = 0; break;
        case 'i': config.interface = optarg; break;
        case 'h':
        default:
            print_usage();
            exit(1);
            break;
        }
    }
}

int main(int argc, char **argv)
{
    int sockfd, nread;
    static uint8_t packet[0xffff];

    setlinebuf(stdout);
    set_options(argc, argv);
    sockfd = configure_interface(config.interface, config.promisc);

    (void)signal(SIGINT, handle_signal);
    (void)signal(SIGTERM, handle_signal);
    (void)signal(SIGPIPE, SIG_IGN);

    for(;;) {
        nread = recv(sockfd, packet, sizeof(packet), 0);
        if (nread > 0 && handle_packet(packet, nread) == 0) {
            packet_count++;
        }
    }
    return 0;
}

