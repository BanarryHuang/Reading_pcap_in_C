#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <time.h>
typedef struct eth_hdr
{
    u_char dst_mac[6];
    u_char src_mac[6];
    u_short eth_type;
}eth_hdr;
eth_hdr *ethernet;

typedef struct ip_hdr
{
    int version:4;
    int header_len:4;
    u_char tos:8;
    int total_len:16;
    int ident:16;
    int flags:16;
    u_char ttl:8;
    u_char protocol:8;
    int checksum:16;
    u_char sourceIP[4];
    u_char destIP[4];
}ip_hdr;
ip_hdr *ip;

typedef struct tcp_hdr
{
    u_short sport;
    u_short dport;
    u_int seq;
    u_int ack;
    u_char head_len;
    u_char flags;
    u_short wind_size;
    u_short check_sum;
    u_short urg_ptr;
}tcp_hdr;
tcp_hdr *tcp;

typedef struct udp_hdr
{
    u_short sport;
    u_short dport;
    u_short tot_len;
    u_short check_sum;
}udp_hdr;
udp_hdr *udp;
int i=0;
void my_packet_handler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
)
{
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }
    u_int eth_len=sizeof(struct eth_hdr);
    u_int ip_len=sizeof(struct ip_hdr);
    u_int tcp_len=sizeof(struct tcp_hdr);
    u_int udp_len=sizeof(struct udp_hdr);

    printf("analyse information(packet %d):\n\n",++i);

    printf("ethernet header information:\n");
    ethernet=(eth_hdr *)packet;
    printf("src_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->src_mac[0],ethernet->src_mac[1],ethernet->src_mac[2],ethernet->src_mac[3],ethernet->src_mac[4],ethernet->src_mac[5]);
    printf("dst_mac : %02x-%02x-%02x-%02x-%02x-%02x\n",ethernet->dst_mac[0],ethernet->dst_mac[1],ethernet->dst_mac[2],ethernet->dst_mac[3],ethernet->dst_mac[4],ethernet->dst_mac[5]);
    printf("ethernet type : %u\n\n",ethernet->eth_type);

    if(ntohs(ethernet->eth_type)==0x0800){
        printf("IPV4 is used.\n");
        printf("IPV4 header information:\n");
        ip=(ip_hdr*)(packet+eth_len);
        printf("source ip : %d.%d.%d.%d\n",ip->sourceIP[0],ip->sourceIP[1],ip->sourceIP[2],ip->sourceIP[3]);
        printf("dest ip : %d.%d.%d.%d\n",ip->destIP[0],ip->destIP[1],ip->destIP[2],ip->destIP[3]);
        if(ip->protocol==6){
            printf("tcp is used:\n");
            tcp=(tcp_hdr*)(packet+eth_len+ip_len);
            printf("tcp source port : %d\n",ntohs(tcp->sport));
            printf("tcp dest port : %d\n",ntohs(tcp->dport));
        }
        else if(ip->protocol==17){
            printf("udp is used:\n");
            udp=(udp_hdr*)(packet+eth_len+ip_len);
            printf("udp source port : %d\n",ntohs(udp->sport));
            printf("udp dest port : %d\n",ntohs(udp->dport));
        }
        else {
            printf("Other transport protocol is used.\n");
        }
    }
    else {
        printf("IPV6 is used.\n");
    }

    printf("\n");

    printf("Packet length (Expected packet size) : %d\n",header->len);
    printf("Number of bytes (Total packet available) : %d\n",header->caplen);
    printf("Received time : %s",ctime((const time_t*)&header->ts.tv_sec));

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14;
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    if(payload_length!=0) {
        printf("Payload size: %d bytes\n", payload_length);
        payload = packet + total_headers_size;
        printf("Memory address where payload begins: %p\n", payload);
    }
    printf("\n");

    return;
}

int main(int argc, char **argv) {
    char *device = "eth0";
    char filename[80];
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int snapshot_length = 1024;
    int total_packet_count = 200;
    u_char *my_arguments = NULL;
    struct bpf_program filter;
    char filter_exp[100];
    int i=2;
    bpf_u_int32 subnet_mask, ip;

    strcpy(filename, argv[1]);

    while(argv[i]!=NULL){
        strcat(filter_exp,argv[i++]);
        filter_exp[strlen(filter_exp)]=' ';
    }

    handle = pcap_open_offline(filename, error_buffer);
    if (pcap_compile(handle, &filter, filter_exp, 0, ip) == -1) {
        printf("Bad filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &filter) == -1) {
        printf("Error setting filter - %s\n", pcap_geterr(handle));
        return 2;
    }
    pcap_loop(handle, total_packet_count, my_packet_handler, my_arguments);

    return 0;
}
