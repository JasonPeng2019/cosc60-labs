#ifndef PACKETS_H
#define PACKETS_H

//coded with help from Claude Code Inline Autocomplete for CS60
//-Jason P

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
// Following only available on linux
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/ether.h>

typedef struct packet_t
{
    void * packet;
    const void * data; // the base data (WITHOUT the headers) - NULL when not applicable
    uint8_t data_len; // base data length (NO HEADERS) - NULL when not applicable
    uint8_t src_ip[4]; // src ip address (ipv4) - NULL when not in icmp+ pack struct
    uint8_t dst_ip[4]; // dst ip address (ipv4) - NULL when not in icmp+ pack struct
} packet_t;

typedef struct ether{
    packet_t packet;
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t eth_type[2];
} ether_t;

typedef struct ipv4{
    packet_t packet;
    uint8_t version; // 4 bits
    uint8_t ihl; //4 bits; 5 for "no options"
    uint8_t tos; // 1 byte
    uint16_t total_length; //2 bytes
    uint16_t identification; //2 bytes
    uint8_t flags; // 3 bits
    uint16_t flags_fragment_offset; //13 bits
    uint8_t ttl; //1 byte
    uint8_t protocol; //Protocol field (1 byte: 1=ICMP, 6=TCP, 17=UDP) <-- pay attention!
    uint16_t header_checksum; //2 bytes
    uint8_t src_ip[4]; //assuming ipv4
    uint8_t dst_ip[4]; //assuming ipv4
} ipv4_t;

// ICMP (Layer 3)
typedef struct icmp{
    packet_t packet;
    uint8_t type; // 1 byte (e.g., 8=echo request, 0=echo reply)
    uint8_t code; // 1 byte
    uint16_t checksum; // 2 bytes
    uint16_t id; // 2 bytes (Identifier, used for echo)
    uint16_t seq; // 2 bytes (Sequence number, used for echo)
} icmp_t;

// TCP (Layer 4)
// Note: src_ip and dst_ip are included for checksum calculation (from IP layer)
typedef struct tcp{
    packet_t packet;
    uint16_t src_port; // 2 bytes
    uint16_t dst_port; // 2 bytes
    uint32_t seq; // 4 bytes (sequence number)
    uint32_t ack; // 4 bytes (acknowledgement number)
    uint8_t data_offset; // 4 bits (header length in 32-bit words), stored in 1 byte here
    uint8_t reserved; // 3 bits + NS flag space; stored as 1 byte for alignment
    uint16_t flags; // 9 bits normally (CWR, ECE, URG, ACK, PSH, RST, SYN, FIN, plus one), stored in 2 bytes
    uint16_t window; // 2 bytes (window size)
    uint16_t checksum; // 2 bytes (TCP checksum)
    uint16_t urgent_ptr; // 2 bytes (urgent pointer)
} tcp_t;

// UDP (Layer 4)
// Note: src_ip and dst_ip are included for checksum calculation (from IP layer)
typedef struct udp{
    packet_t packet;
    uint16_t src_port; // 2 bytes
    uint16_t dst_port; // 2 bytes
    uint16_t length; // 2 bytes (UDP header + data)
    uint16_t checksum; // 2 bytes
} udp_t;

// DNS (Layer 7)

// DNS question entry
typedef struct dns_question{
    char* qname; // domain name (as a human-readable C string or encoded name pointer)
    uint16_t qtype; // 2 bytes (type of the query, e.g., 1=A)
    uint16_t qclass; // 2 bytes (class of the query, e.g., 1=IN)
} dns_question_t;

// DNS resource record (answer/authority/additional)
typedef struct dns_ans{
    char* name; // domain name (C string or encoded)
    uint16_t type; // 2 bytes
    uint16_t rr_class; // 2 bytes 
    uint32_t ttl; // 4 bytes
    uint16_t rdlength; // 2 bytes
    uint8_t* rdata; // variable length data (rdlength bytes)
} dns_ans_t;

typedef struct dns{
    packet_t packet;
    uint16_t id; // 2 bytes (transaction ID)
    uint16_t flags; // 2 bytes (QR, opcode, AA, TC, RD, RA, Z, RCODE)
    uint16_t qd_count; // 2 bytes (number of questions)
    uint16_t an_count; // 2 bytes (number of answer RRs)
    uint16_t ns_count; // 2 bytes (number of authority RRs)
    uint16_t ar_count; // 2 bytes (number of additional RRs)
    dns_question_t* questions; // pointer to question struct
    dns_ans_t* answers; // pointer to answer struct
} dns_t;

// Constructor functions
ether_t* create_ether(const uint8_t dst_mac[6], const uint8_t src_mac[6], uint16_t eth_type);
ipv4_t* create_ipv4(const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t protocol, 
                    uint16_t total_length, uint8_t ttl, uint16_t identification,
                    uint8_t tos, uint8_t flags, uint16_t fragment_offset);
icmp_t* create_icmp(ipv4_t* ip_packet, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, 
                    const void* data, size_t data_len);
tcp_t* create_tcp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, uint32_t seq_num, uint32_t ack_num,
                  uint16_t flags, uint16_t window, uint16_t urgent_ptr,
                  const void* data, size_t data_len);
udp_t* create_udp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, 
                  const void* data, size_t data_len);
dns_question_t* create_dns_question(const char* qname, uint16_t qtype, uint16_t qclass);
dns_ans_t* create_dns_answer(const char* name, uint16_t type, uint16_t rr_class, uint32_t ttl,
                             const uint8_t* rdata, uint16_t rdlength);
dns_t* create_dns(uint16_t id, uint16_t flags, dns_question_t* questions, uint16_t qd_count,
                  dns_ans_t* answers, uint16_t an_count, uint16_t ns_count, uint16_t ar_count);

// Utility functions for checksum calculation
uint16_t calculate_ip_checksum(const ipv4_t* ip_header);
uint16_t calculate_icmp_checksum(const icmp_t* icmp_header);
uint16_t calculate_tcp_checksum(const tcp_t* tcp_header);
uint16_t calculate_udp_checksum(const udp_t* udp_header);

// Parser functions
ether_t* parse_ether(const uint8_t* raw_bytes, size_t len);
ipv4_t* parse_ipv4(const uint8_t* raw_bytes, size_t len);
icmp_t* parse_icmp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len);
tcp_t* parse_tcp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len);
udp_t* parse_udp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len);
dns_t* parse_dns(const uint8_t* raw_bytes, size_t len);

// to_bytes functions - convert struct to bytes for transmission
size_t ether_to_bytes(const ether_t* eth, uint8_t* buffer, size_t buffer_size, void* payload, size_t payload_size);
size_t ipv4_to_bytes(const ipv4_t* ip, uint8_t* buffer, size_t buffer_size);
size_t icmp_to_bytes(const icmp_t* icmp, uint8_t* buffer, size_t buffer_size);
size_t tcp_to_bytes(const tcp_t* tcp, uint8_t* buffer, size_t buffer_size);
size_t udp_to_bytes(const udp_t* udp, uint8_t* buffer, size_t buffer_size);
size_t dns_to_bytes(const dns_t* dns, uint8_t* buffer, size_t buffer_size);

// show functions - display packet contents in Scapy-style format
void ether_show(const ether_t* eth);
void ipv4_show(const ipv4_t* ip);
void icmp_show(const icmp_t* icmp);
void tcp_show(const tcp_t* tcp);
void udp_show(const udp_t* udp);
void dns_show(const dns_t* dns);

// Packet stacking functions - simulate division operator
ether_t* stack_ether_ipv4(ether_t* eth, ipv4_t* ip);
ipv4_t* stack_ipv4_icmp(ipv4_t* ip, icmp_t* icmp);
ipv4_t* stack_ipv4_tcp(ipv4_t* ip, tcp_t* tcp);
ipv4_t* stack_ipv4_udp(ipv4_t* ip, udp_t* udp);
udp_t* stack_udp_dns(udp_t* udp, dns_t* dns);
ether_t* stack_ether_icmp(ether_t* eth, icmp_t* icmp);
ether_t* stack_ether_tcp(ether_t* eth, tcp_t* tcp);
ether_t* stack_ether_udp(ether_t* eth, udp_t* udp);

// Macro to simulate division operator - usage: STACK(eth, ip) instead of eth / ip
#define STACK(layer1, layer2) _Generic((layer2), \
    ipv4_t*: _Generic((layer1), \
        ether_t*: stack_ether_ipv4, \
        default: (void*)0 \
    ), \
    icmp_t*: _Generic((layer1), \
        ipv4_t*: stack_ipv4_icmp, \
        ether_t*: stack_ether_icmp, \
        default: (void*)0 \
    ), \
    tcp_t*: _Generic((layer1), \
        ipv4_t*: stack_ipv4_tcp, \
        ether_t*: stack_ether_tcp, \
        default: (void*)0 \
    ), \
    udp_t*: _Generic((layer1), \
        ipv4_t*: stack_ipv4_udp, \
        ether_t*: stack_ether_udp, \
        default: (void*)0 \
    ), \
    dns_t*: _Generic((layer1), \
        udp_t*: stack_udp_dns, \
        default: (void*)0 \
    ), \
    default: (void*)0 \
)((layer1), (layer2))

// Raw socket functions
int create_layer3_socket();
int create_layer2_socket(const char* interface_name);
int create_layer2_recv_socket();
int send_packet(void* pkt, int packet_type);
int send(void* pkt);
int sendp(ether_t* eth_pkt, const char* interface_name);
ether_t* recv_layer2(int sockfd);
ether_t* recv();
ether_t* sr(void* pkt);
ether_t* sniff();

#endif // PACKETS_H