#ifndef PACKETS_H
#define PACKETS_H

//coded with help from Claude Code Inline Autocomplete for CS60
//-Jason P

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <arpa/inet.h>

typedef struct packet_t
{
    void * packet;
    const void * data; // the base data (WITHOUT the headers) - NULL when not applicable
    uint8_t data_len; // base data length (NO HEADERS) - NULL when not applicable
    uint8_t src_ip[4]; // src ip address (ipv4) - NULL when not in icmp+ pack struct
    uint8_t dst_ip[4]; // dst ip address (ipv4) - NULL when not in icmp+ pack struct
} packet_t;

typedef struct ether{
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
                    uint16_t total_length = 20, uint8_t ttl = 64, uint16_t identification = 0,
                    uint8_t tos = 0, uint8_t flags = 0, uint16_t fragment_offset = 0);
icmp_t* create_icmp(ipv4_t* ip_packet, uint8_t type, uint8_t code, uint16_t id = 0, uint16_t seq = 0, 
                    const void* data = nullptr, size_t data_len = 0);
tcp_t* create_tcp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, uint32_t seq_num = 0, uint32_t ack_num = 0,
                  uint16_t flags = 0, uint16_t window = 8192, uint16_t urgent_ptr = 0,
                  const void* data = nullptr, size_t data_len = 0);
udp_t* create_udp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, 
                  const void* data = nullptr, size_t data_len = 0);
dns_question_t* create_dns_question(const char* qname, uint16_t qtype = 1, uint16_t qclass = 1);
dns_ans_t* create_dns_answer(const char* name, uint16_t type, uint16_t rr_class, uint32_t ttl,
                             const uint8_t* rdata, uint16_t rdlength);
dns_t* create_dns(uint16_t id, uint16_t flags, dns_question_t* questions = nullptr, uint16_t qd_count = 0,
                  dns_ans_t* answers = nullptr, uint16_t an_count = 0, uint16_t ns_count = 0, uint16_t ar_count = 0);

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

#endif // PACKETS_H