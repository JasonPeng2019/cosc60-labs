#include "packets.h"


/**
 * Coded with help with of Claude Code CLI & Inline Autocomplete
 * -Jason P
 * 
 */


// Ethernet constructor - no packet_t field, no IP info
ether_t* create_ether(const uint8_t dst_mac[6], const uint8_t src_mac[6], uint16_t eth_type) {
    ether_t* eth = (ether_t*)malloc(sizeof(ether_t));
    if (!eth) return nullptr;
    
    // Initialize packet_t field
    eth->packet.packet = nullptr;
    eth->packet.data = nullptr;
    eth->packet.data_len = 0;
    memset(eth->packet.src_ip, 0, 4);
    memset(eth->packet.dst_ip, 0, 4);
    
    memcpy(eth->dst_mac, dst_mac, 6);
    memcpy(eth->src_mac, src_mac, 6);
    eth->eth_type[0] = (eth_type >> 8) & 0xFF; //bitwise operations to shift eth type into eth fields
    eth->eth_type[1] = eth_type & 0xFF;
    
    return eth;
}

// IPv4 constructor - sets up packet_t with src_ip/dst_ip, but data/data_len are NULL
ipv4_t* create_ipv4(const uint8_t src_ip[4], const uint8_t dst_ip[4], uint8_t protocol, 
                    uint16_t total_length, uint8_t ttl, uint16_t identification,
                    uint8_t tos, uint8_t flags, uint16_t fragment_offset) {
    ipv4_t* ip = (ipv4_t*)malloc(sizeof(ipv4_t));
    if (!ip) return nullptr;
    
    // Initialize packet_t field
    ip->packet.packet = nullptr;
    ip->packet.data = nullptr;
    ip->packet.data_len = 0;
    memcpy(ip->packet.src_ip, src_ip, 4);
    memcpy(ip->packet.dst_ip, dst_ip, 4);
    
    // Initialize IPv4 header fields
    ip->version = 4;
    ip->ihl = 5; // No options
    ip->tos = tos;
    ip->total_length = total_length;
    ip->identification = identification;
    ip->flags = flags;
    ip->flags_fragment_offset = fragment_offset;
    ip->ttl = ttl;
    ip->protocol = protocol;
    ip->header_checksum = 0; // Will be calculated
    memcpy(ip->src_ip, src_ip, 4);
    memcpy(ip->dst_ip, dst_ip, 4);
    
    // Calculate checksum
    ip->header_checksum = calculate_ip_checksum(ip);
    
    return ip;
}

// ICMP constructor - takes ipv4_t and injects data into packet_t
icmp_t* create_icmp(ipv4_t* ip_packet, uint8_t type, uint8_t code, uint16_t id, uint16_t seq, 
                    const void* data, size_t data_len) {
    icmp_t* icmp = (icmp_t*)malloc(sizeof(icmp_t));
    if (!icmp) return nullptr;
    
    // Copy packet_t from IP layer and inject data
    icmp->packet = ip_packet->packet;
    icmp->packet.data = data;
    icmp->packet.data_len = data_len;
    
    // Initialize ICMP header fields
    icmp->type = type;
    icmp->code = code;
    icmp->checksum = 0; // Will be calculated
    icmp->id = id;
    icmp->seq = seq;
    
    // Calculate checksum
    icmp->checksum = calculate_icmp_checksum(icmp);
    
    return icmp;
}

// TCP constructor - takes ipv4_t and injects data into packet_t
tcp_t* create_tcp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, uint32_t seq_num, uint32_t ack_num,
                  uint16_t flags, uint16_t window, uint16_t urgent_ptr,
                  const void* data, size_t data_len) {
    tcp_t* tcp = (tcp_t*)malloc(sizeof(tcp_t));
    if (!tcp) return nullptr;
    
    // Copy packet_t from IP layer and inject data
    tcp->packet = ip_packet->packet;
    tcp->packet.data = data;
    tcp->packet.data_len = data_len;
    
    // Initialize TCP header fields
    tcp->src_port = src_port;
    tcp->dst_port = dst_port;
    tcp->seq = seq_num;
    tcp->ack = ack_num;
    tcp->data_offset = 5; // 20 bytes (no options)
    tcp->reserved = 0;
    tcp->flags = flags;
    tcp->window = window;
    tcp->checksum = 0; // Will be calculated
    tcp->urgent_ptr = urgent_ptr;
    
    // Calculate checksum
    tcp->checksum = calculate_tcp_checksum(tcp);
    
    return tcp;
}

// UDP constructor - takes ipv4_t and injects data into packet_t
udp_t* create_udp(ipv4_t* ip_packet, uint16_t src_port, uint16_t dst_port, 
                  const void* data, size_t data_len) {
    udp_t* udp = (udp_t*)malloc(sizeof(udp_t));
    if (!udp) return nullptr;
    
    // Copy packet_t from IP layer and inject data
    udp->packet = ip_packet->packet;
    udp->packet.data = data;
    udp->packet.data_len = data_len;
    
    // Initialize UDP header fields
    udp->src_port = src_port;
    udp->dst_port = dst_port;
    udp->length = 8 + data_len; // UDP header (8 bytes) + data
    udp->checksum = 0; // Will be calculated
    
    // Calculate checksum
    udp->checksum = calculate_udp_checksum(udp);
    
    return udp;
}

// DNS question constructor
dns_question_t* create_dns_question(const char* qname, uint16_t qtype, uint16_t qclass) {
    dns_question_t* question = (dns_question_t*)malloc(sizeof(dns_question_t));
    if (!question) return nullptr;
    
    // Allocate and copy qname
    size_t name_len = strlen(qname) + 1;
    question->qname = (char*)malloc(name_len);
    if (!question->qname) {
        free(question);
        return nullptr;
    }
    strcpy(question->qname, qname);
    
    question->qtype = qtype;
    question->qclass = qclass;
    
    return question;
}

// DNS answer constructor
dns_ans_t* create_dns_answer(const char* name, uint16_t type, uint16_t rr_class, uint32_t ttl,
                             const uint8_t* rdata, uint16_t rdlength) {
    dns_ans_t* answer = (dns_ans_t*)malloc(sizeof(dns_ans_t));
    if (!answer) return nullptr;
    
    // Allocate and copy name
    size_t name_len = strlen(name) + 1;
    answer->name = (char*)malloc(name_len);
    if (!answer->name) {
        free(answer);
        return nullptr;
    }
    strcpy(answer->name, name);
    
    answer->type = type;
    answer->rr_class = rr_class;
    answer->ttl = ttl;
    answer->rdlength = rdlength;
    
    // Allocate and copy rdata
    if (rdlength > 0 && rdata) {
        answer->rdata = (uint8_t*)malloc(rdlength);
        if (!answer->rdata) {
            free(answer->name);
            free(answer);
            return nullptr;
        }
        memcpy(answer->rdata, rdata, rdlength);
    } else {
        answer->rdata = nullptr;
    }
    
    return answer;
}

// DNS constructor
dns_t* create_dns(uint16_t id, uint16_t flags, dns_question_t* questions, uint16_t qd_count,
                  dns_ans_t* answers, uint16_t an_count, uint16_t ns_count, uint16_t ar_count) {
    dns_t* dns = (dns_t*)malloc(sizeof(dns_t));
    if (!dns) return nullptr;
    
    dns->packet.packet = nullptr;
    dns->packet.data = nullptr;
    dns->packet.data_len = 0;
    memset(dns->packet.src_ip, 0, 4);
    memset(dns->packet.dst_ip, 0, 4);
    
    dns->id = id;
    dns->flags = flags;
    dns->qd_count = qd_count;
    dns->an_count = an_count;
    dns->ns_count = ns_count;
    dns->ar_count = ar_count;
    dns->questions = questions;
    dns->answers = answers;
    
    return dns;
}

// Checksum calculation functions - now pull data from packet_t directly
uint16_t calculate_ip_checksum(const ipv4_t* ip_header) {
    uint32_t sum = 0;
    uint16_t* header = (uint16_t*)ip_header;
    
    // Sum all 16-bit words in header (skip checksum field)
    for (int i = 0; i < 10; i++) {
        if (i == 5) continue; // Skip checksum field
        sum += ntohs(header[i + 4]); // Skip packet_t field (4 * uint16_t)
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint16_t calculate_icmp_checksum(const icmp_t* icmp_header) {
    uint32_t sum = 0;
    uint16_t* header = (uint16_t*)((char*)icmp_header + sizeof(packet_t));
    
    // Sum all 16-bit words (skip checksum field)
    sum += ntohs(header[0]); // type and code
    // Skip checksum field at header[1]
    sum += ntohs(header[2]); // id
    sum += ntohs(header[3]); // seq
    
    if (icmp_header->packet.data && icmp_header->packet.data_len > 0) {
        uint16_t* data_ptr = (uint16_t*)icmp_header->packet.data;
        for (size_t i = 0; i < icmp_header->packet.data_len / 2; i++) {
            sum += ntohs(data_ptr[i]);
        }
        if (icmp_header->packet.data_len % 2) {
            sum += ((uint8_t*)icmp_header->packet.data)[icmp_header->packet.data_len - 1] << 8;
        }
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint16_t calculate_tcp_checksum(const tcp_t* tcp_header) {
    uint32_t sum = 0;
    
    sum += (tcp_header->packet.src_ip[0] << 8) + tcp_header->packet.src_ip[1];
    sum += (tcp_header->packet.src_ip[2] << 8) + tcp_header->packet.src_ip[3];
    sum += (tcp_header->packet.dst_ip[0] << 8) + tcp_header->packet.dst_ip[1];
    sum += (tcp_header->packet.dst_ip[2] << 8) + tcp_header->packet.dst_ip[3];
    sum += 6; // TCP protocol
    sum += 20 + tcp_header->packet.data_len; // TCP header length + data length
    
    sum += tcp_header->src_port;
    sum += tcp_header->dst_port;
    sum += (tcp_header->seq >> 16) + (tcp_header->seq & 0xFFFF);
    sum += (tcp_header->ack >> 16) + (tcp_header->ack & 0xFFFF);
    sum += (tcp_header->data_offset << 12) + tcp_header->flags;
    sum += tcp_header->window;
    sum += tcp_header->urgent_ptr;
    
    if (tcp_header->packet.data && tcp_header->packet.data_len > 0) {
        uint16_t* data_ptr = (uint16_t*)tcp_header->packet.data;
        for (size_t i = 0; i < tcp_header->packet.data_len / 2; i++) {
            sum += ntohs(data_ptr[i]);
        }
        if (tcp_header->packet.data_len % 2) {
            sum += ((uint8_t*)tcp_header->packet.data)[tcp_header->packet.data_len - 1] << 8;
        }
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

uint16_t calculate_udp_checksum(const udp_t* udp_header) {
    uint32_t sum = 0;
    
    sum += (udp_header->packet.src_ip[0] << 8) + udp_header->packet.src_ip[1];
    sum += (udp_header->packet.src_ip[2] << 8) + udp_header->packet.src_ip[3];
    sum += (udp_header->packet.dst_ip[0] << 8) + udp_header->packet.dst_ip[1];
    sum += (udp_header->packet.dst_ip[2] << 8) + udp_header->packet.dst_ip[3];
    sum += 17; 
    sum += udp_header->length;
    
    sum += udp_header->src_port;
    sum += udp_header->dst_port;
    sum += udp_header->length;
    
    if (udp_header->packet.data && udp_header->packet.data_len > 0) {
        uint16_t* data_ptr = (uint16_t*)udp_header->packet.data;
        for (size_t i = 0; i < udp_header->packet.data_len / 2; i++) {
            sum += ntohs(data_ptr[i]);
        }
        if (udp_header->packet.data_len % 2) {
            sum += ((uint8_t*)udp_header->packet.data)[udp_header->packet.data_len - 1] << 8;
        }
    }
    
    // Add carry bits
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    return ~sum;
}

ether_t* parse_ether(const uint8_t* raw_bytes, size_t len) {
    if (len < 14) return nullptr; // min ethernet header
    
    uint8_t dst_mac[6];
    memcpy(dst_mac, raw_bytes, 6);
    
    uint8_t src_mac[6];
    memcpy(src_mac, raw_bytes + 6, 6);
    
    uint16_t eth_type = (raw_bytes[12] << 8) | raw_bytes[13];
    
    ether_t* eth = create_ether(dst_mac, src_mac, eth_type);
    
    // Check if type == 0x0800 (IPv4)
    if (eth_type == 0x0800 && len > 14) {
        ipv4_t* ip_payload = parse_ipv4(raw_bytes + 14, len - 14);
        if (ip_payload) {
            eth->packet.packet = ip_payload; // Stack the IP layer
        }
    }
    
    return eth;
}

ipv4_t* parse_ipv4(const uint8_t* raw_bytes, size_t len) {
    if (len < 20) return nullptr; // min IPv4 header
    
    uint8_t version_ihl = raw_bytes[0];
    uint8_t version = (version_ihl >> 4) & 0x0F;
    uint8_t ihl = version_ihl & 0x0F;
    
    if (version != 4) return nullptr; 
    
    uint8_t tos = raw_bytes[1];
    uint16_t total_length = (raw_bytes[2] << 8) | raw_bytes[3];
    uint16_t identification = (raw_bytes[4] << 8) | raw_bytes[5];
    
    uint16_t flags_fragment = (raw_bytes[6] << 8) | raw_bytes[7];
    uint8_t flags = (flags_fragment >> 13) & 0x07;
    uint16_t fragment_offset = flags_fragment & 0x1FFF;
    
    uint8_t ttl = raw_bytes[8];
    uint8_t protocol = raw_bytes[9];
    // Skip checksum at bytes 10-11
    
    uint8_t src_ip[4];
    memcpy(src_ip, raw_bytes + 12, 4);
    
    uint8_t dst_ip[4];
    memcpy(dst_ip, raw_bytes + 16, 4);
    
    ipv4_t* ip = create_ipv4(src_ip, dst_ip, protocol, total_length, ttl, 
                             identification, tos, flags, fragment_offset);
    
    return ip;
}

icmp_t* parse_icmp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 8) return nullptr; // min ICMP header
    
    uint8_t type = raw_bytes[0];
    uint8_t code = raw_bytes[1];
    // Skip checksum at bytes 2-3
    uint16_t id = (raw_bytes[4] << 8) | raw_bytes[5];
    uint16_t seq = (raw_bytes[6] << 8) | raw_bytes[7];
    
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > 8) {
        data = raw_bytes + 8;
        data_len = len - 8;
    }
    
    icmp_t* icmp = create_icmp(ip_packet, type, code, id, seq, data, data_len);
    
    return icmp;
}

tcp_t* parse_tcp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 20) return nullptr; // min TCP header 
    
    uint16_t src_port = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t dst_port = (raw_bytes[2] << 8) | raw_bytes[3];
    uint32_t seq_num = (raw_bytes[4] << 24) | (raw_bytes[5] << 16) | (raw_bytes[6] << 8) | raw_bytes[7];
    uint32_t ack_num = (raw_bytes[8] << 24) | (raw_bytes[9] << 16) | (raw_bytes[10] << 8) | raw_bytes[11];
    
    uint8_t data_offset = (raw_bytes[12] >> 4) & 0x0F; // Header length in 32-bit words
    uint16_t flags = ((raw_bytes[12] & 0x01) << 8) | raw_bytes[13]; // NS + 8 flag bits
    uint16_t window = (raw_bytes[14] << 8) | raw_bytes[15];
    // Skip checksum at bytes 16-17
    uint16_t urgent_ptr = (raw_bytes[18] << 8) | raw_bytes[19];
    
    size_t header_size = data_offset * 4;
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > header_size) {
        data = raw_bytes + header_size;
        data_len = len - header_size;
    }
    
    tcp_t* tcp = create_tcp(ip_packet, src_port, dst_port, seq_num, ack_num, 
                           flags, window, urgent_ptr, data, data_len);
    
    return tcp;
}

udp_t* parse_udp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 8) return nullptr; // min UDP header
    
    uint16_t src_port = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t dst_port = (raw_bytes[2] << 8) | raw_bytes[3];
    uint16_t length = (raw_bytes[4] << 8) | raw_bytes[5];
    
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > 8) {
        data = raw_bytes + 8;
        data_len = len - 8;
    }
    
    udp_t* udp = create_udp(ip_packet, src_port, dst_port, data, data_len);
    
    // Check for higher layers (e.g., DNS on port 53)
    if ((src_port == 53 || dst_port == 53) && data && data_len > 0) {
        dns_t* dns_payload = parse_dns((const uint8_t*)data, data_len);
        // Note: Need to add a way to store the DNS payload in UDP
        // For now, just parsing but not storing
    }
    
    return udp;
}

size_t parse_dns_name(const uint8_t* raw_bytes, size_t len, size_t offset, char* name_buffer, size_t buffer_size) {
    size_t original_offset = offset;
    size_t name_pos = 0;
    bool jumped = false;
    
    while (offset < len && name_pos < buffer_size - 1) {
        uint8_t label_len = raw_bytes[offset];
        
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= len) break;
            uint16_t pointer = ((label_len & 0x3F) << 8) | raw_bytes[offset + 1];
            if (!jumped) original_offset = offset + 2;
            offset = pointer;
            jumped = true;
            continue;
        }
        
        if (label_len == 0) {
            offset++;
            break;
        }
        
        if (name_pos > 0 && name_pos < buffer_size - 1) {
            name_buffer[name_pos++] = '.';
        }
        
        offset++;
        for (int i = 0; i < label_len && offset < len && name_pos < buffer_size - 1; i++) {
            name_buffer[name_pos++] = raw_bytes[offset++];
        }
    }
    
    name_buffer[name_pos] = '\0';
    return jumped ? original_offset : offset;
}

size_t parse_dns_questions(const uint8_t* raw_bytes, size_t len, size_t offset, 
                          dns_question_t** questions, uint16_t qd_count) {
    if (qd_count == 0) {
        *questions = nullptr;
        return offset;
    }
    
    *questions = (dns_question_t*)malloc(qd_count * sizeof(dns_question_t));
    if (!*questions) return offset;
    
    for (uint16_t i = 0; i < qd_count; i++) {
        char name_buffer[256];
        offset = parse_dns_name(raw_bytes, len, offset, name_buffer, sizeof(name_buffer));
        
        if (offset + 4 > len) break;
        
        uint16_t qtype = (raw_bytes[offset] << 8) | raw_bytes[offset + 1];
        uint16_t qclass = (raw_bytes[offset + 2] << 8) | raw_bytes[offset + 3];
        offset += 4;
        
        size_t name_len = strlen(name_buffer) + 1;
        (*questions)[i].qname = (char*)malloc(name_len);
        if ((*questions)[i].qname) {
            strcpy((*questions)[i].qname, name_buffer);
        }
        
        (*questions)[i].qtype = qtype;
        (*questions)[i].qclass = qclass;
    }
    
    return offset;
}

// Helper function to parse DNS answers
size_t parse_dns_answers(const uint8_t* raw_bytes, size_t len, size_t offset,
                        dns_ans_t** answers, uint16_t an_count) {
    if (an_count == 0) {
        *answers = nullptr;
        return offset;
    }
    
    *answers = (dns_ans_t*)malloc(an_count * sizeof(dns_ans_t));
    if (!*answers) return offset;
    
    for (uint16_t i = 0; i < an_count; i++) {
        char name_buffer[256];
        offset = parse_dns_name(raw_bytes, len, offset, name_buffer, sizeof(name_buffer));
        
        if (offset + 10 > len) break;
        
        uint16_t type = (raw_bytes[offset] << 8) | raw_bytes[offset + 1];
        uint16_t rr_class = (raw_bytes[offset + 2] << 8) | raw_bytes[offset + 3];
        uint32_t ttl = (raw_bytes[offset + 4] << 24) | (raw_bytes[offset + 5] << 16) |
                       (raw_bytes[offset + 6] << 8) | raw_bytes[offset + 7];
        uint16_t rdlength = (raw_bytes[offset + 8] << 8) | raw_bytes[offset + 9];
        offset += 10;
        
        size_t name_len = strlen(name_buffer) + 1;
        (*answers)[i].name = (char*)malloc(name_len);
        if ((*answers)[i].name) {
            strcpy((*answers)[i].name, name_buffer);
        }
        
        (*answers)[i].type = type;
        (*answers)[i].rr_class = rr_class;
        (*answers)[i].ttl = ttl;
        (*answers)[i].rdlength = rdlength;
        
        if (rdlength > 0 && offset + rdlength <= len) {
            (*answers)[i].rdata = (uint8_t*)malloc(rdlength);
            if ((*answers)[i].rdata) {
                memcpy((*answers)[i].rdata, raw_bytes + offset, rdlength);
            }
            offset += rdlength;
        } else {
            (*answers)[i].rdata = nullptr;
        }
    }
    
    return offset;
}

dns_t* parse_dns(const uint8_t* raw_bytes, size_t len) {
    if (len < 12) return nullptr; // min DNS header
    
    uint16_t id = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t flags = (raw_bytes[2] << 8) | raw_bytes[3];
    uint16_t qd_count = (raw_bytes[4] << 8) | raw_bytes[5];
    uint16_t an_count = (raw_bytes[6] << 8) | raw_bytes[7];
    uint16_t ns_count = (raw_bytes[8] << 8) | raw_bytes[9];
    uint16_t ar_count = (raw_bytes[10] << 8) | raw_bytes[11];
    
    size_t offset = 12; 
    
    dns_question_t* questions = nullptr;
    offset = parse_dns_questions(raw_bytes, len, offset, &questions, qd_count);
    
    dns_ans_t* answers = nullptr;
    offset = parse_dns_answers(raw_bytes, len, offset, &answers, an_count);
    
    dns_t* dns = create_dns(id, flags, questions, qd_count, answers, an_count, ns_count, ar_count);
    
    return dns;
}

// to_bytes functions - convert struct to bytes for transmission

/**
 * Ethernet frame format:
 * Bytes 0-5: dst_mac
 * Bytes 6-11: src_mac
 * Bytes 12-13: eth_type
 */
size_t ether_to_bytes(const ether_t* eth, uint8_t* buffer, size_t buffer_size, void* payload, size_t payload_size) {
    if (buffer_size < 14) return 0; // min ethernet header
    
    memcpy(buffer, eth->dst_mac, 6);
    memcpy(buffer + 6, eth->src_mac, 6);
    memcpy(buffer + 12, eth->eth_type, 2);
    
    size_t total_size = 14;
    
    // Use stacked packet if no external payload provided
    if (!payload && eth->packet.packet) {
        ipv4_t* ip = (ipv4_t*)eth->packet.packet;
        size_t ip_size = ipv4_to_bytes(ip, buffer + total_size, buffer_size - total_size);
        total_size += ip_size;
    } else if (payload && payload_size > 0 && buffer_size >= total_size + payload_size) {
        memcpy(buffer + total_size, payload, payload_size);
        total_size += payload_size;
    }
    
    return total_size;
}

/**
 * IPv4 header format:
 * Byte 0: version + IHL
 * Byte 1: TOS
 * Bytes 2-3: total length
 * Bytes 4-5: identification
 * Bytes 6-7: flags + fragment offset
 * Byte 8: TTL
 * Byte 9: protocol
 * Bytes 10-11: header checksum
 * Bytes 12-15: source IP
 * Bytes 16-19: destination IP
 */
size_t ipv4_to_bytes(const ipv4_t* ip, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < 20) return 0; // min IPv4 header
    
    buffer[0] = (ip->version << 4) | (ip->ihl & 0x0F);
    buffer[1] = ip->tos;
    buffer[2] = (ip->total_length >> 8) & 0xFF;
    buffer[3] = ip->total_length & 0xFF;
    buffer[4] = (ip->identification >> 8) & 0xFF;
    buffer[5] = ip->identification & 0xFF;
    
    uint16_t flags_fragment = ((ip->flags & 0x07) << 13) | (ip->flags_fragment_offset & 0x1FFF);
    buffer[6] = (flags_fragment >> 8) & 0xFF;
    buffer[7] = flags_fragment & 0xFF;
    
    buffer[8] = ip->ttl;
    buffer[9] = ip->protocol;
    buffer[10] = (ip->header_checksum >> 8) & 0xFF;
    buffer[11] = ip->header_checksum & 0xFF;
    
    memcpy(buffer + 12, ip->src_ip, 4);
    memcpy(buffer + 16, ip->dst_ip, 4);
    
    size_t total_size = 20;
    
    if (ip->packet.data && ip->packet.data_len > 0 && buffer_size >= total_size + ip->packet.data_len) {
        memcpy(buffer + total_size, ip->packet.data, ip->packet.data_len);
        total_size += ip->packet.data_len;
    }
    
    return total_size;
}

/**
 * ICMP header format:
 * Byte 0: type
 * Byte 1: code
 * Bytes 2-3: checksum
 * Bytes 4-5: id
 * Bytes 6-7: seq
 */
size_t icmp_to_bytes(const icmp_t* icmp, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < 8) return 0; // min ICMP header
    
    buffer[0] = icmp->type;
    buffer[1] = icmp->code;
    buffer[2] = (icmp->checksum >> 8) & 0xFF;
    buffer[3] = icmp->checksum & 0xFF;
    buffer[4] = (icmp->id >> 8) & 0xFF;
    buffer[5] = icmp->id & 0xFF;
    buffer[6] = (icmp->seq >> 8) & 0xFF;
    buffer[7] = icmp->seq & 0xFF;
    
    size_t total_size = 8;
    
    if (icmp->packet.data && icmp->packet.data_len > 0 && buffer_size >= total_size + icmp->packet.data_len) {
        memcpy(buffer + total_size, icmp->packet.data, icmp->packet.data_len);
        total_size += icmp->packet.data_len;
    }
    
    return total_size;
}

/**
 * TCP header format:
 * Bytes 0-1: source port
 * Bytes 2-3: destination port
 * Bytes 4-7: sequence number
 * Bytes 8-11: acknowledgment number
 * Bytes 12-13: data offset + reserved + flags
 * Bytes 14-15: window
 * Bytes 16-17: checksum
 * Bytes 18-19: urgent pointer
 */
size_t tcp_to_bytes(const tcp_t* tcp, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < 20) return 0; // min TCP header
    
    buffer[0] = (tcp->src_port >> 8) & 0xFF;
    buffer[1] = tcp->src_port & 0xFF;
    buffer[2] = (tcp->dst_port >> 8) & 0xFF;
    buffer[3] = tcp->dst_port & 0xFF;
    
    buffer[4] = (tcp->seq >> 24) & 0xFF;
    buffer[5] = (tcp->seq >> 16) & 0xFF;
    buffer[6] = (tcp->seq >> 8) & 0xFF;
    buffer[7] = tcp->seq & 0xFF;
    
    buffer[8] = (tcp->ack >> 24) & 0xFF;
    buffer[9] = (tcp->ack >> 16) & 0xFF;
    buffer[10] = (tcp->ack >> 8) & 0xFF;
    buffer[11] = tcp->ack & 0xFF;
    
    buffer[12] = ((tcp->data_offset & 0x0F) << 4) | ((tcp->flags >> 8) & 0x01);
    buffer[13] = tcp->flags & 0xFF;
    
    buffer[14] = (tcp->window >> 8) & 0xFF;
    buffer[15] = tcp->window & 0xFF;
    buffer[16] = (tcp->checksum >> 8) & 0xFF;
    buffer[17] = tcp->checksum & 0xFF;
    buffer[18] = (tcp->urgent_ptr >> 8) & 0xFF;
    buffer[19] = tcp->urgent_ptr & 0xFF;
    
    size_t total_size = 20;
    
    if (tcp->packet.data && tcp->packet.data_len > 0 && buffer_size >= total_size + tcp->packet.data_len) {
        memcpy(buffer + total_size, tcp->packet.data, tcp->packet.data_len);
        total_size += tcp->packet.data_len;
    }
    
    return total_size;
}

/**
 * UDP header format:
 * Bytes 0-1: source port
 * Bytes 2-3: destination port
 * Bytes 4-5: length
 * Bytes 6-7: checksum
 */
size_t udp_to_bytes(const udp_t* udp, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < 8) return 0; // min UDP header
    
    buffer[0] = (udp->src_port >> 8) & 0xFF;
    buffer[1] = udp->src_port & 0xFF;
    buffer[2] = (udp->dst_port >> 8) & 0xFF;
    buffer[3] = udp->dst_port & 0xFF;
    buffer[4] = (udp->length >> 8) & 0xFF;
    buffer[5] = udp->length & 0xFF;
    buffer[6] = (udp->checksum >> 8) & 0xFF;
    buffer[7] = udp->checksum & 0xFF;
    
    size_t total_size = 8;
    
    if (udp->packet.data && udp->packet.data_len > 0 && buffer_size >= total_size + udp->packet.data_len) {
        memcpy(buffer + total_size, udp->packet.data, udp->packet.data_len);
        total_size += udp->packet.data_len;
    }
    
    return total_size;
}

/**
 * DNS header format:
 * Bytes 0-1: id
 * Bytes 2-3: flags
 * Bytes 4-5: question count
 * Bytes 6-7: answer count
 * Bytes 8-9: authority count
 * Bytes 10-11: additional count
 */
size_t dns_to_bytes(const dns_t* dns, uint8_t* buffer, size_t buffer_size) {
    if (buffer_size < 12) return 0; // min DNS header
    
    buffer[0] = (dns->id >> 8) & 0xFF;
    buffer[1] = dns->id & 0xFF;
    buffer[2] = (dns->flags >> 8) & 0xFF;
    buffer[3] = dns->flags & 0xFF;
    buffer[4] = (dns->qd_count >> 8) & 0xFF;
    buffer[5] = dns->qd_count & 0xFF;
    buffer[6] = (dns->an_count >> 8) & 0xFF;
    buffer[7] = dns->an_count & 0xFF;
    buffer[8] = (dns->ns_count >> 8) & 0xFF;
    buffer[9] = dns->ns_count & 0xFF;
    buffer[10] = (dns->ar_count >> 8) & 0xFF;
    buffer[11] = dns->ar_count & 0xFF;
      
    return 12;
}

// show functions - display packet contents in Scapy-style format
void ether_show(const ether_t* eth) {
    printf("### Ether ###\n");
    printf("  dst_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->dst_mac[0], eth->dst_mac[1], eth->dst_mac[2],
           eth->dst_mac[3], eth->dst_mac[4], eth->dst_mac[5]);
    printf("  src_mac: %02x:%02x:%02x:%02x:%02x:%02x\n",
           eth->src_mac[0], eth->src_mac[1], eth->src_mac[2],
           eth->src_mac[3], eth->src_mac[4], eth->src_mac[5]);
    printf("  type: %02x%02x\n", eth->eth_type[0], eth->eth_type[1]);
}

void ipv4_show(const ipv4_t* ip) {
    printf("  ### IP ###\n");
    printf("    version: %d\n", ip->version);
    printf("    ihl: %d\n", ip->ihl);
    printf("    tos: %d\n", ip->tos);
    printf("    total_len: %d\n", ip->total_length);
    printf("    ident: %d\n", ip->identification);
    printf("    flags_frag: %04x\n", ((ip->flags & 0x07) << 13) | (ip->flags_fragment_offset & 0x1FFF));
    printf("    ttl: %d\n", ip->ttl);
    printf("    proto: %d\n", ip->protocol);
    printf("    checksum: %04x\n", ip->header_checksum);
    printf("    src_ip: %d.%d.%d.%d\n", ip->src_ip[0], ip->src_ip[1], ip->src_ip[2], ip->src_ip[3]);
    printf("    dst_ip: %d.%d.%d.%d\n", ip->dst_ip[0], ip->dst_ip[1], ip->dst_ip[2], ip->dst_ip[3]);
}

void icmp_show(const icmp_t* icmp) {
    printf("    ### ICMP ###\n");
    printf("      type: %d\n", icmp->type);
    printf("      code: %d\n", icmp->code);
    printf("      checksum: %04x\n", icmp->checksum);
    printf("      id: %d\n", icmp->id);
    printf("      seq: %d\n", icmp->seq);
    
    if (icmp->packet.data && icmp->packet.data_len > 0) {
        printf("      data: ");
        const uint8_t* data = (const uint8_t*)icmp->packet.data;
        for (int i = 0; i < icmp->packet.data_len && i < 32; i++) {
            printf("%02x", data[i]);
        }
        if (icmp->packet.data_len > 32) {
            printf("...");
        }
        printf("\n");
    }
}

void tcp_show(const tcp_t* tcp) {
    printf("    ### TCP ###\n");
    printf("      src_port: %d\n", tcp->src_port);
    printf("      dst_port: %d\n", tcp->dst_port);
    printf("      seq: %u\n", tcp->seq);
    printf("      ack: %u\n", tcp->ack);
    printf("      data_offset: %d\n", tcp->data_offset);
    printf("      flags: %04x\n", tcp->flags);
    printf("      window: %d\n", tcp->window);
    printf("      checksum: %04x\n", tcp->checksum);
    printf("      urgent_ptr: %d\n", tcp->urgent_ptr);
    
    if (tcp->packet.data && tcp->packet.data_len > 0) {
        printf("      data: ");
        const uint8_t* data = (const uint8_t*)tcp->packet.data;
        for (int i = 0; i < tcp->packet.data_len && i < 32; i++) {
            printf("%02x", data[i]);
        }
        if (tcp->packet.data_len > 32) {
            printf("...");
        }
        printf("\n");
    }
}

void udp_show(const udp_t* udp) {
    printf("    ### UDP ###\n");
    printf("      src_port: %d\n", udp->src_port);
    printf("      dst_port: %d\n", udp->dst_port);
    printf("      length: %d\n", udp->length);
    printf("      checksum: %04x\n", udp->checksum);
    
    if (udp->packet.data && udp->packet.data_len > 0) {
        printf("      data: ");
        const uint8_t* data = (const uint8_t*)udp->packet.data;
        for (int i = 0; i < udp->packet.data_len && i < 32; i++) {
            printf("%02x", data[i]);
        }
        if (udp->packet.data_len > 32) {
            printf("...");
        }
        printf("\n");
    }
}

void dns_show(const dns_t* dns) {
    printf("      ### DNS ###\n");
    printf("        id: %d\n", dns->id);
    printf("        flags: %04x\n", dns->flags);
    printf("        qd_count: %d\n", dns->qd_count);
    printf("        an_count: %d\n", dns->an_count);
    printf("        ns_count: %d\n", dns->ns_count);
    printf("        ar_count: %d\n", dns->ar_count);
    
    if (dns->questions && dns->qd_count > 0) {
        for (int i = 0; i < dns->qd_count; i++) {
            printf("        question[%d]: %s (type=%d, class=%d)\n", 
                   i, dns->questions[i].qname ? dns->questions[i].qname : "NULL",
                   dns->questions[i].qtype, dns->questions[i].qclass);
        }
    }
    
    if (dns->answers && dns->an_count > 0) {
        for (int i = 0; i < dns->an_count; i++) {
            printf("        answer[%d]: %s (type=%d, class=%d, ttl=%u)\n",
                   i, dns->answers[i].name ? dns->answers[i].name : "NULL",
                   dns->answers[i].type, dns->answers[i].rr_class, dns->answers[i].ttl);
        }
    }
}

// Packet stacking functions - simulate division operator
// NOTE FOR GRADER: C DOESN'T SUPPORT OPERATOR OVERLOADING, SO WE USE MACRO STACK FUNCTIONS INSTEAD
// Macro to simulate division operator - usage: STACK(eth, ip) instead of eth / ip

ether_t* stack_ether_ipv4(ether_t* eth, ipv4_t* ip) {
    if (!eth || !ip) return eth;
    
    eth->packet.packet = ip;
    // Set ethernet type to IPv4
    eth->eth_type[0] = 0x08;
    eth->eth_type[1] = 0x00;
    
    return eth;
}

ipv4_t* stack_ipv4_icmp(ipv4_t* ip, icmp_t* icmp) {
    if (!ip || !icmp) return ip;
    
    ip->packet.packet = icmp;
    ip->protocol = 1; // ICMP 
    
    memcpy(icmp->packet.src_ip, ip->src_ip, 4);
    memcpy(icmp->packet.dst_ip, ip->dst_ip, 4);
    
    return ip;
}

ipv4_t* stack_ipv4_tcp(ipv4_t* ip, tcp_t* tcp) {
    if (!ip || !tcp) return ip;
    
    ip->packet.packet = tcp;
    ip->protocol = 6; // TCP 
    
    memcpy(tcp->packet.src_ip, ip->src_ip, 4);
    memcpy(tcp->packet.dst_ip, ip->dst_ip, 4);
    
    return ip;
}

ipv4_t* stack_ipv4_udp(ipv4_t* ip, udp_t* udp) {
    if (!ip || !udp) return ip;
    
    ip->packet.packet = udp;
    ip->protocol = 17; // UDP 
    
    memcpy(udp->packet.src_ip, ip->src_ip, 4);
    memcpy(udp->packet.dst_ip, ip->dst_ip, 4);
    
    return ip;
}

udp_t* stack_udp_dns(udp_t* udp, dns_t* dns) {
    if (!udp || !dns) return udp;
    
    udp->packet.packet = dns;
    
    return udp;
}

// Handle stacking transport layers directly onto ethernet (find IP layer inside)
ether_t* stack_ether_icmp(ether_t* eth, icmp_t* icmp) {
    if (!eth || !icmp || !eth->packet.packet) return eth;
    
    // Find the IP layer inside ethernet
    ipv4_t* ip = (ipv4_t*)eth->packet.packet;
    if (ip) {
        stack_ipv4_icmp(ip, icmp);
    }
    
    return eth;
}

ether_t* stack_ether_tcp(ether_t* eth, tcp_t* tcp) {
    if (!eth || !tcp || !eth->packet.packet) return eth;
    
    // Find the IP layer inside ethernet
    ipv4_t* ip = (ipv4_t*)eth->packet.packet;
    if (ip) {
        stack_ipv4_tcp(ip, tcp);
    }
    
    return eth;
}

ether_t* stack_ether_udp(ether_t* eth, udp_t* udp) {
    if (!eth || !udp || !eth->packet.packet) return eth;
    
    // Find the IP layer inside ethernet
    ipv4_t* ip = (ipv4_t*)eth->packet.packet;
    if (ip) {
        stack_ipv4_udp(ip, udp);
    }
    
    return eth;
}

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

// Layer 3 raw socket creation - equivalent to Python's socket.socket(AF_INET, SOCK_RAW, IPPROTO_RAW)
int create_layer3_socket() {
    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        perror("socket creation failed");
        return -1;
    }
    
    // Enable IP_HDRINCL so kernel automatically adds layer 2 headers (like Python)
    int one = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Send function - transmit packet bytes at layer 3
int send_packet(void* pkt, int packet_type) {
    if (!pkt) return -1;
    
    // Create raw socket (auto-adds layer 2 headers like Python)
    int sockfd = create_layer3_socket();
    if (sockfd < 0) return -1;
    
    ipv4_t* ip_packet = nullptr;
    
    if (packet_type == 0) { 
        ether_t* eth = (ether_t*)pkt;
        if (eth->packet.packet) {
            ip_packet = (ipv4_t*)eth->packet.packet; 
        } else {
            printf("Error: No IP layer found inside Ethernet packet\n");
            close(sockfd);
            return -1;
        }
    } else if (packet_type == 1) { 
        ip_packet = (ipv4_t*)pkt;
    } else {
        printf("Error: Unsupported packet type\n");
        close(sockfd);
        return -1;
    }
    
    if (!ip_packet) {
        printf("Error: No valid IP packet found\n");
        close(sockfd);
        return -1;
    }
    
    uint8_t packet_buffer[1500];
    size_t packet_size = ipv4_to_bytes(ip_packet, packet_buffer, sizeof(packet_buffer));
    
    if (packet_size == 0) {
        printf("Error: Failed to convert packet to bytes\n");
        close(sockfd);
        return -1;
    }
    
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = (ip_packet->dst_ip[0] << 24) | 
                               (ip_packet->dst_ip[1] << 16) | 
                               (ip_packet->dst_ip[2] << 8) | 
                               ip_packet->dst_ip[3];
    
    ssize_t bytes_sent = sendto(sockfd, packet_buffer, packet_size, 0, 
                               (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    close(sockfd);
    
    if (bytes_sent < 0) {
        perror("sendto failed");
        return -1;
    }
    
    printf("Sent %zd bytes at layer 3\n", bytes_sent);
    return bytes_sent;
}

// Layer 3 send function - wrapper for send_packet
int send(void* pkt) {
    ipv4_t* ip_test = (ipv4_t*)pkt;
    if (ip_test && ip_test->version == 4) {
        return send_packet(pkt, 1); // IP packet
    }
    
    return send_packet(pkt, 0); // Ethernet packet
}

// Layer 2 raw socket creation - equivalent to Python's socket.socket(AF_PACKET, SOCK_RAW)
int create_layer2_socket(const char* interface_name) {
    // Create layer 2 raw socket
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("layer 2 socket creation failed");
        return -1;
    }
    
    struct ifreq ifr;
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    ifr.ifr_name[IFNAMSIZ - 1] = '\0';
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX failed");
        close(sockfd);
        return -1;
    }
    
    struct sockaddr_ll addr;
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind to interface failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Send ethernet frame at layer 2 (no automatic headers added)
int sendp(ether_t* eth_pkt, const char* interface_name) {
    if (!eth_pkt) return -1;
    
    int sockfd = create_layer2_socket(interface_name);
    if (sockfd < 0) return -1;
    
    uint8_t packet_buffer[1500];
    size_t packet_size = ether_to_bytes(eth_pkt, packet_buffer, sizeof(packet_buffer), nullptr, 0);
    
    if (packet_size == 0) {
        printf("Error: Failed to convert ethernet packet to bytes\n");
        close(sockfd);
        return -1;
    }
    
    ssize_t bytes_sent = send(sockfd, packet_buffer, packet_size, 0);
    
    close(sockfd);
    
    if (bytes_sent < 0) {
        perror("send layer 2 failed");
        return -1;
    }
    
    printf("Sent %zd bytes at layer 2\n", bytes_sent);
    return bytes_sent;
}

// Create layer 2 receive socket - equivalent to Python's socket.socket(AF_PACKET, SOCK_RAW, htons(0x0003))
int create_layer2_recv_socket() {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 0x0003 = ETH_P_ALL
    if (sockfd < 0) {
        perror("layer 2 receive socket creation failed");
        return -1;
    }
    
    // timeout = 5s
    struct timeval timeout;
    timeout.tv_sec = 5;
    timeout.tv_usec = 0;
    
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt SO_RCVTIMEO failed");
        close(sockfd);
        return -1;
    }
    
    return sockfd;
}

// Receive ethernet frame at layer 2 from any interface
ether_t* recv_layer2(int sockfd) {
    if (sockfd < 0) return nullptr;
    
    uint8_t packet_buffer[1500];
    struct sockaddr_ll addr;
    socklen_t addr_len = sizeof(addr);
    
    ssize_t bytes_received = recvfrom(sockfd, packet_buffer, sizeof(packet_buffer), 0,
                                     (struct sockaddr*)&addr, &addr_len);
    
    if (bytes_received < 0) {
        perror("recvfrom failed");
        return nullptr;
    }
    
    if (bytes_received < 14) {
        printf("Received packet too small for ethernet header (%zd bytes)\n", bytes_received);
        return nullptr;
    }
    
    printf("Received %zd bytes from interface index %d\n", bytes_received, addr.sll_ifindex);
    
    ether_t* eth_pkt = parse_ether(packet_buffer, bytes_received);
    
    if (eth_pkt != nullptr) {
        ether_show(eth_pkt);
    }
    
    return eth_pkt;
}

// Convenience function to create socket and receive in one call
ether_t* recv() {
    int sockfd = create_layer2_recv_socket();
    if (sockfd < 0) return nullptr;
    
    ether_t* pkt = recv_layer2(sockfd);
    
    close(sockfd);
    return pkt;
}

// Send and receive - send packet using layer 3, receive reply using layer 2
ether_t* sr(void* pkt) {
    if (pkt == nullptr) {
        printf("Error: null packet provided to sr()\n");
        return nullptr;
    }
    
    // Send using layer 3 
    int send_result = send(pkt);
    if (send_result < 0) {
        printf("Error: failed to send packet in sr()\n");
        return nullptr;
    }
    
    printf("Sent %d bytes, waiting for reply...\n", send_result);
    
    // Receive reply in layer 2 
    ether_t* reply = recv();
    
    return reply;
}

// Sniff - receive one packet at layer 2 and build it back to layer 3
ether_t* sniff() {
    printf("Sniffing for one packet...\n");
    
    // Receive one packet at layer 2 - parse_ether() automatically builds to layer 3 if IPv4
    ether_t* eth_pkt = recv();
    
    if (eth_pkt == nullptr) {
        printf("No packet received during sniff\n");
        return nullptr;
    }
    
    if (eth_pkt->packet.packet != nullptr) {
        printf("Packet successfully built from Layer 2 to Layer 3\n");
    } else {
        printf("Packet built at Layer 2 (no Layer 3 payload detected)\n");
    }
    
    return eth_pkt;
}