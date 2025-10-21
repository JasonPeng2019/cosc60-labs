#include "packets.h"
#include <cstdlib>
#include <cstring>

// Ethernet constructor - no packet_t field, no IP info
ether_t* create_ether(const uint8_t dst_mac[6], const uint8_t src_mac[6], uint16_t eth_type) {
    ether_t* eth = (ether_t*)malloc(sizeof(ether_t));
    if (!eth) return nullptr;
    
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
    
    // Add data from packet_t
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
    // Pull src_ip, dst_ip, data, and data_len from packet_t
    uint32_t sum = 0;
    
    // Add pseudo-header
    sum += (tcp_header->packet.src_ip[0] << 8) + tcp_header->packet.src_ip[1];
    sum += (tcp_header->packet.src_ip[2] << 8) + tcp_header->packet.src_ip[3];
    sum += (tcp_header->packet.dst_ip[0] << 8) + tcp_header->packet.dst_ip[1];
    sum += (tcp_header->packet.dst_ip[2] << 8) + tcp_header->packet.dst_ip[3];
    sum += 6; // TCP protocol
    sum += 20 + tcp_header->packet.data_len; // TCP header length + data length
    
    // Add TCP header (simplified)
    sum += tcp_header->src_port;
    sum += tcp_header->dst_port;
    sum += (tcp_header->seq >> 16) + (tcp_header->seq & 0xFFFF);
    sum += (tcp_header->ack >> 16) + (tcp_header->ack & 0xFFFF);
    sum += (tcp_header->data_offset << 12) + tcp_header->flags;
    sum += tcp_header->window;
    sum += tcp_header->urgent_ptr;
    
    // Add data from packet_t
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
    // Pull src_ip, dst_ip, data, and data_len from packet_t
    uint32_t sum = 0;
    
    // Add pseudo-header
    sum += (udp_header->packet.src_ip[0] << 8) + udp_header->packet.src_ip[1];
    sum += (udp_header->packet.src_ip[2] << 8) + udp_header->packet.src_ip[3];
    sum += (udp_header->packet.dst_ip[0] << 8) + udp_header->packet.dst_ip[1];
    sum += (udp_header->packet.dst_ip[2] << 8) + udp_header->packet.dst_ip[3];
    sum += 17; // UDP protocol
    sum += udp_header->length;
    
    // Add UDP header
    sum += udp_header->src_port;
    sum += udp_header->dst_port;
    sum += udp_header->length;
    
    // Add data from packet_t
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

// Parser functions
ether_t* parse_ether(const uint8_t* raw_bytes, size_t len) {
    if (len < 14) return nullptr; // Minimum ethernet header size
    
    // Extract bytes 0-5 for dst_mac
    uint8_t dst_mac[6];
    memcpy(dst_mac, raw_bytes, 6);
    
    // Extract bytes 6-11 for src_mac  
    uint8_t src_mac[6];
    memcpy(src_mac, raw_bytes + 6, 6);
    
    // Extract bytes 12-13 for type
    uint16_t eth_type = (raw_bytes[12] << 8) | raw_bytes[13];
    
    // Call Ether constructor
    ether_t* eth = create_ether(dst_mac, src_mac, eth_type);
    
    // Check if type == 0x0800 (IPv4)
    if (eth_type == 0x0800 && len > 14) {
        // Call IP.from_bytes(raw_bytes[14:]) and set as payload
        ipv4_t* ip_payload = parse_ipv4(raw_bytes + 14, len - 14);
        // Note: Need to add payload field to ether_t or handle this differently
        // For now, just returning the ethernet header
    }
    
    return eth;
}

ipv4_t* parse_ipv4(const uint8_t* raw_bytes, size_t len) {
    if (len < 20) return nullptr; // Minimum IPv4 header size
    
    // Extract fields from IPv4 header
    uint8_t version_ihl = raw_bytes[0];
    uint8_t version = (version_ihl >> 4) & 0x0F;
    uint8_t ihl = version_ihl & 0x0F;
    
    if (version != 4) return nullptr; // Not IPv4
    
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
    
    // Call IPv4 constructor
    ipv4_t* ip = create_ipv4(src_ip, dst_ip, protocol, total_length, ttl, 
                             identification, tos, flags, fragment_offset);
    
    return ip;
}

icmp_t* parse_icmp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 8) return nullptr; // Minimum ICMP header size
    
    // Extract header fields
    uint8_t type = raw_bytes[0];
    uint8_t code = raw_bytes[1];
    // Skip checksum at bytes 2-3
    uint16_t id = (raw_bytes[4] << 8) | raw_bytes[5];
    uint16_t seq = (raw_bytes[6] << 8) | raw_bytes[7];
    
    // Extract data if any
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > 8) {
        data = raw_bytes + 8;
        data_len = len - 8;
    }
    
    // Call the regular constructor with extracted parameters
    icmp_t* icmp = create_icmp(ip_packet, type, code, id, seq, data, data_len);
    
    return icmp;
}

tcp_t* parse_tcp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 20) return nullptr; // Minimum TCP header size
    
    // Extract header fields
    uint16_t src_port = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t dst_port = (raw_bytes[2] << 8) | raw_bytes[3];
    uint32_t seq_num = (raw_bytes[4] << 24) | (raw_bytes[5] << 16) | (raw_bytes[6] << 8) | raw_bytes[7];
    uint32_t ack_num = (raw_bytes[8] << 24) | (raw_bytes[9] << 16) | (raw_bytes[10] << 8) | raw_bytes[11];
    
    uint8_t data_offset = (raw_bytes[12] >> 4) & 0x0F; // Header length in 32-bit words
    uint16_t flags = ((raw_bytes[12] & 0x01) << 8) | raw_bytes[13]; // NS + 8 flag bits
    uint16_t window = (raw_bytes[14] << 8) | raw_bytes[15];
    // Skip checksum at bytes 16-17
    uint16_t urgent_ptr = (raw_bytes[18] << 8) | raw_bytes[19];
    
    // Calculate actual header size and data
    size_t header_size = data_offset * 4;
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > header_size) {
        data = raw_bytes + header_size;
        data_len = len - header_size;
    }
    
    // Call the regular constructor with extracted parameters
    tcp_t* tcp = create_tcp(ip_packet, src_port, dst_port, seq_num, ack_num, 
                           flags, window, urgent_ptr, data, data_len);
    
    return tcp;
}

udp_t* parse_udp(ipv4_t* ip_packet, const uint8_t* raw_bytes, size_t len) {
    if (len < 8) return nullptr; // Minimum UDP header size
    
    // Extract header fields
    uint16_t src_port = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t dst_port = (raw_bytes[2] << 8) | raw_bytes[3];
    uint16_t length = (raw_bytes[4] << 8) | raw_bytes[5];
    // Skip checksum at bytes 6-7
    
    // Extract data
    const void* data = nullptr;
    size_t data_len = 0;
    if (len > 8) {
        data = raw_bytes + 8;
        data_len = len - 8;
    }
    
    // Call the regular constructor with extracted parameters
    udp_t* udp = create_udp(ip_packet, src_port, dst_port, data, data_len);
    
    // Check for higher layers (e.g., DNS on port 53)
    if ((src_port == 53 || dst_port == 53) && data && data_len > 0) {
        // Create DNS object if needed and set as payload
        dns_t* dns_payload = parse_dns((const uint8_t*)data, data_len);
        // Note: Need to add a way to store the DNS payload in UDP
        // For now, just parsing but not storing
    }
    
    return udp;
}

// Helper function to parse DNS names (with compression support)
size_t parse_dns_name(const uint8_t* raw_bytes, size_t len, size_t offset, char* name_buffer, size_t buffer_size) {
    size_t original_offset = offset;
    size_t name_pos = 0;
    bool jumped = false;
    
    while (offset < len && name_pos < buffer_size - 1) {
        uint8_t label_len = raw_bytes[offset];
        
        // Check for compression pointer (top 2 bits set)
        if ((label_len & 0xC0) == 0xC0) {
            if (offset + 1 >= len) break;
            uint16_t pointer = ((label_len & 0x3F) << 8) | raw_bytes[offset + 1];
            if (!jumped) original_offset = offset + 2;
            offset = pointer;
            jumped = true;
            continue;
        }
        
        // End of name
        if (label_len == 0) {
            offset++;
            break;
        }
        
        // Add dot separator (except for first label)
        if (name_pos > 0 && name_pos < buffer_size - 1) {
            name_buffer[name_pos++] = '.';
        }
        
        // Copy label
        offset++;
        for (int i = 0; i < label_len && offset < len && name_pos < buffer_size - 1; i++) {
            name_buffer[name_pos++] = raw_bytes[offset++];
        }
    }
    
    name_buffer[name_pos] = '\0';
    return jumped ? original_offset : offset;
}

// Helper function to parse DNS questions
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
        
        // Allocate and copy name
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
        
        // Allocate and copy name
        size_t name_len = strlen(name_buffer) + 1;
        (*answers)[i].name = (char*)malloc(name_len);
        if ((*answers)[i].name) {
            strcpy((*answers)[i].name, name_buffer);
        }
        
        (*answers)[i].type = type;
        (*answers)[i].rr_class = rr_class;
        (*answers)[i].ttl = ttl;
        (*answers)[i].rdlength = rdlength;
        
        // Copy rdata
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
    if (len < 12) return nullptr; // Minimum DNS header size
    
    // Parse DNS header
    uint16_t id = (raw_bytes[0] << 8) | raw_bytes[1];
    uint16_t flags = (raw_bytes[2] << 8) | raw_bytes[3];
    uint16_t qd_count = (raw_bytes[4] << 8) | raw_bytes[5];
    uint16_t an_count = (raw_bytes[6] << 8) | raw_bytes[7];
    uint16_t ns_count = (raw_bytes[8] << 8) | raw_bytes[9];
    uint16_t ar_count = (raw_bytes[10] << 8) | raw_bytes[11];
    
    size_t offset = 12; // Start after header
    
    // Parse questions
    dns_question_t* questions = nullptr;
    offset = parse_dns_questions(raw_bytes, len, offset, &questions, qd_count);
    
    // Parse answers
    dns_ans_t* answers = nullptr;
    offset = parse_dns_answers(raw_bytes, len, offset, &answers, an_count);
    
    // Call DNS constructor with extracted parameters
    dns_t* dns = create_dns(id, flags, questions, qd_count, answers, an_count, ns_count, ar_count);
    
    return dns;
}