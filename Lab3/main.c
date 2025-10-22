#include "packets.h"

//ipv4
#define ICMP_PROTOCOL 1
#define ICMP_HEADER_SIZE 8
#define IP_HEADER_SIZE 20
#define TTL 64

//ipv4 fields
#define IDENTIFICATION 0
#define TOS 0
#define FLAGS 0
#define FRAGMENT_OFFSET 0

//icmp
#define PING_TYPE 8
#define PING_CODE 0
#define PING_ID 1234

//ethernet
#define IPv4_ETYPE 0x0800

//udp/dns
#define UDP_PROTOCOL 17
#define DNS_PORT 53
#define UDP_HEADER_SIZE 8
#define DNS_HEADER_SIZE 12
#define DNS_PAYLOAD_SIZE 100



/**
 * Coded with help with of Claude Code CLI & Inline Autocomplete
 * -Jason P
 * 
 */

int main() {
    printf("Hello World!\n");
    
//***************************************************************************************************** */
    // First: Test Send_f(pkt) and Sendp(pkt), then confirm over wireshark
    
    printf("\n=== Testing send_f(pkt) ===\n");
    
    uint8_t src_ip[4] = {192, 168, 1, 100};  // VM IP
    uint8_t dst_ip[4] = {8, 8, 8, 8};        // Google DNS

    ipv4_t* ip = create_ipv4(src_ip, dst_ip, ICMP_PROTOCOL, ICMP_HEADER_SIZE+IP_HEADER_SIZE, TTL, IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!ip) {
        printf("Failed to create IPv4 packet\n"); // Use "Failed to create...." often for debugging and identifying
                                                //issues quickly
        return 1;
    }
    
    icmp_t* icmp = create_icmp(ip, PING_TYPE, PING_CODE, PING_ID, 1, "test", 4);
    if (!icmp) {
        printf("Failed to create ICMP packet\n");
        free(ip);
        return 1;
    }
    
    ip = STACK(ip, icmp);
    
    printf("Sending ICMP echo request to 8.8.8.8...\n");
    
    int result = send_f(ip);
    
    if (result == 0) {
        printf("Packet sent successfully via Layer 3\r\n");
    } else {
        printf("✗ Failed to send packet (error: %d)\r\n", result);
    }
    
    free(icmp);
    free(ip);
    
    printf("\nPress Enter to continue to Layer 2 test...");
    getchar();


    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    

    printf("\n=== Testing sendp() ===\n");
    
    uint8_t src_mac[6] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    uint8_t dst_mac[6] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05};
    
    ether_t* eth = create_ether(dst_mac, src_mac, IPv4_ETYPE);
    if (!eth) {
        printf("Failed to create Ethernet frame\n");
        return 1;
    }
    
    ip = create_ipv4(src_ip, dst_ip, ICMP_PROTOCOL, IP_HEADER_SIZE+ICMP_HEADER_SIZE, TTL, IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!ip) {
        printf("Failed to create IPv4 packet\n");
        free(eth);
        return 1;
    }
    
    icmp = create_icmp(ip, PING_TYPE, PING_CODE, PING_ID, 1, "test", 4);
    if (!icmp) {
        printf("Failed to create ICMP packet\n");
        free(ip);
        free(eth);
        return 1;
    }
    
    eth = STACK(eth, STACK(ip, icmp));
    
    printf("Sending Ethernet frame with ICMP payload...\n");
    
    int result2 = sendp(eth, "eth0");
    
    if (result2 == 0) {
        printf("Packet sent successfully via Layer 2!\n");
    } else {
        printf("Failed to send packet (error: %d)\n", result2);
    }
    
    free(icmp);
    free(ip);
    free(eth);

    //***************************************************************************************************** */

    // Wait for user input before continuing
    printf("\nPress Enter to continue to vibrantcloud.org test...");
    getchar();

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    

    //Next: Create a valid ICMP ping packet with all necessary layers. 
    //Send it to a server 
    //Send the packet using your send function at layer 3. 
    //Also send the ICMP packet using your sendp function at layer 2. 
    //Finally, send the packet using your sr function. 
    //Capture on WireShark

    // Get the A record of vibrantcloud.org via DNS
    // Send packet to Google's DNS server (8.8.8.8)
    // Test DNS resolution and ping to vibrantcloud.org

        printf("\n=== Testing DNS resolution and ping to vibrantcloud.org ===\n");
    
    printf("Resolving vibrantcloud.org via DNS...\n");
    
    uint8_t dns_server[4] = {8, 8, 8, 8};  // Google DNS server
    
    dns_question_t* question = create_dns_question("vibrantcloud.org", 1, 1);  // A record, IN class
    if (!question) {
        printf("Failed to create DNS question\n");
        return 1;
    }
    
    dns_t* dns_query = create_dns(1234, 0x0100, question, 1, NULL, 0, 0, 0);  // Standard query
    if (!dns_query) {
        printf("Failed to create DNS query\n");
        free(question);
        return 1;
    }
    
    ipv4_t* dns_ip = create_ipv4(src_ip, dns_server, UDP_PROTOCOL, 
                                IP_HEADER_SIZE + UDP_HEADER_SIZE + DNS_PAYLOAD_SIZE, TTL, 
                                IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!dns_ip) {
        printf("Failed to create IP packet for DNS\n");
        free(question);
        free(dns_query);
        return 1;
    }
    
    udp_t* dns_udp = create_udp(dns_ip, 12345, DNS_PORT, NULL, 0);  // Random src port, dst port 53
    if (!dns_udp) {
        printf("Failed to create UDP packet for DNS\n");
        free(question);
        free(dns_query);
        free(dns_ip);
        return 1;
    }
    
    dns_ip = STACK(dns_ip, STACK(dns_udp, dns_query));
    
    printf("Sending DNS query for vibrantcloud.org...\n");
    
    ether_t* dns_response = sr(dns_ip);
    
    uint8_t vibrant_ip[4] = {1, 1, 1, 1};  // Fallback to Cloudflare if DNS fails r the ping
    
    if (dns_response) {
        printf("DNS response received\n");
        
        if (dns_response->packet.packet) { //check IP
            ipv4_t* response_ip = (ipv4_t*)dns_response->packet.packet;
            if (response_ip->packet.packet) {  // check UDP
                udp_t* response_udp = (udp_t*)response_ip->packet.packet;
                if (response_udp->packet.packet) {  // check DNS
                    dns_t* response_dns = (dns_t*)response_udp->packet.packet;
                    
                    if (response_dns->an_count > 0 && response_dns->answers) {
                        for (int i = 0; i < response_dns->an_count; i++) {
                            dns_ans_t* answer = &response_dns->answers[i];
                            if (answer->type == 1 && answer->rdlength == 4 && answer->rdata) {
                                vibrant_ip[0] = answer->rdata[0];
                                vibrant_ip[1] = answer->rdata[1];
                                vibrant_ip[2] = answer->rdata[2];
                                vibrant_ip[3] = answer->rdata[3];
                                printf("Resolved vibrantcloud.org to: %d.%d.%d.%d\n", 
                                       vibrant_ip[0], vibrant_ip[1], vibrant_ip[2], vibrant_ip[3]);
                                break;  // Use the first A record found
                            }
                        }
                    } else {
                        printf("DNS response contains no A records\n");
                    }
                } else {
                    printf("DNS response missing UDP layer\n");
                }
            } else {
                printf("DNS response missing IP layer\n");
            }
        } else {
            printf("DNS response missing packet dataP\n");
        }
        
        free(dns_response);
    } else {
        printf("✗ DNS resolution failed, using fallback IP: 1.1.1.1\n");
    }
    
    free(question);
    free(dns_query);
    free(dns_udp);
    free(dns_ip);
    
    // Create IPv4 packet for vibrantcloud.org ping
    ipv4_t* vibrant_ip_pkt = create_ipv4(src_ip, vibrant_ip, ICMP_PROTOCOL, 
                                         IP_HEADER_SIZE + ICMP_HEADER_SIZE, TTL, 
                                         IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!vibrant_ip_pkt) {
        printf("Failed to create IPv4 packet for vibrantcloud.org\n");
        return 1;
    }
    
    // Create ICMP ping for vibrantcloud.org
    icmp_t* vibrant_icmp = create_icmp(vibrant_ip_pkt, PING_TYPE, PING_CODE, PING_ID, 3, "ping", 4);
    if (!vibrant_icmp) {
        printf("Failed to create ICMP packet for vibrantcloud.org\n");
        free(vibrant_ip_pkt);
        return 1;
    }
    
    // Stack IP and ICMP
    vibrant_ip_pkt = STACK(vibrant_ip_pkt, vibrant_icmp);
    
    printf("Sending ICMP echo request to 1.1.1.1 (Cloudflare DNS)...\n");
    
    // Send using Layer 3
    int vibrant_result = send_f(vibrant_ip_pkt);
    
    if (vibrant_result == 0) {
        printf("✓ Packet sent successfully to vibrantcloud.org via Layer 3\n");
    } else {
        printf("✗ Failed to send packet to vibrantcloud.org (error: %d)\n", vibrant_result);
    }
    
    // Cleanup
    free(vibrant_icmp);
    free(vibrant_ip_pkt);
    
    return 0;
}
