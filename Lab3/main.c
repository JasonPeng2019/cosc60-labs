#include "packets.h"
#include <stdlib.h>  // For system() calls

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

//tcp/http
#define TCP_PROTOCOL 6
#define HTTP_PORT 80
#define TCP_HEADER_SIZE 20
#define TCP_SYN 0x02
#define TCP_ACK 0x10
#define TCP_SYN_ACK 0x12
#define TCP_WINDOW_SIZE 8192



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
    
    uint8_t src_ip[4] = {10, 0, 2, 15};  // VM IP
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
    
    if (result > 0) {
        printf("✓ Packet sent successfully via Layer 3 (%d bytes)\r\n", result);
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
    
    int result2 = sendp(eth, "enp0s3");
    
    if (result2 >= 0) {
        printf("✓ Packet sent successfully via Layer 2! (%d bytes)\n", result2);
    } else {
        printf("✗ Failed to send packet (error: %d)\n", result2);
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
    
    // Layer 2 DNS as required: Ether + IP + UDP + DNS
    uint8_t gateway_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};  // Gateway MAC
    uint8_t my_mac[6] = {0x08, 0x00, 0x27, 0x28, 0xb0, 0xf2};        // My MAC
    
    ether_t* dns_eth = create_ether(gateway_mac, my_mac, IPv4_ETYPE);
    if (!dns_eth) {
        printf("Failed to create Ethernet frame for DNS\n");
        free(question);
        free(dns_query);
        free(dns_udp);
        free(dns_ip);
        return 1;
    }
    
    // Create complete IP packet: IP -> UDP -> DNS for sr()
    dns_ip = STACK(dns_ip, STACK(dns_udp, dns_query));
    
    // Also create complete Layer 2 packet for assignment requirement: Ethernet -> IP -> UDP -> DNS
    dns_eth = STACK(dns_eth, dns_ip);
    
    printf("DEBUG: Created Layer 2 DNS packet (Ethernet + IP + UDP + DNS)\n");
    printf("Sending DNS query for vibrantcloud.org via sr()...\n");
    
    // Use sr() with IP packet - sr() handles Layer 3 send + Layer 2 receive
    ether_t* dns_response = sr(dns_ip);
    
    uint8_t vibrant_ip[4] = {8, 8, 8, 8};  // Fallback to Google DNS if DNS fails (8.8.8.8 responds to ICMP)
    
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
        printf("✗ DNS resolution failed, using fallback IP: 8.8.8.8\n");
    }
    
    free(question);
    free(dns_query);
    free(dns_udp);
    free(dns_ip);
    free(dns_eth);
    
    printf("\n=== Comprehensive ICMP Testing to vibrantcloud.org ===\n");
    printf("Target IP: %d.%d.%d.%d\n", vibrant_ip[0], vibrant_ip[1], vibrant_ip[2], vibrant_ip[3]);
    
    // Test 1: send_f() - Layer 3 routing
    printf("\n--- Test 1: send_f() Layer 3 Routing ---\n");
    
    ipv4_t* test1_ip = create_ipv4(src_ip, vibrant_ip, ICMP_PROTOCOL, 
                                   IP_HEADER_SIZE + ICMP_HEADER_SIZE, TTL, 
                                   IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!test1_ip) {
        printf("Failed to create IPv4 packet for Test 1\n");
        return 1;
    }
    
    icmp_t* test1_icmp = create_icmp(test1_ip, PING_TYPE, PING_CODE, PING_ID, 1, "ping", 4);
    if (!test1_icmp) {
        printf("Failed to create ICMP packet for Test 1\n");
        free(test1_ip);
        return 1;
    }
    
    test1_ip = STACK(test1_ip, test1_icmp);
    
    printf("Sending ICMP via Layer 3 routing...\n");
    int test1_result = send_f(test1_ip);
    
    if (test1_result > 0) {
        printf("✓ Test 1 SUCCESS: Layer 3 packet sent (%d bytes)\n", test1_result);
        printf("  Note: Reply may occur but won't be captured by send_f()\n");
    } else {
        printf("✗ Test 1 FAILED: Layer 3 send error (%d)\n", test1_result);
    }
    
    // Test 2: sendp() - Layer 2 direct
    printf("\n--- Test 2: sendp() Layer 2 Direct ---\n");
    
    // Real MAC addresses from your system
    uint8_t real_src_mac[6] = {0x08, 0x00, 0x27, 0x28, 0xb0, 0xf2};  // Your enp0s3 MAC
    uint8_t real_dst_mac[6] = {0x52, 0x55, 0x0a, 0x00, 0x02, 0x02};  // Gateway MAC
    
    ether_t* test2_eth = create_ether(real_dst_mac, real_src_mac, IPv4_ETYPE);
    if (!test2_eth) {
        printf("Failed to create Ethernet frame for Test 2\n");
        free(test1_icmp);
        free(test1_ip);
        return 1;
    }
    
    ipv4_t* test2_ip = create_ipv4(src_ip, vibrant_ip, ICMP_PROTOCOL,
                                   IP_HEADER_SIZE + ICMP_HEADER_SIZE, TTL,
                                   IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!test2_ip) {
        printf("Failed to create IPv4 packet for Test 2\n");
        free(test2_eth);
        free(test1_icmp);
        free(test1_ip);
        return 1;
    }
    
    icmp_t* test2_icmp = create_icmp(test2_ip, PING_TYPE, PING_CODE, PING_ID, 2, "ping", 4);
    if (!test2_icmp) {
        printf("Failed to create ICMP packet for Test 2\n");
        free(test2_ip);
        free(test2_eth);
        free(test1_icmp);
        free(test1_ip);
        return 1;
    }
    
    // Stack: Ethernet -> IP -> ICMP
    test2_eth = STACK(test2_eth, STACK(test2_ip, test2_icmp));
    
    printf("Sending ICMP via Layer 2 direct (real MACs)...\n");
    printf("  Src MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
           real_src_mac[0], real_src_mac[1], real_src_mac[2],
           real_src_mac[3], real_src_mac[4], real_src_mac[5]);
    printf("  Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
           real_dst_mac[0], real_dst_mac[1], real_dst_mac[2],
           real_dst_mac[3], real_dst_mac[4], real_dst_mac[5]);
    
    int test2_result = sendp(test2_eth, "enp0s3");
    
    if (test2_result > 0) {
        printf("✓ Test 2 SUCCESS: Layer 2 packet sent (%d bytes)\n", test2_result);
        printf("  Note: Reply may occur but won't be captured by sendp()\n");
    } else {
        printf("✗ Test 2 FAILED: Layer 2 send error (%d)\n", test2_result);
    }
    
    // Test 3: sr() - Send and capture reply
    printf("\n--- Test 3: sr() Send and Receive ---\n");
    
    ipv4_t* test3_ip = create_ipv4(src_ip, vibrant_ip, ICMP_PROTOCOL,
                                   IP_HEADER_SIZE + ICMP_HEADER_SIZE, TTL,
                                   IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!test3_ip) {
        printf("Failed to create IPv4 packet for Test 3\n");
        free(test2_icmp);
        free(test2_ip);
        free(test2_eth);
        free(test1_icmp);
        free(test1_ip);
        return 1;
    }
    
    icmp_t* test3_icmp = create_icmp(test3_ip, PING_TYPE, PING_CODE, PING_ID, 3, "ping", 4);
    if (!test3_icmp) {
        printf("Failed to create ICMP packet for Test 3\n");
        free(test3_ip);
        free(test2_icmp);
        free(test2_ip);
        free(test2_eth);
        free(test1_icmp);
        free(test1_ip);
        return 1;
    }
    
    test3_ip = STACK(test3_ip, test3_icmp);
    
    printf("Sending ICMP and waiting for reply...\n");
    ether_t* ping_reply = sr(test3_ip);
    
    if (ping_reply) {
        printf("✓ Test 3 SUCCESS: ICMP reply received!\n");
        
        // Parse the ICMP reply
        if (ping_reply->packet.packet) {
            ipv4_t* reply_ip = (ipv4_t*)ping_reply->packet.packet;
            if (reply_ip->packet.packet) {
                icmp_t* reply_icmp = (icmp_t*)reply_ip->packet.packet;
                
                printf("  ICMP Reply Details:\n");
                printf("    Type: %d (0 = Echo Reply)\n", reply_icmp->type);
                printf("    Code: %d\n", reply_icmp->code);
                printf("    ID: %d\n", reply_icmp->id);
                printf("    Sequence: %d\n", reply_icmp->seq);
                printf("    From IP: %d.%d.%d.%d\n", 
                       reply_ip->src_ip[0], reply_ip->src_ip[1], 
                       reply_ip->src_ip[2], reply_ip->src_ip[3]);
                
                if (reply_icmp->type == 0) {
                    printf("  ✓ Valid ICMP Echo Reply received!\n");
                } else {
                    printf("  ⚠ Received ICMP type %d (not Echo Reply)\n", reply_icmp->type);
                }
            } else {
                printf("  ⚠ Reply missing ICMP layer\n");
            }
        } else {
            printf("  ⚠ Reply missing IP layer\n");
        }
        
        free(ping_reply);
    } else {
        printf("✗ Test 3 FAILED: No ICMP reply received\n");
    }
    
    // Cleanup all test structures
    free(test3_icmp);
    free(test3_ip);
    free(test2_icmp);
    free(test2_ip);
    free(test2_eth);
    free(test1_icmp);
    free(test1_ip);
    
    printf("\n=== End Comprehensive ICMP Testing ===\n");

    //////////////////////////////////////////////////////////////////////////////////////////////////////////
    
    printf("\nPress Enter to continue to TCP HTTP test...");
    getchar();
    
    printf("\n=== Testing TCP HTTP GET to vibrantcloud.org ===\n");
    
    // Step 0: Set firewall rule to prevent Linux from sending RST packets
    printf("Setting firewall rule to prevent RST interference...\n");
    int firewall_result = system("sudo iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP");
    if (firewall_result == 0) {
        printf("✓ Firewall rule set successfully\n");
    } else {
        printf("⚠ Warning: Failed to set firewall rule (error: %d)\n", firewall_result);
        printf("  You may need to run this program with sudo privileges\n");
    }
    
    // Step 1: TCP Three-way Handshake
    printf("Starting TCP three-way handshake...\n");
    
    // Generate initial sequence number (random)
    uint32_t initial_seq = 12345;
    uint32_t server_seq = 0;
    uint32_t ack_num = 0;
    
    // SYN Packet (Step 1 of handshake)
    printf("1. Sending SYN packet...\n");
    
    ipv4_t* syn_ip = create_ipv4(src_ip, vibrant_ip, TCP_PROTOCOL, 
                                 IP_HEADER_SIZE + TCP_HEADER_SIZE, TTL,
                                 IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!syn_ip) {
        printf("Failed to create IP packet for SYN\n");
        return 1;
    }
    
    tcp_t* syn_tcp = create_tcp(syn_ip, 12345, HTTP_PORT, initial_seq, 0, 
                               TCP_SYN, TCP_WINDOW_SIZE, 0, NULL, 0);
    if (!syn_tcp) {
        printf("Failed to create SYN packet\n");
        free(syn_ip);
        return 1;
    }
    
    syn_ip = STACK(syn_ip, syn_tcp);
    
    // Send SYN and wait for SYN-ACK
    ether_t* syn_ack_response = sr(syn_ip);
    
    if (syn_ack_response) {
        printf("✓ SYN-ACK received\n");
        
        // Parse SYN-ACK to get server sequence number
        if (syn_ack_response->packet.packet) {
            ipv4_t* response_ip = (ipv4_t*)syn_ack_response->packet.packet;
            if (response_ip->packet.packet) {
                tcp_t* response_tcp = (tcp_t*)response_ip->packet.packet;
                
                // Verify it's a SYN-ACK
                if ((response_tcp->flags & TCP_SYN_ACK) == TCP_SYN_ACK) {
                    server_seq = response_tcp->seq;
                    ack_num = response_tcp->ack;
                    printf("   Server SEQ: %u, ACK: %u\n", server_seq, ack_num);
                } else {
                    printf("⚠ Received TCP packet but not SYN-ACK\n");
                }
            }
        }
        free(syn_ack_response);
    } else {
        printf("✗ No SYN-ACK received\n");
        free(syn_tcp);
        free(syn_ip);
        
        // Cleanup firewall rule before exiting
        system("sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP");
        return 1;
    }
    
    // ACK Packet (Step 3 of handshake)
    printf("2. Sending ACK packet...\n");
    
    ipv4_t* ack_ip = create_ipv4(src_ip, vibrant_ip, TCP_PROTOCOL,
                                 IP_HEADER_SIZE + TCP_HEADER_SIZE, TTL,
                                 IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!ack_ip) {
        printf("Failed to create IP packet for ACK\n");
        free(syn_tcp);
        free(syn_ip);
        return 1;
    }
    
    tcp_t* ack_tcp = create_tcp(ack_ip, 12345, HTTP_PORT, ack_num, server_seq + 1,
                               TCP_ACK, TCP_WINDOW_SIZE, 0, NULL, 0);
    if (!ack_tcp) {
        printf("Failed to create ACK packet\n");
        free(ack_ip);
        free(syn_tcp);
        free(syn_ip);
        return 1;
    }
    
    ack_ip = STACK(ack_ip, ack_tcp);
    
    // Send ACK (no response expected)
    int ack_result = send_f(ack_ip);
    if (ack_result > 0) {
        printf("✓ ACK sent successfully - TCP connection established! (%d bytes)\n", ack_result);
    } else {
        printf("✗ Failed to send ACK (error: %d)\n", ack_result);
    }
    
    // Step 2: HTTP GET Request
    printf("3. Sending HTTP GET request...\n");
    
    // Create HTTP GET request
    const char* http_request = 
        "GET /index.html HTTP/1.1\r\n"
        "Host: vibrantcloud.org\r\n"
        "Connection: close\r\n"
        "\r\n";
    
    size_t http_len = strlen(http_request);
    
    ipv4_t* http_ip = create_ipv4(src_ip, vibrant_ip, TCP_PROTOCOL,
                                  IP_HEADER_SIZE + TCP_HEADER_SIZE + http_len, TTL,
                                  IDENTIFICATION, TOS, FLAGS, FRAGMENT_OFFSET);
    if (!http_ip) {
        printf("Failed to create IP packet for HTTP\n");
        free(ack_tcp);
        free(ack_ip);
        free(syn_tcp);
        free(syn_ip);
        return 1;
    }
    
    tcp_t* http_tcp = create_tcp(http_ip, 12345, HTTP_PORT, ack_num, server_seq + 1,
                                TCP_ACK, TCP_WINDOW_SIZE, 0, http_request, http_len);
    if (!http_tcp) {
        printf("Failed to create HTTP TCP packet\n");
        free(http_ip);
        free(ack_tcp);
        free(ack_ip);
        free(syn_tcp);
        free(syn_ip);
        return 1;
    }
    
    http_ip = STACK(http_ip, http_tcp);
    
    // Send HTTP request and wait for response
    ether_t* http_response = sr(http_ip);
    
    if (http_response) {
        printf("✓ HTTP response received\n");
        
        // Parse HTTP response to extract HTML
        if (http_response->packet.packet) {
            ipv4_t* response_ip = (ipv4_t*)http_response->packet.packet;
            if (response_ip->packet.packet) {
                tcp_t* response_tcp = (tcp_t*)response_ip->packet.packet;
                
                // Check if there's HTTP data in the TCP packet
                if (response_tcp->packet.data && response_tcp->packet.data_len > 0) {
                    printf("\n=== HTTP Response Content ===\n");
                    printf("%.*s\n", (int)response_tcp->packet.data_len, (char*)response_tcp->packet.data);
                    printf("=== End of HTTP Response ===\n");
                } else {
                    printf("⚠ HTTP response contains no data\n");
                }
            }
        }
        free(http_response);
    } else {
        printf("✗ No HTTP response received\n");
    }
    
    // Step 3: Remove firewall rule to restore normal TCP behavior
    printf("Removing firewall rule to restore normal operation...\n");
    int cleanup_result = system("sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP");
    if (cleanup_result == 0) {
        printf("✓ Firewall rule removed successfully\n");
    } else {
        printf("⚠ Warning: Failed to remove firewall rule (error: %d)\n", cleanup_result);
        printf("  You may need to manually run: sudo iptables -D OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP\n");
    }
    
    // Cleanup TCP structures
    free(http_tcp);
    free(http_ip);
    free(ack_tcp);
    free(ack_ip);
    free(syn_tcp);
    free(syn_ip);
    
    return 0;
}
