#include "packets.h"

/**
 * Coded with help with of Claude Code CLI & Inline Autocomplete
 * -Jason P
 * 
 */

int main() {
    printf("Hello World!\n");
    
    // First: Test Send_f(pkt) and Sendp(pkt), then confirm over wireshark
    
    printf("\n=== Testing send_f(pkt) ===\n");
    
    // Create an ICMP echo request packet
    uint8_t src_ip[4] = {192, 168, 1, 100};  // VM IP
    uint8_t dst_ip[4] = {8, 8, 8, 8};        // Google DNS
    
    ipv4_t* ip = create_ipv4(src_ip, dst_ip, 1, 28, 64, 0, 0, 0, 0);
    if (!ip) {
        printf("Failed to create IPv4 packet\n");
        return 1;
    }
    
    // Create ICMP echo request
    icmp_t* icmp = create_icmp(ip, 8, 0, 1234, 1, "test", 4);
    if (!icmp) {
        printf("Failed to create ICMP packet\n");
        free(ip);
        return 1;
    }
    
    // Stack IP and ICMP
    ip = stack_ipv4_icmp(ip, icmp);
    
    printf("Sending ICMP echo request to 8.8.8.8...\n");
    
    // Send packet using Layer 3 (send_f)
    int result = send_f(ip);
    
    if (result == 0) {
        printf("✓ Packet sent successfully via Layer 3!\n");
        printf("Check Wireshark for the outgoing ICMP packet\n");
    } else {
        printf("✗ Failed to send packet (error: %d)\n", result);
        printf("Make sure to run with sudo for raw socket access\n");
    }
    
    free(icmp);
    free(ip);
    return 0;
}
