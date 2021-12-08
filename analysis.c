#include "analysis.h"
#include "queue.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define DEFAULT_ARRAY_CAPACITY 2000

// Mutex lock for accessing static counters
static pthread_mutex_t packet_data_mutex = PTHREAD_MUTEX_INITIALIZER;
// Mutex lock for accessing unique_syn_ips dynamic array (as well as associated static counters)
static pthread_mutex_t unique_syn_ips_mutex = PTHREAD_MUTEX_INITIALIZER;

// ---------- Strings to record all packet data ---------- //
char str_syn_pcount[10] = "0";
char str_size_unique_syn_ips[10] = "0";
char str_arp_responses[10] = "0";
char str_bl_violations[10] = "0";

/**
 * @brief Prints relevant program data once the program is interrupted by a SIGINT signal.
 * 
 * @return Void.
 */
void printData(void) {
    char syn_msg[80] = "";              // SYN Message
    strcat(syn_msg, str_syn_pcount);    // 'strcat()' is signal safe
    strcat(syn_msg, " SYN  packets detected from ");
    strcat(syn_msg, str_size_unique_syn_ips);
    strcat(syn_msg, " different IPs (syn attack)\n");

    char arp_msg[50] = "";              // ARP Message
    strcat(arp_msg, str_arp_responses);
    strcat(arp_msg, " ARP responses (cache poisoning)\n");

    char blv_msg[50] = "";              // Blacklist Violations Message
    strcat(blv_msg, str_bl_violations);
    strcat(blv_msg, " URL Blacklist violations\n");
    
    // Signal Safe alternative to 'printf()'
    write(STDOUT_FILENO, "\n--------------------------------------------", 45);
    write(STDOUT_FILENO, "\nIntrusion Detection Report:\n", 30);
    write(STDOUT_FILENO, syn_msg, 80);
    write(STDOUT_FILENO, arp_msg, 50);
    write(STDOUT_FILENO, blv_msg, 50);
    write(STDOUT_FILENO, "--------------------------------------------\n", 45);
}

/**
 * @brief Signal Handler which uses signal safe functions to print relevant program data and exit.
 * 
 * @param signum The type of signal to handle, in this case CTRL+C (SIGINT).
 * @return Void.
 */
void sig_handler(int signum) {
    printData();
    _exit(EXIT_SUCCESS);    // Signal safe version of 'exit()'
}

/**
 * @brief Determines whether a packet is a SYN packet.
 * 
 * @param tcp_header A pointer to the TCP layer of a particular packet.
 * @return 1 or 0 depending on if its a SYN packet or not respectively.
 */
int isSynPacket(const struct tcphdr * tcp_header) {
    return 
        !tcp_header->fin &&
        !tcp_header->rst &&
        !tcp_header->psh &&
        !tcp_header->ack &&
        !tcp_header->urg &&
        tcp_header->syn;
}

void analyse(const struct pcap_pkthdr * header, const unsigned char * packet, int verbose) {

    // ---------- Variables to record all packet properties ---------- //
    static unsigned int pcount = 0;                 // Number of packets
    static unsigned int syn_pcount = 0;             // Number of SYN packets
    static unsigned int arp_responses = 0;          // Number of ARP responses
    static unsigned int bl_violations = 0;          // Number of Blacklist Violations
    static unsigned int size_unique_syn_ips = 0;    // Current number of unique syn ips
    static unsigned int capacity_unique_syn_ips = DEFAULT_ARRAY_CAPACITY;       // Capacity of unique syn ips array
    static struct in_addr * unique_syn_ips;         // Array to store unique SYN packet ips

    // ---------- Variables to store current packet properties ---------- //
    int isSynPckt = 0;
    int isARPresponse = 0;
    int isBLviolation = 0;
    int isUnique = 1;

    // First time 'analysis()' is called, signal handler and dynamic array is created
    if (pcount == 0) {
        signal(SIGINT, sig_handler);        // Signal Handler for CTRL+C
        unique_syn_ips = (struct in_addr *) malloc(DEFAULT_ARRAY_CAPACITY * sizeof(struct in_addr));
        !unique_syn_ips ? memoryError() : NULL;  // Error handler
    }

    // ---------- Pointers to various packet layers ---------- //
    const struct ip * ip_header = (struct ip *) (packet + ETH_HLEN);
    const struct tcphdr * tcp_header = (struct tcphdr *) (packet + ETH_HLEN + ip_header->ip_hl*4);
    const unsigned char * payload = packet + ETH_HLEN + ip_header->ip_hl*4 + tcp_header->th_off*4;

    // ---------- Checks for SYN Flooding Attack ---------- //
    if (isSynPacket(tcp_header)) {
        unsigned int i;
        pthread_mutex_lock(&unique_syn_ips_mutex);
        for (i = 0; i < size_unique_syn_ips; i++) {     // Loops through ips to check whether current ip is unique
            if (strcmp(inet_ntoa(unique_syn_ips[i]), inet_ntoa(ip_header->ip_src))) {
                pthread_mutex_unlock(&unique_syn_ips_mutex);
                isUnique = 0;   // If a matching ip is found, current IP is no longer unique
                break;
            }
        }
        if (isUnique) {
            if (size_unique_syn_ips == capacity_unique_syn_ips) {       // If array is full, realloc
                capacity_unique_syn_ips *= 2;
                unique_syn_ips = (struct in_addr *) realloc(unique_syn_ips, capacity_unique_syn_ips);
                !unique_syn_ips ? memoryError() : NULL;
            }
            unique_syn_ips[size_unique_syn_ips] = ip_header->ip_src;     // Adds ip to array of unique ips
            size_unique_syn_ips++;
            sprintf(str_size_unique_syn_ips, "%d", size_unique_syn_ips);    // Global string is updated
            pthread_mutex_unlock(&unique_syn_ips_mutex);
        }
        isSynPckt = 1;
    }

    // ---------- Checks for ARP Cache Poisoning ---------- //
    const struct ether_arp * arp_reponse = (struct ether_arp *) (packet + ETH_HLEN);
    if (ntohs(arp_reponse->ea_hdr.ar_op) == 2) {    // Checks if packet has an opcode of 2 and is therefore an ARP response
        isARPresponse = 1;
    }

    // ---------- Checks for Blacklisted URL Violations ---------- //
    const char * bbc = "Host: www.bbc.com";
    const char * google = "Host: www.google.co.uk";

    if (htons(tcp_header->th_dport) == 80) {    // Checks if packet is being sent to port 80 (HTTP)
        if (strstr((char *) payload, bbc) != NULL || strstr((char *) payload, google) != NULL) {      // Checks if application message contains URLs to one of the blacklisted domains
            printf("\n==============================\n");
            printf("Blacklisted URL violation detected\n");
            printf("Source IP address: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP address: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("==============================\n");
            isBLviolation = 1;
        }
    }

    // ---------- Packet Information is printed if verbose flag is true ---------- //
    if (verbose) {
        printf("// ---------------- PACKET INFO ---------------- //\n");
        printf("   Source IP addr: \t%s\n", inet_ntoa(ip_header->ip_src));
        printf("   Dest IP addr: \t%s\n", inet_ntoa(ip_header->ip_dst));
        isSynPckt     ? printf("   Syn Packet:  \tTRUE\n")       : printf("   Syn Packet:  \tFALSE\n");
        isARPresponse ? printf("   ARP Response:  \tTRUE\n")     : printf("   ARP Response:  \tFALSE\n");
        isBLviolation ? printf("   Blacklisted URL: \tTRUE\n")   : printf("   Blacklisted URL: \tFALSE\n");
        printf("   Size (Bytes): \t%u\n", header->len);
        printf("// --------------------------------------------- //\n");
    }

    // ---------- Safely updates static counters ---------- //
    pthread_mutex_lock(&packet_data_mutex);
    syn_pcount += isSynPckt;
    arp_responses += isARPresponse;
    bl_violations += isBLviolation;
    pcount++;
    sprintf(str_syn_pcount, "%d", syn_pcount);
    sprintf(str_arp_responses, "%d", arp_responses);
    sprintf(str_bl_violations, "%d", bl_violations);
    pthread_mutex_unlock(&packet_data_mutex);
}