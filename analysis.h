#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

/**
 * @brief Determines whether the packet is a SYN packet, an ARP response and/or being sent to a Blacklisted URL.
 * 
 * Function will never be called with NULL arguments (check is made in "sniff.c").
 * 
 * @param header The header of the packet containing meta information such as packet length, timestamp etc.
 * @param packet The actual packet itself.
 * @param verbose A flag that determines whether extra information should be printed.
 * @return Void.
 */
void analyse(const struct pcap_pkthdr * header,
              const unsigned char *packet,
              int verbose);

#endif
