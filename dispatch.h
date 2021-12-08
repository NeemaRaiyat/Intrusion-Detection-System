#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

/**
 * @brief Creates threadpool and enqueues packets to the shared queue.
 * 
 * @param header The header of the packet containing meta information such as packet length, timestamp etc.
 * @param packet The actual packet itself.
 * @param verbose A flag that determines whether extra information should be printed.
 */
void dispatch(const struct pcap_pkthdr *header, 
              const unsigned char *packet,
              int verbose);

#endif
