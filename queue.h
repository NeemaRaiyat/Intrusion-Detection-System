#ifndef QUEUE_H
#define QUEUE_H

/**
 * @brief Contains the header of the packet, the packet itself and the verbose flag for the packet.
 * 
 */
struct pcktData {
    const struct pcap_pkthdr * header;
    const unsigned char * packet;
    int verbose;
};

/**
 * @brief Contains a pointer to the pcktData struct and the next element in the queue.
 * 
 */
struct element {
    struct pcktData * item;
    struct element * next;
};

/**
 * @brief Contains pointers to the head and tail of the queue.
 * 
 */
struct queue {
    struct element * head;
    struct element * tail;
};

/**
 * @brief Prints error message to stderr and exits the program with exit code set to failure.
 * 
 * @return Void.
 */
void memoryError(void);

/**
 * @brief Creates a queue.
 * 
 * @return Pointer to a queue struct. 
 */
struct queue * createQueue(void);

/**
 * @brief Determines whether queue is empty.
 * 
 * @param q Pointer to a queue.
 * @return 1 if queue is empty, 0 otherwise.
 */
int isEmpty(struct queue * q);

/**
 * @brief Adds a particular item to the queue.
 * 
 * @param q Pointer to a queue.
 * @param item The packet to be added.
 */
void enqueue(struct queue * q, struct pcktData * item);

/**
 * @brief Removes an item from the queue.
 * 
 * @param q Pointer to a queue.
 */
void dequeue(struct queue * q);

/**
 * @brief Prints the source IP addresses of all packets in the queue.
 * 
 * @param q Pointer to a queue.
 */
void printQueue(struct queue * q);

/**
 * @brief Calculates the size of the queue.
 * 
 * @param q Pointer to a queue.
 * @return The size of the queue.
 */
int size(struct queue * q);

#endif