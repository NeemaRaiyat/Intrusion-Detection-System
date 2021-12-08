#include "dispatch.h"
#include "analysis.h"
#include "queue.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>

#define NUMTHREADS 4
                      
static struct queue * packet_queue;

// Mutex lock for the shared queue between the threads
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
// Condition variable associated with sending the signal to wake sleeping threads
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

/**
 * @brief Dequeues packets from the shared queue so that it can be analysed.
 * 
 * @param arg The argument passed to each thread (NULL is passed to all threads).
 * @return Void * (NULL for all cases).
 */
void * thread_function(void * arg) {
    struct pcktData * pcktData;
    while (1) {
        pthread_mutex_lock(&queue_mutex);
        while(isEmpty(packet_queue)){
            // Thread falls asleep (and releases mutex lock) while queue is empty to prevent wasting CPU cycles 
            pthread_cond_wait(&queue_cond, &queue_mutex);
        }
        pcktData = packet_queue->head->item;
        dequeue(packet_queue);
        pthread_mutex_unlock(&queue_mutex);
        analyse(pcktData->header, pcktData->packet, pcktData->verbose);     // Packet is analysed
        free(pcktData);     // No memory is leaked
    }
    return NULL;
}

void dispatch(const struct pcap_pkthdr * header, const unsigned char * packet, int verbose) {

    static pthread_t tid[NUMTHREADS];   // Array storing thread ids
    static unsigned int pcount = 0;     // Number of packets

    struct pcktData * currentPacket = malloc(sizeof(struct pcktData));
    !currentPacket ? memoryError() : NULL;
    currentPacket->header = header;
    currentPacket->packet = packet;
    currentPacket->verbose = verbose;

    // First time 'dispatch()' is called, the threadpool and shared queue is created
    if (pcount == 0) {
        packet_queue = createQueue();
        for (int i = 0; i < NUMTHREADS; i++) {
            if (pthread_create(&tid[i], NULL, thread_function, NULL)) {
                fprintf(stderr, "%s","\nERROR: Could not create thread\n");
                fsync(STDERR_FILENO);   // 'fsync()' is used to ensure that the print statement above has finished before exiting
                exit(EXIT_FAILURE);
            }
        }
    }

    // ---------- Mutex lock is obtained to safely enqueue ---------- //
    pthread_mutex_lock(&queue_mutex);
    pcount++;
    enqueue(packet_queue, currentPacket);
    pthread_cond_signal(&queue_cond);	    // Threads waiting on this lock will wake up
    pthread_mutex_unlock(&queue_mutex);
}
