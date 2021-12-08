#include "queue.h"
#include "analysis.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/ip.h>

void memoryError(void) {
    fprintf(stderr, "%s","\nERROR: Could not allocate memory\n");
    fsync(STDERR_FILENO); // 'fsync()' is used to ensure that the print statement above has finished before exiting
    exit(EXIT_FAILURE);
}

struct queue * createQueue(void) {
    struct queue * q = (struct queue *) malloc(sizeof(struct queue));
    !q ? memoryError() : NULL;
    q->head = NULL;
    q->tail = NULL;
    return q;
}

int isEmpty(struct queue * q) {
    return q->head == NULL;
}

void enqueue(struct queue * q, struct pcktData * item) {
    struct element * elem = (struct element *) malloc(sizeof(struct element));
    !elem ? memoryError() : NULL;
    elem->item = item;
    elem->next = NULL;
    if (isEmpty(q)) {
        q->head = elem;
        q->tail = elem;
        return;
    }
    q->tail->next = elem;
    q->tail = elem;
}

void dequeue(struct queue * q) {
    if (q->head == NULL)  {
        printf("ERROR: Attempt to dequeue from an empty queue\n");
        return;
    }
    struct element * oldHead = q->head;
    q->head = q->head->next;
    if (q->head == NULL) {
        q->tail = NULL;
    }
    free(oldHead);      // No memroy leaked
}

void printQueue(struct queue * q) {
    if (q->head == NULL) {
        printf("Empty Queue\n");
        return;
    }
    struct element * ptr = q->head;
    struct ip * ip_header;
    printf("[");
    while (ptr->next != NULL) {
        ip_header = (struct ip *) (ptr->item->packet + 14);
        printf("%s, ", inet_ntoa(ip_header->ip_src));   // ip address is converted to a string
        ptr = ptr->next;
    }
    ip_header = (struct ip *) (q->tail->item->packet + 14);
    printf("%s]\n", inet_ntoa(ip_header->ip_src));
}

int size(struct queue * q) {
    if (q->head == NULL) {
        return 0;
    }
    int count = 0;
    struct element * ptr = q->head;
    while (ptr != NULL) {
        count++;
        ptr = ptr->next;
    }
    return count;
}