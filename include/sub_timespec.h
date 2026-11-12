#ifndef SUB_TIMESPEC_H
#define SUB_TIMESPEC_H


#include <time.h>


enum { NS_PER_SECOND = 1000000000 };


long long elapsed_ns(struct timespec start, struct timespec finish) {
    return (finish.tv_sec - start.tv_sec) * 1000000000LL
         + (finish.tv_nsec - start.tv_nsec);
}


#endif