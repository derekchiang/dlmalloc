#include "memreq.h"

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

char* get_memory(unsigned num_bytes) {
    char *page = sbrk((intptr_t) num_bytes);

    return (page != (char*) -1 ? page : NULL);
}
