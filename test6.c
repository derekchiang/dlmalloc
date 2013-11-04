#include <stdio.h>
#include "malloc.h"

#define NUM_MALLOCS 10

int main() {
    int i;
    int* ptrs[NUM_MALLOCS];

    for(i=0; i < NUM_MALLOCS; i++)
        ptrs[i] = malloc(0);

    for(i=0; i <NUM_MALLOCS; i++)
        free(ptrs[i]);

    return 0;
}
