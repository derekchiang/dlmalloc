#include <stdio.h>
#include <assert.h>
#include "malloc.h"

int main(void)
{
    const int NUM_ALLOCS = 1000;
    void *ptrs[NUM_ALLOCS];
    int i;
    for (i = 0; i < NUM_ALLOCS; i++) {
        ptrs[i] = malloc(i * sizeof(int));
    }

    for (i = 0; i < NUM_ALLOCS; i++) {
        free(ptrs[i]);
    }

    for (i = 0; i < NUM_ALLOCS; i++) {
        ptrs[i] = malloc(i * sizeof(int));
    }

    return 0;
}
