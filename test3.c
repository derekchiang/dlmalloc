#include <stdio.h>
#include "malloc.h"

#define NUM_MALLOCS 800

int main()
{
    int i;
    int *ptrs[NUM_MALLOCS];

    for (i = 0; i < NUM_MALLOCS; i++) {
        ptrs[i] = (int *) malloc(sizeof(int) * (i + 1));
        ptrs[i][i] = i;
    }

    for (i = 0; i < NUM_MALLOCS; i++) {
        free(ptrs[i]);
    }

    return 0;
}
