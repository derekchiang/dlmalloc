#include <stdio.h>
#include "malloc.h"

#define NUM_MALLOCS 1000
#define quarter NUM_MALLOCS/4
#define half quarter*2
#define three_q quarter*3

char buf[100];
int main(void)
{
    int i;
    int *ptrs[NUM_MALLOCS];

    for (i = 0; i < half; i++) {
        ptrs[i] = (int *)malloc(sizeof(int) * (i + 1));
        ptrs[i][i] = i;
        printf("%d\n", ptrs[i][i]);
    }

    for (i = quarter; i < half; i++) {
        printf("freeing %d\n", i);
        free(ptrs[i]);
    }

    for (i = half; i < three_q; i++) {
        ptrs[i] = (int *)malloc(sizeof(int) * (i + 1));
        ptrs[i][i] = i;
        printf("half %d\n", ptrs[i][i]);
    }

    for (i = 0; i < quarter; i++)
        free(ptrs[i]);

    for (i = three_q; i < NUM_MALLOCS; i++) {
        ptrs[i] = (int *)malloc(sizeof(int) * (i + 1));
        ptrs[i][i] = i;
        printf("%d\n", ptrs[i][i]);
    }

    for (i = half; i < NUM_MALLOCS; i++)
        free(ptrs[i]);

    return 0;
}
