#include <stdio.h>
#include "malloc.h"


int main() {

    int* ptr = (int*) malloc(sizeof(int));
    free(ptr);

    ptr = (int*) malloc(sizeof(int) * 100);
    free(ptr);

    return 0;
}
