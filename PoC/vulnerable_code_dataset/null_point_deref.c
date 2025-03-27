// Label: vulnerable
#include <stdio.h>

int main() {
    int* ptr = NULL;
    printf("%d\n", *ptr); // Dereferencing NULL
    return 0;
}
