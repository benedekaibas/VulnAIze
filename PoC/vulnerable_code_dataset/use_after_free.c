// Label: vulnerable
#include <stdlib.h>

int main() {
    int* data = (int*)malloc(sizeof(int) * 5);
    free(data);
    data[0] = 42; // Use after free happens here
    return 0;
}
