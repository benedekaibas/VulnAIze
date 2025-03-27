// Label: safe
#include <stdlib.h>

int main() {
    int* data = (int*)malloc(sizeof(int) * 5);
    if (data != NULL) {
        data[0] = 42;
        free(data);
    }
    return 0;
}
