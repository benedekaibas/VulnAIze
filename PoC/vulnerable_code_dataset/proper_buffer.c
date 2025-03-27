// Label: safe
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[20];
    strncpy(buffer, "Hello", sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    printf("%s\n", buffer);
    return 0;
}
