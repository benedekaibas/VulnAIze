// Label: vulnerable
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    strcpy(buffer, "This is too long!");
    return 0;
}
