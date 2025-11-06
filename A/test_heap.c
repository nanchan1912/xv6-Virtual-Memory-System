#include "types.h"
#include "stat.h"
#include "user.h"

int main(void) {
    printf(1, "About to grow heap by one page...\n");
    char *mem = sbrk(4096); // Grow heap by one page
    printf(1, "Heap grown. Now writing to the new page...\n");
    mem[0] = 'A'; // First access, should trigger a page fault
    printf(1, "Write successful. Value is: %c\n", mem[0]);
    exit();
}