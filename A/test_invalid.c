#include "types.h"
#include "stat.h"
#include "user.h"

int main(void) {
    printf(1, "About to access address 0...\n");
    int *p = 0;
    printf(1, "Value is: %d\n", *p); // Should fault and terminate
    printf(1, "This should not be printed.\n");
    exit();
}