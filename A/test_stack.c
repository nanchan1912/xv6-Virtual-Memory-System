#include "types.h"
#include "stat.h"
#include "user.h"

void deep_stack() {
    char big_array[4096 * 2]; // Use more than one page of stack
    big_array[0] = 'S';       // Access first page
    big_array[4095] = 'T';    // Access first page
    printf(1, "Accessing second stack page...\n");
    big_array[4096] = 'K';    // Access second page, should fault
    printf(1, "Second stack page access successful.\n");
}

int main(void) {
    printf(1, "Calling function with large stack frame...\n");
    deep_stack();
    printf(1, "Function returned.\n");
    exit();
}