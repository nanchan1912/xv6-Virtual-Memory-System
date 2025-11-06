#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

void deep_stack(void) {
  // Use > 1 page on stack
  char big_array[4096 * 2];
  big_array[0] = 'S';
  big_array[4095] = 'T';
  printf("Accessing second stack page...\n");
  big_array[4096] = 'K';
  printf("Second stack page access successful. %c\n", big_array[4096]);
}

int main(int argc, char *argv[]) {
  printf("Calling function with large stack frame...\n");
  deep_stack();
  printf("Function returned.\n");
  exit(0);
}
