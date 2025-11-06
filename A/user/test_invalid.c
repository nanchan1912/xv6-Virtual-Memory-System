#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[]) {
  printf("About to access address 0...\n");
  volatile int *p = 0;
  // Trigger a fault by reading from NULL
  int v = *p;
  printf("This should not print: %d\n", v);
  exit(-1);
}
