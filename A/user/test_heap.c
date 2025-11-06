#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int main(int argc, char *argv[]) {
  printf("About to grow heap by one page...\n");
  char *mem = (char *)sbrk(4096);
  if(mem == (char*)-1){
    printf("sbrk failed\n");
    exit(-1);
  }
  printf("Heap grown. Now writing to the new page...\n");
  mem[0] = 'A'; // First access, should trigger a page fault
  printf("Write successful. Value is: %c\n", mem[0]);
  exit(0);
}
