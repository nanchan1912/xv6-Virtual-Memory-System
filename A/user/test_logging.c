#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

// Test program to verify all logging events

int main(void) {
  printf("=== Testing Part 4 Logging ===\n");
  
  // Test 1: ALLOC (heap allocation)
  printf("\n[TEST 1] Allocating heap memory...\n");
  char *p = sbrk(4096);
  if(p == (char*)-1){
    printf("sbrk failed\n");
    exit(1);
  }
  *p = 'A'; // Trigger page fault -> ALLOC -> RESIDENT
  printf("Heap allocated successfully\n");
  
  // Test 2: More allocations to see seq numbers
  printf("\n[TEST 2] Allocating more pages...\n");
  for(int i = 0; i < 5; i++){
    char *q = sbrk(4096);
    if(q == (char*)-1){
      printf("sbrk failed at iteration %d\n", i);
      exit(1);
    }
    *q = 'B'; // Trigger ALLOC -> RESIDENT with increasing seq
  }
  printf("Multiple pages allocated\n");
  
  // Test 3: Invalid access (should trigger KILL)
  printf("\n[TEST 3] Testing invalid access...\n");
  printf("This test would crash the process, so skipping\n");
  // char *bad = (char*)0xFFFFFFFFFFFF;
  // *bad = 'X'; // Would trigger KILL invalid-access
  
  printf("\n=== All tests completed ===\n");
  printf("Check kernel logs for:\n");
  printf("- [pid X] PAGEFAULT va=... access=write cause=heap\n");
  printf("- [pid X] ALLOC va=...\n");
  printf("- [pid X] RESIDENT va=... seq=...\n");
  printf("- Sequence numbers should be 0, 1, 2, 3, 4, 5\n");
  
  exit(0);
}
