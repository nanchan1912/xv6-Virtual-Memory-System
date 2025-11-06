#include "param.h"
#include "types.h"
#include "memlayout.h"
#include "elf.h"
#include "riscv.h"
#include "defs.h"
#include "spinlock.h"
#include "proc.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "stat.h"

 static struct rpage *rpage_find(struct proc *p, uint64 va) {
  for(int i=0;i<p->rcount;i++){
    if(p->rset[i].va == va)
      return &p->rset[i];
  }
  return 0;
 }

 static struct rpage *rpage_touch(struct proc *p, uint64 va) {
  struct rpage *rp = rpage_find(p, va);
  if(rp == 0) {
    if(p->rcount < (int)(sizeof(p->rset)/sizeof(p->rset[0]))){
      rp = &p->rset[p->rcount++];
      rp->va = va;
      rp->dirty = 0;
      rp->in_swap = 0;
      rp->slot = -1;
    } else {
      rp = 0;
    }
  }
  if(rp){
    rp->in_mem = 1;
    rp->seq = p->pgseq++;
  }
  return rp;
 }

 static int swap_alloc_slot(struct proc *p){
  for(int i=0;i<1024;i++){
    if(p->swap_used[i] == 0){
      p->swap_used[i] = 1;
      p->swap_used_count++;
      return i;
    }
  }
  return -1;
 }

 void swap_free_slot(struct proc *p, int slot){
  if(slot>=0 && slot<1024 && p->swap_used[slot]){
    p->swap_used[slot] = 0;
    if(p->swap_used_count>0) p->swap_used_count--;
  }
 }

 static int evict_one(struct proc *p){
  // choose oldest resident in memory (min seq) with valid PTE
  struct rpage *victim = 0;
  int candidates = 0;
  for(int i=0;i<p->rcount;i++){
    struct rpage *rp = &p->rset[i];
    if(rp->in_mem){
      candidates++;
      // Verify PTE is valid before selecting as victim
      pte_t *pte = walk(p->pagetable, rp->va, 0);
      if(pte && (*pte & PTE_V)){
        if(victim == 0 || rp->seq < victim->seq)
          victim = rp;
      }
    }
  }
  if(victim == 0){
    printf("[pid %d] EVICT_FAILED: no valid victim found (candidates=%d, rcount=%d)\n", 
           p->pid, candidates, p->rcount);
    return -1;
  }

  printf("[pid %d] VICTIM va=0x%lx seq=%lu algo=FIFO\n", p->pid, victim->va, (unsigned long)victim->seq);

  // unmap victim
  pte_t *pte = walk(p->pagetable, victim->va, 0);
  if(pte == 0 || (*pte & PTE_V) == 0){
    printf("[pid %d] EVICT_FAILED: victim va=0x%lx has invalid PTE (pte=%p, valid=%lu)\n",
           p->pid, victim->va, pte, pte ? (*pte & PTE_V) : 0);
    return -1;
  }
  uint64 pa = PTE2PA(*pte);

  int is_dirty = victim->dirty || !victim->in_exec; // no backing -> must swap
  
  if(is_dirty){
    int slot = swap_alloc_slot(p);
    if(slot < 0){
      printf("[pid %d] SWAPFULL\n", p->pid);
      setkilled(p);
      return -1;
    }
    
    // Start single transaction for both file creation and write
    begin_op();
    
    // Create swap file on-demand if it doesn't exist
    if(p->swapip == 0){
      // Build swap file name /pgswpXXXXX
      int cpid = p->pid;
      int n = cpid; char tmp[16]; int ti=0; if(n==0){ tmp[ti++]='0'; }
      while(n>0){ tmp[ti++] = '0' + (n%10); n/=10; }
      char pidstr[16]; int pi=0; while(ti>0){ pidstr[pi++] = tmp[--ti]; } pidstr[pi]=0;
      safestrcpy(p->swapname, "/pgswp", sizeof(p->swapname));
      int base = strlen(p->swapname);
      int j=0;
      while(pidstr[j] && base + j + 1 < sizeof(p->swapname)){
        p->swapname[base + j] = pidstr[j];
        j++;
      }
      p->swapname[base + j] = '\0';
      
      struct inode *dp = 0, *sip = 0;
      char nm[DIRSIZ];
      if((dp = nameiparent(p->swapname, nm)) != 0){
        ilock(dp);
        if((sip = dirlookup(dp, nm, 0)) == 0){
          sip = ialloc(dp->dev, T_FILE);
          if(sip){
            ilock(sip);
            sip->major = 0; sip->minor = 0; sip->nlink = 1; iupdate(sip);
            if(dirlink(dp, nm, sip->inum) < 0){ iunlockput(sip); sip = 0; }
            else { iunlock(sip); }
          }
        }
        iunlockput(dp);
      }
      p->swapip = sip;
      if(p->swapip == 0){
        end_op();
        printf("[pid %d] EVICT_FAILED: could not create swap file for va=0x%lx\n", p->pid, victim->va);
        setkilled(p);
        return -1;
      }
    }
    
    // Write page to swap file from kernel memory (BEFORE freeing!)
    printf("[pid %d] DEBUG: About to swap out va=0x%lx pa=0x%lx slot=%d\n", p->pid, victim->va, pa, slot);
    ilock(p->swapip);
    int n = writei(p->swapip, 0, pa, slot*PGSIZE, PGSIZE);
    iunlock(p->swapip);
    end_op();
    
    printf("[pid %d] DEBUG: writei returned %d\n", p->pid, n);
    if(n != PGSIZE){
      setkilled(p);
      printf("[pid %d] EVICT_FAILED: writei returned %d (expected %d) for va=0x%lx slot=%d\n",
             p->pid, n, PGSIZE, victim->va, slot);
      return -1;
    }
    printf("[pid %d] EVICT  va=0x%lx state=dirty\n", p->pid, victim->va);
    printf("[pid %d] SWAPOUT va=0x%lx slot=%d\n", p->pid, victim->va, slot);
    victim->in_swap = 1;
    victim->slot = slot;
    victim->in_mem = 0;
    victim->dirty = 0;
  } else {
    // clean: discard and remove from resident set (can be reloaded from exec)
    printf("[pid %d] EVICT  va=0x%lx state=clean\n", p->pid, victim->va);
    printf("[pid %d] DISCARD va=0x%lx\n", p->pid, victim->va);
    // Remove from resident set by swapping with last entry
    int victim_idx = victim - p->rset;
    if(victim_idx < p->rcount - 1){
      p->rset[victim_idx] = p->rset[p->rcount - 1];
    }
    p->rcount--;
  }
  
  // remove mapping and free memory (AFTER swap write if needed)
  *pte = 0;
  sfence_vma();
  kfree((void*)pa);
  
  return 0;
 }
/*
 * the kernel's page table.
 */
pagetable_t kernel_pagetable;

extern char etext[];  // kernel.ld sets this to end of kernel code.

extern char trampoline[]; // trampoline.S

// Make a direct-map page table for the kernel.
pagetable_t
kvmmake(void)
{
  pagetable_t kpgtbl;

  kpgtbl = (pagetable_t) kalloc();
  memset(kpgtbl, 0, PGSIZE);

  // uart registers
  kvmmap(kpgtbl, UART0, UART0, PGSIZE, PTE_R | PTE_W);

  // virtio mmio disk interface
  kvmmap(kpgtbl, VIRTIO0, VIRTIO0, PGSIZE, PTE_R | PTE_W);

  // PLIC
  kvmmap(kpgtbl, PLIC, PLIC, 0x4000000, PTE_R | PTE_W);

  // map kernel text executable and read-only.
  kvmmap(kpgtbl, KERNBASE, KERNBASE, (uint64)etext-KERNBASE, PTE_R | PTE_X);

  // map kernel data and the physical RAM we'll make use of.
  kvmmap(kpgtbl, (uint64)etext, (uint64)etext, PHYSTOP-(uint64)etext, PTE_R | PTE_W);

  // map the trampoline for trap entry/exit to
  // the highest virtual address in the kernel.
  kvmmap(kpgtbl, TRAMPOLINE, (uint64)trampoline, PGSIZE, PTE_R | PTE_X);

  // allocate and map a kernel stack for each process.
  proc_mapstacks(kpgtbl);
  
  return kpgtbl;
}

// add a mapping to the kernel page table.
// only used when booting.
// does not flush TLB or enable paging.
void
kvmmap(pagetable_t kpgtbl, uint64 va, uint64 pa, uint64 sz, int perm)
{
  if(mappages(kpgtbl, va, sz, pa, perm) != 0)
    panic("kvmmap");
}

// Initialize the kernel_pagetable, shared by all CPUs.
void
kvminit(void)
{
  kernel_pagetable = kvmmake();
}

// Switch the current CPU's h/w page table register to
// the kernel's page table, and enable paging.
void
kvminithart()
{
  // wait for any previous writes to the page table memory to finish.
  sfence_vma();

  w_satp(MAKE_SATP(kernel_pagetable));

  // flush stale entries from the TLB.
  sfence_vma();
}

// Return the address of the PTE in page table pagetable
// that corresponds to virtual address va.  If alloc!=0,
// create any required page-table pages.
//
// The risc-v Sv39 scheme has three levels of page-table
// pages. A page-table page contains 512 64-bit PTEs.
// A 64-bit virtual address is split into five fields:
//   39..63 -- must be zero.
//   30..38 -- 9 bits of level-2 index.
//   21..29 -- 9 bits of level-1 index.
//   12..20 -- 9 bits of level-0 index.
//    0..11 -- 12 bits of byte offset within the page.
pte_t *
walk(pagetable_t pagetable, uint64 va, int alloc)
{
  if(va >= MAXVA)
    panic("walk");

  for(int level = 2; level > 0; level--) {
    pte_t *pte = &pagetable[PX(level, va)];
    if(*pte & PTE_V) {
      pagetable = (pagetable_t)PTE2PA(*pte);
    } else {
      if(!alloc || (pagetable = (pde_t*)kalloc()) == 0)
        return 0;
      memset(pagetable, 0, PGSIZE);
      *pte = PA2PTE(pagetable) | PTE_V;
    }
  }
  return &pagetable[PX(0, va)];
}

// Look up a virtual address, return the physical address,
// or 0 if not mapped.
// Can only be used to look up user pages.
uint64
walkaddr(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  uint64 pa;

  if(va >= MAXVA)
    return 0;

  pte = walk(pagetable, va, 0);
  if(pte == 0)
    return 0;
  if((*pte & PTE_V) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  pa = PTE2PA(*pte);
  return pa;
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa.
// va and size MUST be page-aligned.
// Returns 0 on success, -1 if walk() couldn't
// allocate a needed page-table page.
int
mappages(pagetable_t pagetable, uint64 va, uint64 size, uint64 pa, int perm)
{
  uint64 a, last;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("mappages: va not aligned");

  if((size % PGSIZE) != 0)
    panic("mappages: size not aligned");

  if(size == 0)
    panic("mappages: size");
  
  a = va;
  last = va + size - PGSIZE;
  for(;;){
    if((pte = walk(pagetable, a, 1)) == 0)
      return -1;
    if(*pte & PTE_V)
      panic("mappages: remap");
    *pte = PA2PTE(pa) | perm | PTE_V;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// create an empty user page table.
// returns 0 if out of memory.
pagetable_t
uvmcreate()
{
  pagetable_t pagetable;
  pagetable = (pagetable_t) kalloc();
  if(pagetable == 0)
    return 0;
  memset(pagetable, 0, PGSIZE);
  return pagetable;
}

// Remove npages of mappings starting from va. va must be
// page-aligned. It's OK if the mappings don't exist.
// Optionally free the physical memory.
void
uvmunmap(pagetable_t pagetable, uint64 va, uint64 npages, int do_free)
{
  uint64 a;
  pte_t *pte;

  if((va % PGSIZE) != 0)
    panic("uvmunmap: not aligned");

  for(a = va; a < va + npages*PGSIZE; a += PGSIZE){
    if((pte = walk(pagetable, a, 0)) == 0) // leaf page table entry allocated?
      continue;   
    if((*pte & PTE_V) == 0)  // has physical page been allocated?
      continue;
    if(do_free){
      uint64 pa = PTE2PA(*pte);
      kfree((void*)pa);
    }
    *pte = 0;
  }
}

// Allocate PTEs and physical memory to grow a process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
uint64
uvmalloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz, int xperm)
{
  char *mem;
  uint64 a;

  if(newsz < oldsz)
    return oldsz;

  oldsz = PGROUNDUP(oldsz);
  for(a = oldsz; a < newsz; a += PGSIZE){
    mem = kalloc();
    if(mem == 0){
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
    memset(mem, 0, PGSIZE);
    if(mappages(pagetable, a, PGSIZE, (uint64)mem, PTE_R|PTE_U|xperm) != 0){
      kfree(mem);
      uvmdealloc(pagetable, a, oldsz);
      return 0;
    }
  }
  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
uint64
uvmdealloc(pagetable_t pagetable, uint64 oldsz, uint64 newsz)
{
  if(newsz >= oldsz)
    return oldsz;

  if(PGROUNDUP(newsz) < PGROUNDUP(oldsz)){
    int npages = (PGROUNDUP(oldsz) - PGROUNDUP(newsz)) / PGSIZE;
    uvmunmap(pagetable, PGROUNDUP(newsz), npages, 1);
  }

  return newsz;
}

// Recursively free page-table pages.
// All leaf mappings must already have been removed.
void
freewalk(pagetable_t pagetable)
{
  // there are 2^9 = 512 PTEs in a page table.
  for(int i = 0; i < 512; i++){
    pte_t pte = pagetable[i];
    if((pte & PTE_V) && (pte & (PTE_R|PTE_W|PTE_X)) == 0){
      // this PTE points to a lower-level page table.
      uint64 child = PTE2PA(pte);
      freewalk((pagetable_t)child);
      pagetable[i] = 0;
    } else if(pte & PTE_V){
      panic("freewalk: leaf");
    }
  }
  kfree((void*)pagetable);
}

// Free user memory pages,
// then free page-table pages.
void
uvmfree(pagetable_t pagetable, uint64 sz)
{
  if(sz > 0)
    uvmunmap(pagetable, 0, PGROUNDUP(sz)/PGSIZE, 1);
  freewalk(pagetable);
}

// Given a parent process's page table, copy
// its memory into a child's page table.
// Copies both the page table and the
// physical memory.
// returns 0 on success, -1 on failure.
// frees any allocated pages on failure.
int
uvmcopy(pagetable_t old, pagetable_t new, uint64 sz)
{
  pte_t *pte;
  uint64 pa, i;
  uint flags;
  char *mem;

  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walk(old, i, 0)) == 0)
      continue;   // page table entry hasn't been allocated
    if((*pte & PTE_V) == 0)
      continue;   // physical page hasn't been allocated
    pa = PTE2PA(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto err;
    memmove(mem, (char*)pa, PGSIZE);
    if(mappages(new, i, PGSIZE, (uint64)mem, flags) != 0){
      kfree(mem);
      goto err;
    }
  }
  return 0;

 err:
  uvmunmap(new, 0, i / PGSIZE, 1);
  return -1;
}

// mark a PTE invalid for user access.
// used by exec for the user stack guard page.
void
uvmclear(pagetable_t pagetable, uint64 va)
{
  pte_t *pte;
  
  pte = walk(pagetable, va, 0);
  if(pte == 0)
    panic("uvmclear");
  *pte &= ~PTE_U;
}

// Copy from kernel to user.
// Copy len bytes from src to virtual address dstva in a given page table.
// Return 0 on success, -1 on error.
int
copyout(pagetable_t pagetable, uint64 dstva, char *src, uint64 len)
{
  uint64 n, va0, pa0;
  pte_t *pte;

  while(len > 0){
    va0 = PGROUNDDOWN(dstva);
    if(va0 >= MAXVA)
      return -1;
  
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 0, 0)) == 0) {
        return -1;
      }
    }

    pte = walk(pagetable, va0, 0);
    // forbid copyout over read-only user text pages.
    if((*pte & PTE_W) == 0)
      return -1;
      
    n = PGSIZE - (dstva - va0);
    if(n > len)
      n = len;
    memmove((void *)(pa0 + (dstva - va0)), src, n);

    len -= n;
    src += n;
    dstva = va0 + PGSIZE;
  }
  return 0;
}

// Copy from user to kernel.
// Copy len bytes to dst from virtual address srcva in a given page table.
// Return 0 on success, -1 on error.
int
copyin(pagetable_t pagetable, char *dst, uint64 srcva, uint64 len)
{
  uint64 n, va0, pa0;

  while(len > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0) {
      if((pa0 = vmfault(pagetable, va0, 1, 0)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > len)
      n = len;
    memmove(dst, (void *)(pa0 + (srcva - va0)), n);

    len -= n;
    dst += n;
    srcva = va0 + PGSIZE;
  }
  return 0;
}

// Copy a null-terminated string from user to kernel.
// Copy bytes to dst from virtual address srcva in a given page table,
// until a '\0', or max.
// Return 0 on success, -1 on error.
int
copyinstr(pagetable_t pagetable, char *dst, uint64 srcva, uint64 max)
{
  uint64 n, va0, pa0;
  int got_null = 0;

  while(got_null == 0 && max > 0){
    va0 = PGROUNDDOWN(srcva);
    pa0 = walkaddr(pagetable, va0);
    if(pa0 == 0){
      if((pa0 = vmfault(pagetable, va0, 1, 0)) == 0) {
        return -1;
      }
    }
    n = PGSIZE - (srcva - va0);
    if(n > max)
      n = max;

    char *p = (char *) (pa0 + (srcva - va0));
    while(n > 0){
      if(*p == '\0'){
        *dst = '\0';
        got_null = 1;
        break;
      } else {
        *dst = *p;
      }
      --n;
      --max;
      p++;
      dst++;
    }

    srcva = va0 + PGSIZE;
  }
  if(got_null){
    return 0;
  } else {
    return -1;
  }
}

// allocate and map user memory if process is referencing a page
// that was lazily allocated in sys_sbrk().
// returns 0 if va is invalid or already mapped, or if
// out of physical memory, and physical address if successful.
// read: 0=write, 1=read, 2=instruction fetch
uint64
vmfault(pagetable_t pagetable, uint64 va, int read, int maykill)
{
  uint64 mem;
  struct proc *p = myproc();

  // page-align the faulting address
  uint64 pva = PGROUNDDOWN(va);

  // Disallow any access to the top two user pages (trapframe and trampoline region)
  if(pva >= TRAPFRAME){
    if(maykill){
      printf("[pid %d] KILL invalid-access va=0x%lx access=read\n", p->pid, va);
      p->killed = 1;
    }
    return 0;
  }
  
  // SECURITY: Reject instruction fetch from NULL page (even if data access might be allowed)
  if(pva < PGSIZE && read == 2){
    if(maykill){
      printf("[pid %d] KILL invalid-access va=0x%lx access=exec\n", p->pid, va);
      p->killed = 1;
    }
    return 0;
  }
  
  // If already mapped, handle potential write-fault to set dirty and enable write
  pte_t *pte0 = walk(pagetable, pva, 0);
  if(pte0 && (*pte0 & PTE_V)){
    if(!read){
      if(((*pte0) & PTE_W) == 0){
        // Log write-protection fault
        printf("[pid %d] PAGEFAULT va=0x%lx access=write cause=write-protect\n", p->pid, pva);
        (*pte0) |= PTE_W;
        struct rpage *rp = rpage_find(p, pva);
        if(rp) rp->dirty = 1;
        sfence_vma();
      }
    }
    return PTE2PA(*pte0);
  }

  // Determine valid dynamic regions: heap and stack
  // heap: [exec_end, sz - USERSTACK*PGSIZE)
  // stack: entire configured user stack window to allow argument setup and growth
  int is_stack = (pva >= p->sz - (USERSTACK * PGSIZE) && pva < p->sz);
  int is_heap = (pva >= p->exec_end && pva < (p->sz - (USERSTACK * PGSIZE)) && !is_stack);
  
  // Do NOT modify p->sz here - let exec() and sbrk() manage it

  // Find if within any exec segment
  int is_exec = 0;
  struct vphdr *seg = 0;
  for(int i = 0; i < p->nph; i++){
    struct vphdr *ph = &p->ph[i];
    uint64 seg_start = ph->vaddr;
    uint64 seg_end = ph->vaddr + ph->memsz;
    if(pva >= seg_start && pva < seg_end){
      is_exec = 1;
      seg = ph;
      break;
    }
  }

  // SECURITY: NULL page (0x0-0xFFF) protection - TEMPORARILY DISABLED
  // TODO: Re-enable after debugging why ls accesses address 0
  // if(pva < PGSIZE && !(is_exec || is_heap || is_stack)) {
  //   if(maykill){
  //     printf("INVALID ACCESS pid=%d va=0x%lx\n", p->pid, pva);
  //     setkilled(p);
  //   }
  //   return 0;
  // }

  if(!(is_exec || is_heap || is_stack)){
    // invalid access
    if(maykill){
      printf("[pid %d] KILL invalid-access va=0x%lx access=read\n", p->pid, pva);
      setkilled(p);
    }
    return 0;
  }

  // Allocate a physical page (with replacement on MEMFULL or resident set full)
  mem = (uint64)kalloc();
  if(mem == 0){
    printf("[pid %d] MEMFULL\n", p->pid);
    if(evict_one(p) < 0)
      return 0;
    mem = (uint64)kalloc();
    if(mem == 0)
      return 0;
  }
  
  // If resident set is full, evict a page to make room
  // Count only pages actually in memory, not swapped out
  int in_mem_count = 0;
  for(int i = 0; i < p->rcount; i++){
    if(p->rset[i].in_mem) in_mem_count++;
  }
  if(in_mem_count >= (int)(sizeof(p->rset)/sizeof(p->rset[0]))){
    printf("[pid %d] MEMFULL\n", p->pid);
    if(evict_one(p) < 0){
      if(maykill){
        printf("[pid %d] KILL eviction-failed va=0x%lx\n", p->pid, pva);
        setkilled(p);
      }
      kfree((void*)mem);
      return 0;
    }
  }
  memset((void*)mem, 0, PGSIZE);
  
  int perm = PTE_U | PTE_R; // default: no initial write to enable dirty tracking via write fault

  // Check if this page is swapped out for this process
  struct rpage *rpchk = rpage_find(p, pva);
  if(rpchk && rpchk->in_swap){
    const char *atype = (read == 2) ? "exec" : (read ? "read" : "write");
    printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=swap\n", p->pid, pva, atype);
    if(p->swapip == 0){
      kfree((void*)mem);
      return 0;
    }
    begin_op();
    ilock(p->swapip);
    int rn = readi(p->swapip, 0, mem, rpchk->slot*PGSIZE, PGSIZE);
    iunlock(p->swapip);
    end_op();
    if(rn != PGSIZE){
      kfree((void*)mem);
      return 0;
    }
    // Determine permissions for swapped-in page.
    // Keep read-only initially to preserve dirty tracking; restore execute when needed.
    int perm = PTE_U | PTE_R;
    // If the page belongs to an executable segment, restore execute bit if that segment is executable.
    if(p->nph > 0){
      for(int i = 0; i < p->nph; i++){
        struct vphdr *ph = &p->ph[i];
        if(pva >= ph->vaddr && pva < ph->vaddr + ph->memsz){
          if(ph->flags & 0x1) // PF_X
            perm |= PTE_X;
          break;
        }
      }
    }
    if(mappages(pagetable, pva, PGSIZE, mem, perm) != 0){
      kfree((void*)mem);
      return 0;
    }
    // Defensive check on swap-in mapping as well
    pte_t *vchk2 = walk(pagetable, pva, 0);
    if(vchk2 == 0 || ((*vchk2 & PTE_V) == 0) || ((*vchk2 & PTE_U) == 0)){
      panic("vmfault: swapin map verification failed");
    }
    // clear swap slot
    printf("[pid %d] SWAPIN va=0x%lx slot=%d\n", p->pid, pva, rpchk->slot);
    swap_free_slot(p, rpchk->slot);
    rpchk->in_swap = 0;
    rpchk->slot = -1;
    rpchk->in_mem = 1;
    rpchk->seq = p->pgseq++;
    // Use pgseq-1 for consistency (rpchk->seq contains the value before increment)
    printf("[pid %d] RESIDENT va=0x%lx seq=%lu\n", p->pid, pva, (unsigned long)(p->pgseq - 1));
    return mem;
  }

  if(is_exec){
    // Map permissions from ELF flags
    perm = PTE_U | PTE_R;
    if(seg->flags & 0x2) perm |= PTE_W; // writable (data/bss)
    if(seg->flags & 0x1) perm |= PTE_X; // executable (text)

    // Load from executable inode
    if(p->execip == 0){
      kfree((void*)mem);
      return 0;
    }
    // bytes to read from file for this page
    uint64 page_off = pva - seg->vaddr;
    uint64 file_end = seg->filesz;
    uint64 to_read = 0;
    if(page_off < file_end){
      to_read = file_end - page_off;
      if(to_read > PGSIZE) to_read = PGSIZE;
      ilock(p->execip);
      int rbytes = readi(p->execip, 0, mem, seg->off + page_off, to_read);
      iunlock(p->execip);
      if(rbytes != to_read){
        kfree((void*)mem);
        return 0;
      }
    }
    // Log LOADEXEC event
    printf("[pid %d] LOADEXEC va=0x%lx\n", p->pid, pva);
  } else {
    // heap or stack zero-fill
    // Log ALLOC event
    printf("[pid %d] ALLOC va=0x%lx\n", p->pid, pva);
    // Allow kernel copyout to write into heap/stack immediately
    perm |= PTE_W;
  }

  // Map the page
  if(mappages(pagetable, pva, PGSIZE, mem, perm) != 0){
    kfree((void*)mem);
    return 0;
  }
  // Defensive check: ensure PTE is present & user after mapping
  pte_t *vchk = walk(pagetable, pva, 0);
  if(vchk == 0 || ((*vchk & PTE_V) == 0) || ((*vchk & PTE_U) == 0)){
    panic("vmfault: map verification failed");
  }

  // Log every page fault and residency, as required by the spec
  const char *atype = (read == 2) ? "exec" : (read ? "read" : "write");
  const char *cause = (is_exec ? "exec" : (is_heap ? "heap" : "stack"));
  printf("[pid %d] PAGEFAULT va=0x%lx access=%s cause=%s\n", p->pid, pva, atype, cause);
  struct rpage *rp = rpage_touch(p, pva);
  if(rp){
    rp->in_exec = is_exec && (seg && (pva - seg->vaddr) < seg->filesz);
    // Mark writable pages dirty immediately since we can't trap on first write
    rp->dirty = (perm & PTE_W) ? 1 : 0;
  }
  printf("[pid %d] RESIDENT va=0x%lx seq=%lu\n", p->pid, pva, (unsigned long)(p->pgseq - 1));

  return mem;
}

int
ismapped(pagetable_t pagetable, uint64 va)
{
  pte_t *pte = walk(pagetable, va, 0);
  if (pte == 0) {
    return 0;
  }
  if (*pte & PTE_V){
    return 1;
  }
  return 0;
}
