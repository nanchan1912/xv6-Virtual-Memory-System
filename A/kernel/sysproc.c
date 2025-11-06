#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "memstat.h"

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int n;

  argint(0, &n);
  addr = myproc()->sz;
  // Lazily adjust process size without allocating; vmfault() will allocate on first touch.
  if(n == 0)
    return addr;
  struct proc *p = myproc();
  if(n > 0){
    if(addr + n < addr)
      return -1;
    p->sz += n;
    return addr;
  } else {
    // shrink: deallocate any mapped pages beyond new size and cleanup swap slots
    uint64 oldsz = p->sz;
    uint64 newsz = addr + n; // n negative
    if(newsz > oldsz)
      return -1;
    // perform unmap/free of physical pages
    uint64 res = uvmdealloc(p->pagetable, oldsz, newsz);
    p->sz = res;
    // cleanup resident set and swap slots for pages >= PGROUNDUP(newsz)
    uint64 cutoff = PGROUNDUP(newsz);
    for(int i=0;i<p->rcount;i++){
      if(p->rset[i].va >= cutoff){
        if(p->rset[i].in_swap){
          // free occupied swap slot
          // local declaration to match vm.c helpers not visible here
          extern void swap_free_slot(struct proc *p, int slot);
          swap_free_slot(p, p->rset[i].slot);
          p->rset[i].in_swap = 0;
          p->rset[i].slot = -1;
        }
        p->rset[i].in_mem = 0;
        p->rset[i].dirty = 0;
      }
    }
    return addr;
  }
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

// Part 4: Memory statistics syscall
uint64
sys_memstat(void)
{
  uint64 addr;
  struct proc *p = myproc();
  
  argaddr(0, &addr);
  if(addr == 0)
    return -1;
  
  struct proc_mem_stat info;
  info.pid = p->pid;
  info.next_fifo_seq = p->pgseq;
  
  // Count pages and populate info
  int total_pages = 0;
  int resident_pages = 0;
  int swapped_pages = 0;
  int page_idx = 0;
  
  // Iterate through all possible pages in process address space
  for(uint64 va = 0; va < p->sz && page_idx < MAX_PAGES_INFO; va += PGSIZE) {
    pte_t *pte = walk(p->pagetable, va, 0);
    
    // Check if page is in resident set
    struct rpage *rp = 0;
    for(int i = 0; i < p->rcount; i++) {
      if(p->rset[i].va == va) {
        rp = &p->rset[i];
        break;
      }
    }
    
    if(rp) {
      total_pages++;
      
      if(rp->in_swap) {
        // Page is swapped out
        swapped_pages++;
        info.pages[page_idx].va = va;
        info.pages[page_idx].state = SWAPPED;
        info.pages[page_idx].is_dirty = rp->dirty;
        info.pages[page_idx].seq = rp->seq;
        info.pages[page_idx].swap_slot = rp->slot;
        page_idx++;
      } else if(rp->in_mem && pte && (*pte & PTE_V)) {
        // Page is resident in memory
        resident_pages++;
        info.pages[page_idx].va = va;
        info.pages[page_idx].state = RESIDENT;
        info.pages[page_idx].is_dirty = rp->dirty;
        info.pages[page_idx].seq = rp->seq;
        info.pages[page_idx].swap_slot = -1;
        page_idx++;
      }
    } else if(pte && (*pte & PTE_V)) {
      // Page is mapped but not tracked (shouldn't happen in our design)
      total_pages++;
      resident_pages++;
      info.pages[page_idx].va = va;
      info.pages[page_idx].state = RESIDENT;
      info.pages[page_idx].is_dirty = 0;
      info.pages[page_idx].seq = 0;
      info.pages[page_idx].swap_slot = -1;
      page_idx++;
    }
  }
  
  info.num_pages_total = total_pages;
  info.num_resident_pages = resident_pages;
  info.num_swapped_pages = swapped_pages;
  
  // Copy to user space
  if(copyout(p->pagetable, addr, (char*)&info, sizeof(info)) < 0)
    return -1;
  
  return 0;
}
