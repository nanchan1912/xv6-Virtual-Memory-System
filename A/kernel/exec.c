#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "proc.h"
#include "defs.h"
#include "elf.h"
#include "fs.h"
#include "sleeplock.h"
#include "file.h"
#include "stat.h"

// (permissions are derived during vmfault; no helper needed here)

//
// the implementation of the exec() system call
//
int
kexec(char *path, char **argv)
{
  char *s, *last;
  int i, off;
  uint64 argc, sz = 0, sp, ustack[MAXARG], stackbase, old_sz = 0;
  struct elfhdr elf;
  struct inode *ip;
  struct proghdr ph;
  pagetable_t pagetable = 0, oldpagetable;
  struct proc *p = myproc();
  // printf("exec: starting %s\n", path);

  begin_op();

  // Open the executable file.
  if((ip = namei(path)) == 0){
    // printf("exec: namei failed\n");
    end_op();
    return -1;
  }
  ilock(ip);
  // printf("exec: opened file\n");

  // Read the ELF header.
  if(readi(ip, 0, (uint64)&elf, 0, sizeof(elf)) != sizeof(elf)) {
    printf("exec: readi ELF header failed\n");
    goto bad;
  }

  // Is this really an ELF file?
  if(elf.magic != ELF_MAGIC) {
    printf("exec: bad ELF magic\n");
    goto bad;
  }

  if((pagetable = proc_pagetable(p)) == 0) {
    printf("exec: proc_pagetable failed\n");
    goto bad;
  }
  // printf("exec: created pagetable\n");

  // Initialize process lazy exec state
  p->nph = 0;
  // Do NOT reset pgseq - it must be monotonically increasing across exec
  // Scan program headers but do not allocate/load; cache headers for vmfault
  // printf("exec: scanning %d program headers\n", elf.phnum);
  for(i=0, off=elf.phoff; i<elf.phnum && p->nph < 16; i++, off+=sizeof(ph)){
    if(readi(ip, 0, (uint64)&ph, off, sizeof(ph)) != sizeof(ph)) {
      printf("exec: readi program header %d failed\n", i);
      goto bad;
    }
    if(ph.type != ELF_PROG_LOAD)
      continue;
    if(ph.memsz < ph.filesz) {
      printf("exec: ph.memsz < ph.filesz\n");
      goto bad;
    }
    if(ph.vaddr + ph.memsz < ph.vaddr) {
      printf("exec: address overflow\n");
      goto bad;
    }
    // Allow segments starting at 0 (e.g., forktest with -Ttext 0)
    // Runtime protection in vmfault will reject NULL page access
    if(ph.vaddr % PGSIZE != 0) {
      printf("exec: ph.vaddr not page-aligned\n");
      goto bad;
    }
    // Track the maximum virtual size for p->sz
    uint64 end = ph.vaddr + ph.memsz;
    if(end > sz)
      sz = end;
    // Cache minimal header for lazy load
    p->ph[p->nph].vaddr = ph.vaddr;
    p->ph[p->nph].off = ph.off;
    p->ph[p->nph].filesz = ph.filesz;
    p->ph[p->nph].memsz = ph.memsz;
    p->ph[p->nph].flags = ph.flags;
    p->nph++;
  }
  // Keep exec inode for demand paging
  p->execip = ip;
  // Done with log transaction but keep inode reference
  iunlock(ip);
  end_op();
  ip = 0;
  // printf("exec: loaded segments, sz=0x%lx\n", sz);

  p = myproc();
  uint64 oldsz = p->sz;

  // Initialize paging/swap state
  p->rcount = 0;
  p->exec_end = 0;
  p->swapip = 0;
  p->swap_used_count = 0;
  for(int bi=0; bi<1024; bi++) p->swap_used[bi] = 0;
  // Create per-process swap file /pgswpXXXXX
  int pid = p->pid;
  // simple itoa
  int n = pid; char tmp[16]; int ti=0; if(n==0){ tmp[ti++]='0'; }
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
  begin_op();
  struct inode *dp = 0, *sip = 0;
  char nm[DIRSIZ];
  // find parent and name
  if((dp = nameiparent(p->swapname, nm)) != 0){
    ilock(dp);
    if((sip = dirlookup(dp, nm, 0)) == 0){
      // allocate
      sip = ialloc(dp->dev, T_FILE);
      if(sip){
        ilock(sip);
        sip->major = 0; sip->minor = 0; sip->nlink = 1; iupdate(sip);
        if(dirlink(dp, nm, sip->inum) < 0){ iunlockput(sip); sip = 0; }
        else { iunlock(sip); }
      }
    } else {
      // already exists; leave sip as is (unlocked)
    }
    iunlockput(dp);
  }
  end_op();
  p->swapip = sip;

  // Set up stack region lazily: don't allocate; just extend sz to include stack
  sz = PGROUNDUP(sz);
  p->exec_end = sz;
  sp = sz + (USERSTACK)*PGSIZE;
  stackbase = sp - USERSTACK*PGSIZE;
  
  // Set sz and sp BEFORE copyout so vmfault has correct boundaries
  // Do NOT pre-allocate stack pages - let copyout trigger page faults on-demand
  old_sz = p->sz;
  p->sz = sp;
  p->trapframe->sp = sp;
  // printf("exec: setup stack, sp=0x%lx exec_end=0x%lx p->sz=0x%lx\n", sp, p->exec_end, p->sz);

  // Copy argument strings into new stack, remember their
  // addresses in ustack[].
  for(argc = 0; argv[argc]; argc++) {
    if(argc >= MAXARG)
      goto bad;
    sp -= strlen(argv[argc]) + 1;
    sp -= sp % 16; // riscv sp must be 16-byte aligned
    if(sp < stackbase) {
      printf("exec: sp < stackbase\n");
      goto bad;
    }
    if(copyout(pagetable, sp, argv[argc], strlen(argv[argc]) + 1) < 0) {
      printf("exec: copyout argv failed\n");
      goto bad;
    }
    ustack[argc] = sp;
  }
  ustack[argc] = 0;

  // push a copy of ustack[], the array of argv[] pointers.
  sp -= (argc+1) * sizeof(uint64);
  sp -= sp % 16;
  if(sp < stackbase) {
    printf("exec: sp < stackbase (2)\n");
    goto bad;
  }
  if(copyout(pagetable, sp, (char *)ustack, (argc+1)*sizeof(uint64)) < 0) {
    printf("exec: copyout ustack failed\n");
    goto bad;
  }

  // a0 and a1 contain arguments to user main(argc, argv)
  // argc is returned via the system call return
  // value, which goes in a0.
  p->trapframe->a1 = sp;

  // Save program name for debugging.
  for(last=s=path; *s; s++)
    if(*s == '/')
      last = s+1;
  safestrcpy(p->name, last, sizeof(p->name));
    
  // Commit to the user image.
  oldpagetable = p->pagetable;
  p->pagetable = pagetable;
  // process size covers up through the current user stack top
  p->sz = sp;
  p->trapframe->epc = elf.entry;  // initial program counter = main
  p->trapframe->sp = sp; // initial stack pointer
  proc_freepagetable(oldpagetable, oldsz);

  return argc; // this ends up in a0, the first argument to main(argc, argv)

 bad:
  if(pagetable)
    uvmfree(pagetable, p->sz);
  // Restore old sz if exec failed after modifying it
  p->sz = old_sz;
  if(ip){
    iunlockput(ip);
    end_op();
  }
  return -1;
}

// loadseg() is not used in demand-paging version.
